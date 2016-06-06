#
# Copyright (c) 2008-2015 Hans van Kranenburg <hans.van.kranenburg@mendix.com>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# .
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of Mendix nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
# .
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL MENDIX BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import dns.resolver
import logging
import re

logger = logging.getLogger("oinkwall")


class OinkwallException(Exception):
    pass


class IPTables:
    def __init__(self):

        self.tables_noipv6nat = {
            4: ['raw', 'mangle', 'nat', 'filter'],
            6: ['raw', 'mangle', 'filter']
        }
        self.tables_ipv6nat = {
            4: ['raw', 'mangle', 'nat', 'filter'],
            6: ['raw', 'mangle', 'nat', 'filter']
        }
        self.tables = self.tables_noipv6nat

        self.default_chains = {
            'raw': ['PREROUTING', 'OUTPUT'],
            'mangle': ['PREROUTING', 'INPUT', 'FORWARD', 'OUTPUT', 'POSTROUTING'],
            'nat': ['PREROUTING', 'POSTROUTING', 'OUTPUT'],
            'filter': ['INPUT', 'FORWARD', 'OUTPUT'],
        }
        self.default_policy = {
            'raw': 'ACCEPT',
            'mangle': 'ACCEPT',
            'nat': 'ACCEPT',
            'filter': 'DROP',
        }

        self.rules = {}
        self.custom_chains = {}
        self.override_policy = {}
        for ipv in [4, 6]:
            self.rules[ipv] = {}
            self.custom_chains[ipv] = {}
            self.override_policy[ipv] = {}
            for table in self.tables_ipv6nat[ipv]:
                self.rules[ipv][table] = {}
                self.override_policy[ipv][table] = {}
                self.custom_chains[ipv][table] = []
                for chain in self.default_chains[table]:
                    self.rules[ipv][table][chain] = []

    def enable_ipv6_nat(self, enable=True):
        if enable:
            self.tables = self.tables_ipv6nat
        else:
            self.tables = self.tables_noipv6nat

    def add(self, rulesets):
        for ruleset in flatten(rulesets):
            for ipv in [4, 6]:
                if len(ruleset.rules[ipv]) == 0:
                    continue

                if ruleset.table not in self.tables[ipv]:
                    other_ipv = (set([4, 6]) - set([ipv])).pop()
                    if ruleset.table in self.tables[other_ipv]:
                        logger.warning('Not generating %s rules, table: %s, table only '
                                       'valid for: %s' % (ipv, ruleset.table, other_ipv))
                    else:
                        logger.error('Table %s for %s is not valid! has to be one of %s' %
                                     (ruleset.table, ipv, self.tables[ipv]))
                    continue

                if ((ruleset.chain not in self.default_chains[ruleset.table]
                     and ruleset.chain not in self.custom_chains[ipv][ruleset.table])):
                    logger.error('Chain %s is not available for use in %s table %s!' %
                                 (ruleset.chain, ipv, ruleset.table))
                    continue

                self.rules[ipv][ruleset.table][ruleset.chain].extend(
                    ruleset.rules[ipv])

    def add_custom_chain(self, table, chain, ipv=None):
        if ipv is None:
            ipv = [4, 6]
        for ipvx in flatten(ipv):
            if table not in self.tables[ipvx]:
                logger.error('Table %s for %s is not valid! has to be one of %s' %
                             (table, ipvx, self.tables[ipvx]))
                continue

            if chain in self.default_chains[table]:
                logger.warning('Chain %s is a built-in chain for ipv: %s, table %s, '
                               'ignoring' % (chain, table, ipvx))
                continue

            if chain not in self.custom_chains[ipvx][table]:
                self.custom_chains[ipvx][table].append(chain)
                self.rules[ipvx][table][chain] = []

    def set_policy(self, table, chain, target, ipv=None):
        if ipv is None:
            ipv = [4, 6]
        for p in ipv:
            self.override_policy[p][table][chain] = target

    def get_iptables_restore_script(self, ipv=4):
        lines = []
        for table in self.tables[ipv]:
            lines.append('*%s' % table)

            for chain in self.default_chains[table]:
                policy = self.override_policy[ipv][table].get(
                    chain,
                    self.default_policy[table])
                lines.append(':%s %s [0:0]' % (chain, policy))

            for chain in self.custom_chains[ipv][table]:
                lines.append(':%s - [0:0]' % chain)

            for chain in self.default_chains[table]:
                for rule in self.rules[ipv][table][chain]:
                    if 'comment' in rule:
                        lines.append('# %s' % rule['comment'])
                    s = []
                    if 'command' in rule:
                        s.append('-%s %s' % (rule['command'], rule['chain']))
                        for c in ['i', 'o', 's', 'd']:
                            if c in rule:
                                s.append('-%s %s' % (c, rule[c]))
                        if 'r' in rule:
                            s.append(rule['r'])
                        if len(s) > 0:
                            lines.append(' '.join(s))
                    elif 'comment' not in rule:
                        logger.error('No command specified, and not a comment-only '
                                     'rule: %s' % rule)
            lines.append('COMMIT')
        lines.append('')
        return '\n'.join(lines)

    def get_ip6tables_restore_script(self):
        return self.get_iptables_restore_script(6)


class IPTablesRuleset:
    """ list of firewall rules """

    wannaio = {
        'INPUT': 'i',
        'OUTPUT': 'o',
        'PREROUTING': 'i',
        'POSTROUTING': 'o',
        'FORWARD': 'io',
    }

    def __init__(self, table, chain):
        self.table = table
        self.chain = chain
        self.rules = {4: [], 6: []}

    def add(self, command='A', i=None, o=None, s=None, d=None, r=None, comment=None):
        if i is None:
            i = []
        else:
            i = [{4: x, 6: x} if isinstance(x, str) else x for x in flatten(i)]
        if o is None:
            o = []
        else:
            o = [{4: x, 6: x} if isinstance(x, str) else x for x in flatten(o)]

        if s is None:
            s = []
        if d is None:
            d = []

        if len(i) > 0 and 'i' not in IPTablesRuleset.wannaio.get(self.chain, 'i'):
            logger.warning('Input interface %s set on %s rule (o=%s, s=%s, d=%s, r=%s) '
                           'will be ignored' % (i, self.chain, o, s, d, r))
            i = []
        if len(o) > 0 and 'o' not in IPTablesRuleset.wannaio.get(self.chain, 'o'):
            logger.warning('Output interface %s set on %s rule (i=%s, s=%s, d=%s, r=%s) '
                           'will be ignored' % (o, self.chain, i, s, d, r))
            o = []

        i4 = [iface for iface in i if 4 in iface]
        i6 = [iface for iface in i if 6 in iface]
        o4 = [iface for iface in o if 4 in iface]
        o6 = [iface for iface in o if 6 in iface]

        has_i4 = len(i4) > 0
        has_i6 = len(i6) > 0
        has_o4 = len(o4) > 0
        has_o6 = len(o6) > 0

        # When both input and output interfaces are set, and we care about them
        # (forward-rules), prevent generating input/output-only rules.
        # e.g.: i=if_vpn4, o=[if_lan4, if_lan6, if_vpn4] must not result in
        #       a rule to be added with i=[], o=[if_lan6]
        #
        # The same holds for combinations of ipv4 and ipv6 source and destination
        # addresses.
        # e.g.: s=[ipv4, ipv4], d=[ipv4, ipv6] must not result in a rule to be
        #       added with s=[], d=[ipv6]
        #
        # Cases that point at broken logic in the input trigger a warning.
        has4_has6_do46_w46 = {
            # is4,  od4,   is6,   od6,     do4,   do6,   warn4, warn6
            (False, False, False, False): (True,  True,  False, False),
            (False, False, False, True):  (False, True,  False, False),
            (False, False, True,  False): (False, True,  False, False),
            (False, False, True,  True):  (False, True,  False, False),

            (False, True,  False, False): (True,  False, False, False),
            (False, True,  False, True):  (True,  True,  False, False),
            (False, True,  True,  False): (False, False, True,  True),
            (False, True,  True,  True):  (False, True,  True,  False),

            (True,  False, False, False): (True,  False, False, False),
            (True,  False, False, True):  (False, False, True,  True),
            (True,  False, True,  False): (True,  True,  False, False),
            (True,  False, True,  True):  (False, True,  True,  False),

            (True,  True,  False, False): (True,  False, False, False),
            (True,  True,  False, True):  (True,  False, False, True),
            (True,  True,  True,  False): (True,  False, False, True),
            (True,  True,  True,  True):  (True,  True,  False, False),
        }

        if (('i' in IPTablesRuleset.wannaio[self.chain] and
             'o' in IPTablesRuleset.wannaio[self.chain])):
            do_io_4, do_io_6, warn_io_4, warn_io_6 = (
                has4_has6_do46_w46[(has_i4, has_o4, has_i6, has_o6)])

            if warn_io_4 and warn_io_6:
                assert do_io_4 is False and do_io_6 is False
                logger.warning('Not generating any IPv4/IPv6 rule, your input logic '
                               'is likely broken: i4=%s, o4=%s, i6=%s, o6=%s' %
                               (i4, o4, i6, o6))
            elif warn_io_4:
                assert do_io_4 is False
                logger.debug('Ignoring IPv4 interface: i4=%s, o4=%s, i6=%s, o6=%s' %
                             (i4, o4, i6, o6))
            elif warn_io_6:
                assert do_io_6 is False
                logger.debug('Ignoring IPv6 interface: i4=%s, o4=%s, i6=%s, o6=%s' %
                             (i4, o4, i6, o6))
        else:
            do_io_4, do_io_6 = (True, True)

        s = flatten(s)
        s4, s6 = parse_address_list(s)
        d = flatten(d)
        d4, d6 = parse_address_list(d)

        has_io4 = len(i4) + len(o4) > 0
        has_io6 = len(i6) + len(o6) > 0

        has_s4 = len(s4) > 0
        has_s6 = len(s6) > 0
        has_d4 = len(d4) > 0
        has_d6 = len(d6) > 0
        has_sd4 = has_s4 and has_d4
        has_sd6 = has_s6 and has_d6

        # Based on the presence of input/output interface definitions and
        # source/destionation address lists, we filter out unwanted
        # combinations.
        io46_sd46_do46_w46 = {
            # io4,   io6,   sd4,   sd6,     do4,   do6,   warn4, warn6
            (False, False, False, False): (True,  True,  False, False),
            (False, False, False, True):  (False, True,  False, False),
            (False, False, True,  False): (True,  False, False, False),
            (False, False, True,  True):  (True,  True,  False, False),

            (False, True,  False, False): (False, True,  False, False),
            (False, True,  False, True):  (False, True,  False, False),
            (False, True,  True,  False): (False, True,  True,  False),
            (False, True,  True,  True):  (False, True,  True,  False),

            (True,  False, False, False): (True,  False, False, False),
            (True,  False, False, True):  (True,  False, False, True),
            (True,  False, True,  False): (True,  False, False, False),
            (True,  False, True,  True):  (True,  False, False, True),

            (True,  True,  False, False): (True,  True,  False, False),
            (True,  True,  False, True):  (False, True,  False, False),
            (True,  True,  True,  False): (True,  False, False, False),
            (True,  True,  True,  True):  (True,  True,  False, False),
        }

        do_iosd_4, do_iosd_6, warn_iosd_4, warn_iosd_6 = (
            io46_sd46_do46_w46[(has_io4, has_io6, has_sd4, has_sd6)])

        if warn_iosd_4:
            assert do_iosd_4 is False
            logger.debug('IPv4 address list will be ignored, because no IPv4 '
                         'rules will be generated: s:%s d:%s' % (s4, d4))
        if warn_iosd_6:
            assert do_iosd_6 is False
            logger.debug('IPv6 address list will be ignored, because no IPv6 '
                         'rules will be generated: s:%s d:%s' % (s6, d6))

        # now, look again at the source/destination combination, to filter
        # combinations that would lead to wrong permissive rules
        do_sd_4, do_sd_6, warn_sd_4, warn_sd_6 = (
            has4_has6_do46_w46[(has_s4, has_d4, has_s6, has_d6)])

        if warn_sd_4 and warn_sd_6:
            assert do_sd_4 is False and do_sd_6 is False
            logger.warning('Not generating any IPv4/IPv6 rule, your input logic '
                           'is likely broken: s4=%, d4=%, s6=%, d6=%' %
                           (s4, d4, s6, d6))
        elif warn_sd_4:
            assert do_sd_4 is False
            logger.debug('Ignoring IPv4 addresses: s4=%s, d4=%s, s6=%s, d6=%s' %
                         (s4, d4, s6, d6))
        elif warn_sd_6:
            assert do_sd_6 is False
            logger.debug('Ignoring IPv6 addresses: s4=%s, d4=%s, s6=%s, d6=%s' %
                         (s4, d4, s6, d6))

        todo = {}
        if do_io_4 and do_iosd_4 and do_sd_4:
            todo[4] = (i4, o4, s4, d4)
        if do_io_6 and do_iosd_6 and do_sd_6:
            todo[6] = (i6, o6, s6, d6)

        for ipv in todo:
            rules = self.mk_iosd(ipv, command, *todo[ipv])

            if comment:
                self.rules[ipv].append({'comment': comment})

            if r is not None:
                for rule in rules:
                    rule.update({'r': r})
                    self.rules[ipv].append(rule)

    def mk_iosd(self, ipv, command, i, o, s, d):
        rules = []
        # INPUT, OUTPUT, PREROUTING, POSTROUTING use either input or output
        # interfaces. FORWARD is different, when multiple in or out interfaces
        # are specified, we allow traffic between all of the input interfaces
        # to all of the output interfaces.

        # haveio will remember all combinations of input/ouput we find
        haveio = []

        # first of all, let's think about the case when only a single list of
        # input or output interfaces will are mentioned
        if len(i) != 0 and len(o) == 0:
            haveio = [(iface_in, None) for iface_in in i]
        # then... only output...
        elif len(i) == 0 and len(o) != 0:
            haveio = [(None, iface_out) for iface_out in o]
        # input and output are both set, this must be a bug or FORWARD
        elif len(i) != 0 and len(o) != 0:
            haveio = [(iface_in, iface_out)
                      for iface_in in i for iface_out in o]
        # when none of input/output are specified, just do nothing, for it is
        # already an empty list

        if len(haveio) == 0:
            rule = {
                'chain': self.chain,
                't': self.table,
                'command': command
            }
            rules.append(rule)
        else:
            for (iface_in, iface_out) in haveio:
                rule = {
                    'chain': self.chain,
                    't': self.table,
                    'command': command
                }
                if iface_in is not None and iface_in[ipv] is not None:
                    rule['i'] = iface_in[ipv]
                if iface_out is not None and iface_out[ipv] is not None:
                    rule['o'] = iface_out[ipv]
                rules.append(rule)

        if len(s) > 0:
            tmp = []
            for src in s:
                for rule in rules:
                    newrule = rule.copy()
                    newrule.update({'s': src})
                    tmp.append(newrule)
            rules = tmp

        if len(d) > 0:
            tmp = []
            for dst in d:
                for rule in rules:
                    newrule = rule.copy()
                    newrule.update({'d': dst})
                    tmp.append(newrule)
            rules = tmp

        return rules

    def __str__(self):
        return str({'table': self.table, 'chain': self.chain, 'rules': self.rules})


class Interface(object):
    def __init__(self, ifname, ipv=None):
        if ipv is None:
            ipv = [4, 6]


# Simple regex to distuingish between ipv4, ipv6 addresses and hostnames we
# need to resolve ourselves. This supports IPv6 addresses with optional extra
# brackets (like [::1]/128) which are also used for for hosts.allow
sd_regex = re.compile(r'(?P<negate>(!\s+|))?(?:(?P<ipv4>[\d./]+)|(?P<ipv6>(?=.*:)'
                      '\[?[\d:a-fA-F]+\]?(/\d+)?)|(?P<fqdn>.*))$')


def parse_address_list(a):
    a4, a6 = ([], [])
    for addr in a:
        m = sd_regex.match(addr).groupdict()
        if m['ipv4']:
            a4.append(addr)
        elif m['ipv6']:
            a6.append(addr)
        elif m['fqdn']:
            # throw up badly if domain names cannot be resolved
            # ignoring dns.resolver.NXDOMAIN silently here leads to generated
            # rules with missing src/dst filters, which is bad
            r4 = None
            r6 = None
            try:
                r4 = dns.resolver.query(m['fqdn'], dns.rdatatype.A)
                a4.extend(['%s%s' % (m['negate'], rr.to_text())
                          for rr in sorted(r4.rrset)])
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN, e:
                logger.critical("NXDOMAIN on %s" % m['fqdn'])
                raise e
            try:
                r6 = dns.resolver.query(m['fqdn'], dns.rdatatype.AAAA)
                addresses = [rr.to_text() for rr in sorted(r6.rrset)]
                a6.extend(['%s%s' % (m['negate'], addr) for addr in addresses])
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN, e:
                logger.critical("NXDOMAIN on %s" % m['fqdn'])
                raise e
            rtxt = None
            if r4 is None and r6 is None:
                try:
                    rtxt = dns.resolver.query(m['fqdn'], dns.rdatatype.TXT)
                    for rr in sorted(rtxt.rrset):
                        txt = rr.to_text()
                        if txt.startswith('"') and txt.endswith('"'):
                            txt = txt[1:-1]
                        (txt_a4, txt_a6) = parse_address_list([txt])
                        a4.extend(txt_a4)
                        a6.extend(txt_a6)
                except dns.resolver.NoAnswer:
                    pass
                except dns.resolver.NXDOMAIN, e:
                    logger.critical("NXDOMAIN on %s" % m['fqdn'])
                    raise e

            if r4 is None and r6 is None and rtxt is None:
                raise OinkwallException('No A, AAAA or TXT found for %s' % m['fqdn'])
        else:
            logger.critical('Regular expression for parse_address_list cannot '
                            'deal with %s' % addr)
    return (a4, a6)


class HostsAllow:

    def __init__(self):
        # [
        #  {comment: "Blub", daemon: 'sshd', s: ['10.1.0.0/16', 'all']},
        #  {daemon: 'nrpe', s: ['192.0.2.66']},
        # ]
        self.rules = []

    def add(self, ruleset):
        self.rules.extend(ruleset.rules)

    def get_hosts_allow_content(self):
        lines = []
        for rule in self.rules:
            if 'comment' in rule:
                lines.append("# %s" % rule['comment'])
            if 'daemon' in rule:
                lines.append("%s: %s" % (rule['daemon'], ', '.join(rule['s'])))
        lines.append('')
        return '\n'.join(lines)


class HostsAllowRuleset:

    def __init__(self):
        self.rules = []

    def add(self, daemon=None, s=None, comment=None):
        rule = {}
        if daemon is not None:
            if s is None or len(s) == 0:
                logger.warning("Ignoring hosts.allow daemon %s with empty address list" % daemon)
            else:
                s = flatten(s)
                parsed_s = []
                if any([item for item in s if item.lower() == 'all']):
                    parsed_s.append('all')
                else:
                    s4, s6 = parse_address_list(s)
                    # add square brackets to IPv6 addresses
                    # (e.g. 2001:db8:1::/48 -> [2001:db8:1::]/48)
                    s6 = map(lambda x: re.sub(r'(^[\d:a-fA-F]+)([\/\d]*)$', r'[\1]\2', x), s6)
                    parsed_s.extend(s4)
                    parsed_s.extend(s6)
                rule.update({'daemon': daemon, 's': parsed_s})

        if comment:
            rule.update({'comment': comment})

        if len(rule) > 0:
            self.rules.append(rule)

    def __str__(self):
        return str(self.rules)


def flatten(l):
    return [l] if not isinstance(l, list) else sum(map(flatten, l), [])
