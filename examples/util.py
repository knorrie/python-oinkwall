import oinkwall

# Dummy network interfaces to force a rule to IPv4 or IPv6 only
if_4 = {4: None}
if_6 = {6: None}

# Define an interface to use with i= or o=
if_lo4 = {4: 'lo'}
if_lo6 = {6: 'lo'}
if_lo = [if_lo4, if_lo6]

# ...or just an ipv4 and ipv6 enabled interface
if_eth0 = {4: 'eth0', 6: 'eth0'}

# If your public IPv6 interface is different from IPv4, because
# it's a tunnel, e.g. via HE:
if_public = {4: 'ppp0', 6: 'he-tunnel'}


def input_lo():
    r = oinkwall.IPTablesRuleset('filter', 'INPUT')
    h = oinkwall.HostsAllowRuleset()
    h.add(comment="SSH localhost", daemon='sshd', s='localhost')
    r.add(command='I', i=if_lo, r='-j ACCEPT')
    return(r, h)


def output_lo():
    r = oinkwall.IPTablesRuleset('filter', 'OUTPUT')
    r.add(command='I', o=if_lo, r='-j ACCEPT')
    return r


def start(chain):
    r = oinkwall.IPTablesRuleset('filter', chain)
    r.add(r='-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT')
    r.add(r='-m conntrack --ctstate INVALID -j DROP')
    return r


def end(chain):
    r = oinkwall.IPTablesRuleset('filter', chain)
    if chain == 'INPUT':
        r.add(i=if_4, r='-p icmp -m icmp --icmp-type 8 -j ACCEPT')
        r.add(i=if_6, r='-p ipv6-icmp -j ACCEPT')
        r.add(i=if_6, r='-d ff02::/16 -j ACCEPT')
    if chain == 'OUTPUT':
        r.add(o=if_4, r='-p icmp -j ACCEPT')
        r.add(o=if_6, r='-p ipv6-icmp -j ACCEPT')
        r.add(o=if_6, r='-d ff02::/16 -j ACCEPT')
    if chain == 'FORWARD':
        r.add(i=if_4, r='-p icmp -j ACCEPT')
        r.add(i=if_6, r='-p ipv6-icmp -j ACCEPT')
        r.add(i=if_6, r='-d ff02::/16 -j ACCEPT')

    if chain == 'INPUT':
        r.add(r='-p udp -m multiport --dport 33434:33535 -j REJECT')

    if chain == 'OUTPUT':
        r.add(r='-m owner --uid-owner 0 -j ACCEPT')
        r.add(r='-m owner --uid-owner 487 -j ACCEPT')

    r.add(r='-m limit --limit 10/sec --limit-burst 100 '
            '-j LOG --log-prefix "IPT %s DEAD: " --log-level 7' % chain)

    return r


#
# some other examples of fun little helper functions:
#
def input_ssh(s, comment=None):
    r = oinkwall.IPTablesRuleset('filter', 'INPUT')
    r.add(comment=comment, s=s, r='-p tcp -m tcp --dport 22 -j ACCEPT')

    h = oinkwall.HostsAllowRuleset()
    h.add(comment=comment, daemon='sshd', s=s)

    return(r, h)


def input_ipsec_ipip6_bgp(ipip6_endpoints, ipip6_ptp):
    r = oinkwall.IPTablesRuleset('filter', 'INPUT')
    r.add(comment='IPSec', i=if_6, s=ipip6_endpoints, r='-p esp -j ACCEPT')
    r.add(comment='IKE', i=if_6, s=ipip6_endpoints, r='-p udp -m udp --dport 500 -j ACCEPT')
    r.add(comment='4in6', i=if_6, s=ipip6_endpoints, r='-p 4 -j ACCEPT')
    r.add(comment='eBGP', s=ipip6_ptp, r='-p tcp -m tcp --dport 179 -j ACCEPT')
    return r


def output_ipsec_ipip6_bgp(ipip6_endpoints, ipip6_ptp):
    r = oinkwall.IPTablesRuleset('filter', 'OUTPUT')
    r.add(comment='IPSec', o=if_6, d=ipip6_endpoints, r='-p esp -j ACCEPT')
    r.add(comment='IKE', o=if_6, d=ipip6_endpoints, r='-p udp -m udp --dport 500 -j ACCEPT')
    r.add(comment='4in6', o=if_6, d=ipip6_endpoints, r='-p 4 -j ACCEPT')
    r.add(comment='eBGP', d=ipip6_ptp, r='-p tcp -m tcp --dport 179 -j ACCEPT')
    return r


def fix_tunnel_mss(o, mss):
    rulesets = []
    for chain in('FORWARD', 'OUTPUT'):
        r = oinkwall.IPTablesRuleset('filter', chain)
        r.add(command='I', o=o,
              r='-p tcp --tcp-flags SYN,RST SYN -m tcpmss --mss %s:1536 '
                '-j TCPMSS --set-mss %s' % (mss, mss))
        rulesets.append(r)
    return rulesets


#
# simple way to store results
#
def write_everything(name, fw, ha):
    with open('%s-firewall' % name, 'w') as f:
        f.writelines(fw.get_iptables_restore_script())
    with open('%s-firewall6' % name, 'w') as f:
        f.writelines(fw.get_ip6tables_restore_script())
    with open('%s-hosts.allow' % name, 'w') as f:
        f.writelines(ha.get_hosts_allow_content())
