#!/usr/bin/python

import oinkwall
import util

fw = oinkwall.IPTables()
fw.enable_ipv6_nat(True)  # :-D
ha = oinkwall.HostsAllow()

# Subnets
net_lan4 = '192.168.25.0/24'
net_lan6 = '2001:db8:1998:fb::/64'
net_lan = [net_lan4, net_lan6]

ip_lo = '10.252.0.0'
ip_lan4 = '192.168.25.1'
ip_lan6 = '2001:db8:1998:fb::1'
ip_lan = [ip_lan4, ip_lan6]
ip_ppp4 = '203.0.113.46'

ip_that_we_nat_something_to = '192.168.25.17'

if_lan4 = {4: 'eth0'}
if_lan6 = {6: 'eth0'}
if_lan = [if_lan4, if_lan6]
if_openvpn = {4: 'tun0'}
if_ppp4 = {4: 'ppp0'}
if_ppp6 = {6: 'ppp0'}
if_ppp = [if_ppp4, if_ppp6]

if_ipip6 = {4: 'ipip6'}

ipip6_endpoints = [
    'ip-in-ip-tunnel-endpoint.example.knorrie.org',
]

ipip6_ptp = [
    '10.252.0.3',
]

#########################################################################
# Default Rules

fw.add(util.start('INPUT'))
fw.add(util.start('FORWARD'))
fw.add(util.start('OUTPUT'))
r, h = util.input_lo()
fw.add(r)
ha.add(h)
fw.add(util.output_lo())

#########################################################################
# PREROUTING

r = oinkwall.IPTablesRuleset('nat', 'PREROUTING')
r.add(i=if_ppp4, d=ip_ppp4,
      r='-p tcp -m tcp --dport 26540 -j DNAT --to %s' % ip_that_we_nat_something_to)
fw.add(r)

r = oinkwall.IPTablesRuleset('mangle', 'PREROUTING')
r.add(i=if_lan, r='-m mac --mac-source 14:56:e2:b5:a5:eb -j MARK --set-mark 200')
fw.add(r)

#########################################################################
# POSTROUTING

r = oinkwall.IPTablesRuleset('nat', 'POSTROUTING')
r.add(o=if_ppp4, r='-j SNAT --to-source %s' % ip_ppp4)
fw.add(r)

#########################################################################
# INPUT

# SSH from ext_mgt
r, h = util.input_ssh(['_net.example.knorrie.org', net_lan])
fw.add(r)
ha.add(h)

r = oinkwall.IPTablesRuleset('filter', 'INPUT')
r.add(r='-p udp -m udp --dport 1194 -j ACCEPT')
r.add(s=net_lan, r='-p udp -m udp --dport 53 -j ACCEPT')
r.add(s=net_lan, r='-p tcp -m tcp --dport 53 -j ACCEPT')
r.add(i=if_ppp6, s='fe80::/10', r='-p udp --dport 546 -j ACCEPT')
fw.add(r)

fw.add(util.input_ipsec_ipip6_bgp(ipip6_endpoints, ipip6_ptp))

#########################################################################
# OUTPUT

r = oinkwall.IPTablesRuleset('filter', 'OUTPUT')
r.add(r='-m owner --uid-owner 0 -j ACCEPT')
r.add(r='-m owner --uid-owner 487 -j ACCEPT')
r.add(r='-p tcp -m tcp --dport 53 -m owner --uid-owner bind -j ACCEPT')
r.add(r='-p udp -m udp --dport 53 -m owner --uid-owner bind -j ACCEPT')
r.add(r='-p udp -m udp --dport 123 -m owner --uid-owner ntp -j ACCEPT')
fw.add(r)

fw.add(util.output_ipsec_ipip6_bgp(ipip6_endpoints, ipip6_ptp))

########################################################################
# FORWARD

r = oinkwall.IPTablesRuleset('mangle', 'FORWARD')
r.add(o=if_ppp, r='-p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu')
fw.add(r)

r = oinkwall.IPTablesRuleset('filter', 'FORWARD')

# allow anything from lan to the outside...
r.add(i=if_lan, o=if_ppp, r='-j ACCEPT')

# forwards to local hosts (nat or ipv6)
r.add(i=if_ppp, o=if_lan6,
      s='_net.another-example.knorrie.org',
      d='2001:db8:1998:fb::5678', r='-p tcp -m tcp --dport 22 -j ACCEPT')
r.add(i=if_ppp, o=if_lan,
      d=ip_that_we_nat_something_to,
      r='-p tcp -m tcp --dport 26540 -j ACCEPT')

fw.add(r)

########################################################################
# Default Rules

fw.add(util.end('INPUT'))
fw.add(util.end('FORWARD'))
fw.add(util.end('OUTPUT'))

util.write_everything('example-router', fw, ha)

# vim:sw=4:ts=4:expandtab
