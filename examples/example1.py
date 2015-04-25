#!/usr/bin/python

# This is an example of a really simple firewall that only
# filters incoming traffic.

import oinkwall
import util

fw = oinkwall.IPTables()
ha = oinkwall.HostsAllow()

fw.add(util.start('INPUT'))

r, h = util.input_lo()
fw.add(r)
ha.add(h)

r = oinkwall.IPTablesRuleset('filter', 'INPUT')
r.add(comment="This is a comment",
      s=[
          'somehost.example.knorrie.org',
          'v4only.example.knorrie.org',
      ],
      r='-p tcp -m tcp --dport 25 -j ACCEPT')
r.add(r='-p tcp -m tcp --dport 80 -j ACCEPT')
fw.add(r)

r, h = util.input_ssh('_net.example.knorrie.org')
fw.add(r)
ha.add(h)

fw.add(util.end('INPUT'))

fw.set_policy('filter', 'OUTPUT', 'ALLOW')

util.write_everything('example1', fw, ha)
