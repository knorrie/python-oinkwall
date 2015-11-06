python-oinkwall
===============

Oinkwall is a python library that provides a highly programmable way to help you to generate low level Linux IPTables rule files and hosts.allow rules. It aims at handling the boring parts (resolving domain names, putting the IPv4 and IPv6 addresses in the right place) for you, while it completely leaves you with the freedom to use raw iptables commands as much as possible.

Unlike most firewall tools, it does not try to impose using any higher level abstractions on you. It operates on the level that programs like iptables-save and iptables-restore work on. It simply helps you to easier organize your iptables rules, if you like writing them directly and adding them together programmatically.

The library can be used to assemble a firewall for a single host or router, or for generating a lot of them, as building your own templating system or higher level tools 100% tailored to your own specific situation and your low level rule needs should be pretty easy.

## A simple example

This...

    import oinkwall
    fw = oinkwall.IPTables()
    r = oinkwall.IPTablesRuleset('filter', 'INPUT')
    r.add(s='example.com', r='-p tcp -m tcp --dport 25 -j ACCEPT')
    fw.add(r)
    print("IPv4:")
    print(fw.get_iptables_restore_script())
    print("IPv6:")
    print(fw.get_ip6tables_restore_script())

...will give you the basic idea of what's going on here. You don't have to worry about whether example.com has an IPv4 of IPv6 addres, or both, and what to do with them. It just happens!

Now, just make this work on your computer also first, and then continue on.

If you want to have a look at more examples instead of reading on, look inside the examples folder inside this repository.

## History

Long, long ago, in a network far far away, when I first started configuring IPTables firewalls on Linux, I started writing bash scripts that called the iptables binary. Of course, I quickly discovered the problems of doing so, after the first time I made a typo in the script, that left me with an already executed "iptables -F" and no useful extra rules to be able to fix it.

So, I continued my journey and learned about the iptables-save and iptables-restore programs that allowed me to apply firewall rulesets in a better way. But, after starting to write firewall rulesets in this low level language, both for IPv4 and IPv6, and also trying to keep my hosts.allow rules in sync, this started to be a really frustrating job. But ok, once in a while, editing a bunch of files... whatever.

A few years later, instead of having a few Linux boxes to care about I started to manage the firewalls of more than a dozen machines at my first job. This made me realize I had to find a better solution to do this.

I started looking around for existing tools to generate firewall scripts for me. Surprisingly... the goal of all of them were to abstract away complexities and build some other language which supports a subset of the functionality of IPTables and NetFilter. O\_o So during the christmas holidays of 2008, I decided to write a python library that would help me to do the boring parts, while not trying to put any constraints on using low level iptables constructs.

## So, Oinkwall...

The strenghts of using this library should be:
* No need to worry about keeping your IPv4 and IPv6 firewall and hosts.allow configuration in sync.
* Usage of DNS to resolve names to addresses, or to define network ranges and arbitrary lists of addresses.
* Stays out of your way and does not try to be clever about your actual rules.
* Ways of usage are limited to your own imagination and effort. It's just a little library, not a stand alone tool, so it can be integrated in any other system.

## Let's do a tour...

The oinkwall library contains a single python module, `firewall.py`, which contains the classes `IPTables`, `IPTablesRuleset`, `HostsAllow` and `HostsAllowRuleset`.

The idea is that you can create an `IPTables` and `HostsAllow` object, and then add `IPTablesRuleset` and `HostsAllowRuleset` to it. When you're done adding rules, call the `get_iptables_restore_script` and `get_ip6tables_restore_script` on the `IPTables` object to get output you can directly feed to iptables-restore and ip6tables-restore. `HostsAllow` has a `get_hosts_allow_content` function, which returns the content of your `hosts.allow` file. It assumes you have `ALL:ALL` in hosts.deny.

    import oinkwall

    fw = oinkwall.IPTables()
    r = oinkwall.IPTablesRuleset('filter', 'INPUT')
    r.add(s='example.com', r='-p tcp -m tcp --dport 25 -j ACCEPT')
    fw.add(r)

    ha = oinkwall.HostsAllow()
    h = oinkwall.HostsAllowRuleset()
    h.add(comment="I'm a comment!", daemon='sshd', s='localhost')
    ha.add(h)

The firewall.py file isn't that big, and I hope the function definitions are quite self-explanatory, because they resemble the low level iptables syntax.

## Some more tour...

As you can see in the IPTablesRuleset class source, the add function accepts the arguments `command, i, o, s, d, r` and `comment`.

Command corresponds to using `-I` or `-A` etc... on the iptables command line, so specifying `command='I'` will help you insert a rule into on top of the ruleset when applied by iptables. command='A' is the default.

i and o are input or output interfaces, accepting a single interface description, or a dictionary for an interface, or a list of them. You can just pass `i='eth0'`, or use a dictionary, like `{4: 'ppp0', 6: 'he-ipv6-tunnel'}` or `{4: 'eth0'}` if your IPv4 and IPv6 traffic uses separate interfaces (e.g. when using an IPv6 tunnel), or when an interface only supports IPv4 or IPv6.

This...

    r = oinkwall.IPTablesRuleset('filter', 'FORWARD')
    r.add(s=['_net.another-example.knorrie.org', '2001:db8:77:88::99'],
          d='example.knorrie.org',
          r='-p tcp -m tcp --dport 443 -j ACCEPT')

will, when used in a full script, result in these rules being written:

    -A FORWARD -s 203.0.113.0/24 -d 192.0.2.11 -p tcp -m tcp --dport 443 -j ACCEPT
    -A FORWARD -s 2001:db8:77:2::/120 -d 2001:db8:1998::251 -p tcp -m tcp --dport 443 -j ACCEPT
    -A FORWARD -s 2001:db8:77:88::99 -d 2001:db8:1998::251 -p tcp -m tcp --dport 443 -j ACCEPT

And this...

    if_ppp4 = {oinkwall.ipv4: 'ppp0'}
    r = oinkwall.IPTablesRuleset('nat', 'POSTROUTING')
    r.add(comment='Ugh, NAT :|', o=if_ppp4, r='-j SNAT --to-source 203.0.113.45')

will result in an IPv4 only rule in the nat section like:

    *nat
    :PREROUTING ACCEPT [0:0]
    :POSTROUTING ACCEPT [0:0]
    :OUTPUT ACCEPT [0:0]
    # Ugh, NAT :|
    -A POSTROUTING -o ppp0 -j SNAT --to-source 203.0.113.45

s and d are just anything you want to use as source or destination. It's possible to use IPv4 or IPv6 addresses, or hostnames, which will be resolved using DNS, or lists of them, or even nested lists, or you can even use names in DNS which have a TXT record that point to adresses or other names. Below is an example of how you can do this with DNS records.

In r, you can put the remainder of the iptables or ip6tables rule, like `"-j ACCEPT"`, or `"-p tcp -m tcp --dport 80 -j ACCEPT"` or anything else that iptables or ip6tables accept.

If a comment is given, it's put above the rule in the output, as comment line.

## Using DNS to store subnet information

One of the fun and really helpful things of this library is that it looks into DNS for quite some things. Of course, there's the normal resolving of DNS names to A and AAAA records, which end up in your IPv4 of IPv6 firewall, but, there's more!

Normal A and AAAA records do not allow you to store subnet information. When you submit a name to oinkwall for resolving, it will try to lookup a TXT record if no A or AAAA is available. In the TXT record (or multiple of them), you can specify other names or IP addresses, or IP address ranges.

Let me demonstrate:

    $ORIGIN knorrie.org.
    example         IN    A      192.0.2.11
                    IN    AAAA   2001:db8:1998::251

    $ORIGIN example.knorrie.org.
    v4only          IN    A      192.0.2.4
    *               IN    A      192.0.2.51
                    IN    AAAA   2001:db8::42:11
    _net        60  IN    TXT    "_net4.example.knorrie.org"
                60  IN    TXT    "_net6.example.knorrie.org"
    _net4       60  IN    TXT    "192.0.2.0/24"
    _net6       60  IN    TXT    "2001:db8:1998::/120"
                60  IN    TXT    "2001:db8:42:99::/64"
    listofhosts 60  IN    TXT    "some-server.example.knorrie.org"
                60  IN    TXT    "other-server.example.knorrie.org"
                60  IN    TXT    "203.0.113.11"

    $ORIGIN another-example.knorrie.org.
    _net        60  IN    TXT    "203.0.113.0/24"
                60  IN    TXT    "2001:db8:77:2::/120"

If I would use `s="_net.example.knorrie.org"` in a rule, oinkwall will lookup the TXT records and resolve it to `192.0.2.0/24`, `2001:db8:1998::/120` and `2001:db8:42:99::/64` for you. The IPv4 range will end up in the IPv4 firewall, and the IPv6 ranges will end up in the IPv6 firewall.

## F.A.Q.

Q: Can I use IPv6 NAT?  
A: Yes, but it's disabled by default, resulting in errors when you try to use it. Use `enable_ipv6_nat()` on an `IPTables` object to enable it.

Q: How do I use custom chains?  
A: Use `add_custom_chain` on the IPTables object, like `add_custom_chain('filter', 'MYCHAIN')`. This will result in the custom chain being added on top of the iptables-restore compatible output.

Q: I don't want to learn how iptables and netfilter work, I just want a simple way to enable a firewall.  
A: You're probably not the target audience. Have a look at one of the many other tools that exist.

## Help!!

It's probable you just arrived at this page, because you were searching for a tool or programming library that just provides all the funtionality and flexibility that this library does provide you. But... After ending up at the bottom of this page, you think the documentation you just scanned does not really help you that much, or just missing the exact thing you needed. In that case, just help me improve it! Email me at hans@knorrie.org with your questions, or talk to me on IRC. I'm Knorrie on IRCnet, OFTC and Freenode.
