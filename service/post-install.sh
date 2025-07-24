#!/bin/sh

if test -f "/etc/fck-nat.conf"; then
    . /etc/fck-nat.conf
fi

if test -n "$allow_dns"; then
  curl -o /etc/unbound/root.hints https://www.internic.net/domain/named.root

  cat << EOM > /etc/unbound/unbound.conf
server:
	interface: 0.0.0.0
	interface: ::0
	interface-automatic: yes
	port: 53
	root-hints: "root.hints"
	#auto-trust-anchor-file: "root.key"
	access-control: 0.0.0.0/0 refuse
	access-control: 127.0.0.0/8 allow_snoop
	access-control: 10.0.0.0/8 allow_snoop
	access-control: 172.16.0.0/12 allow_snoop
	access-control: 192.168.0.0/16 allow_snoop
	access-control: 169.254.0.0/16 allow_snoop
	access-control: 100.64.0.0/10 allow_snoop
	access-control: ::0/0 refuse
	access-control: ::1 allow_snoop
	access-control: ::ffff:127.0.0.0/104 allow_snoop
	access-control: ::ffff:10.0.0.0/104 allow_snoop
	access-control: ::ffff:172.16.0.0/108 allow_snoop
	access-control: ::ffff:192.168.0.0/112 allow_snoop
	access-control: ::ffff:100.64.0.0/106 allow_snoop
 	access-control: ::ffff:169.254.0.0/112 allow_snoop
	access-control: ::/128 allow_snoop
	access-control: ::1/128 allow_snoop
	access-control: fc00::/7 allow_snoop
	access-control: fd00::/8 allow_snoop
	access-control: fe80::/10 allow_snoop
	hide-identity: yes
	hide-version: yes
	qname-minimisation: yes
        incoming-num-tcp: 100
	cache-min-ttl: 30
	cache-max-ttl: 14400
	prefetch: yes
	prefetch-key: yes
	verbosity: 0
	tls-cert-bundle: /etc/ssl/cert.pem
        statistics-interval: 0
        extended-statistics: no
        statistics-cumulative: no 
        verbosity:          0
        do-ip4:             yes
        do-ip6:             yes
        do-udp:             yes
        do-tcp:             yes

        num-threads:        2
        msg-cache-slabs:    4
        rrset-cache-slabs:  4
        infra-cache-slabs:  4
        key-cache-slabs:    4
        rrset-cache-size:   128m
        msg-cache-size:     64m
        key-cache-size:     64m
        neg-cache-size:     32m
        infra-cache-numhosts: 10000
        so-rcvbuf:          4m
        so-sndbuf:          4m
        outgoing-range:     950
        num-queries-per-thread:     450
        so-reuseport:       yes

forward-zone:
	name: "."
EOM
  for dnsip in ${allow_dns}; do
    echo "        forward-addr: ${dnsip}" >> /etc/unbound/unbound.conf
  done
  cat << EOM >> /etc/unbound/unbound.conf
	forward-first: yes

forward-zone:
	name: "internal"
	forward-addr: 169.254.169.253

forward-zone:
	name: "cloudfront.net"
	forward-addr: 169.254.169.253

forward-zone:
	name: "amazoncognito.com"
        forward-addr: 169.254.169.253

forward-zone:
	name: "amazon.com"
        forward-addr: 169.254.169.253

forward-zone:
	name: "awsapps.com"
        forward-addr: 169.254.169.253

forward-zone:
	name: "amazonaws-us-gov.com"
        forward-addr: 169.254.169.253

forward-zone:
	name: "amazonaws.com"
        forward-addr: 169.254.169.253

EOM

  systemctl enable unbound
  systemctl start unbound
fi

systemctl enable fck-nat
systemctl start fck-nat
