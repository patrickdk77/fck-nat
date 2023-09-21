#!/bin/sh

if test -f "/etc/fck-nat.conf"; then
    echo "Found fck-nat configuration at /etc/fck-nat.conf"
    . /etc/fck-nat.conf
else
    echo "No fck-nat configuration at /etc/fck-nat.conf"
fi

if test -n "$eip_id"; then
  echo "Found eip_id configuration, attaching $eip_id..."

  aws_region="$(/opt/aws/bin/ec2-metadata -z | cut -f2 -d' ' | sed 's/.$//')"
  instance_id="$(/opt/aws/bin/ec2-metadata -i | cut -f2 -d' ')"

  aws ec2 associate-address \
    --region "$aws_region" \
    --instance-id "$instance_id" \
    --allocation-id "$eip_id"
fi

if test -n "$eni_id"; then
    echo "Found eni_id configuration, attaching $eni_id..."

    aws_region="$(/opt/aws/bin/ec2-metadata -z | cut -f2 -d' ' | sed 's/.$//')"
    instance_id="$(/opt/aws/bin/ec2-metadata -i | cut -f2 -d' ')"

    eth0_mac="$(cat /sys/class/net/eth0/address)"
    
    token="$(curl -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 300' http://169.254.169.254/latest/api/token)"
    eth0_eni_id="$(curl -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/network/interfaces/macs/$eth0_mac/interface-id)"
    
    aws ec2 modify-network-interface-attribute \
        --region "$aws_region" \
        --network-interface-id "$eth0_eni_id" \
        --no-source-dest-check

    aws ec2 attach-network-interface \
        --region "$aws_region" \
        --instance-id "$instance_id" \
        --device-index 1 \
        --network-interface-id "$eni_id"

    while ! ip link show dev eth1; do
        echo "Waiting for ENI to come up..."
        sleep 1
    done

    nat_interface="eth0"
elif test -n "$interface"; then
    echo "Found interface configuration, using $interface"
    nat_interface=$interface
else
    nat_interface=$(ip route | grep default | cut -d ' ' -f 5)
    echo "No eni_id or interface configuration found, using default interface $nat_interface"
fi

echo "Enabling ip_forward..."
sysctl -q -w net.ipv4.ip_forward=1

echo "Disabling reverse path protection..."
for i in $(find /proc/sys/net/ipv4/conf/ -name rp_filter) ; do
  echo 0 > $i;
done

echo "Flushing NAT table..."
iptables -t nat -F

echo "Adding NAT rule..."
iptables -t nat -A POSTROUTING -o "$nat_interface" -j MASQUERADE -m comment --comment "NAT routing rule installed by fck-nat"

echo "Adding DNS redirect rules..."
if test -n "$eni_id"; then
  iptables -t nat -A PREROUTING -i eth1 -p udp --dport 53 -j REDIRECT --to-port 53
  iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 53 -j REDIRECT --to-port 53
else
  #Access out DNS servers
  iptables -t nat -A PREROUTING -p tcp --dport 53 -d 169.254.169.253/32 -j ACCEPT
  iptables -t nat -A PREROUTING -p udp --dport 53 -d 169.254.169.253/32 -j ACCEPT
  iptables -t nat -A PREROUTING -p tcp --dport 53 -d 172.64.36.0/24 -j ACCEPT
  iptables -t nat -A PREROUTING -p udp --dport 53 -d 172.64.36.0/24 -j ACCEPT

  #Add resolv.conf servers
  awk '/nameserver/ { print "iptables -t nat -A PREROUTING -p udp --dport 53 -d " $2 " -j ACCEPT"; }' /etc/resolv.conf | sh
  awk '/nameserver/ { print "iptables -t nat -A PREROUTING -p tcp --dport 53 -d " $2 " -j ACCEPT"; }' /etc/resolv.conf | sh

  #Accept local forwards/redirects
  iptables -t nat -A PREROUTING -p tcp --dport 53 -d 172.16.0.0/12 -j ACCEPT
  iptables -t nat -A PREROUTING -p udp --dport 53 -d 172.16.0.0/12 -j ACCEPT
  iptables -t nat -A PREROUTING -p tcp --dport 53 -d 10.0.0.0/8 -j ACCEPT
  iptables -t nat -A PREROUTING -p udp --dport 53 -d 10.0.0.0/8 -j ACCEPT
  iptables -t nat -A PREROUTING -p tcp --dport 53 -d 192.168.0.0/16 -j ACCEPT
  iptables -t nat -A PREROUTING -p udp --dport 53 -d 192.168.0.0/16 -j ACCEPT

  #Redirect from private ips to local unbound
  iptables -t nat -A PREROUTING -p tcp --dport 53 -s 172.16.0.0/12 -j REDIRECT --to-port 53
  iptables -t nat -A PREROUTING -p udp --dport 53 -s 172.16.0.0/12 -j REDIRECT --to-port 53
  iptables -t nat -A PREROUTING -p tcp --dport 53 -s 10.0.0.0/8 -j REDIRECT --to-port 53
  iptables -t nat -A PREROUTING -p udp --dport 53 -s 10.0.0.0/8 -j REDIRECT --to-port 53
  iptables -t nat -A PREROUTING -p tcp --dport 53 -s 192.168.0.0/16 -j REDIRECT --to-port 53
  iptables -t nat -A PREROUTING -p udp --dport 53 -s 192.168.0.0/16 -j REDIRECT --to-port 53
fi

systemctl restart unbound

echo "Done!"
