#!/bin/sh

if test -f "/etc/fck-nat.conf"; then
    echo "Found fck-nat configuration at /etc/fck-nat.conf"
    . /etc/fck-nat.conf
else
    echo "No fck-nat configuration at /etc/fck-nat.conf"
fi

token="$(curl -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 300' http://169.254.169.254/latest/api/token)"
instance_id="$(curl -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/instance-id)"
aws_region="$(curl -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/placement/region)"
outbound_mac="$(curl -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/mac)"
outbound_eni_id="$(curl -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/network/interfaces/macs/$outbound_mac/interface-id)"
nat_interface=$(ip link show dev "$outbound_eni_id" | head -n 1 | awk '{print $2}' | sed s/://g )

if test -n "$eip_id"; then
    echo "Found eip_id configuration, associating $eip_id..."

    aws ec2 associate-address \
        --region "$aws_region" \
        --allocation-id "$eip_id" \
        --network-interface-id "$outbound_eni_id" \
        --allow-reassociation
    sleep 3
fi

if test -n "$eni_id"; then
    echo "Found eni_id configuration, attaching $eni_id..."

    aws ec2 modify-network-interface-attribute \
        --region "$aws_region" \
        --network-interface-id "$outbound_eni_id" \
        --no-source-dest-check

    if ! ip link show dev "$eni_id"; then
        while ! aws ec2 attach-network-interface \
            --region "$aws_region" \
            --instance-id "$instance_id" \
            --device-index 1 \
            --network-interface-id "$eni_id"; do
            echo "Waiting for ENI to attach..."
            sleep 5
        done

        while ! ip link show dev "$eni_id"; do
            echo "Waiting for ENI to come up..."
            sleep 1
        done
    else
        echo "$eni_id already attached, skipping ENI attachment"
    fi
elif test -n "$interface"; then
    echo "Found interface configuration, using $interface"
    nat_interface=$interface
else
    echo "No eni_id or interface configuration found, using default interface $nat_interface"
fi

cat << EOM | sysctl -q -p -
net.netfilter.nf_conntrack_sctp_timeout_established=1800
net.netfilter.nf_conntrack_udp_timeout=180
net.netfilter.nf_conntrack_tcp_timeout_close = 10
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 10
net.netfilter.nf_conntrack_tcp_timeout_established = 1800
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 15
net.netfilter.nf_conntrack_tcp_timeout_last_ack = 15
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 20
net.netfilter.nf_conntrack_tcp_timeout_syn_sent = 20
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 15
net.netfilter.nf_conntrack_tcp_loose = 0

net.ipv4.tcp_slow_start_after_idle = 0

net.ipv4.tcp_mtu_probing=1

net.ipv4.tcp_fin_timeout=10
net.ipv4.tcp_tw_recycle=1

net.ipv4.tcp_no_metrics_save=1

net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

net.ipv4.ip_local_port_range = 10000 64000
EOM


echo "Enabling ip_forward..."
sysctl -q -w net.ipv4.ip_forward=1

echo "Disabling reverse path protection..."
for i in $(find /proc/sys/net/ipv4/conf/ -name rp_filter) ; do
  echo 0 > $i;
done

echo "Flushing NAT table..."
iptables -t nat -F

echo "Adding NAT rule..."
iptables -t nat -A POSTROUTING -o "$nat_interface" -s 172.16.0.0/12 -j MASQUERADE -m comment --comment "NAT routing rule installed by fck-nat"
iptables -t nat -A POSTROUTING -o "$nat_interface" -s 192.168.0.0/16 -j MASQUERADE -m comment --comment "NAT routing rule installed by fck-nat"
iptables -t nat -A POSTROUTING -o "$nat_interface" -s 10.0.0.0/8 -j MASQUERADE -m comment --comment "NAT routing rule installed by fck-nat"

iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -m state --state NEW -s 172.16.0.0/12 -j ACCEPT
iptables -A INPUT -m state --state NEW -s 192.168.0.0/16 -j ACCEPT
iptables -A INPUT -m state --state NEW -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -m state --state NEW -s 127.0.0.0/8 -j ACCEPT
iptables -P INPUT DROP

for sship in ${allow_ssh}; do
  iptables -A INPUT -m state --state NEW -s ${sship} -j ACCEPT
done


echo "Adding DNS redirect rules..."
if test -n "$eni_id"; then
  iptables -A INPUT -m state --state NEW -i ! "$nat_interface" -j ACCEPT
  iptables -A FORWARD -i "$nat_interface" -o "$nat_interface" -j REJECT

  iptables -t nat -A PREROUTING -i eth1 -p udp --dport 53 -j REDIRECT --to-port 53
  iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 53 -j REDIRECT --to-port 53
else
  #Access out DNS servers
  iptables -t nat -A PREROUTING -p tcp --dport 53 -d 169.254.169.253/32 -j ACCEPT
  iptables -t nat -A PREROUTING -p udp --dport 53 -d 169.254.169.253/32 -j ACCEPT
  for dnsip in ${allow_dns}; do
    iptables -t nat -A PREROUTING -p tcp --dport 53 -d ${dnsip} -j ACCEPT
    iptables -t nat -A PREROUTING -p udp --dport 53 -d ${dnsip} -j ACCEPT
  done

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

echo "Adjusting conntrack"
MAXMEM=$(awk '/MemTotal/ { print $2; }' /proc/meminfo)
CONN_MAX=$((($MAXMEM-200000)/3))
CONN_HASH=$(($CONN_MAX/4))

echo $CONN_MAX > /proc/sys/net/nf_conntrack_max
echo $CONN_HASH > /sys/module/nf_conntrack/parameters/hashsize


if test -n "$cwagent_enabled" && test -n "$cwagent_cfg_param_name"; then
    echo "Found cwagent_enabled and cwagent_cfg_param_name configuration, starting CloudWatch agent..."
    systemctl enable amazon-cloudwatch-agent
    /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c "ssm:$cwagent_cfg_param_name"
fi

echo "Done!"
