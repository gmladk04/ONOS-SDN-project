#s1
sudo ovs-ofctl add-flow s1 dl_type=0x86dd,ipv6_dst=ff02::/16,in_port=1,actions=output:3
sudo ovs-ofctl add-flow s1 dl_type=0x86dd,ipv6_dst=ff02::/16,in_port=2,actions=output:3
sudo ovs-ofctl add-flow s1 dl_type=0x86dd,ipv6_dst=ff02::/16,in_port=3,actions=output:1,2
sudo ovs-ofctl add-flow s1 dl_type=0x86dd,ipv6_dst=1218:1234:1234::/64,actions=output:3

#s2
sudo ovs-ofctl add-flow s2 dl_type=0x86dd,ipv6_dst=ff02::/16,in_port=1,actions=output:2
sudo ovs-ofctl add-flow s2 dl_type=0x86dd,ipv6_dst=ff02::/16,in_port=2,actions=output:1
sudo ovs-ofctl add-flow s2 dl_type=0x86dd,ipv6_dst=1218:1234:1234::/64,actions=output:2

#s3
sudo ovs-ofctl add-flow s3 dl_type=0x86dd,ipv6_dst=ff02::/16,in_port=1,actions=output:2
sudo ovs-ofctl add-flow s3 dl_type=0x86dd,ipv6_dst=ff02::/16,in_port=2,actions=output:1
sudo ovs-ofctl add-flow s3 dl_type=0x86dd,ipv6_dst=1218:1234:1234::/64,actions=output:3

#s4
sudo ovs-ofctl add-flow s4 dl_type=0x86dd,ipv6_dst=ff02::/16,in_port=1,actions=output:2
sudo ovs-ofctl add-flow s4 dl_type=0x86dd,ipv6_dst=ff02::/16,in_port=2,actions=output:1
sudo ovs-ofctl add-flow s4 dl_type=0x86dd,ipv6_dst=1218:1234:1234::/64,actions=output:2


#s5
sudo ovs-ofctl add-flow s5 dl_type=0x86dd,ipv6_dst=1218:1234:1234::/64,actions=output:1

# rsu1
sudo ovs-ofctl add-flow rsu1 dl_type=0x86dd,ipv6_dst=ff02::/16,in_port=1,actions=output:2
sudo ovs-ofctl add-flow rsu1 dl_type=0x86dd,ipv6_dst=ff02::/16,in_port=2,actions=output:1

sudo ovs-ofctl add-flow rsu1 dl_type=0x86dd,ipv6_dst=1218:1234:1234::/64,actions=output:2

# rsu2
sudo ovs-ofctl add-flow rsu2 dl_type=0x86dd,ipv6_dst=ff02::/16,in_port=1,actions=output:2
sudo ovs-ofctl add-flow rsu2 dl_type=0x86dd,ipv6_dst=ff02::/16,in_port=2,actions=output:1

sudo ovs-ofctl add-flow rsu2 dl_type=0x86dd,ipv6_dst=1218:1234:1234::/64,actions=output:2


# rsu3
sudo ovs-ofctl add-flow rsu3 dl_type=0x86dd,ipv6_dst=ff02::/16,in_port=1,actions=output:2
sudo ovs-ofctl add-flow rsu3 dl_type=0x86dd,ipv6_dst=ff02::/16,in_port=2,actions=output:1

sudo ovs-ofctl add-flow rsu3 dl_type=0x86dd,ipv6_dst=1218:1234:1234::/64,actions=output:2




