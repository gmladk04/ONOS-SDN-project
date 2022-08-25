#!/usr/bin/python

'Setting the position of nodes and providing mobility'

import sys

from mininet.node import RemoteController, Controller, OVSKernelSwitch, Host, OVSSwitch
from mn_wifi.net import Station, OVSKernelAP
from mininet.log import setLogLevel, info
from mn_wifi.cli import CLI
from mn_wifi.link import wmediumd
from mininet.link import Intf
from mn_wifi.net import Mininet_wifi
from mn_wifi.wmediumdConnector import interference
from subprocess import call
from mn_wifi.link import wmediumd, ITSLink

def topology(args):
    "Create a network."
    net = Mininet_wifi(topo=None,
                       build=False,
                       link=wmediumd,
                       wmediumd_mode=interference
                       )

    info("*** Creating nodes\n")

    h1 = net.addHost('h1', cls=Host, mac='00:00:00:00:00:01', ip='10.0.0.1/8') #CN
    h2 = net.addHost('h2', cls=Host, mac='00:00:00:00:00:33', ip='10.0.0.2/8') #router

    s1 = net.addSwitch('s1', cls=OVSKernelSwitch)
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch)
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch)
    s4 = net.addSwitch('s4', cls=OVSKernelSwitch)
    s5 = net.addSwitch('s5', cls=OVSKernelSwitch)

    rsu1 = net.addAccessPoint('rsu1', cls=OVSKernelAP, ssid='rsu1-ssid', mode="g", channel='1',
                             position='40,70,0',range=30)
    rsu2 = net.addAccessPoint('rsu2', cls=OVSKernelAP, ssid='rsu2-ssid', mode='g', channel='1',
                             position='100,70,0', range=30)
    rsu3 = net.addAccessPoint('rsu3', cls=OVSKernelAP, ssid='rsu3-ssid', mode='g', channel='1',
                             position='150,70,0',range=30)
    sta1 = net.addStation('sta1', mac='00:00:00:00:00:22')
   
    c0 = net.addController(name='c0', controller=RemoteController, 
                           ip='127.0.0.1',
                           protocol='tcp',
                           port=6653)

    info("*** Configuring propagation model\n")
    net.setPropagationModel(model="logDistance", exp=6)

    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()

    info("*** Associating and Creating links\n")

    
    net.addLink(s1,rsu1)
    net.addLink(s1,rsu2)
    net.addLink(s2,rsu3)

    net.addLink(s1,s3)
    net.addLink(s2,s4)
    net.addLink(s3,s5)
    net.addLink(s2,s5)
    net.addLink(s1,s5)
    net.addLink(s3,h2)
    net.addLink(s4,h2)
    net.addLink(s4,s5)
    net.addLink(h1,h2)
   
    h2.setMAC('00:00:00:00:03:33', 'h2-eth1')
    h2.setMAC('00:00:00:00:00:02', 'h2-eth2')

    rsu1sta1 = {'bw':80 }
    net.addLink(rsu1, sta1, **rsu1sta1)
    rsu2sta1 = {'bw':80 }
    net.addLink(rsu2, sta1, **rsu2sta1)
    rsu3sta1 = {'bw':80 }
    net.addLink(rsu3, sta1, **rsu3sta1)
    
    if '-p' not in args:
        net.plotGraph(max_x=200,max_y=200) 
    
    #net.addLink(sta1, cls=ITSLink,  channel=165)

    net.startMobility(time=0, mob_rep=1, reverse=False)

    p1, p2= dict(), dict()
    if '-c' not in args:
        p1 = {'position' : '20.0,70.0,0.0'}
        p2 = {'position' : '150.0,70.0,0.0'}

    net.mobility(sta1, 'start',time=30, **p1)
    net.mobility(sta1, 'stop', time=90, **p2)
    net.stopMobility(time=130)

    info("*** Starting network\n")
    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])
    s4.start([c0])
    s5.start([c0])
    rsu1.start([c0])
    rsu2.start([c0])
    rsu3.start([c0])
    
    h1.cmd("ifconfig h1-eth0 inet add 1218:1234:1234::101:101:101:101/128")
    h1.cmd("ip -6 route add default via fe80::3 dev h1-eth0")

    h2.cmd("echo 0000 | sudo -S sysctl -w net.ipv6.conf.all.forwarding=1")
    h2.cmd("ifconfig h2-eth2 inet add fe80::3/128")
    h2.cmd("ifconfig h2-eth0 inet add fe80::33/128")
    h2.cmd("ifconfig h2-eth1 inet add fe80::333/128")

    h2.cmd("ip -6 route add 1218:1234:1234::/64 dev h2-eth2")
    h2.cmd("ip -6 route add 1234:db8:f00d::/64 via fe80::6 dev h2-eth0")
    h2.cmd("ip -6 neigh add fe80::6 lladdr 00:00:00:00:00:44 dev h2-eth0")
    h2.cmd("ip -6 route add 1234:db8:c0a0::/64 via fe80::7 dev h2-eth1")
    h2.cmd("ip -6 neigh add fe80::7 lladdr 00:00:00:00:04:44 dev h2-eth1")

    sta1.cmd("ifconfig sta1-wlan0 inet add 1234:1234:1234::101:101:101:101/128")
    rsu1.cmd("ifconfig sta1-wlan0 inet add fe80::5/128")
    rsu2.cmd("ifconfig sta1-wlan0 inet add fe80::55/128")
    rsu3.cmd("ifconfig sta1-wlan0 inet add fe80::555/128")
    sta1.setIP6('', intf='sta1-wlan0')

    
    #sta1.cmd("ip -6 route add default dev sta1-wlan0")
       
    info("*** Running CLI\n")
    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topology(sys.argv)
