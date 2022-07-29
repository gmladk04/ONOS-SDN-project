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
   
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch)
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch)
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch)
    s4 = net.addSwitch('s4', cls=OVSKernelSwitch)
    s5 = net.addSwitch('s5', cls=OVSKernelSwitch)
    rsu1 = net.addAccessPoint('rsu1', cls=OVSKernelAP, ssid='rsu1-ssid', mode="g", channel='1',
                             position='40,70,0')
    rsu2 = net.addAccessPoint('rsu2', cls=OVSKernelAP, ssid='rsu2-ssid', mode='g', channel='1',
                             position='100,70,0')
    rsu3 = net.addAccessPoint('rsu3', cls=OVSKernelAP, ssid='rsu3-ssid', mode='g', channel='1',
                             position='150,70,0')
    sta1 = net.addStation('sta1', mac='00:00:00:00:00:04', ip='10.0.0.4/8')
   
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
    net.addLink(s2, rsu3)

    net.addLink(s1,s3)
    net.addLink(s2, s4)
    net.addLink(s3,s5)
    net.addLink(s4,s5)
    net.addLink(s5, h1)
   
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
        p1 = {'position' : '30.0,70.0,0.0'}
        p2 = {'position' : '150.0,70.0,0.0'}

    net.mobility(sta1, 'start',time=70, **p1)
    net.mobility(sta1, 'stop', time=95, **p2)
    net.stopMobility(time=95)

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
    sta1.cmd("ifconfig sta1-wlan0 inet add 1234:1234:1234::101:101:101:101/128")
    rsu1.cmd("ifconfig sta1-wlan0 inet add fe80::200:ff:fe00:8/128")
    rsu2.cmd("ifconfig sta1-wlan0 inet add fe80::200:ff:fe00:9/128")
    rsu3.cmd("ifconfig sta1-wlan0 inet add fe80::200:ff:fe00:10/128")
    sta1.setIP6('', intf='sta1-wlan0')

    h1.cmd("ip -6 route add default dev h1-eth0")
    sta1.cmd("ip -6 route add default dev sta1-wlan0")
       
    info("*** Running CLI\n")
    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topology(sys.argv)

