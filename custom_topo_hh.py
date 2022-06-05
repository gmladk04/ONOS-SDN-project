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
    ap1 = net.addAccessPoint('ap1', cls=OVSKernelAP, ssid='ap1-ssid', mode='g', channel='1',
                             position='37,70,0')
    ap2 = net.addAccessPoint('ap2', cls=OVSKernelAP, ssid='ap2-ssid', mode='g', channel='1',
                             position='70,70,0')
    ap3 = net.addAccessPoint('ap3', cls=OVSKernelAP, ssid='ap3-ssid', mode='g', channel='1',
                             position='103,70,0')
    sta1 = net.addStation('sta1', mac='00:00:00:00:00:04', ip='10.0.0.4/8', position='30,60,0')
   
    c0 = net.addController(name='c0', controller=RemoteController, 
                           ip='127.0.0.1',
                           protocol='tcp',
                           port=6653)

    info("*** Configuring propagation model\n")
    net.setPropagationModel(model="logDistance", exp=6)

    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()

    info("*** Associating and Creating links\n")
    net.addLink(s1,ap1)
    net.addLink(s1,ap2)
    net.addLink(s2, ap3)

    net.addLink(s1,s3)
    net.addLink(s2, s4)
    net.addLink(s3,s5)
    net.addLink(s4,s5)
    net.addLink(s5, h1)
   
    ap1sta1 = {'bw':80 }
    net.addLink(ap1, sta1, **ap1sta1)

    net.plotGraph(max_x=200, max_y=200)


    info("*** Starting network\n")
    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])
    s4.start([c0])
    s5.start([c0])
    ap1.start([c0])
    ap2.start([c0])
    ap3.start([c0])

    info("*** Running CLI\n")
    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topology(sys.argv)
