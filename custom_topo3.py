#!/usr/bin/python

"""
NOTE: you have to install wireless-regdb and CRDA
      please refer to https://mininet-wifi.github.io/80211p/
"""
import sys

from mininet.node import RemoteController, Controller, OVSKernelSwitch, Host, OVSSwitch
from mn_wifi.net import Station, OVSKernelAP
from mininet.log import setLogLevel, info
from mn_wifi.link import wmediumd, ITSLink
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi
from mn_wifi.wmediumdConnector import interference


def topology():
    "Create a network."
    net = Mininet_wifi(link=wmediumd, wmediumd_mode=interference)

    info("*** Creating nodes\n")

    h1 = net.addHost('h1', cls=Host, mac='00:00:00:00:00:01', ip='10.0.0.1/8') #CN

    s1 = net.addSwitch('s1', cls=OVSKernelSwitch)
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch)
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch)
    s4 = net.addSwitch('s4', cls=OVSKernelSwitch)
    s5 = net.addSwitch('s5', cls=OVSKernelSwitch)

    sta1 = net.addStation('sta1', mac='00:00:00:00:00:04', ip='10.0.0.4/8', position='30,60,0') # 
    sta2 = net.addStation('sta2', ip='10.0.0.2/8', position='70,70,0')
    sta3 = net.addStation('sta3', ip='10.0.0.3/8', position='103,70,0')
    sta4 = net.addStation('sta4', ip='10.0.0.4/8', position='37,70,0')
   # ap1 = net.addAccessPoint('ap1', cls=OVSKernelAP, ssid='ap1-ssid', mode='g', channel='1',
   #                          position='37,70,0')
    
    c0 = net.addController(name='c0', controller=RemoteController, 
                           ip='127.0.0.1',
                           protocol='tcp',
                           port=6653)

    info("*** Configuring Propagation Model\n")
    net.setPropagationModel(model="logDistance", exp=6)

    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()
 
    info("*** Plotting Graph\n")
    net.plotGraph(max_x=300, max_y=300)

    info("*** Starting ITS Links\n")
    
    net.addLink(sta1, intf='sta1-wlan0', cls=ITSLink,
                channel=176)
    net.addLink(sta2, intf='sta2-wlan0', cls=ITSLink,
                channel=176)
    net.addLink(sta3, intf='sta3-wlan0', cls=ITSLink,
                channel=176)
    net.addLink(sta4, intf='sta4-wlan0', cls=ITSLink,
                channel=176)


    net.addLink(s1,s3)
    net.addLink(s2, s4)
    net.addLink(s3,s5)
    net.addLink(s4,s5)
    net.addLink(s5, h1)
   # net.addLink(sta4,s1)
   # net.addLink(sta2, s1)
   # net.addLink(sta3, s2)
    
    sta1sta4 = {'bw':80 }
    net.addLink(sta1, sta4, **sta1sta4)
    s1sta4 = {'bw':80 }
    net.addLink(s1, sta4, **s1sta4)
    s1sta2 = {'bw':80 }
    net.addLink(s1, sta2, **s1sta2)
    s2sta3 = {'bw':80 }
    net.addLink(s2, sta3, **s2sta3)

    info("*** Starting network\n")
    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])
    s4.start([c0])
    s5.start([c0])
   # ap1.start([c0])

    info("*** Running CLI\n")
    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topology()
