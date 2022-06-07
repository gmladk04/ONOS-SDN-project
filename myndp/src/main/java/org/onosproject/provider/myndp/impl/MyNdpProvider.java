/*
 * Copyright 2015-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.onosproject.provider.myndp.impl;

import org.onlab.packet.*;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.cluster.ClusterService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.link.LinkProviderRegistry;
import org.onosproject.net.link.LinkService;
import org.onosproject.net.packet.*;
import org.onosproject.net.provider.AbstractProvider;
import org.onosproject.net.provider.ProviderId;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.slf4j.Logger;

import java.nio.ByteBuffer;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * Provider which uses LLDP and BDDP packets to detect network infrastructure links.
 */
@Component(immediate = true)
public class MyNdpProvider extends AbstractProvider {

    private static final String PROVIDER_NAME = "org.onosproject.provider.myndp";

    public static final String NO_MYNDP = "no-myndp";

    private final Logger log = getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected LinkProviderRegistry providerRegistry;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected LinkService linkService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected MastershipService masterService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ClusterService clusterService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry cfgRegistry;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    private ScheduledExecutorService executor;
    protected ExecutorService eventExecutor;

    private boolean shuttingDown = false;

    /**
     * If false, link discovery is disabled.
     */
    protected boolean enabled = true;

    private final InternalPacketProcessor packetProcessor = new InternalPacketProcessor();
    //private final InternalContext myContext = new InternalContext();
    private ApplicationId appId;

    public static final String CONFIG_KEY = "suppression";
    public static final String FEATURE_NAME = "myNDP";


    class VehicleInfo {
        MacAddress vehicleMacAddr;
        PortNumber inport;

        public VehicleInfo(MacAddress mac, PortNumber port){
            this.vehicleMacAddr = mac;
            this.inport = port;
        }

        void setValues(MacAddress mac, IPv4 ip, PortNumber port){
        	vehicleMacAddr = mac;
        	inport = port;
		}
    }
    ConcurrentHashMap<byte[], VehicleInfo> addrDB = new ConcurrentHashMap<byte[], VehicleInfo>();

    /**
     * Creates an OpenFlow link provider.
     */
    public MyNdpProvider() {
        super(new ProviderId("myndp", PROVIDER_NAME));
    }

    @Activate
    public void activate(ComponentContext context) {

        shuttingDown = false;
        enabled = true;
        appId = coreService.registerApplication(PROVIDER_NAME);
        modified(context);
        enable();
        log.info("Started");
    }

    @Deactivate
    public void deactivate() {
        shuttingDown = true;

        disable();
        eventExecutor = null;
        log.info("Stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
        log.info("Modified");
    }

    /**
     * Enables link discovery processing.
     */
    private void enable() {
        packetService.addProcessor(packetProcessor, PacketProcessor.advisor(0));
        requestIntercepts();
    }

    /**
     * Disables link discovery processing.
     */
    private void disable() {
        withdrawIntercepts();

        packetService.removeProcessor(packetProcessor);

        if (executor != null) {
            executor.shutdownNow();
        }

    }

    /**
     * Requests packet intercepts.
     */
    private void requestIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType((short)0x86dd);
        selector.matchIPProtocol((byte)17);
        selector.matchUdpDst(TpPort.tpPort(12345));

        packetService.requestPackets(selector.build(), PacketPriority.CONTROL, appId);
    }

    /**
     * Withdraws packet intercepts.
     */
    private void withdrawIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchIPProtocol((byte)17);
        selector.matchUdpDst(TpPort.tpPort(12345));

        packetService.cancelPackets(selector.build(), PacketPriority.CONTROL, appId);
    }

    /**
     * Processes incoming packets.
     */
    private class InternalPacketProcessor implements PacketProcessor {
        private boolean test = false;

        @Override
        public void process(PacketContext context) {
            if (context == null || context.isHandled()) {
                return;
            }
            ConnectPoint connectPoint = context.inPacket().receivedFrom();
            PortNumber inport = connectPoint.port();

            Ethernet eth = context.inPacket().parsed();
            if (eth == null) {
                return;
            }
            MacAddress vehicle_mac = eth.getSourceMAC();

            log.info("" + eth.getEtherType());
            if(eth.getEtherType() != (short)0x86dd) {
                return;
            }

            IPv6 ipv6 = (IPv6) eth.getPayload();

            log.info("" + ipv6.getNextHeader());
            if(ipv6.getNextHeader() != 17) {
                return;
            }

            UDP udp = (UDP) ipv6.getPayload();

            log.info("" + udp.getDestinationPort());
            if(udp.getDestinationPort() != 12345) {
                return;
            }

            log.info("UDP-ND Frame is received");
            NsFrame ns = new NsFrame(udp.getPayload().serialize());

            byte[] target_addr = ns.getTarget_addr();

            // code checking -> if the code is zero, then go to Registration, else then go to Handover
            addrDB.put(target_addr, new VehicleInfo(vehicle_mac, inport));
            sendNa(target_addr, vehicle_mac);
        }
    }

    private void sendNa(byte[] target_addr, MacAddress vehicle_mac) {
        log.info("woooooooooooooooooooooooooooooooooooooooooooooooooooooooow");
        Ethernet ethPacket = new Ethernet();
        IPv6 ipPacket = new IPv6();
        UDP udpPacket = new UDP();
        NaFrame naPacket = new NaFrame();

        //Na contents
        naPacket.setPacket_type((byte)136);
        naPacket.setCode((byte) 0);
        naPacket.setTarget_addr(target_addr);
        naPacket.setMac(vehicle_mac);

        //udp contents
        udpPacket.setPayload(naPacket);

        //ip contents
        ipPacket.setPayload(udpPacket);

        //ethernet contents
        ethPacket.setEtherType((short) 0x86dd);
        ethPacket.setSourceMACAddress(MacAddress.valueOf("02:eb:d8:f4:17:84")).setPayload(ipPacket);
        ethPacket.setDestinationMACAddress(MacAddress.valueOf("ff:ff:ff:ff:ff:ff"));
        ethPacket.setPad(true);

        OutboundPacket pkt = new DefaultOutboundPacket(DeviceId.deviceId("of:1000000000000001"), DefaultTrafficTreatment.builder().setOutput(PortNumber.portNumber(1)).build(), ByteBuffer.wrap(ethPacket.serialize()));
        packetService.emit(pkt);
    }

}
