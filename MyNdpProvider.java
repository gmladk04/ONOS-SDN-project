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
import org.onosproject.net.flow.*;
import org.onosproject.net.link.LinkProviderRegistry;
import org.onosproject.net.link.LinkService;
import org.onosproject.net.packet.*;
import org.onosproject.net.provider.AbstractProvider;
import org.onosproject.net.provider.ProviderId;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.onosproject.net.flow.instructions.Instructions;
import org.slf4j.Logger;

import java.nio.ByteBuffer;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Flow;
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
    protected ApplicationId appId;

    public static final String CONFIG_KEY = "suppression";
    public static final String FEATURE_NAME = "myNDP";


    class VehicleInfo {
        MacAddress vehicleMacAddr;
        DeviceId deviceId;

        public VehicleInfo(MacAddress mac, DeviceId did){
            this.vehicleMacAddr = mac;
            this.deviceId = did;
        }
    }
    ConcurrentHashMap<byte[], VehicleInfo> addrDB = new ConcurrentHashMap<byte[], VehicleInfo>();
    ConcurrentHashMap<Integer, FlowRule> lbrFlowDB= new ConcurrentHashMap<Integer, FlowRule>();
    ConcurrentHashMap<Integer, FlowRule> rsuFlowDB= new ConcurrentHashMap<Integer, FlowRule>();

    ConcurrentHashMap<byte[], VehicleInfo> addrDB2 = new ConcurrentHashMap<byte[], VehicleInfo>();
    ConcurrentHashMap<Integer, FlowRule> lbrFlowDB2= new ConcurrentHashMap<Integer, FlowRule>();
    ConcurrentHashMap<Integer, FlowRule> rsuFlowDB2= new ConcurrentHashMap<Integer, FlowRule>();


    ConcurrentHashMap<DeviceId, IpAddress> rsuIpDB= new ConcurrentHashMap<DeviceId, IpAddress>();
    ConcurrentHashMap<DeviceId, IpAddress> rsuIpDB2= new ConcurrentHashMap<DeviceId, IpAddress>();
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

        //add RSU ip addr
        rsuIpDB.put(DeviceId.deviceId("of:1000000000000001"), IpAddress.valueOf("fe80::200:ff:fe00:8"));
        rsuIpDB.put(DeviceId.deviceId("of:1000000000000002"), IpAddress.valueOf("fe80::200:ff:fe00:9"));
        rsuIpDB2.put(DeviceId.deviceId("of:1000000000000003"), IpAddress.valueOf("fe80::200:ff:fe00:10"));
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
        selector.matchEthType((short)0x86dd);

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
            DeviceId deviceId = connectPoint.deviceId();

            Ethernet eth = context.inPacket().parsed();
            if (eth == null) {
                return;
            }
            MacAddress vehicle_mac = eth.getSourceMAC();

            log.info("Ethertype: " + (short)eth.getEtherType());
            if(eth.getEtherType() != (short)0x86dd) {
                return;
            }

            IPv6 ipv6 = (IPv6) eth.getPayload();

            log.info("Next Header: " + ipv6.getNextHeader());
            if(ipv6.getNextHeader() != 17) {
                return;
            }

            UDP udp = (UDP) ipv6.getPayload();

            log.info("Destination port: " + udp.getDestinationPort());
            if(udp.getDestinationPort() != 12345) {
                return;
            }

            if(eth.getEtherType()==(short)0x86dd && ipv6.getNextHeader()==17 && udp.getDestinationPort()==12345) {
                log.info("UDP-ND Frame is received");
                NsFrame ns = new NsFrame(udp.getPayload().serialize());

                byte[] target_addr = ns.getTarget_addr();

                if(ns.getCode()==0){ //Registration
                    if(addrDB.containsKey(target_addr)){ //entry exist - send error UDP-NA
                        sendErrorNa(target_addr, vehicle_mac);
                    }
                    else{ // no entry - normal situation, insert new entry with the target address
                        addrDB.put(target_addr, new VehicleInfo(vehicle_mac, deviceId));
                    }
                    log.info("registration");
                    // set LBR switch's flow rule
                    //  log.info(IpAddress.valueOf("fe80::200:ff:fe00:9").toString());
                    //  log.info(addrDB.get(target_addr).toString());
                    log.info(addrDB.get(target_addr).deviceId.toString());
                    log.info(rsuIpDB.get(DeviceId.deviceId("of:1000000000000001")).toString());
                    installFlowRule(DeviceId.deviceId("of:0000000000000002"), rsuIpDB.get(DeviceId.deviceId("of:1000000000000001")), true);
                    // set RSU 's flow rule
                    installFlowRule(DeviceId.deviceId("of:1000000000000001"), rsuIpDB.get(DeviceId.deviceId("of:1000000000000001")), false);
                    //IpAddress.valueOf(IpAddress.Version.INET6,target_addr)
                    sendSuccessNa(target_addr, vehicle_mac);
                }
                else if(ns.getCode()==1){ //Handover intra
                    if(!addrDB.containsKey(target_addr)){ // no entry - send error NDP-NA
                        sendErrorNa(target_addr, vehicle_mac);
                    }
                    // modify LBR 's flow rule
                    modifyFlowRule(DeviceId.deviceId("of:0000000000000002"), lbrFlowDB.get(1), rsuIpDB.get(DeviceId.deviceId("of:1000000000000002")), true);
                    // modify RSU's flow rule
                    modifyFlowRule(DeviceId.deviceId("of:1000000000000002"), rsuFlowDB.get(1), IpAddress.valueOf(IpAddress.Version.INET6,target_addr), false);
                    sendSuccessNa(target_addr, vehicle_mac);
                }
               else if(ns.getCode()==2){ //Handover inter
                    if(addrDB2.containsKey(target_addr)){ // no entry - send error NDP-NA
                        sendErrorNa(target_addr, vehicle_mac);
                    }
                    else{ // no entry - normal situation, insert new entry with the target address
                        addrDB2.put(target_addr, new VehicleInfo(vehicle_mac, deviceId));
                    }
                    // modify LBR 's flow rule
                    log.info(addrDB2.get(target_addr).deviceId.toString());
                    log.info(rsuIpDB2.get(DeviceId.deviceId("of:1000000000000003")).toString());
                    installFlowRule2(DeviceId.deviceId("of:0000000000000003"), rsuIpDB2.get(DeviceId.deviceId("of:1000000000000003")), true);
                    // set RSU 's flow rule
                    installFlowRule2(DeviceId.deviceId("of:1000000000000003"), rsuIpDB2.get(DeviceId.deviceId("of:1000000000000003")), false);
                    //IpAddress.valueOf(IpAddress.Version.INET6,target_addr)
                    sendSuccessNa3(target_addr, vehicle_mac);

                    modifyFlowRule2(DeviceId.deviceId("of:0000000000000002"), lbrFlowDB.get(1), rsuIpDB.get(DeviceId.deviceId("of:1000000000000002")), true);
                    // modify RSU's flow rule
                    modifyFlowRule2(DeviceId.deviceId("of:1000000000000002"), rsuFlowDB.get(1), IpAddress.valueOf(IpAddress.Version.INET6,target_addr), false);
                    sendSuccessNa2(target_addr, vehicle_mac);
                }
            }
        }
    }

    private void installFlowRule(DeviceId deviceId, IpAddress ipv6, boolean isLBR){
        log.info("install rule module");
        log.info(ipv6.toString());
        FlowRule.Builder flowRule = DefaultFlowRule.builder();
        flowRule.fromApp(appId)
                .withPriority(40000)
                .forTable(1)
                .forDevice(deviceId)
                .makePermanent();

        if(isLBR) {
            log.info("set LBR");

            TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
            selector.matchEthType((short)0x86dd);
            selector.matchIPv6Dst(IpPrefix.valueOf(ipv6, 128));

            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();
            treatment.add(Instructions.modL3IPv6Dst(ipv6)); //rsu's ip from rsuIpDB
            treatment.setOutput(PortNumber.portNumber(1));
            log.info("treatment and selector setting done");

            flowRule.withTreatment(treatment.build());
            flowRule.withSelector(selector.build());
            log.info("what is problem?");

            flowRuleService.applyFlowRules(flowRule.build());  log.info("apply rule - done - lbr");
            lbrFlowDB.put(1, flowRule.build()); log.info("put entry to DB - done - lbr");

        }
        else{ //RSU1
            log.info("set RSU1");
            TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
            selector.matchEthType((short)0x86dd);
            selector.matchIPv6Dst(IpPrefix.valueOf(ipv6, 128));

            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();
            treatment.add(Instructions.modL3IPv6Dst(ipv6));
            treatment.setOutput(PortNumber.portNumber(1));

            flowRule.withTreatment(treatment.build())
                    .withSelector(selector.build());

            flowRuleService.applyFlowRules(flowRule.build()); log.info("apply rule - done - Rsu");
            rsuFlowDB.put(1, flowRule.build()); log.info("put entry to DB - done -Rsu");
        }
    }
    private void installFlowRule2(DeviceId deviceId, IpAddress ipv6, boolean isLBR){
        log.info("install rule module");
        log.info(ipv6.toString());
        FlowRule.Builder flowRule = DefaultFlowRule.builder();
        flowRule.fromApp(appId)
                .withPriority(40000)
                .forTable(1)
                .forDevice(deviceId)
                .makePermanent();

        if(isLBR) { //LBR2
            log.info("set LBR");

            TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
            selector.matchEthType((short)0x86dd);
            selector.matchIPv6Dst(IpPrefix.valueOf(ipv6, 128));

            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();
            treatment.add(Instructions.modL3IPv6Dst(ipv6)); //rsu's ip from rsuIpDB
            treatment.setOutput(PortNumber.portNumber(1));
            log.info("treatment and selector setting done");

            flowRule.withTreatment(treatment.build());
            flowRule.withSelector(selector.build());
            log.info("what is problem?");

            flowRuleService.applyFlowRules(flowRule.build());  log.info("apply rule - done - lbr");
            lbrFlowDB2.put(1, flowRule.build()); log.info("put entry to DB - done - lbr");

        }
        else{ //RSU3
            log.info("set RSU3");
            TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
            selector.matchEthType((short)0x86dd);
            selector.matchIPv6Dst(IpPrefix.valueOf(ipv6, 128));

            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();
            treatment.add(Instructions.modL3IPv6Dst(ipv6));
            treatment.setOutput(PortNumber.portNumber(1));

            flowRule.withTreatment(treatment.build())
                    .withSelector(selector.build());

            flowRuleService.applyFlowRules(flowRule.build()); log.info("apply rule - done - Rsu");
            rsuFlowDB2.put(1, flowRule.build()); log.info("put entry to DB - done -Rsu");
        }
    }
    private void modifyFlowRule(DeviceId deviceId, FlowRule preRule, IpAddress ipv6, boolean isLBR){
        log.info("modify flow rule module");
        flowRuleService.removeFlowRules(preRule); log.info("rule remove done");
        FlowRule.Builder flowRule = DefaultFlowRule.builder();
        flowRule.fromApp(appId)
                .withPriority(40000)
                .forDevice(deviceId)
                .forTable(1)
                .makePermanent();

        if(isLBR) {
            log.info("modify LBR's");
            TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
            selector.matchEthType((short)0x86dd);
            selector.matchIPv6Dst(IpPrefix.valueOf(ipv6, 128));

            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();
            treatment.add(Instructions.modL3IPv6Dst(ipv6))
                    .setOutput(PortNumber.portNumber(1));

            flowRule.withTreatment(treatment.build())
                    .withSelector(selector.build());

            flowRuleService.applyFlowRules(flowRule.build()); log.info("modify rule - done - lbr");
            lbrFlowDB.replace(1, flowRule.build()); log.info("replace entry to DB - done -lbr");

        }
        else{ //RSU2
            log.info("modify RSU's");
            TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
            selector.matchEthType((short)0x86dd);
            selector.matchIPv6Dst(IpPrefix.valueOf(ipv6, 128));

            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();
            treatment.add(Instructions.modL3IPv6Dst(ipv6))
                    .setOutput(PortNumber.portNumber(1));

            flowRule.withTreatment(treatment.build())
                    .withSelector(selector.build());

            flowRuleService.applyFlowRules(flowRule.build()); log.info("modify rule - done - Rsu");
            rsuFlowDB.replace(1, flowRule.build()); log.info("replace entry to DB - done -Rsu");

        }
    }
    private void modifyFlowRule2(DeviceId deviceId, FlowRule preRule, IpAddress ipv6, boolean isLBR){
        log.info("modify flow rule module");
        flowRuleService.removeFlowRules(preRule); log.info("rule remove done");
        FlowRule.Builder flowRule = DefaultFlowRule.builder();
        flowRule.fromApp(appId)
                .withPriority(40000)
                .forDevice(deviceId)
                .forTable(1)
                .makePermanent();
    /*
        if(isLBR) {
            log.info("modify LBR's");
            TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
            selector.matchEthType((short)0x86dd);
            selector.matchIPv6Dst(IpPrefix.valueOf(ipv6, 128));

            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();
            treatment.add(Instructions.modL3IPv6Dst(ipv6))
                    .setOutput(PortNumber.portNumber(1));

            flowRule.withTreatment(treatment.build())
                    .withSelector(selector.build());

            flowRuleService.applyFlowRules(flowRule.build()); log.info("remove rule - done - lbr");
            lbrFlowDB.remove(1, flowRule.build()); log.info("remove entry to DB - done -lbr");

        }
        else{ //RSU2
            log.info("modify RSU's");
            TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
            selector.matchEthType((short)0x86dd);
            selector.matchIPv6Dst(IpPrefix.valueOf(ipv6, 128));

            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();
            treatment.add(Instructions.modL3IPv6Dst(ipv6))
                    .setOutput(PortNumber.portNumber(1));

            flowRule.withTreatment(treatment.build())
                    .withSelector(selector.build());

            flowRuleService.applyFlowRules(flowRule.build()); log.info("remove rule - done - Rsu");
            rsuFlowDB.remove(1, flowRule.build()); log.info("remove entry to DB - done -Rsu");

        }*/
    }
    private void sendSuccessNa(byte[] target_addr, MacAddress vehicle_mac) {
        log.info("send success NA");
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
        udpPacket.setDestinationPort(1234);
        udpPacket.setSourcePort(1234);
        //ip contents
        byte[] sourceaddr = new byte[] {(byte) 0x12, 0x12, 0x34, 0x34, 0x12, 0x12, 0x34, 0x34,0x12, 0x12, 0x34, 0x34,0x12, 0x12, 0x34, 0x34};
        ipPacket.setPayload(udpPacket);
        ipPacket.setDestinationAddress(sourceaddr);
        ipPacket.setSourceAddress(sourceaddr);
        ipPacket.setNextHeader((byte)17);
        ipPacket.setHopLimit((byte)64);

        //ethernet contents
        ethPacket.setEtherType((short) 0x86dd);
        ethPacket.setSourceMACAddress(MacAddress.valueOf("02:eb:d8:f4:17:84")).setPayload(ipPacket);
        ethPacket.setDestinationMACAddress(MacAddress.valueOf("ff:ff:ff:ff:ff:ff"));
        ethPacket.setPad(true);

        OutboundPacket pkt = new DefaultOutboundPacket(DeviceId.deviceId("of:1000000000000001"), DefaultTrafficTreatment.builder().setOutput(PortNumber.portNumber(1)).build(), ByteBuffer.wrap(ethPacket.serialize()));
        packetService.emit(pkt);
    }
    private void sendSuccessNa2(byte[] target_addr, MacAddress vehicle_mac) {
        log.info("send success NA to RSU2");
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
        udpPacket.setDestinationPort(1234);
        udpPacket.setSourcePort(1234);
        //ip contents
        byte[] sourceaddr = new byte[] {(byte) 0x12, 0x12, 0x34, 0x34, 0x12, 0x12, 0x34, 0x34,0x12, 0x12, 0x34, 0x34,0x12, 0x12, 0x34, 0x34};
        ipPacket.setPayload(udpPacket);
        ipPacket.setDestinationAddress(sourceaddr);
        ipPacket.setSourceAddress(sourceaddr);
        ipPacket.setNextHeader((byte)17);
        ipPacket.setHopLimit((byte)64);

        //ethernet contents
        ethPacket.setEtherType((short) 0x86dd);
        ethPacket.setSourceMACAddress(MacAddress.valueOf("12:eb:d8:f4:17:84")).setPayload(ipPacket);
        ethPacket.setDestinationMACAddress(MacAddress.valueOf("ff:ff:ff:ff:ff:ff"));
        ethPacket.setPad(true);

        OutboundPacket pkt = new DefaultOutboundPacket(DeviceId.deviceId("of:1000000000000002"), DefaultTrafficTreatment.builder().setOutput(PortNumber.portNumber(1)).build(), ByteBuffer.wrap(ethPacket.serialize()));
        packetService.emit(pkt);
    }
    private void sendSuccessNa3(byte[] target_addr, MacAddress vehicle_mac) {
        log.info("send success NA to RSU3");
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
        udpPacket.setDestinationPort(1234);
        udpPacket.setSourcePort(1234);
        //ip contents
        byte[] sourceaddr = new byte[] {(byte) 0x12, 0x12, 0x34, 0x34, 0x12, 0x12, 0x34, 0x34,0x12, 0x12, 0x34, 0x34,0x12, 0x12, 0x34, 0x34};
        ipPacket.setPayload(udpPacket);
        ipPacket.setDestinationAddress(sourceaddr);
        ipPacket.setSourceAddress(sourceaddr);
        ipPacket.setNextHeader((byte)17);
        ipPacket.setHopLimit((byte)64);

        //ethernet contents
        ethPacket.setEtherType((short) 0x86dd);
        ethPacket.setSourceMACAddress(MacAddress.valueOf("22:eb:d8:f4:17:84")).setPayload(ipPacket);
        ethPacket.setDestinationMACAddress(MacAddress.valueOf("ff:ff:ff:ff:ff:ff"));
        ethPacket.setPad(true);

        OutboundPacket pkt = new DefaultOutboundPacket(DeviceId.deviceId("of:1000000000000003"), DefaultTrafficTreatment.builder().setOutput(PortNumber.portNumber(1)).build(), ByteBuffer.wrap(ethPacket.serialize()));
        packetService.emit(pkt);
    }
    private void sendErrorNa(byte[] target_addr, MacAddress vehicle_mac) {
        log.info("send Error NA");
        Ethernet ethPacket = new Ethernet();
        IPv6 ipPacket = new IPv6();
        UDP udpPacket = new UDP();
        NaFrame naPacket = new NaFrame();

        //Na contents
        naPacket.setPacket_type((byte)136);
        naPacket.setCode((byte) 1); // it means error when it is not 0
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
