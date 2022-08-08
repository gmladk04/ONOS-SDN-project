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
package org.onosproject.provider.myndp2.impl;

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

    int code = 2;

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

    // ConcurrentHashMap<byte[], VehicleInfo> addrDB = new ConcurrentHashMap<byte[], VehicleInfo>();
    ConcurrentHashMap<IpAddress, VehicleInfo> addrDB = new ConcurrentHashMap<IpAddress, VehicleInfo>(); // byte[] cannot be used as key
    ConcurrentHashMap<IpAddress, FlowRule> lbrFlowDB= new ConcurrentHashMap<IpAddress, FlowRule>(); // Integer? Use IpAddress as key
    ConcurrentHashMap<IpAddress, FlowRule> rsuFlowDB= new ConcurrentHashMap<IpAddress, FlowRule>(); // Integer? Use IpAddress as key

    ConcurrentHashMap<DeviceId, IpAddress> rsuIpDB= new ConcurrentHashMap<DeviceId, IpAddress>();
    ConcurrentHashMap<DeviceId, String> rsuNameDB= new ConcurrentHashMap<DeviceId, String>();


    /**
     * Creates an OpenFlow link provider.
     */
    public MyNdpProvider() {
        super(new ProviderId("myndp", PROVIDER_NAME));
    }

    boolean first = true;
    boolean second = false;
    boolean third = false;

    @Activate
    public void activate(ComponentContext context) {

        shuttingDown = false;
        enabled = true;
        appId = coreService.registerApplication(PROVIDER_NAME);
        modified(context);
        enable();

        //add RSU ip addr

        rsuIpDB.put(DeviceId.deviceId("of:1000000000000003"), IpAddress.valueOf("fe80::200:ff:fe00:10"));
        rsuNameDB.put(DeviceId.deviceId("of:1000000000000003"), "rsu3");

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
            log.info(deviceId.toString()+" is okay?");
            if(!( deviceId.toString().equals("of:1000000000000003")))
                return;

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
                log.info("UDP-Ns Frame is received");
                NsFrame ns = new NsFrame(udp.getPayload().serialize());

                byte[] target_addr = ns.getTarget_addr();
                IpAddress targetAddr = IpAddress.valueOf(IpAddress.Version.INET6, target_addr); // Convert byte[] to IPv6 address

                if(ns.getCode()==2) { //Registration
                    if (addrDB.containsKey(targetAddr)) { //entry exist - send error UDP-NA
                        sendErrorNa(deviceId, target_addr, vehicle_mac);
                    } else { // no entry - normal situation, insert new entry with the target address
                        addrDB.put(targetAddr, new VehicleInfo(vehicle_mac, deviceId)); // targetAddr use
                    }
                    log.info("registration");
                    //  log.info(IpAddress.valueOf("fe80::200:ff:fe00:9").toString());
                    //  log.info(addrDB.get(target_addr).toString());

                    // log.info(addrDB.get(targetAddr).deviceId.toString()); // use targetAddr, printf deviceId for target vehicle
                    log.info(rsuIpDB.get(deviceId).toString()); // print IPv6 address of the RSU which received the NS

                    // set LBR, RSU switch's flow rule
                    installFlowRuleToLbr(DeviceId.deviceId("of:0000000000000003"), targetAddr, rsuIpDB.get(deviceId), vehicle_mac); // Change the IPv6 address using deviceId (The switch which received this NS)
                    installFlowRuleToRsu(deviceId, targetAddr, vehicle_mac);

                    sendSuccessNa(deviceId, target_addr, vehicle_mac);
                }
            }
        }
    }

    private void installFlowRuleToRsu(DeviceId deviceId, IpAddress target, MacAddress vehicle_mac) {
        log.info("install new flow rule (registration) to RSU");
        log.info(deviceId.toString());

        FlowRule.Builder flowRule = DefaultFlowRule.builder();
        flowRule.fromApp(appId)
                .withPriority(60000)
                .forTable(0)
                .forDevice(deviceId)
                .makePermanent();

        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType((short)0x86dd);
        selector.matchIPv6Dst(IpPrefix.valueOf(rsuIpDB.get(deviceId), 128)); // RSU IP

        TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();
        // treatment.add(Instructions.modL2Dst(vehicle_mac)); // Original Vehicle IP
        //treatment.setIpv6Src(target);
        treatment.setEthDst(vehicle_mac);
        treatment.setOutput(PortNumber.portNumber(2));

        flowRule.withTreatment(treatment.build())
                .withSelector(selector.build());


        FlowRule newFlow = flowRule.build();

        flowRuleService.applyFlowRules(newFlow); log.info("apply rule - done - Rsu");
        rsuFlowDB.put(target, newFlow); log.info("put entry to DB - done -Rsu");
    }

    private void installFlowRuleToLbr(DeviceId deviceId, IpAddress target, IpAddress rsuIp, MacAddress vehicle_mac){
        log.info("install new flow rule (registration) to LBR");
        log.info(deviceId.toString());

        FlowRule.Builder flowRule = DefaultFlowRule.builder();
        flowRule.fromApp(appId)
                .withPriority(60000)
                .forTable(0)
                .forDevice(deviceId)
                .makePermanent();

        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType((short)0x86dd);
        selector.matchIPv6Dst(IpPrefix.valueOf(target, 128)); // vehicle IP

        TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();
        //treatment.add(Instructions.modL2Dst(vehicle_mac));
        //  treatment.setIpv6Dst(target);
        treatment.setOutput(PortNumber.portNumber(1)); // Check whether portNumber 1 is right
        log.info("treatment and selector setting done");

        flowRule.withTreatment(treatment.build());
        flowRule.withSelector(selector.build());
        log.info("what is problem?");

        FlowRule newFlow = flowRule.build();

        flowRuleService.applyFlowRules(newFlow);  log.info("apply rule - done - lbr");
        lbrFlowDB.put(target, newFlow); log.info("put entry to DB - done - lbr");
    }


    private void modifyFlowRuleOfRsu(DeviceId deviceId, IpAddress target, MacAddress vehicle_mac) {
        log.info("modify RSU");
        log.info(deviceId.toString());
        flowRuleService.removeFlowRules(rsuFlowDB.get(target)); log.info("rule remove done");

        installFlowRuleToRsu(deviceId, target,vehicle_mac);
    }

    private void modifyFlowRuleOfLbr(DeviceId deviceId, IpAddress target, IpAddress ipv6, MacAddress vehicle_mac) {
        log.info("modify LBR");
        log.info(deviceId.toString());

        flowRuleService.removeFlowRules(lbrFlowDB.get(target)); log.info("rule remove done");

        installFlowRuleToLbr(deviceId, target, ipv6, vehicle_mac);
    }


    private void sendSuccessNa(DeviceId deviceId, byte[] target_addr, MacAddress vehicle_mac) {
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
        byte[] sourceaddr = new byte[] {(byte) 0x34, 0x15, 0x34, 0x34, 0x12, 0x12, 0x34, 0x34, 0x12, 0x12, 0x34, 0x34, 0x12, 0x12, 0x34, 0x34};
        byte[] destaddr = new byte[] {(byte) 0x12, 0x12, 0x34, 0x34, 0x12, 0x34, 0x0, 0x0, 0x1, 0x1, 0x1, 0x1,0x1, 0x1, 0x1, 0x1,};
        ipPacket.setPayload(udpPacket);
        ipPacket.setDestinationAddress(destaddr);
        ipPacket.setSourceAddress(sourceaddr);
        ipPacket.setNextHeader((byte)17);
        ipPacket.setHopLimit((byte)64);

        //ethernet contents
        ethPacket.setEtherType((short) 0x86dd);
        ethPacket.setSourceMACAddress(MacAddress.valueOf("22:eb:d8:f4:17:84")).setPayload(ipPacket);
        ethPacket.setDestinationMACAddress(MacAddress.valueOf("ff:ff:ff:ff:ff:ff"));
        ethPacket.setPad(true);

        OutboundPacket pkt = new DefaultOutboundPacket(deviceId, DefaultTrafficTreatment.builder().setOutput(PortNumber.portNumber(1)).build(), ByteBuffer.wrap(ethPacket.serialize()));
        packetService.emit(pkt);
    }

    private void sendErrorNa(DeviceId deviceId, byte[] target_addr, MacAddress vehicle_mac) {
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
        ethPacket.setSourceMACAddress(MacAddress.valueOf("22:eb:d8:f4:17:84")).setPayload(ipPacket);
        ethPacket.setDestinationMACAddress(MacAddress.valueOf("ff:ff:ff:ff:ff:ff"));
        ethPacket.setPad(true);

        OutboundPacket pkt = new DefaultOutboundPacket(deviceId, DefaultTrafficTreatment.builder().setOutput(PortNumber.portNumber(1)).build(), ByteBuffer.wrap(ethPacket.serialize()));
        packetService.emit(pkt);
    }
}