/*
 * Copyright 2016-present Open Networking Laboratory
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
package org.onosproject.provider.myapp;

import org.onlab.packet.MacAddress;
import org.onosproject.net.DeviceId;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.host.HostService;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.onosproject.provider.myapp.WsaFrame;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.UDP;

import java.nio.ByteBuffer;
import java.util.Calendar;
import java.util.Date;
import java.text.SimpleDateFormat;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Sending WSA Agent Application Component.
 */
@Component(immediate = true)
public class AppComponent{

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    private ApplicationId appId;
    private int i = 0;

    @Activate
    protected void activate() {
        //start the sending WSA agent
        appId = coreService.registerApplication("org.example.sendWSA"); //do i need to synchronize this with app name?

        //how to repetitively call sendWSA

        /*every100mseconds sendWSA = new every100mseconds();
        sendWSA.setDaemon(true);
        sendWSA.start();
        */

       every3seconds();
        log.info("Sending WSA Started");
        log.info("started the apps sending WSA");
    }

    @Deactivate
    protected void deactivate() {

        log.info("Sending WSA Stopped");
    }

    public class every100mseconds extends Thread{
        final SimpleDateFormat fmt = new SimpleDateFormat("HH:mm:ss");
        final ScheduledThreadPoolExecutor exec = new ScheduledThreadPoolExecutor(1);
        public void run(){
            for(;;){
                try{
                    Thread.sleep(100);
                    Calendar cal = Calendar.getInstance();
                    sendPacket();

                    log.info(fmt.format(cal.getTime()));
                }catch (Exception e) {
                    e.printStackTrace();
                    exec.shutdown();
                }
            }
        }
    }
    private void every3seconds() {
        int sleepSec = 1;
        final SimpleDateFormat fmt = new SimpleDateFormat("HH:mm:ss");
        final ScheduledThreadPoolExecutor exec = new ScheduledThreadPoolExecutor(1);

        exec.scheduleAtFixedRate(new Runnable() {
            public void run() {
                try {
                    Calendar cal = Calendar.getInstance();
                    sendPacket();

                    log.info(fmt.format(cal.getTime()));
                } catch (Exception e) {
                    e.printStackTrace();
                    exec.shutdown();
                }
            }
        }, 0, sleepSec, TimeUnit.SECONDS);

    }

    private void sendPacket() {
        Ethernet ethPacket = new Ethernet();
        WsaFrame wsa = new WsaFrame();

        ethPacket.setEtherType((short)0x88dc);
        ethPacket.setSourceMACAddress(MacAddress.valueOf("02:eb:d8:f4:17:84")).setPayload(wsa);
        ethPacket.setDestinationMACAddress(MacAddress.valueOf("ff:ff:ff:ff:ff:ff"));
        ethPacket.setPad(true);
        OutboundPacket pkt = new DefaultOutboundPacket(DeviceId.deviceId("of:1000000000000001"), DefaultTrafficTreatment.builder().setOutput(PortNumber.portNumber(1)).build(), ByteBuffer.wrap(ethPacket.serialize()));
        packetService.emit(pkt);
    }
}
