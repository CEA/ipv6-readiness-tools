package com.ptr.v6app.plugin.impl;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip6;

import com.ptr.v6app.injector.LiveInjector;
import com.ptr.v6app.jnetpcap.packet.Icmp6;
import com.ptr.v6app.plugin.InjectorPlugin;
import com.ptr.v6app.util.JNetPcapUtils;
import com.ptr.v6app.util.NetUtils;

/**
 * This class is an injector plugin that injects ICMPv6 packets on the wire.
 */
public class Icmp6Plugin implements InjectorPlugin {

    // -- Logger
    private static final Logger log = LogManager.getLogger(Icmp6Plugin.class.getName());

    // -- Plugin name
    private static final String NAME = "ICMPv6";

    // -- Injection packets
    private List<JPacket> packets;

    private String[][] dstMacIps = { { "33:33:00:00:00:0C", "ff02::c" },
            { "33:33:00:00:00:0f", "ff02::f" }, { "33:33:00:00:00:01", "ff02::1" },
            { "33:33:00:00:00:fb", "ff02::fb" } };

    // -- Directory holding our pcap files
    private static final String PCAP_DIR = "pcap/icmp/v6";

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public void initialize(PcapIf pcapIf) {
        packets = new ArrayList<JPacket>();

        // extract source MAC from injection interface
        byte[] srcMac;
        try {
            srcMac = pcapIf.getHardwareAddress();
        } catch (IOException ioe) {
            log.error("Error obtaining injection interface address: ", ioe);
            return;
        }

        // extract a source IPv4 address from injection interface
        byte[] srcIp = NetUtils.getLinkLocal6Addr(pcapIf);
        if (srcIp == null) {
            log.error("Failed to find a IPv6 link-local source address");
            return;
        }

        // get a list of pcap files we'll use for injection
        String[] pcapFiles = JNetPcapUtils.getPcapFilenames(PCAP_DIR);
        
        // packet headers
        Ethernet eth = new Ethernet();
        Ip6 ip = new Ip6();
        Icmp6 icmp = new Icmp6();

        // load pcap files one-by-one
        for (String pcapFile : pcapFiles) {
            PcapPacket packet = JNetPcapUtils.pcapPacketFromFile(pcapFile);
            if (packet == null) {
                log.warn("No packet found in [{}]", pcapFile);
                continue;
            }
            
            // validate packet
            if (!packet.hasHeader(eth) || !packet.hasHeader(ip) || !packet.hasHeader(icmp)) {
                log.error("Invalid packet type in [{}]", pcapFile);
                continue;
            }

            // set the source MAC/IP in the packet
            eth.source(srcMac);
            ip.setByteArray(8, srcIp);

            // set destination mac/ip
            for (String[] dst : dstMacIps) {
                eth.destination(NetUtils.getMacBytes(dst[0]));
                ip.setByteArray(24, NetUtils.getAddressBytes(dst[1]));
                
                // calculate checksums
                eth.calculateChecksum();
                icmp.calculateChecksum();

                // make a deep copy of the packet and add it to the list
                packets.add(new PcapPacket(packet));
            }
        }
    }

    @Override
    public List<JPacket> getInjectionPackets() {
        return packets;
    }

    @Override
    public void registerLiveInjector(LiveInjector injector) {
        // not supported
    }

    @Override
    public void unregisterLiveInjector(LiveInjector injector) {
        // not supported
    }
}
