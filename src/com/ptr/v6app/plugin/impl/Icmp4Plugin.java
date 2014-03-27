package com.ptr.v6app.plugin.impl;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapIf;
import org.jnetpcap.PcapSockAddr;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;

import com.ptr.v6app.injector.LiveInjector;
import com.ptr.v6app.plugin.InjectorPlugin;
import com.ptr.v6app.util.JNetPcapUtils;
import com.ptr.v6app.util.NetUtils;

/**
 * This class is an injector plugin that injects ICMP (v4) packets onto the wire.
 */
public class Icmp4Plugin implements InjectorPlugin {

    // -- Logger
    private static final Logger log = LogManager.getLogger(Icmp4Plugin.class.getName());
    
    // -- Plugin name
    private static final String NAME = "ICMPv4";
    
    // -- Injection packets
    private List<JPacket> packets;

    // -- Destination MACs (TODO: make this configurable)
    private String[] dstMacs = { "FF:FF:FF:FF:FF:FF",   // broadcast 
            "33-33-06-06-06-06",                        // in the IPv6 multicast range
            "01-00-5E-7f-ff-fa",                        // IPv4 mcast for 239.255.255.250
            "01-00-5E-00-00-fb", "01-00-5E-00-00-01" };

    // -- Destination IPs (TODO: make this configurable)
    private String[] dstIps = { "224.0.0.1", "224.0.0.251", "239.255.255.250" };

    // -- Directory holding our pcap files
    private static final String PCAP_DIR = "pcap/icmp/v4";

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
        byte[] srcIp = null;
        for (PcapAddr addr : pcapIf.getAddresses()) {
            if (addr.getAddr().getFamily() == PcapSockAddr.AF_INET) {
                srcIp = addr.getAddr().getData();
                break;
            }
        }
        if (srcIp == null) {
            log.error("Failed to find a IPv4 source address");
            return;
        }
        
        // get a list of pcap files we'll use for injection
        String[] pcapFiles = JNetPcapUtils.getPcapFilenames(PCAP_DIR);
        
        // packet headers
        Ethernet eth = new Ethernet();
        Ip4 ip = new Ip4();
        Icmp icmp = new Icmp();

        // load pcap files one-by-one
        for (String pcapFile : pcapFiles) {
            
            // load packet from file
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
            ip.source(srcIp);

            // build a list of packets based on various destination MACs/IPs
            for (String dstMac : dstMacs) {
                eth.destination(NetUtils.getMacBytes(dstMac));
                for (String dstIp : dstIps) {
                    ip.destination(NetUtils.getAddressBytes(dstIp));
                    
                    // calculate checksums
                    eth.calculateChecksum();
                    ip.checksum(ip.calculateChecksum());
                    icmp.calculateChecksum();

                    // make a deep copy of the packet and add it to the list
                    packets.add(new PcapPacket(packet));
                }
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
