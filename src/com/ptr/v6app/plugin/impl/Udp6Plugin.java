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
import org.jnetpcap.protocol.tcpip.Udp;

import com.ptr.v6app.injector.LiveInjector;
import com.ptr.v6app.plugin.InjectorPlugin;
import com.ptr.v6app.util.JNetPcapUtils;
import com.ptr.v6app.util.NetUtils;

/**
 * This class is an injector plugin that injects UDP (v6) packets on the wire.
 */
public class Udp6Plugin implements InjectorPlugin {

    // -- Logger
    private static final Logger log = LogManager.getLogger(Udp6Plugin.class.getName());

    // -- Plugin name
    private static final String NAME = "UDP IPv6";

    // -- Injection packets
    private List<JPacket> packets;

    // -- Destinatino MAC addresses (TODO: make this configurable)
    private String[] dstMacs = new String[] { "33-33-00-00-00-01", "33-33-00-00-00-02",
            "33-33-00-00-00-0c", "33-33-00-00-00-0f", "33-33-00-00-00-fb" };

    // -- Destination IPv6 addresses (TODO: make this configurable)
    private String[] dstIps = new String[] { "FF02::01", // All nodes
            "FF02::02", // All routers
            "FF02::0c", "FF02::0f", "FF02::fb" };

    // -- Directory holding our pcap files
    private static final String PCAP_DIR = "pcap/udp/v6";

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public void initialize(PcapIf pcapIf) {
        packets = new ArrayList<JPacket>();

        // Extract source MAC from injection interface.
        byte[] srcMac;
        try {
            srcMac = pcapIf.getHardwareAddress();
        } catch (IOException ioe) {
            log.error("Error obtaining injection interface address: ", ioe);
            return;
        }

        // Extract a source IPv6 address from the injection interface.
        // We only want to use a link local address. 
        byte[] srcIp = NetUtils.getLinkLocal6Addr(pcapIf);
        if (srcIp == null) {
            log.error("Failed to find an IPv6 link-local source address.");
            // TODO: We might be able to function without a valid source addr.
            // But, that will take more testing than just failing.
            // Also, we don't have any way to communicate to the user that
            // they have no assigned IPv6 address, but that we're faking it
            // for the purposes of the test.
            return;
        }

        // packet headers
        Ethernet eth = new Ethernet();
        Ip6 ip = new Ip6();
        Udp udp = new Udp();

        // get a list of pcap files we'll use for injection
        String[] pcapFiles = JNetPcapUtils.getPcapFilenames(PCAP_DIR);

        // Load the pcap files one-by-one
        for (String pcapFile : pcapFiles) {
            PcapPacket packet = JNetPcapUtils.pcapPacketFromFile(pcapFile);
            if (packet == null) {
                log.warn("No packet found in '" + pcapFile + "'");
                continue;
            }

            // validate packet
            if (!packet.hasHeader(eth) || !packet.hasHeader(ip) || !packet.hasHeader(udp)) {
                log.error("Invalid UDP packet in [{}]", pcapFile);
                continue;
            }

            // Set the source MAC and IP in the packet.
            eth.source(srcMac);
            ip.setByteArray(8, srcIp);

            // Build a list of potential packets from this one.
            for (String dstMac : dstMacs) {
                eth.destination(NetUtils.getMacBytes(dstMac));
                for (String dstIp : dstIps) {
                    ip.setByteArray(24, NetUtils.getAddressBytes(dstIp));

                    // calculate checksums
                    eth.calculateChecksum();

                    // Make a deep copy of the packet and add it to the list.
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
