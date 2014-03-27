package com.ptr.v6app.plugin.impl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip6;

import com.googlecode.ipv6.IPv6Address;
import com.ptr.v6app.injector.LiveInjector;
import com.ptr.v6app.jnetpcap.packet.EchoReply6;
import com.ptr.v6app.jnetpcap.packet.EchoRequest6;
import com.ptr.v6app.jnetpcap.packet.Icmp6;
import com.ptr.v6app.listener.ListenerPacket;
import com.ptr.v6app.node.NetworkNode;
import com.ptr.v6app.node.data.Router6Info;
import com.ptr.v6app.plugin.InjectorPlugin;
import com.ptr.v6app.plugin.ListenerPlugin;
import com.ptr.v6app.util.NetUtils;

public class Ping6Plugin implements ListenerPlugin, InjectorPlugin {

    // -- Logger
    private static final Logger log = LogManager.getLogger(Ping6Plugin.class.getName());

    // -- Plugin name
    private static final String NAME = Ping6Plugin.class.getSimpleName();

    // -- Live injector references
    private final Set<LiveInjector> liveInjectors = new HashSet<LiveInjector>();

    // -- Pcap packets for reuse
    private final Ethernet eth = new Ethernet();
    private final Ip6 ip = new Ip6();
    private final Icmp6 icmp = new Icmp6();
    private final EchoRequest6 echoRequest6 = new EchoRequest6();
    private final EchoReply6 echoReply6 = new EchoReply6();

    // -- Pcap interface attributes
    private byte[] srcMac;
    private byte[] srcIp;

    // -- Global /64 prefixes for the local node
    private final List<Long> globalPrefixes = new ArrayList<Long>();

    // -- Running collection of processed addresses
    private final Set<String> processedAddrs = new HashSet<String>();

    // -- EchoRequest6 fields
    private static final String IP6_TEMPLATE = "33330000 00020000 00000000 86dd6000 00000040 "
            + "3afffe80 00000000 00000000 00000000 0000ff02 00000000 00000000 00000000 0002";
    private static final String ICMP6_TYPE_CODE_CKSUM = "80000000";
    public static final String ROUTER_ID = "7304";
    public static final String NEIGHBOR_ID = "cea1";
    public static final String SEQUENCE_NUM = "0001";
    private static final String PING6_DATA = "01234567 89abcdef 01234567 89abcdef 01234567 "
            + "89abcdef 01234567 89abcdef 01234567 89abcdef 01234567 89abcdef 01234567 89abcdef";

    // -- Injection packets
    private List<JPacket> packets;

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public void initialize(PcapIf pcapIf) {
        packets = new ArrayList<JPacket>();

        // extract source MAC from injection interface
        try {
            srcMac = pcapIf.getHardwareAddress();
        } catch (IOException ioe) {
            log.error("Error obtaining injection interface address: ", ioe);
            return;
        }

        // extract a source IPv4 address from injection interface
        srcIp = NetUtils.getLinkLocal6Addr(pcapIf);
        if (srcIp == null) {
            log.error("Failed to find a IPv6 link-local source address");
            return;
        }

        // load router ping6 packet
        String packetStr = IP6_TEMPLATE + ICMP6_TYPE_CODE_CKSUM + ROUTER_ID + SEQUENCE_NUM
                + PING6_DATA;
        JPacket packet = new JMemoryPacket(JProtocol.ETHERNET_ID, packetStr);
        
        // validate packet
        if (!packet.hasHeader(eth) || !packet.hasHeader(ip) || !packet.hasHeader(icmp)
                || !packet.hasHeader(echoRequest6)) {
            log.error("Invalid ping6 packet");
            return;
        }        

        // set the source MAC/IP in the packet
        eth.source(srcMac);
        ip.setByteArray(8, srcIp);
        
        // calculate checksums
        eth.calculateChecksum();
        icmp.calculateChecksum();

        // add the packet
        packets.add(packet);

        // obtain global /64 prefixes for the local node
        List<Long> prefixes = NetUtils.getGlobalPrefixes();
        if (prefixes != null && !prefixes.isEmpty()) {
            globalPrefixes.addAll(prefixes);
        }
    }

    @Override
    public List<JPacket> getInjectionPackets() {
        return packets;
    }

    @Override
    public void processPacket(ListenerPacket listenerPacket) {
        PcapPacket packet = listenerPacket.getPacket();

        // check for at least one live injector and global prefix
        if (!liveInjectors.isEmpty() && !globalPrefixes.isEmpty()) {

            // process IPv6 source/destination
            if (packet.hasHeader(eth) && packet.hasHeader(ip)) {
                processAddr(eth.source(), ip.source());
                processAddr(eth.destination(), ip.destination());
            }
        }

        // is this an IPv6 EchoReply message?
        if (packet.hasHeader(echoReply6)) {

            // only proceed if we haven't yet flagged this source as an IPv6 router
            NetworkNode src = listenerPacket.getSrc();
            if (src.getNodeDataMap().containsKey(Router6Info.ID)) {
                return;
            }

            // get echo reply contents
            int identifier = echoReply6.identifier();
            int sequenceNum = echoReply6.sequenceNum();
            byte[] data = echoReply6.getPayload();

            // make sure this packet is a router response
            if (identifier != Integer.parseInt(ROUTER_ID, 16)
                    || sequenceNum != Integer.parseInt(SEQUENCE_NUM)
                    || !Arrays.equals(data, FormatUtils.toByteArray(PING6_DATA))) {
                return;
            }

            // flag the source node as an IPv6 router
            log.info("Node[{}] is an IPv6 router", src.getMacAddress());
            src.addNodeData(new Router6Info());
        }
    }

    @Override
    public void registerLiveInjector(LiveInjector injector) {
        liveInjectors.add(injector);
    }

    @Override
    public void unregisterLiveInjector(LiveInjector injector) {
        liveInjectors.remove(injector);
    }

    private void processAddr(byte[] mac, byte[] ipAddr) {

        // build InetAddress
        InetAddress inetAddr;
        try {
            inetAddr = InetAddress.getByAddress(ipAddr);
        } catch (UnknownHostException e) {
            return;
        }

        // if this isn't a link-local address, we're done
        if (!(inetAddr.isLinkLocalAddress() || inetAddr.isSiteLocalAddress())) {
            return;
        }

        // if we've already processed this address, no need to do it again
        String key = inetAddr.getHostAddress();
        if (processedAddrs.contains(key)) {
            return;
        }

        // build a ping6 packet template
        String packetStr = IP6_TEMPLATE + ICMP6_TYPE_CODE_CKSUM + NEIGHBOR_ID + SEQUENCE_NUM
                + PING6_DATA;

        // craft a ping6 packet for every global prefix
        for (Long prefix : globalPrefixes) {

            // load ping6 template
            JPacket packet = new JMemoryPacket(JProtocol.ETHERNET_ID, packetStr);
            if (!packet.hasHeader(eth) || !packet.hasHeader(ip) || !packet.hasHeader(icmp)
                    || !packet.hasHeader(echoRequest6)) {
                log.error("Invalid Echo Request packet");
                return;
            }

            // generate global addresses ([Global Prefix] + [Link-Local lower 64 bits])
            long lowerDstBits = IPv6Address.fromByteArray(ipAddr).getLowBits();
            IPv6Address globalDstIp = IPv6Address.fromLongs(prefix, lowerDstBits);
            long lowerSrcBits = IPv6Address.fromByteArray(srcIp).getLowBits();
            IPv6Address globalSrcIp = IPv6Address.fromLongs(prefix, lowerSrcBits);

            // update packet template
            eth.source(srcMac);
            eth.destination(mac);
            ip.setByteArray(8, globalSrcIp.toByteArray());
            ip.setByteArray(24, globalDstIp.toByteArray());
            
            // calculate checksums
            eth.calculateChecksum();
            icmp.calculateChecksum();

            // add packet to live injectors
            for (LiveInjector injector : liveInjectors) {
                injector.addInjectionPacket(packet);
            }
        }

        // mark this address as processed
        processedAddrs.add(key);
    }
}
