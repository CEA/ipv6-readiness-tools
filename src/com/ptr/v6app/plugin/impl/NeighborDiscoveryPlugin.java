package com.ptr.v6app.plugin.impl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
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
import com.ptr.v6app.jnetpcap.packet.Icmp6;
import com.ptr.v6app.jnetpcap.packet.NeighborSolicitation;
import com.ptr.v6app.listener.ListenerPacket;
import com.ptr.v6app.plugin.InjectorPlugin;
import com.ptr.v6app.plugin.ListenerPlugin;
import com.ptr.v6app.util.NetUtils;

public class NeighborDiscoveryPlugin implements ListenerPlugin, InjectorPlugin {

    // -- Logger
    private static final Logger log = LogManager.getLogger(NeighborDiscoveryPlugin.class.getName());

    // -- Plugin name
    private static final String NAME = NeighborDiscoveryPlugin.class.getSimpleName();

    // -- Live injector references
    private final Set<LiveInjector> liveInjectors = new HashSet<LiveInjector>();

    // -- Pcap interface attributes
    private byte[] srcMac;
    private byte[] srcIp;

    // -- Pcap packet headers for reuse
    private final Ethernet eth = new Ethernet();
    private final Ip6 ip = new Ip6();
    private final Icmp6 icmp = new Icmp6();
    private final NeighborSolicitation ns = new NeighborSolicitation();

    // -- Global /64 prefixes for the local node
    private final List<Long> globalPrefixes = new ArrayList<Long>();

    // -- Running collection of processed addresses
    private final Set<String> processedAddrs = new HashSet<String>();

    // -- Neighbor Solicitation template
    private static final String NS_TEMPLATE = "33330000 00000000 00000000 86dd6000 00000020 "
            + "3afffe80 00000000 00000000 00000000 0000ff02 00000000 00000000 00000000 00018700 "
            + "00000000 0000ff02 00000000 00000000 00000000 0001";

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public void initialize(PcapIf pcapIf) {

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

        // obtain global /64 prefixes for the local node
        List<Long> prefixes = NetUtils.getGlobalPrefixes();
        if (prefixes != null && !prefixes.isEmpty()) {
            globalPrefixes.addAll(prefixes);
        }
    }

    @Override
    public void processPacket(ListenerPacket listenerPacket) {

        // if we have no live injectors registered or global prefixes, don't bother
        if (liveInjectors.isEmpty() || globalPrefixes.isEmpty()) {
            return;
        }

        // process IPv6 source/destination
        PcapPacket packet = listenerPacket.getPacket();
        if (packet.hasHeader(eth) && packet.hasHeader(ip)) {
            processAddr(eth.source(), ip.source());
            processAddr(eth.destination(), ip.destination());
        }
    }

    @Override
    public List<JPacket> getInjectionPackets() {
        // we don't have static packets to add
        return null;
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

        // build NS template with source link-layer option
        // (FIXME: Option should be handled in com.ptr.v6app.jnetpcap.packet.NeighborSolicitation)
        String nsStr = NS_TEMPLATE + "0101" + FormatUtils.mac(srcMac).replaceAll(":", "");

        // build multicast destination address 
        // (three lower order octets OR'd with MAC 33:33:ff:00:00:00)
        byte[] dstMac = { (byte) 0x33, (byte) 0x33, (byte) 0xff, (byte) 0x00, (byte) 0x00,
                (byte) 0x00 };
        System.arraycopy(ipAddr, 13, dstMac, 3, 3);

        // solicited node destination address
        byte[] sDstIp = { (byte) 0xff, (byte) 0x02, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x01, (byte) 0xff, (byte) 0x00, (byte) 0x00, (byte) 0x00 };
        System.arraycopy(ipAddr, 13, sDstIp, 13, 3);

        // craft a NS packet for every global prefix
        for (Long prefix : globalPrefixes) {

            // load NS template
            JPacket packet = new JMemoryPacket(JProtocol.ETHERNET_ID, nsStr);
            if (!packet.hasHeader(eth) || !packet.hasHeader(ip) || !packet.hasHeader(icmp)
                    || !packet.hasHeader(ns)) {
                log.error("Invalid Neighbor Solicitation packet");
                return;
            }

            // generate global address ([Global Prefix] + [Link-Local lower 64 bits])
            long lowerDstBits = IPv6Address.fromByteArray(ipAddr).getLowBits();
            IPv6Address globalDstIp = IPv6Address.fromLongs(prefix, lowerDstBits);
            long lowerSrcBits = IPv6Address.fromByteArray(srcIp).getLowBits();
            IPv6Address globalSrcIp = IPv6Address.fromLongs(prefix, lowerSrcBits);

            // update packet template
            ns.targetAddress(globalDstIp.toByteArray());
            eth.source(srcMac);
            eth.destination(dstMac);
            ip.setByteArray(8, globalSrcIp.toByteArray());
            ip.setByteArray(24, sDstIp);
            
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