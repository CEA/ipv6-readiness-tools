package com.ptr.v6app.plugin.impl;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;

import com.ptr.v6app.injector.LiveInjector;
import com.ptr.v6app.jnetpcap.packet.Icmp6;
import com.ptr.v6app.jnetpcap.packet.RouterAdvertisement;
import com.ptr.v6app.jnetpcap.packet.RouterSolicitation;
import com.ptr.v6app.listener.ListenerPacket;
import com.ptr.v6app.node.NetworkNode;
import com.ptr.v6app.node.data.Router4Info;
import com.ptr.v6app.node.data.Router6Info;
import com.ptr.v6app.plugin.InjectorPlugin;
import com.ptr.v6app.plugin.ListenerPlugin;
import com.ptr.v6app.util.NetUtils;

public class RouterDiscoveryPlugin implements ListenerPlugin, InjectorPlugin {

    // -- Logger
    private static final Logger log = LogManager.getLogger(RouterDiscoveryPlugin.class.getName());

    // -- Plugin name
    private static final String NAME = RouterDiscoveryPlugin.class.getSimpleName();

    // -- Router Solicitation template
    private static final String RS_TEMPLATE = "33330000 00020000 00000000 86dd6000 00000010 "
            + "3afffe80 00000000 00000000 00000000 0000ff02 00000000 00000000 00000000 00028500 "
            + "00000000 0000";

    // -- Packet headers for reuse
    private final RouterAdvertisement ra = new RouterAdvertisement();
    private final Ip4 ip4 = new Ip4();

    // -- Injection packets
    private List<JPacket> packets;

    // -- Default IPv4 gateway for the localhost
    private byte[] ipv4Gateway;

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

        // build RS template with source link-layer option
        // (FIXME: This should be handled in com.ptr.v6app.jnetpcap.packet.RouterSolicitation)
        String rsStr = RS_TEMPLATE + "0101" + FormatUtils.mac(srcMac).replaceAll(":", "");

        // headers
        Ethernet eth = new Ethernet();
        Ip6 ip = new Ip6();
        Icmp6 icmp = new Icmp6();
        RouterSolicitation rs = new RouterSolicitation();

        // load RS template
        JPacket packet = new JMemoryPacket(JProtocol.ETHERNET_ID, rsStr);
        if (!packet.hasHeader(eth) || !packet.hasHeader(ip) || !packet.hasHeader(icmp)
                || !packet.hasHeader(rs)) {
            log.error("Invalid Router Solicitation packet");
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

        // determine the default IPv4 gateway
        try {
            ipv4Gateway = NetUtils.getLocalIpv4Gateway();
            log.debug("Default IPv4 gateway of localhost is [{}]",
                    NetUtils.getHostAddress(ipv4Gateway));
        } catch (IOException ioe) {
            log.warn("Unable to determine IPv4 default gateway");
            ipv4Gateway = null;
        }
    }

    @Override
    public void processPacket(ListenerPacket listenerPacket) {
        PcapPacket packet = listenerPacket.getPacket();
        NetworkNode src = listenerPacket.getSrc();
        NetworkNode dst = listenerPacket.getDst();

        // is this an RA packet?
        if (packet.hasHeader(ra)) {

            // only proceed if we haven't yet flagged this source as an IPv6 router
            if (src.getNodeDataMap().containsKey(Router6Info.ID)) {
                return;
            }

            // flag the source node as an IPv6 router
            log.info("Node[{}] is an IPv6 router", src.getMacAddress());
            src.addNodeData(new Router6Info());
        }

        // is this src/dst a new IPv4 router?
        if (ipv4Gateway != null && packet.hasHeader(ip4)) {
            
            // check src
            if (!src.getNodeDataMap().containsKey(Router4Info.ID)
                    && Arrays.equals(ip4.source(), ipv4Gateway)) {

                // flag the source node as an IPv4 router
                log.info("Node[{}] is an IPv4 router", src.getMacAddress());
                src.addNodeData(new Router4Info());
            }
            
            // check dst
            if (!dst.getNodeDataMap().containsKey(Router4Info.ID)
                    && Arrays.equals(ip4.destination(), ipv4Gateway)) {

                // flag the destination node as an IPv4 router
                log.info("Node[{}] is an IPv4 router", dst.getMacAddress());
                dst.addNodeData(new Router4Info());
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