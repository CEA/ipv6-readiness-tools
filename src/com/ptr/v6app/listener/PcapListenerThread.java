package com.ptr.v6app.listener;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.Lock;

import org.apache.commons.net.util.SubnetUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jnetpcap.JBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.PcapSockAddr;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;

import com.ptr.v6app.jnetpcap.packet.EchoReply6;
import com.ptr.v6app.jnetpcap.packet.NeighborAdvertisement;
import com.ptr.v6app.node.NetworkNode;
import com.ptr.v6app.plugin.ListenerPlugin;
import com.ptr.v6app.plugin.PluginManager;
import com.ptr.v6app.plugin.impl.Ping6Plugin;
import com.ptr.v6app.util.NetUtils;

/**
 * A thread for listening and processing traffic from a jNetPcap capture.
 */
public class PcapListenerThread implements Runnable, JBufferHandler<String> {

    // -- Logger
    private static final Logger log = LogManager.getLogger(PcapListenerThread.class.getName());

    // -- Pcap lock (jNetPcap is non-reentrant)
    private final Lock pcapLock;

    // -- Pcap instance
    private final Pcap pcap;

    // -- Listener packet
    private final PcapPacket packet = new PcapPacket(JMemory.POINTER);

    // -- Packet headers for reuse
    private final Ethernet eth = new Ethernet();
    private final Ip4 ip4 = new Ip4();
    private final Ip6 ip6 = new Ip6();
    private final NeighborAdvertisement na = new NeighborAdvertisement();
    private final EchoReply6 echoReply6 = new EchoReply6();

    // -- Listener plugins
    private final List<ListenerPlugin> plugins;

    // -- Multicast groups we'll want to join
    private static final String[] mGroups = { "224.0.0.251", "239.255.255.250", "ff02::2",
            "ff02::fb", "ff02::f" };

    // -- Observed network nodes on the local network
    private final Map<String, NetworkNode> localNodes;

    // -- Subnets for the listening interface
    private final List<SubnetUtils> subnets = new ArrayList<SubnetUtils>();
    
    // -- Local IPv4 default gateway
    private byte[] ipv4Gateway;

    // -- Constants
    private static final String BROADCAST_MAC = "FF:FF:FF:FF:FF:FF";

    public PcapListenerThread(Lock pcapLock, Pcap pcap, PcapIf pcapIf,
            Map<String, NetworkNode> localNodes) {
        this.pcapLock = pcapLock;
        this.pcap = pcap;
        this.localNodes = localNodes;

        // get listener plugins
        plugins = PluginManager.getInstance().getListenerPlugins();

        // note the IPv4 subnets on this interface
        for (PcapAddr pcapAddr : pcapIf.getAddresses()) {
            if (pcapAddr.getAddr().getFamily() == PcapSockAddr.AF_INET) {
                String addr = FormatUtils.ip(pcapAddr.getAddr().getData());
                String subnet = FormatUtils.ip(pcapAddr.getNetmask().getData());
                subnets.add(new SubnetUtils(addr, subnet));
            }
        }
        
        // determine default IPv4 gateway
        try {
            ipv4Gateway = NetUtils.getLocalIpv4Gateway();
        } catch (IOException ioe) {
            ipv4Gateway = null;
        }
    }

    @Override
    public void nextPacket(PcapHeader header, JBuffer buffer, String user) {

        // parse IP header
        ListenerPacket lPacket = parseIpPacket(header, buffer);

        // if we couldn't parse the IP header (e.g., it's not IP), move on
        if (lPacket == null) {
            return;
        }

        // pass the packet to all listener plugins for processing
        for (ListenerPlugin plugin : plugins) {
            try {
                plugin.processPacket(lPacket);
            } catch (Exception e) {
                log.error("Error processing packet:", e);
            }
        }
    }

    @Override
    public void run() {
        log.debug("Starting listener thread...");

        // join multicast groups
        MulticastSocket mSock = joinMulticastGroups();

        // don't stop unless we're interrupted
        while (!Thread.interrupted()) {

            // synchronize access to the jNetPcap API
            pcapLock.lock();
            try {

                // read one packet at a time so we don't starve the injector thread
                pcap.dispatch(1, this, "PcapListener");
            } finally {
                pcapLock.unlock();
            }
        }

        // leave multicast gruops
        leaveMulticastGroups(mSock);

        log.debug("Exiting listener thread.");
    }

    private MulticastSocket joinMulticastGroups() {
        MulticastSocket mSock = null;

        try {
            mSock = new MulticastSocket(0);
        } catch (IOException ioe) {
            log.error("Error creating multicast socket", ioe);
            return null;
        }

        // join groups
        for (String mGroup : mGroups) {
            InetAddress mInetGroup = null;
            try {
                mInetGroup = InetAddress.getByName(mGroup);
                mSock.joinGroup(mInetGroup);
            } catch (SocketException se) {
                // we expect this if we don't have an assigned address for the multicast
                // address family (IPv4/IPv6), move on
                String addrFam = "[unknown address family]";
                if (mInetGroup != null && mInetGroup instanceof Inet4Address) {
                    addrFam = "IPv4";
                } else if (mInetGroup != null && mInetGroup instanceof Inet6Address) {
                    addrFam = "IPv6";
                }
                log.debug("Unable to join multicast group [{}], is there no assigned {} address?",
                        mGroup, addrFam);
            } catch (Exception e) {
                log.error("Error joining multicast group [" + mGroup + "]", e);
            }
        }

        return mSock;
    }

    private void leaveMulticastGroups(MulticastSocket mSock) {
        if (mSock == null) {
            return;
        }

        // leave all groups
        for (String mGroup : mGroups) {
            try {
                InetAddress mInetGroup = InetAddress.getByName(mGroup);
                mSock.leaveGroup(mInetGroup);
            } catch (SocketException se) {
                // we expect this if we don't have an assigned address for the multicast
                // address family (IPv4/IPv6), move on
            } catch (Exception e) {
                log.error("Error leaving multicast group [" + mGroup + "]", e);
            }
        }
    }

    private ListenerPacket parseIpPacket(PcapHeader header, JBuffer buffer) {

        // prepare packet for processing, these methods map our PcapPacket buffer
        // from Java to native memory (libpcap/winpcap)
        packet.peer(buffer);
        packet.getCaptureHeader().peerTo(header, 0);
        packet.scan(Ethernet.ID);

        // make sure we have an ethernet and ip (v4/v6) header,
        // this also populates the header objects
        if (!packet.hasHeader(eth) || !(packet.hasHeader(ip4) || packet.hasHeader(ip6))) {
            return null;
        }

        // parse MAC addresses in new arrays, original arrays are mapped to native memory
        byte[] srcMac = Arrays.copyOf(eth.source(), eth.source().length);
        byte[] dstMac = Arrays.copyOf(eth.destination(), eth.destination().length);

        // parse IP addresses in new arrays, original arrays are mapped to native memory
        byte[] srcIp;
        byte[] dstIp;
        if (packet.hasHeader(Ip4.ID)) {
            srcIp = Arrays.copyOf(ip4.source(), ip4.source().length);
            dstIp = Arrays.copyOf(ip4.destination(), ip4.destination().length);
        } else {
            srcIp = Arrays.copyOf(ip6.source(), ip6.source().length);
            dstIp = Arrays.copyOf(ip6.destination(), ip6.destination().length);
        }

        // build node instances
        NetworkNode src = getNetworkNode(srcMac, srcIp);
        NetworkNode dst = getNetworkNode(dstMac, dstIp);

        return new ListenerPacket(packet, src, dst);
    }

    private NetworkNode getNetworkNode(byte[] mac, byte[] ip) {

        // convert mac to string
        String macStr = FormatUtils.mac(mac);

        // convert IP to an InetAddress
        InetAddress inetAddr;
        try {
            inetAddr = InetAddress.getByAddress(ip);
        } catch (UnknownHostException uhe) {
            log.warn("Error parsing packet");
            return null;
        }

        // determine if the address is on our local network
        boolean isLocalAddr = isLocalAddr(macStr, inetAddr);

        // get the local node from our cache if we've seen it before
        NetworkNode node = localNodes.get(macStr);

        // if it's not in our cache, create it
        if (node == null) {

            // create the node instance and save it if it's local
            node = new NetworkNode(macStr, isLocalAddr);
            if (isLocalAddr) {
                localNodes.put(macStr, node);
            }
        }

        // note the nodes inet address
        if (isLocalAddr && !node.hasInetAddress(inetAddr)) {
            node.addInetAddress(inetAddr);
            log.info("New node found: MAC[{}], IP[{}], Manufacturer[{}]", macStr,
                    inetAddr.getHostAddress(), node.resolveManufacturer());
        }

        return node;
    }

    private boolean isLocalAddr(String macStr, InetAddress addr) {

        // ignore broadcast MAC (FF:FF:FF:FF:FF:FF)
        if (BROADCAST_MAC.equals(macStr)) {
            return false;
        }

        // ignore multicast addresses
        if (addr.isMulticastAddress()) {
            return false;
        }

        // if the address is link-local or site-local, consider it a new local node
        if (addr.isLinkLocalAddress() || addr.isSiteLocalAddress()) {
            return true;
        }

        // if this is an IPv4 node, consider it a new local node if its on the same subnet
        if (addr instanceof Inet4Address) {
            for (SubnetUtils subnet : subnets) {
                if (subnet.getInfo().isInRange(addr.getHostAddress())) {
                    return true;
                }
            }
        }
        
        // see if this is our local IPv4 gateway
        if (ipv4Gateway != null && Arrays.equals(addr.getAddress(), ipv4Gateway)) {
            return true;
        }

        // if this is a Neighbor Advertisement with a hop limit of 255, the source is local
        if (packet.hasHeader(na) && ip6.hopLimit() == 255
                && macStr.equals(FormatUtils.mac(eth.source()))) {
            return true;
        }

        // if this is an EchoReply with a special ID, the source is local
        //
        // TODO: We probably want to come up with a better way to  identify if an
        // address is on the local network, maybe defer to plugins or allow plugins
        // to add nodes to the master collection?
        if (packet.hasHeader(echoReply6)
                && echoReply6.identifier() == Integer.parseInt(Ping6Plugin.NEIGHBOR_ID, 16)) {
            return true;
        }

        return false;
    }
}
