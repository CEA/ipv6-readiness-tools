package com.ptr.v6app.listener;

import org.jnetpcap.packet.PcapPacket;

import com.ptr.v6app.node.NetworkNode;

public class ListenerPacket {

    // -- jNetPcap packet
    private final PcapPacket packet;
    
    // -- Source node
    private final NetworkNode src;
    
    // -- Destination node
    private final NetworkNode dst;
    
    public ListenerPacket(PcapPacket packet, NetworkNode src, NetworkNode dst) {
        this.packet = packet;
        this.src = src;
        this.dst = dst;
    }

    public PcapPacket getPacket() {
        return packet;
    }

    public NetworkNode getSrc() {
        return src;
    }

    public NetworkNode getDst() {
        return dst;
    }
}
