package com.ptr.v6app;

import java.util.Collection;

import org.jnetpcap.PcapIf;
import org.jnetpcap.PcapStat;

import com.ptr.v6app.node.NetworkNode;

public class NetworkDiscoveryResult {

    // -- Pcap interface used
    private final PcapIf pcapIf;

    // -- Pcap statistics
    private final PcapStat stats;

    // -- Internet accessibility flag
    private final boolean internetAccessible;

    // -- Discovered network nodes
    private final Collection<NetworkNode> nodes;

    public NetworkDiscoveryResult(PcapIf pcapIf, PcapStat stats, boolean internetAccessible,
            Collection<NetworkNode> nodes) {
        this.pcapIf = pcapIf;
        this.stats = stats;
        this.internetAccessible = internetAccessible;
        this.nodes = nodes;
    }

    public PcapIf getPcapIf() {
        return pcapIf;
    }

    public PcapStat getStats() {
        return stats;
    }

    public boolean isInternetAccessible() {
        return internetAccessible;
    }

    public Collection<NetworkNode> getNodes() {
        return nodes;
    }
}
