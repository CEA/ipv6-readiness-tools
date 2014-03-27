package com.ptr.v6app.plugin;

import com.ptr.v6app.listener.ListenerPacket;

public interface ListenerPlugin extends PcapPlugin {

    /**
     * Processes a jNetPcap packet.
     * 
     * @param listenerPacket
     *            A packet object for listeners.
     */
    public void processPacket(ListenerPacket listenerPacket);
}
