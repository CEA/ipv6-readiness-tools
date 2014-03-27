package com.ptr.v6app.plugin;

import java.util.List;

import org.jnetpcap.packet.JPacket;

import com.ptr.v6app.injector.LiveInjector;

public interface InjectorPlugin extends PcapPlugin {

    /**
     * Returns a list of PcapPacket objects ready to be injected on the wire.
     * 
     * @return The List<JPacket> of packets to be injected.
     */
    public List<JPacket> getInjectionPackets();
    
    public void registerLiveInjector(LiveInjector injector);
    
    public void unregisterLiveInjector(LiveInjector injector);
}
