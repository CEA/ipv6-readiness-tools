package com.ptr.v6app.injector;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.locks.Lock;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JPacket;

import com.ptr.v6app.plugin.InjectorPlugin;
import com.ptr.v6app.plugin.PluginManager;

/**
 * A thread for loading pcap packets and injecting them onto a live interface.
 */
public class PcapInjectorThread implements Runnable, LiveInjector {

    // -- Logger
    private static final Logger log = LogManager.getLogger(PcapInjectorThread.class.getName());

    // -- Pcap lock (jNetPcap is non-reentrant)
    private final Lock pcapLock;

    // -- Pcap instance
    private final Pcap pcap;

    // -- Live injection packets
    private final BlockingQueue<JPacket> packetQueue = new LinkedBlockingQueue<JPacket>();

    public PcapInjectorThread(Lock pcapLock, Pcap pcap, PcapIf pcapIf) {
        this.pcapLock = pcapLock;
        this.pcap = pcap;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Runnable#run()
     */
    @Override
    public void run() {
        log.debug("Starting injector thread...");

        // get plugins
        List<InjectorPlugin> plugins = PluginManager.getInstance().getInjectorPlugins();
        
        // register as a live injector with the plugins
        for (InjectorPlugin plugin : plugins) {
            plugin.registerLiveInjector(this);
        }

        // get plugin packets
        List<JPacket> pluginPackets = getPluginPackets(plugins);

        // inject plugin packets
        boolean interrupted = injectPluginPackets(pluginPackets);
        if (interrupted) {
            return;
        }
        
        // inject live packets as they arrive until interrupted
        injectLivePackets();
        
        // unregister as a live injector with the plugins
        for (InjectorPlugin plugin : plugins) {
            plugin.unregisterLiveInjector(this);
        }
        
        log.debug("Exiting injector thread.");
    }

    @Override
    public void addInjectionPacket(JPacket packet) {
        if (!packetQueue.offer(packet)) {
            // this shouldn't happen, it's an unbounded queue
            log.warn("Failed to add live packet to injector queue");
        }
    }

    private List<JPacket> getPluginPackets(List<InjectorPlugin> plugins) {
        List<JPacket> pluginPackets = new ArrayList<JPacket>();

        // synchronize access to the jNetPcap API
        pcapLock.lock();
        try {

            // get injection packets from plugins
            for (InjectorPlugin plugin : plugins) {
                try {
                    List<JPacket> packets = plugin.getInjectionPackets();
                    if (packets != null) {
                        pluginPackets.addAll(packets);
                    }
                } catch (Exception e) {
                    log.error("Error creating injection packets for plugin ["
                            + plugin.getClass().getSimpleName() + "]: ", e);
                }
            }
        } finally {
            pcapLock.unlock();
        }

        return pluginPackets;
    }

    private boolean injectPluginPackets(List<JPacket> pluginPackets) {
        boolean interrupted = false;

        // inject packets one at a time so we don't starve the listener thread
        int numInjectedPackets = 0;
        int injectStatus = -1;
        for (JPacket packet : pluginPackets) {

            // bail out if we've been interrupted
            if (Thread.interrupted()) {
                interrupted = true;
                break;
            }

            // add a delay between injections
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                interrupted = true;
                break;
            }

            // synchronize access to the jNetPcap API
            injectStatus = -1;
            pcapLock.lock();
            try {
                // be as lightweight as possible in the lock so we don't miss any packets
                injectStatus = pcap.sendPacket(packet);
            } finally {
                pcapLock.unlock();
            }

            // check status of packet injection
            if (injectStatus == 0) {
                numInjectedPackets++;
                log.trace("Packet injected: {}", packet);
            } else {
                log.error("Error injecting packet.");
            }
        }

        log.debug("Injected [{}/{}] plugin packets.", numInjectedPackets, pluginPackets.size());
        return interrupted;
    }
    
    private void injectLivePackets() {
        int injectStatus = -1;
        int numInjectedPackets = 0;
        
        // loop until we're interrupted
        while (!Thread.interrupted()) {

            // add a delay between injections
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                break;
            }
            
            // wait for a new packet to arrive (blocking)
            JPacket packet;
            try {
                packet = packetQueue.take();
            } catch (InterruptedException e) {
                break;
            }
            
            // synchronize access to the jNetPcap API
            injectStatus = -1;
            pcapLock.lock();
            try {
                // be as lightweight as possible in the lock so we don't miss any packets
                injectStatus = pcap.sendPacket(packet);
            } finally {
                pcapLock.unlock();
            }

            // check status of packet injection
            if (injectStatus == 0) {
                numInjectedPackets++;
                //log.trace("Packet injected: {}", packet);
            } else {
                log.error("Error injecting live packet.");
            }
        }

        log.debug("Injected {} live packets.", numInjectedPackets);
    }
}
