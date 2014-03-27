package com.ptr.v6app.jnetpcap;

import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.RegistryHeaderErrors;

import com.ptr.v6app.jnetpcap.packet.EchoReply6;
import com.ptr.v6app.jnetpcap.packet.EchoRequest6;
import com.ptr.v6app.jnetpcap.packet.Icmp6;
import com.ptr.v6app.jnetpcap.packet.NeighborAdvertisement;
import com.ptr.v6app.jnetpcap.packet.NeighborSolicitation;
import com.ptr.v6app.jnetpcap.packet.RouterAdvertisement;
import com.ptr.v6app.jnetpcap.packet.RouterSolicitation;

public class PacketRegistry {

    // -- Logger
    private static final Logger log = LogManager.getLogger(PacketRegistry.class.getName());

    // -- Registration flag
    private static boolean registered = false;

    // -- Custom packet headers
    private static final List<Class<? extends JHeader>> packetClasses = new ArrayList<Class<? extends JHeader>>();
    static {
        packetClasses.add(Icmp6.class);
        packetClasses.add(EchoRequest6.class);
        packetClasses.add(EchoReply6.class);
        packetClasses.add(NeighborAdvertisement.class);
        packetClasses.add(NeighborSolicitation.class);
        packetClasses.add(RouterAdvertisement.class);
        packetClasses.add(RouterSolicitation.class);
    }

    /**
     * Registers custom packets with jNetPcap so they can be used by the application.
     * 
     * @throws RegistryHeaderErrors
     *             If jNetPcap fails to load a JHeader class
     */
    public static void registerCustomPackets() throws RegistryHeaderErrors {

        // register only once
        if (!registered) {
            registered = true;

            for (Class<? extends JHeader> clazz : packetClasses) {
                int headerId = JRegistry.register(clazz);
                log.debug("Custom packet registered: [{}], id[{}]", clazz.getSimpleName(), headerId);
            }
        }
    }
}
