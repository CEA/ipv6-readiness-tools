package com.ptr.v6app;

import java.io.IOException;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapIf;
import org.jnetpcap.PcapStat;
import org.jnetpcap.packet.RegistryHeaderErrors;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.ptr.v6app.injector.PcapInjectorThread;
import com.ptr.v6app.jnetpcap.PacketRegistry;
import com.ptr.v6app.listener.PcapListenerThread;
import com.ptr.v6app.node.NetworkNode;
import com.ptr.v6app.plugin.PluginManager;
import com.ptr.v6app.util.NetUtils;
import com.ptr.v6app.util.V6AppProperties;

/**
 * This class is used to perform a network discovery task. Once started, two threads are created and
 * started; a listener thread and an injector thread. The injector thread injects packets onto the
 * wire and the listener thread parses packets seen on the network discovery interface.
 */
public class NetworkDiscovery {

    // -- Logger
    private static final Logger log = LogManager.getLogger(NetworkDiscovery.class.getName());

    // -- jNetPcap is non-reentrant, create a fair lock for protection
    private final Lock pcapLock = new ReentrantLock(true);

    // -- Results
    private final List<NetworkDiscoveryResult> results = new ArrayList<NetworkDiscoveryResult>();

    /**
     * Initializes an NetworkDiscovery instance.
     * 
     * @throws RegistryHeaderErrors
     */
    public NetworkDiscovery() throws RegistryHeaderErrors {

        // register custom packets
        PacketRegistry.registerCustomPackets();
    }

    /**
     * Starts the network discovery task.
     * 
     * @param durationMillis
     *            Duration the task will run in milliseconds.
     * @return true on success, false otherwise.
     */
    public boolean startNetworkDiscovery(long durationMillis) {
        log.info("Starting network discovery...");
        results.clear();

        // find IPv6 Pcap interfaces
        List<PcapIf> pcapIfcs = NetUtils.getPcap6Ifcs();
        if (pcapIfcs == null || pcapIfcs.isEmpty()) {
            log.error("Failed to find an IPv6 Pcap interface");
            return false;
        }
        
        // check if we're limiting discovery to specific interfaces
        Set<String> limitedIfcs = V6AppProperties.getLimitedNetDescoveryIfcs();

        // configure capture options
        int snaplen = 64 * 1024; // Capture all packets, no trucation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 1 * 1000; // 1 second in millis  
        StringBuilder errbuf = new StringBuilder(); // For any error msgs

        // perform network discovery on all candidate interfaces
        for (PcapIf pcapIf : pcapIfcs) {
            NetworkInterface ni = NetUtils.getNetworkInterface(pcapIf);
            
            // if we're limiting discovery to specific interfaces, make sure this is one of them
            if (limitedIfcs != null && !limitedIfcs.contains(ni.getDisplayName())) {
                log.info("Skipping interface [{}]", ni.getDisplayName());
                continue;
            }

            // test interface for internet connectivity
            log.info("Testing interface [{}] for Internet connectivity...", ni.getDisplayName());
            boolean intenetAccess = NetUtils.canReachInternet(ni);
            log.info(intenetAccess ? "  [OK]" : "  [FAIL]");

            // start capture
            final Pcap pcap = Pcap.openLive(pcapIf.getName(), snaplen, flags, timeout, errbuf);
            if (pcap == null) {
                log.error("Error while opening device for capture: {}", errbuf.toString());
                continue;
            }

            // read in non-blocking mode
            pcap.setNonBlock(Pcap.MODE_NON_BLOCKING, errbuf);

            // initialize plugins
            PluginManager.getInstance().initializePlugins(pcapIf);

            // create the collection of network nodes
            Map<String, NetworkNode> localNodes = new HashMap<String, NetworkNode>();

            // create listener/injector threads
            PcapListenerThread listener = new PcapListenerThread(pcapLock, pcap, pcapIf, localNodes);
            PcapInjectorThread injector = new PcapInjectorThread(pcapLock, pcap, pcapIf);
            Thread listenerThread = new Thread(listener, "PcapListener");
            Thread injectorThread = new Thread(injector, "PcapInjector");

            // start threads
            log.info("Scanning interface [{}] for {} seconds...", ni.getDisplayName(),
                    (durationMillis / 1000));
            listenerThread.start();
            injectorThread.start();

            // hang out for some time
            try {
                Thread.sleep(durationMillis);
            } catch (InterruptedException e) {
                log.debug("Sleep interrupted");
            }

            // interrupt the threads
            injectorThread.interrupt();
            listenerThread.interrupt();

            // if the listener is waiting for a packet, break him out
            // of the loop; no pcap protection is needed here
            pcap.breakloop();

            // wait for threads to exit
            try {
                injectorThread.join();
                listenerThread.join();
            } catch (InterruptedException e) {
                log.warn("Interrupted waiting for listener thread to exit.");
            }

            // save stats
            PcapStat pcapStat = new PcapStat();
            pcap.stats(pcapStat);
            log.debug(pcapStat);

            // close the pcap handle, injector/listener threads should be gone so no need to synchronize
            pcap.close();

            // save results
            results.add(new NetworkDiscoveryResult(pcapIf, pcapStat, intenetAccess, localNodes
                    .values()));
        }

        log.info("Network Discovery complete. Scanned {} interface(s).", results.size());
        return true;
    }

    /**
     * Parses the task results into XML format.
     * 
     * @param doc
     *            The output XML document.
     * @param root
     *            The root node of the XML document.
     * @return true on success, false otherwise.
     */
    public boolean parseXmlResults(Document doc, Element root) {
        boolean xmlSuccess = true;

        // create root network discovery element
        Element netDisc = doc.createElement("networkDiscovery");
        root.appendChild(netDisc);

        // lock the pcap lock
        pcapLock.lock();
        try {

            // pcap interfaces
            Element pcapIfcs = doc.createElement("pcapInterfaces");
            netDisc.appendChild(pcapIfcs);

            for (NetworkDiscoveryResult result : results) {

                // pcap interface
                Element pcapIfc = doc.createElement("pcapInterface");
                pcapIfcs.appendChild(pcapIfc);
                PcapIf pcapIf = result.getPcapIf();

                // mac
                Element mac = doc.createElement("mac");
                mac.appendChild(doc.createTextNode(""
                        + NetUtils.getMacString(pcapIf.getHardwareAddress())));
                pcapIfc.appendChild(mac);

                // name
                Element ifName = doc.createElement("name");
                ifName.appendChild(doc.createTextNode("" + pcapIf.getName()));
                pcapIfc.appendChild(ifName);

                // description
                Element ifDesc = doc.createElement("description");
                ifDesc.appendChild(doc.createTextNode("" + pcapIf.getDescription()));
                pcapIfc.appendChild(ifDesc);

                // flags
                Element ifFlags = doc.createElement("flags");
                ifFlags.appendChild(doc.createTextNode("" + pcapIf.getFlags()));
                pcapIfc.appendChild(ifFlags);

                // internet accessibility
                Element inetAccess = doc.createElement("internetConnectivity");
                inetAccess.appendChild(doc.createTextNode("" + result.isInternetAccessible()));
                pcapIfc.appendChild(inetAccess);

                // stats
                Element stats = doc.createElement("stats");
                pcapIfc.appendChild(stats);
                PcapStat pcapStat = result.getStats();

                // packets received
                Element recv = doc.createElement("receive");
                recv.appendChild(doc.createTextNode("" + pcapStat.getRecv()));
                stats.appendChild(recv);

                // packets dropped
                Element drop = doc.createElement("drop");
                drop.appendChild(doc.createTextNode("" + pcapStat.getDrop()));
                stats.appendChild(drop);

                // if packets dropped
                Element ifDrop = doc.createElement("ifDrop");
                ifDrop.appendChild(doc.createTextNode("" + pcapStat.getIfDrop()));
                stats.appendChild(ifDrop);

                // addresses
                Element pcapAddrs = doc.createElement("addresses");
                pcapIfc.appendChild(pcapAddrs);

                // add each address
                for (PcapAddr addr : pcapIf.getAddresses()) {
                    byte[] addrBytes = addr.getAddr().getData();
                    if (addrBytes == null || !(addrBytes.length == 4 || addrBytes.length == 16)) {
                        continue;
                    }
                    Element pcapAddr = doc.createElement("address");
                    pcapAddr.appendChild(doc.createTextNode("" + NetUtils.getHostAddress(addrBytes)));
                    pcapAddrs.appendChild(pcapAddr);
                }

                // network nodes
                Collection<NetworkNode> localNodes = result.getNodes();
                Element netNodes = doc.createElement("networkNodes");
                pcapIfc.appendChild(netNodes);

                // parse each node
                for (NetworkNode node : localNodes) {
                    try {
                        node.parseXmlResults(doc, netNodes);
                    } catch (Exception e) {
                        log.error("Error parsing XML node", e);
                    }
                }
            }

        } catch (IOException ioe) {
            log.error("Error parsing network discovery XML results", ioe);
            xmlSuccess = false;
        } finally {
            pcapLock.unlock();
        }

        return xmlSuccess;
    }
}
