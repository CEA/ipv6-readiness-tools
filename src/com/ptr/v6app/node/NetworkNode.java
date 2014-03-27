package com.ptr.v6app.node;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.ptr.v6app.util.IEEEOuiResolver;
import com.ptr.v6app.util.Inet6AddressInfo;
import com.ptr.v6app.util.Inet6AddressInfo.Ipv6Scope;
import com.ptr.v6app.util.Inet6AddressInfo.TeredoAddrInfo;

/**
 * This class represents a network node.
 */
public class NetworkNode {

    // -- Logger
    private static final Logger log = LogManager.getLogger(NetworkNode.class.getName());

    // -- Node attributes
    private final String macAddress;
    private final boolean isLocal;
    private final Set<InetAddress> inetAddresses = new HashSet<InetAddress>();
    private final Map<String, NodeData> data = new HashMap<String, NodeData>();

    public NetworkNode(String macAddress, boolean isLocal) throws NullPointerException {
        if (macAddress == null) {
            throw new NullPointerException("mac address must not be null");
        }

        this.macAddress = macAddress;
        this.isLocal = isLocal;
    }

    public String getMacAddress() {
        return macAddress;
    }

    public boolean isLocal() {
        return isLocal;
    }

    public Set<InetAddress> getInetAddresses() {
        return inetAddresses;
    }

    public void addInetAddress(InetAddress addr) {
        inetAddresses.add(addr);
    }

    public boolean hasInetAddress(InetAddress addr) {
        return inetAddresses.contains(addr);
    }

    public Map<String, NodeData> getNodeDataMap() {
        return data;
    }

    public void addNodeData(NodeData nodeData) {
        data.put(nodeData.getId(), nodeData);
    }

    public String resolveManufacturer() {
        String manufacturer = null;
        if (macAddress != null) {
            manufacturer = IEEEOuiResolver.resolveManfacturer(macAddress);
        }

        return (manufacturer == null ? "Unknown" : manufacturer);
    }

    public boolean parseXmlResults(Document doc, Element root) {

        // node
        Element netNode = doc.createElement("networkNode");
        root.appendChild(netNode);

        // mac
        Element mac = doc.createElement("mac");
        mac.appendChild(doc.createTextNode("" + getMacAddress()));
        netNode.appendChild(mac);

        // manufacturer
        Element manufacturer = doc.createElement("manufacturer");
        manufacturer.appendChild(doc.createTextNode("" + resolveManufacturer()));
        netNode.appendChild(manufacturer);

        // addresses
        Element addresses = doc.createElement("addresses");
        netNode.appendChild(addresses);

        // add each address
        for (InetAddress addr : getInetAddresses()) {
            if (addr instanceof Inet4Address) {

                // for IPv4 addresses, just write the address
                Element address = doc.createElement("ipv4Address");
                address.appendChild(doc.createTextNode("" + addr.getHostAddress()));
                addresses.appendChild(address);
            } else if (addr instanceof Inet6Address) {

                // IPv6 address
                Element ipv6Address = doc.createElement("ipv6Address");
                addresses.appendChild(ipv6Address);

                // address
                Element address = doc.createElement("address");
                address.appendChild(doc.createTextNode("" + addr.getHostAddress()));
                ipv6Address.appendChild(address);

                // scope
                Inet6AddressInfo info = Inet6AddressInfo.fromInetAddress(addr);
                Element scope = doc.createElement("scope");
                scope.appendChild(doc.createTextNode("" + info.getScope()));
                ipv6Address.appendChild(scope);

                // teredo info
                if (info.getScope() == Ipv6Scope.GLOBAL_TEREDO) {
                    TeredoAddrInfo teredoInfo = info.getTeredoAddrInfo();
                    Element teredo = doc.createElement("teredo");
                    ipv6Address.appendChild(teredo);

                    // teredo server
                    Element teredoSvr = doc.createElement("serverAddr");
                    teredoSvr.appendChild(doc.createTextNode("" + teredoInfo.getServerIpv4()));
                    teredo.appendChild(teredoSvr);

                    // teredo client
                    Element teredoClt = doc.createElement("clientAddr");
                    teredoClt.appendChild(doc.createTextNode("" + teredoInfo.getClientIpv4()));
                    teredo.appendChild(teredoClt);

                    // teredo UDP port
                    Element port = doc.createElement("udpPort");
                    port.appendChild(doc.createTextNode("" + teredoInfo.getPort()));
                    teredo.appendChild(port);
                }

                // 6to4 info
                if (info.getScope() == Ipv6Scope.GLOBAL_6TO4) {
                    Element sixToFour = doc.createElement("sixToFourClientAddr");
                    sixToFour.appendChild(doc.createTextNode("" + info.getSixToFourClientIpv4()));
                    ipv6Address.appendChild(sixToFour);
                }
            }
        }

        // parse data
        for (String key : data.keySet()) {
            NodeData nodeData = data.get(key);

            try {
                nodeData.parseXmlData(doc, netNode);
            } catch (Exception e) {
                log.error("Error parsing XML data [" + nodeData.getClass().getSimpleName() + "]", e);
            }
        }

        return true;
    }

    @Override
    public String toString() {
        String addrs = "";
        for (InetAddress addr : inetAddresses) {
            if (addrs.isEmpty()) {
                addrs += ", ";
            }
            addrs += addr.getHostAddress();
        }
        if (addrs.contains(",")) {
            addrs = "[" + addrs + "]";
        }
        return "NetworkNode [mac=" + macAddress + ", addrs=" + addrs + ", manufacturer="
                + resolveManufacturer() + "]";
    }
}
