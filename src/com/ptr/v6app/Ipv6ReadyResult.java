package com.ptr.v6app;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collections;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.ptr.v6app.util.Inet6AddressInfo;
import com.ptr.v6app.util.Inet6AddressInfo.Ipv6Scope;
import com.ptr.v6app.util.NetUtils;
import com.ptr.v6app.util.Inet6AddressInfo.TeredoAddrInfo;

/**
 * This class stores the results from an IPv6 readiness test.
 */
public class Ipv6ReadyResult {

    // -- Logger
    private static final Logger log = LogManager.getLogger(Ipv6ReadyResult.class.getName());

    // -- Interfaces with IPv6 addresses
    private final List<NetworkInterface> ipv6Ifcs;

    // -- Test results
    private final boolean canResolveAAAA;
    private final boolean canContactIpv6Inet;

    public Ipv6ReadyResult(List<NetworkInterface> ipv6Ifcs, boolean canResolveAAAA,
            boolean canContactIpv6Inet) {
        this.ipv6Ifcs = ipv6Ifcs;
        this.canResolveAAAA = canResolveAAAA;
        this.canContactIpv6Inet = canContactIpv6Inet;
    }

    /**
     * Returns the IPv6-enabled network interfaces for the test.
     * 
     * @return List<NetworkInterface>
     */
    public List<NetworkInterface> getIpv6Ifcs() {
        return ipv6Ifcs;
    }

    /**
     * Returns true if the test could resolve a AAAA DNS query.
     * 
     * @return true on success, false otherwise.
     */
    public boolean isCanResolveAAAA() {
        return canResolveAAAA;
    }

    /**
     * Returns true if the test could contact the IPv6 Internet.
     * 
     * @return true on success, false otherwise.
     */
    public boolean isCanContactIpv6Inet() {
        return canContactIpv6Inet;
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

        // create root test element
        Element v6test = doc.createElement("ipv6Test");
        root.appendChild(v6test);

        // DNS result
        Element dns = doc.createElement("resolveAAAA");
        dns.appendChild(doc.createTextNode("" + canResolveAAAA));
        v6test.appendChild(dns);

        // v6 internet result
        Element v6Inet = doc.createElement("contactIpv6Inet");
        v6Inet.appendChild(doc.createTextNode("" + canContactIpv6Inet));
        v6test.appendChild(v6Inet);

        // v6 interfaces
        if (ipv6Ifcs != null && !ipv6Ifcs.isEmpty()) {

            Element v6Ifcs = doc.createElement("ipv6Interfaces");
            v6test.appendChild(v6Ifcs);

            // add each interface
            for (NetworkInterface ifc : ipv6Ifcs) {
                try {
                    Element v6Ifc = doc.createElement("interface");
                    v6Ifcs.appendChild(v6Ifc);

                    // add mac
                    Element mac = doc.createElement("mac");
                    mac.appendChild(doc.createTextNode(""
                            + NetUtils.getMacString(ifc.getHardwareAddress())));
                    v6Ifc.appendChild(mac);

                    // add name
                    Element name = doc.createElement("name");
                    name.appendChild(doc.createTextNode("" + ifc.getName()));
                    v6Ifc.appendChild(name);

                    // add display name
                    Element displayName = doc.createElement("displayName");
                    displayName.appendChild(doc.createTextNode("" + ifc.getDisplayName()));
                    v6Ifc.appendChild(displayName);

                    // add status
                    Element up = doc.createElement("up");
                    up.appendChild(doc.createTextNode("" + ifc.isUp()));
                    v6Ifc.appendChild(up);

                    // add addresses
                    Element addrs = doc.createElement("addresses");
                    v6Ifc.appendChild(addrs);

                    // add each IPv6 address
                    List<InetAddress> inetAddrs = Collections.list(ifc.getInetAddresses());
                    for (InetAddress inetAddr : inetAddrs) {
                        if (!(inetAddr instanceof Inet6Address)) {
                            continue;
                        }

                        // IPv6 address
                        Element ipv6Address = doc.createElement("ipv6Address");
                        addrs.appendChild(ipv6Address);

                        // address
                        Element address = doc.createElement("address");
                        address.appendChild(doc.createTextNode("" + inetAddr.getHostAddress()));
                        ipv6Address.appendChild(address);

                        // scope
                        Inet6AddressInfo info = Inet6AddressInfo.fromInetAddress(inetAddr);
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
                            teredoSvr.appendChild(doc.createTextNode(""
                                    + teredoInfo.getServerIpv4()));
                            teredo.appendChild(teredoSvr);

                            // teredo client
                            Element teredoClt = doc.createElement("clientAddr");
                            teredoClt.appendChild(doc.createTextNode(""
                                    + teredoInfo.getClientIpv4()));
                            teredo.appendChild(teredoClt);

                            // teredo UDP port
                            Element port = doc.createElement("udpPort");
                            port.appendChild(doc.createTextNode("" + teredoInfo.getPort()));
                            teredo.appendChild(port);
                        }

                        // 6to4 info
                        if (info.getScope() == Ipv6Scope.GLOBAL_6TO4) {
                            Element sixToFour = doc.createElement("sixToFourClientAddr");
                            sixToFour.appendChild(doc.createTextNode(""
                                    + info.getSixToFourClientIpv4()));
                            ipv6Address.appendChild(sixToFour);
                        }
                    }
                } catch (SocketException se) {
                    log.error("Error parsing interface result [" + ifc.getDisplayName() + "]", se);
                    return false;
                }
            }
        }

        return true;
    }

    @Override
    public String toString() {
        return "Ipv6ReadyResult [ipv6Ifcs=" + (ipv6Ifcs == null ? 0 : ipv6Ifcs.size())
                + ", canResolveAAAA=" + canResolveAAAA + ", canContactIpv6Inet="
                + canContactIpv6Inet + "]";
    }
}
