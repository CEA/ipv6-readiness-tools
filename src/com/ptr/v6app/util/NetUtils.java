package com.ptr.v6app.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.format.FormatUtils;

import com.ptr.v6app.util.Inet6AddressInfo.Ipv6Scope;

/**
 * Utility class for various network tasks.
 */
public class NetUtils {

    // -- Logger
    private static final Logger log = LogManager.getLogger(NetUtils.class.getName());

    // -- Network interace map
    private static final Map<String, NetworkInterface> ifcMap = new HashMap<String, NetworkInterface>();
    static {
        // obtain all interfaces
        Enumeration<NetworkInterface> ifcs = null;
        try {
            ifcs = NetworkInterface.getNetworkInterfaces();
        } catch (SocketException e) {
            log.error("Error obtaining network interfaces", e);
        }

        // create the map
        if (ifcs != null) {
            for (NetworkInterface ifc : Collections.list(ifcs)) {
                try {
                    if (ifc.getHardwareAddress() != null) {
                        ifcMap.put(FormatUtils.asString(ifc.getHardwareAddress()), ifc);
                    }
                } catch (SocketException e) {
                    log.error("Error obtaining interface address", e);
                }
            }
        }
    }

    private NetUtils() {
        // do not instantiate, use static methods
    }

    /**
     * Parses a MAC address string into a byte array. The supported octet separators are '-' and
     * ':'.
     * 
     * @param macStr
     *            The MAC address string.
     * @return The byte array representation of the mac address.
     */
    public static byte[] getMacBytes(String macStr) {
        if (macStr == null) {
            throw new NullPointerException("Null MAC string");
        }

        // parse MAC into octets
        String octets[] = macStr.split("[:-]");
        if (octets.length != 6) {
            throw new IllegalArgumentException("Invalid MAC string");
        }

        // parse into byte array
        byte[] macBytes = new byte[6];
        for (int i = 0; i < octets.length; i++) {
            macBytes[i] = Integer.decode("0x" + octets[i]).byteValue();
        }

        return macBytes;
    }

    /**
     * Calculate the Internet Checksum of a buffer (RFC 1071 -
     * http://www.faqs.org/rfcs/rfc1071.html) Algorithm is 1) apply a 16-bit 1's complement sum over
     * all octets (adjacent 8-bit pairs [A,B], final odd length is [A,0]) 2) apply 1's complement to
     * this final sum
     * 
     * Notes: 1's complement is bitwise NOT of positive value. Ensure that any carry bits are added
     * back to avoid off-by-one errors
     * 
     * @param buf
     *            The message
     * @return The checksum
     */
    public static long calculateChecksum(byte[] buf) {
        int length = buf.length;
        int i = 0;

        long sum = 0;
        long data;

        // Handle all pairs
        while (length > 1) {
            // Corrected to include @Andy's edits and various comments on Stack Overflow
            data = (((buf[i] << 8) & 0xFF00) | ((buf[i + 1]) & 0xFF));
            sum += data;
            // 1's complement carry bit correction in 16-bits (detecting sign extension)
            if ((sum & 0xFFFF0000) > 0) {
                sum = sum & 0xFFFF;
                sum += 1;
            }

            i += 2;
            length -= 2;
        }

        // Handle remaining byte in odd length buffers
        if (length > 0) {
            // Corrected to include @Andy's edits and various comments on Stack Overflow
            sum += (buf[i] << 8 & 0xFF00);
            // 1's complement carry bit correction in 16-bits (detecting sign extension)
            if ((sum & 0xFFFF0000) > 0) {
                sum = sum & 0xFFFF;
                sum += 1;
            }
        }

        // Final 1's complement value correction to 16-bits
        sum = ~sum;
        sum = sum & 0xFFFF;
        return sum;

    }

    /**
     * Returns true if the byte array addr corresponds to a valid IPv6 address.
     * 
     * @param addr
     *            The byte array containing an IP address.
     * @return Returns true addr corresponds to a valid IPv6 address, false othewise.
     */
    public static boolean isIpv6Addr(byte[] addr) {
        try {
            InetAddress inetAddr = InetAddress.getByAddress(addr);
            return inetAddr instanceof Inet6Address;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Returns byte array representing IPv4/IPv6 address name.
     * 
     * @param name
     *            Textual IPv4/IPv6 address.
     * @return Address bytes.
     */
    public static byte[] getAddressBytes(String name) {
        try {
            InetAddress inetAddr = InetAddress.getByName(name);
            return inetAddr.getAddress();
        } catch (UnknownHostException uhe) {
            return null;
        }
    }

    /**
     * Returns the IP address in textual form.
     * 
     * @param addr
     *            The raw IP address in network byte order
     * @return The raw IP address in textual form
     */
    public static String getHostAddress(byte[] addr) {
        try {
            InetAddress inetAddr = InetAddress.getByAddress(addr);
            return inetAddr.getHostAddress();
        } catch (UnknownHostException uhe) {
            return null;
        }
    }

    /**
     * Returns the mac address in textual form.
     * 
     * @param mac
     *            The raw mac address
     * @return The raw mac address in textual form
     */
    public static String getMacString(byte[] mac) {
        if (mac == null) {
            return null;
        }

        String macStr = "";
        for (byte b : mac) {
            if (!macStr.isEmpty()) {
                macStr += ":";
            }
            macStr += String.format("%02X", b);
        }

        return macStr;
    }

    /**
     * Returns true if a socket connection can be successfully established to dstAddr:dstPort. The
     * socket is immediately closed after the connect().
     * 
     * @param dstHostname
     *            The destination hostname.
     * @param dstPort
     *            The destination port.
     * @return true if a socket connection was established, false otherwise.
     */
    public static boolean isReachable(String dstHostname, int dstPort) {
        try {
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(dstHostname, dstPort), 5 * 1000);
            socket.close();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Returns true if a socket connection can be successfully established to inetAddr:dstPort. The
     * socket is immediately closed after the connect().
     * 
     * @param inetAddr
     *            The destination address.
     * @param dstPort
     *            The destination port.
     * @return true if a socket connection was established, false otherwise.
     */
    public static boolean isReachable(InetAddress inetAddr, int dstPort) {
        try {
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(inetAddr, dstPort), 3 * 1000);
            socket.close();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Returns true if a socket connection can be successfully established from srcAddr to
     * dstHostname:dstPort. The socket is immediately closed after the connect().
     * 
     * @param srcAddr
     *            The local address representing the source of the socket.
     * @param dstHostname
     *            The destination hostname.
     * @param dstPort
     *            The destination port.
     * @return true if a socket connection was established, false otherwise.
     */
    public static boolean isReachable(InetAddress srcAddr, String dstHostname, int dstPort) {
        try {
            Socket socket = new Socket();
            socket.bind(new InetSocketAddress(srcAddr, 0));
            socket.connect(new InetSocketAddress(dstHostname, dstPort), 5 * 1000);
            socket.close();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Returns a list of Pcap interfaces that have an IPv6 address.
     * 
     * @return The list of IPv6 Pcap interfaces.
     */
    public static List<PcapIf> getPcap6Ifcs() {
        StringBuilder errbuf = new StringBuilder(); // For any error msgs  

        // first get a list of pcap devices on this system
        List<PcapIf> pcapIfcs = new ArrayList<PcapIf>();
        int r = Pcap.findAllDevs(pcapIfcs, errbuf);
        if (r == Pcap.NOT_OK || pcapIfcs.isEmpty()) {
            log.error("Error obtaining Pcap interfaces: {}", errbuf.toString());
            return null;
        }

        // build a list of pcap interfaces that have an IPv6 address sorted by internet
        // accessibility, those that can reach the internet (v4/v6) at the head of the list
        List<PcapIf> pcap6Ifcs = new ArrayList<PcapIf>();
        for (PcapIf pcapIf : pcapIfcs) {
            NetworkInterface netIfc = getNetworkInterface(pcapIf);
            if (netIfc != null && hasInet6Address(netIfc)) {
                pcap6Ifcs.add(pcapIf);
            }
        }

        return pcap6Ifcs;
    }

    public static NetworkInterface getNetworkInterface(PcapIf pcapIf) {
        if (pcapIf == null) {
            throw new NullPointerException("null PcapIf");
        }

        try {
            return ifcMap.get(FormatUtils.asString(pcapIf.getHardwareAddress()));
        } catch (Exception e) {
            return null;
        }
    }

    public static boolean hasInet6Address(NetworkInterface ifc) {
        if (ifc == null) {
            throw new NullPointerException("null NetworkInterface");
        }

        // obtain all addresses on this interface
        Enumeration<InetAddress> addrs = ifc.getInetAddresses();
        if (addrs == null) {
            return false;
        }

        for (InetAddress addr : Collections.list(addrs)) {
            if (addr instanceof Inet6Address) {
                log.debug("[{}]: has IPv6 address [{}]", ifc.getDisplayName(), addr.getHostName());
                return true;
            }
        }

        return false;
    }

    public static boolean canReachInternet(NetworkInterface ifc) {
        if (ifc == null) {
            throw new NullPointerException("null NetworkInterface");
        }

        try {

            // disregard loopback or down interfaces
            if (ifc.isLoopback() || !ifc.isUp()) {
                return false;
            }

            // obtain all addresses on this interface
            Enumeration<InetAddress> addrs = ifc.getInetAddresses();
            if (addrs == null) {
                return false;
            }

            // iterate over each address on this interface
            for (InetAddress addr : Collections.list(addrs)) {

                // make sure this isn't a link-local address
                if (addr.isLinkLocalAddress()) {
                    continue;
                }

                // make sure the address is reachable
                if (!addr.isReachable(3000)) {
                    continue;
                }

                // try to contact the Internet
                if (isReachable(addr, "google.com", 80)) {
                    return true;
                }
            }
        } catch (Exception e) {
            return false;
        }

        return false;
    }

    public static byte[] getLinkLocal6Addr(PcapIf pcapIf) {
        if (pcapIf == null) {
            throw new NullPointerException("null PcapIf");
        }

        for (PcapAddr addr : pcapIf.getAddresses()) {
            try {
                byte[] addrBytes = addr.getAddr().getData();
                InetAddress inetAddr = InetAddress.getByAddress(addrBytes);

                if ((inetAddr instanceof Inet6Address) && inetAddr.isLinkLocalAddress()) {
                    return addrBytes;
                }
            } catch (Exception e) {
            }
        }

        return null;
    }

    public static List<Long> getGlobalPrefixes() {
        List<Long> prefixes = new ArrayList<Long>();
        try {

            // find all interfaces
            Enumeration<NetworkInterface> ifcs = NetworkInterface.getNetworkInterfaces();
            if (ifcs == null) {
                return null;
            }

            // for each interface...
            for (NetworkInterface ifc : Collections.list(ifcs)) {

                // get all addresses
                Enumeration<InetAddress> addrs = ifc.getInetAddresses();
                if (addrs == null) {
                    continue;
                }

                // for each address on this interface...
                for (InetAddress addr : Collections.list(addrs)) {

                    // is this an IPv6 address?
                    if (addr instanceof Inet6Address) {

                        // is this a global IPv6 address?
                        Inet6AddressInfo addrInfo = Inet6AddressInfo.fromInetAddress(addr);
                        if (addrInfo.getScope() == Ipv6Scope.GLOBAL) {

                            // save the /64 network prefix
                            if (!prefixes.contains(addrInfo.getNetworkPrefix64())) {
                                prefixes.add(addrInfo.getNetworkPrefix64());
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.error("Failed to obtain global prefixes for the localhost", e);
            return null;
        }

        return prefixes;
    }

    /**
     * Returns the IPv4 default gateway for the localhost.
     * 
     * @return The IPv4 default gateway bytes.
     * @throws IOException
     */
    public static byte[] getLocalIpv4Gateway() throws IOException {

        // Java doesn't make this easy so we'll use the netstat command and parse
        // the output.  This should work for win/linux/mac
        Process result = Runtime.getRuntime().exec("netstat -rn");

        // parse the output line by line
        BufferedReader output = new BufferedReader(new InputStreamReader(result.getInputStream()));
        String line = output.readLine();
        StringTokenizer st;
        boolean firstToken;
        while (line != null) {

            // depending on the platform, we're looking for the line that starts with 'default'
            // or '0.0.0.0'.  the default gateway will be the first token on this line that
            // isn't 'default' or '0.0.0.0'
            st = new StringTokenizer(line);
            firstToken = true;
            while (st.hasMoreTokens()) {
                String token = st.nextToken();

                // is this the line we're looking for?
                if (firstToken) {
                    if (token.equals("default") || token.equals("0.0.0.0")) {
                        firstToken = false; // yep
                    } else {
                        break; // nope, go to next line
                    }
                } else {

                    // if the token isn't 'default' or '0.0.0.0' then we'll assume it's the gateway
                    if (!token.equals("default") && !token.equals("0.0.0.0")) {

                        // validate the gateway
                        try {
                            InetAddress gateway = InetAddress.getByName(token);
                            if (gateway instanceof Inet4Address) {
                                return gateway.getAddress();
                            }
                        } catch (UnknownHostException uhe) {
                        }

                        // invalid address
                        return null;
                    }
                }
            }

            // next line
            line = output.readLine();
        }

        // couldn't find the gateway
        return null;
    }
}
