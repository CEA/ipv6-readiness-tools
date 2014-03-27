package com.ptr.v6app.util;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.googlecode.ipv6.IPv6Address;
import com.googlecode.ipv6.IPv6Network;

/**
 * Utility class for IPv6 address information.
 */
public class Inet6AddressInfo {

    // -- Logger
    private static final Logger log = LogManager.getLogger(Inet6AddressInfo.class.getName());

    // -- Address corresponding to this instance
    private final IPv6Address addr;
    
    // -- IPv6 scope of this instance
    private final Ipv6Scope scope;

    // -- Known IPv6 scopes
    private static final IPv6Network SIX_TO_FOUR = IPv6Network.fromString("2002::/16");
    private static final IPv6Network TEREDO = IPv6Network.fromString("2001:0::/32");
    private static final IPv6Network ULA = IPv6Network.fromString("fc00::/7");
    private static final IPv6Network IPV4_MAPPED = IPv6Network.fromString("::ffff:0:0/96");
    private static final IPv6Network IPV46_TRANSLATION = IPv6Network.fromString("64:ff9b::/96");
    private static final IPv6Network DOCUMENTATION = IPv6Network.fromString("2001:db8::/32");

    /**
     * IPv6 scope enumeration.
     */
    public enum Ipv6Scope {

        LOCAL("Local"), 
        LINK_LOCAL("Link-Local"), 
        SITE_LOCAL("Site-Local"), 
        IPV4_COMPATIBLE("IPv4 Compatible"), 
        GLOBAL_MULTICAST("Global Multicast"), 
        ORG_LOCAL_MULTICAST("Organization-Local Multicast"), 
        SITE_LOCAL_MULTICAST("Site-Local Multicast"), 
        LINK_LOCAL_MULTICAST("Link-Local Multicast"), 
        IFC_LOCAL_MULTICAST("Interface-Local Multicast"), 
        UNKNOWN_MULTICAST("Unknown Multicast"), 
        GLOBAL_6TO4("Global 6to4"), 
        GLOBAL_TEREDO("Global Teredo"), 
        ULA("ULA"),
        IPV4_MAPPED("IPv4 Mapped"),
        IPv46_TRANSLATION("IPv4-IPv6 Translation"),
        DOCUMENTATION("Documentation"),
        GLOBAL("Global");

        // -- Scope name
        private final String name;

        /**
         * Instantiate a new IPv6 scope.
         * 
         * @param name
         *            Human-readable scope name.
         */
        private Ipv6Scope(String name) {
            this.name = name;
        }

        /**
         * Returns the human-readable name for this IPv6 scope.
         * 
         * @return Scope name string.
         */
        public String toString() {
            return name;
        }
    }

    /*
     * Private constructor.
     */
    private Inet6AddressInfo(IPv6Address addr) {
        if (addr == null) {
            throw new NullPointerException("null address");
        }

        this.addr = addr;
        this.scope = determineScope();
    }

    /**
     * Creates an Inet6AddressInfo instance from string representing an IPv6 address.
     * 
     * @param addr
     *            String representation of an IPv6 address.
     * @return Inet6AddressInfo
     */
    public static Inet6AddressInfo fromString(String addr) {
        return new Inet6AddressInfo(IPv6Address.fromString(addr));
    }

    /**
     * Creates an Inet6AddressInfo instance from an InetAddress object.
     * 
     * @param addr
     *            An InetAddress object.
     * @return Inet6AddressInfo
     */
    public static Inet6AddressInfo fromInetAddress(InetAddress addr) {
        return new Inet6AddressInfo(IPv6Address.fromByteArray(addr.getAddress()));
    }

    /**
     * Returns the InetAddress object corresponding to this instance's address.
     * 
     * @return InetAddress
     * @throws UnknownHostException
     */
    public InetAddress getInetAddress() throws UnknownHostException {
        return addr.toInetAddress();
    }
    
    /**
     * Returns the IPv6 address scope for this instance.
     * 
     * @return Ipv6Scope
     */
    public Ipv6Scope getScope() {
        return scope;
    }

    /**
     * Returns the upper 64 bits of the IPv6 address.
     * 
     * @return long
     */
    public long getNetworkPrefix64() {
        return addr.getHighBits();
    }

    /**
     * If this address is a reserved Teredo address, this method parses the address and returns an
     * object with the parsed values.
     * 
     * @return A TeredoAddrInfo object if this address is a Teredo address, null otherwise.
     */
    public TeredoAddrInfo getTeredoAddrInfo() {
        if (scope != Ipv6Scope.GLOBAL_TEREDO) {
            return null;
        }

        return new TeredoAddrInfo(addr.toByteArray());
    }

    /**
     * If this is a 6to4 address, this method returns the public client IPv4 address encoded in the
     * address.
     * 
     * @return String representation of the public client IPv4 address if this is a 6to4 address,
     *         null otherwise.
     */
    public String getSixToFourClientIpv4() {
        if (scope != Ipv6Scope.GLOBAL_6TO4) {
            return null;
        }

        byte[] addrBytes = addr.toByteArray();
        return (addrBytes[2] & 0xff) + "." + (addrBytes[3] & 0xff) + "." + (addrBytes[4] & 0xff)
                + "." + (addrBytes[5] & 0xff);
    }

    /**
     * Class that parses an IPv6 Teredo address into its components.
     * 
     */
    public class TeredoAddrInfo {

        // -- Teredo address attributes
        private final String serverIpv4;
        private final int flags;
        private final int port;
        private final String clientIpv4;

        public TeredoAddrInfo(byte[] addr) {
            if (addr == null || addr.length != 16) {
                throw new IllegalArgumentException("invalid address");
            }

            // bits 32-63 are the teredo server IP
            serverIpv4 = (addr[4] & 0xff) + "." + (addr[5] & 0xff) + "." + (addr[6] & 0xff) + "."
                    + (addr[7] & 0xff);

            // bits 64-79 are the flags
            ByteBuffer buf = ByteBuffer.wrap(addr, 8, 4).order(ByteOrder.BIG_ENDIAN);
            flags = Unsigned.getUnsignedShort(buf);

            // bits 80-95 are the obfuscated (bits inverted) port
            int obfPort = Unsigned.getUnsignedShort(buf);
            port = ~obfPort & 0xFFFF;

            // bits 96-127 are the obfuscated (bits inverted) client IP
            clientIpv4 = (~addr[12] & 0xff) + "." + (~addr[13] & 0xff) + "." + (~addr[14] & 0xff)
                    + "." + (~addr[15] & 0xff);
        }

        public String getServerIpv4() {
            return serverIpv4;
        }

        public int getFlags() {
            return flags;
        }

        public int getPort() {
            return port;
        }

        public String getClientIpv4() {
            return clientIpv4;
        }

        @Override
        public String toString() {
            return "TeredoAddrInfo [serverIpv4=" + serverIpv4 + ", flags=" + flags + ", port="
                    + port + ", clientIpv4=" + clientIpv4 + "]";
        }
    }

    private Ipv6Scope determineScope() {

        // parse address
        Inet6Address inetAddr;
        try {
            inetAddr = (Inet6Address) getInetAddress();
        } catch (Exception e) {
            log.error("Error parsing address", e);
            return null;
        }

        if (inetAddr.isAnyLocalAddress() || inetAddr.isLoopbackAddress()) {
            return Ipv6Scope.LOCAL;
        }

        if (inetAddr.isLinkLocalAddress()) {
            return Ipv6Scope.LINK_LOCAL;
        }

        if (inetAddr.isSiteLocalAddress()) {
            return Ipv6Scope.SITE_LOCAL;
        }

        if (inetAddr.isIPv4CompatibleAddress()) {
            return Ipv6Scope.IPV4_COMPATIBLE;
        }

        // check all multicast ranges
        if (inetAddr.isMulticastAddress()) {
            if (inetAddr.isMCGlobal()) {
                return Ipv6Scope.GLOBAL_MULTICAST;
            } else if (inetAddr.isMCOrgLocal()) {
                return Ipv6Scope.ORG_LOCAL_MULTICAST;
            } else if (inetAddr.isMCSiteLocal()) {
                return Ipv6Scope.SITE_LOCAL_MULTICAST;
            } else if (inetAddr.isMCLinkLocal()) {
                return Ipv6Scope.LINK_LOCAL_MULTICAST;
            } else if (inetAddr.isMCNodeLocal()) {
                return Ipv6Scope.IFC_LOCAL_MULTICAST;
            } else {
                return Ipv6Scope.UNKNOWN_MULTICAST;
            }
        }

        // check for a 6to4 address
        if (SIX_TO_FOUR.contains(addr)) {
            return Ipv6Scope.GLOBAL_6TO4;
        }

        // check for Teredo address
        if (TEREDO.contains(addr)) {
            return Ipv6Scope.GLOBAL_TEREDO;
        }

        // check for ULA address
        if (ULA.contains(addr)) {
            return Ipv6Scope.ULA;
        }
        
        // check for IPv4-Mapped address
        if (IPV4_MAPPED.contains(addr)) {
            return Ipv6Scope.IPV4_MAPPED;
        }
        
        // check for IPv4-IPv6 translation address
        if (IPV46_TRANSLATION.contains(addr)) {
            return Ipv6Scope.IPv46_TRANSLATION;
        }
        
        // check for documentation address
        if (DOCUMENTATION.contains(addr)) {
            return Ipv6Scope.DOCUMENTATION;
        }

        // if we made it this far, it's a global unicast address
        return Ipv6Scope.GLOBAL;
    }

    public static void main(String[] args) {
        for (String arg : args) {
            Inet6AddressInfo addr = fromString(arg);
            log.info("[{}]: Scope [{}]", arg, addr.getScope());
            if (addr.getScope() == Ipv6Scope.GLOBAL_TEREDO) {
                log.info("[{}]: {}", arg, addr.getTeredoAddrInfo());
            }
            if (addr.getScope() == Ipv6Scope.GLOBAL_6TO4) {
                log.info("[{}]: 6to4 client [{}]", arg, addr.getSixToFourClientIpv4());
            }
        }
    }
}
