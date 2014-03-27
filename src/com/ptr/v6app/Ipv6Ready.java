package com.ptr.v6app;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ptr.v6app.util.NetUtils;
import com.ptr.v6app.util.V6AppProperties;

/**
 * This class is used to test IPv6 readiness of the local host. The host is considered IPv6 Ready if
 * it can resolve AAAA DNS records and successfully open a socket connection to an IPv6-only web
 * domain.
 */
public class Ipv6Ready {

    // -- Logger
    private static final Logger log = LogManager.getLogger(Ipv6Ready.class.getName());

    /**
     * Initializes an Ipv6Ready instance.
     */
    public Ipv6Ready() {
        // no initialization needed
    }

    public Ipv6ReadyResult testIpv6Readiness() {
        log.info("Starting IPv6 Readiness Test...");

        // find IPv6 interfaces
        log.info("  Finding an IPv6-enabled interface...");
        List<NetworkInterface> v6Ifcs = findIpv6Interfaces();
        if (v6Ifcs == null) {
            log.info("    [FAIL]");
            log.info("Local host is NOT IPv6-Ready!");
            return new Ipv6ReadyResult(null, false, false);
        }
        log.info("    [OK]");

        // try to resolve an IPv6-only (AAAA) domain name
        log.info("  Attempting to resolve an IPv6-only (AAAA) domain name...");
        boolean canResolveAAAA = canResolveAAAA();
        log.info(canResolveAAAA ? "    [OK]" : "    [FAIL]");

        // try to contact the IPv6 Internet
        log.info("  Attempting to contact IPv6 Internet...");
        boolean canContactIpv6Inet = canContactIpv6Inet(v6Ifcs, canResolveAAAA);
        log.info(canContactIpv6Inet ? "    [OK]" : "    [FAIL]");

        // report results
        if (canContactIpv6Inet) {
            log.info("Local host is IPv6-Ready and can reach the IPv6 Internet!");
        } else {
            log.info("Local host is IPv6-Ready but CANNOT reach the IPv6 Internet.");
        }
        if (canResolveAAAA) {
            log.info("DNS server appears to have IPv6 Internet access.");
        } else {
            log.info("DNS server does NOT appear to have IPv6 Internet access, "
                    + "user may have trouble accessing IPv6 web sites.");
        }

        return new Ipv6ReadyResult(v6Ifcs, canResolveAAAA, canContactIpv6Inet);
    }

    private List<NetworkInterface> findIpv6Interfaces() {
        List<NetworkInterface> v6Ifcs = new ArrayList<NetworkInterface>();
        try {

            // obtain all interfaces
            Enumeration<NetworkInterface> ifcs = NetworkInterface.getNetworkInterfaces();
            if (ifcs == null) {
                return null;
            }

            // iterate over each interface
            for (NetworkInterface ifc : Collections.list(ifcs)) {

                // disregard loopback or down interfaces
                if (ifc.isLoopback() || !ifc.isUp()) {
                    continue;
                }

                // obtain all addresses on this interface
                Enumeration<InetAddress> addrs = ifc.getInetAddresses();
                if (addrs == null) {
                    continue;
                }

                // iterate over each address on this interface
                for (InetAddress addr : Collections.list(addrs)) {

                    // skip non-IPv6 addresses
                    if (!(addr instanceof Inet6Address)) {
                        continue;
                    }

                    // we have an active IPv6 address
                    v6Ifcs.add(ifc);
                    break;
                }
            }
        } catch (IOException ioe) {
            log.error(ioe);
        }

        return (v6Ifcs.isEmpty() ? null : v6Ifcs);
    }

    private boolean canResolveAAAA() {

        // load IPv6 domains from properties
        String[] domains = V6AppProperties.getIpv6Domains();

        // try to resolve each domain until we find a valid AAAA record
        for (String domain : domains) {
            domain = domain.trim();
            try {
                InetAddress[] addrs = InetAddress.getAllByName(domain);
                for (InetAddress addr : addrs) {
                    if (addr instanceof Inet6Address) {
                        log.debug("Resolved valid AAAA record for [{}]", domain);
                        return true;
                    }
                }
            } catch (UnknownHostException e) {
                continue;
            }
        }

        // no joy
        return false;
    }

    private boolean canContactIpv6Inet(List<NetworkInterface> v6Ifcs, boolean haveDns) {

        // if we have DNS, try to get to the IPv6 Internet via domain name
        if (haveDns) {
            String[] domains = V6AppProperties.getIpv6Domains();
            for (String domain : domains) {
                try {
                    for (InetAddress inetAddr : InetAddress.getAllByName(domain)) {
                        if (inetAddr instanceof Inet6Address) {
                            log.debug("Attempting to contact [{}] at [{}]", inetAddr.getHostName(),
                                    inetAddr.getHostAddress());
                            if (NetUtils.isReachable(inetAddr, 80)) {
                                return true;
                            }
                        }
                    }
                } catch (Exception e) {
                    // move on
                }
            }
        }

        // we don't have DNS or we had trouble with the domain name,
        // try using actual IPv6 addresses from the properties file
        String[] addrs = V6AppProperties.getIpv6TestAddrs();
        for (String addr : addrs) {
            log.debug("Attempting to contact [{}]", addr);
            if (NetUtils.isReachable(addr, 80)) {
                return true;
            }
        }

        // no joy
        return false;
    }
}
