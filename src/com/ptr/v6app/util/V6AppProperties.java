package com.ptr.v6app.util;

import java.io.InputStream;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class V6AppProperties {

    // -- Logger
    private static final Logger log = LogManager.getLogger(V6AppProperties.class.getName());

    // -- Properties file
    private static final String FILE_NAME = "/v6app.properties";

    // -- Properties
    private static final Properties properties = new Properties();

    // -- Initialization flag
    private static boolean initialized = false;

    // -- Property names
    public static final String IPV6_DOMAINS = "ipv6Domains";
    public static final String IPV6_ADDRS = "ipv6TestAddrs";
    public static final String NETWORK_DISCOVERY_SECS = "networkDiscoverySecs";
    public static final String NETWORK_DISCOVERY_IFCS = "networkDiscoveryIfcs";

    // -- Default properties
    private static final String[] DEFAULT_IPV6_DOMAINS = { "ipv6.google.com" };
    private static final String[] DEFAULT_IPV6_ADDRS = { 
        "2607:f8b0:400c:c04::93" // ipv6.google.com 
    };
    private static final String DEFAULT_NET_DISCOVERY_IFC = "all";
    private static final int DEFAULT_NET_DISCOVERY_SECS = 90;

    // -- Load properties
    static {
        try {
            InputStream in = V6AppProperties.class.getResourceAsStream(FILE_NAME);
            if (in != null) {
                properties.load(in);
                in.close();
                initialized = true;
            } else {
                log.error("Error finding properties file");
            }
        } catch (Exception e) {
            log.error("Error loading properties file", e);
        }
    }

    /*
     * Do not instantiate.
     */
    private V6AppProperties() {
    }

    /**
     * Returns the V6App properties object.
     * 
     * @return Properties
     */
    public static Properties getProperties() {
        return (initialized ? properties : null);
    }

    /**
     * Returns the ipv6Domains Java property.
     * 
     * @return String[]
     */
    public static String[] getIpv6Domains() {
        return getPropertyList(IPV6_DOMAINS, DEFAULT_IPV6_DOMAINS, ",");
    }

    /**
     * Returns the ipv6TestAddrs Java property.
     * 
     * @return String[]
     */
    public static String[] getIpv6TestAddrs() {
        return getPropertyList(IPV6_ADDRS, DEFAULT_IPV6_ADDRS, ",");
    }

    /**
     * Returns the networkDiscoverySecs Java property.
     * 
     * @return int
     */
    public static int getNetworkDiscoverySecs() {
        if (!initialized) {
            return DEFAULT_NET_DISCOVERY_SECS;
        }

        try {
            String durationStr = properties.getProperty(NETWORK_DISCOVERY_SECS);
            return Integer.parseInt(durationStr);
        } catch (Exception e) {
            log.warn("Unable to read property [{}] from properties file, defaulting to [{}]",
                    NETWORK_DISCOVERY_SECS, DEFAULT_NET_DISCOVERY_SECS);
            return DEFAULT_NET_DISCOVERY_SECS;
        }
    }

    /**
     * Returns the list of interface names from the networkDiscoveryIfcs Java property.
     * 
     * @return Set<String> of interface names or null if all interfaces should be used.
     */
    public static Set<String> getLimitedNetDescoveryIfcs() {
        if (!initialized) {
            return null;
        }
        
        try {
            String[] def = { DEFAULT_NET_DISCOVERY_IFC };
            String[] ifcs = getPropertyList(NETWORK_DISCOVERY_IFCS, def, ",");
            
            // check if any of the interfaces is the 'all' flag
            for (String ifc : ifcs) {
                if (ifc.equals(DEFAULT_NET_DISCOVERY_IFC)) {
                    return null;
                }
            }
            
            return new HashSet<String>(Arrays.asList(ifcs));
        } catch (Exception e) {
            log.warn("Unable to read property [{}] from properties file, defaulting to [{}]",
                    NETWORK_DISCOVERY_IFCS, DEFAULT_NET_DISCOVERY_IFC);
            return null;
        }
    }

    private static String[] getPropertyList(String prop, String[] defaultProp, String sep) {
        if (!initialized) {
            return defaultProp;
        }

        try {
            String domainProp = properties.getProperty(prop);

            // parse property and trim whitespace
            String[] parts = domainProp.split(sep);
            for (int i = 0; i < parts.length; i++) {
                parts[i] = parts[i].trim();
            }
            return parts;

        } catch (Exception e) {

            // format debug string
            String defaults = "";
            for (int i = 0; i < defaultProp.length; i++) {
                if (i > 0) {
                    defaults += ", ";
                }
                defaults += defaultProp[i];
            }
            log.warn("Unable to read property [{}] from properties file, defaulting to [{}]", prop,
                    defaults);

            return defaultProp;
        }
    }
}
