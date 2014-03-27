package com.ptr.v6app.util;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Utility class for resolving hardware manufacturers based on MAC prefix. Initial implementation
 * assumes that oui.txt is in the classpath.
 */
public class IEEEOuiResolver {

    // -- Logger
    private static final Logger log = LogManager.getLogger(IEEEOuiResolver.class.getName());

    // -- Config params
    private static final String OUI_PATH = "/oui.txt";
    private static final int MAC_LEN = 8;

    // -- Manufacturers map
    private static final Map<String, String> manufacturers = new HashMap<String, String>();
    
    // -- Initialization flag
    private static boolean initialized = false;

    /*
     * Static initializer to load oui.txt
     */
    static {
        initialized = loadOuiFile();
    }
    
    /*
     * Do not instantiate.
     */
    private IEEEOuiResolver() { }

    /**
     * Resolves a MAC address string to a manufacturer.
     * 
     * @param mac
     *            A MAC address string in the format XX:XX:XX:XX:XX:XX. A MAC prefix is also
     *            acceptable: XX:XX:XX
     * @return A String representing a manufacturer name
     */
    public static String resolveManfacturer(String mac) {
        if (!initialized || mac == null || mac.length() < MAC_LEN) {
            return null;
        }

        String macPrefix = mac.substring(0, MAC_LEN).toUpperCase();
        String manufacturer = manufacturers.get(macPrefix);
        return manufacturer;
    }

    /**
     * Loads and parses data from oui.txt to memory.
     */
    private static boolean loadOuiFile() {

        // load oui.txt
        try {
            InputStream in = (new IEEEOuiResolver()).getClass().getResourceAsStream(OUI_PATH);
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));

            // parse each line
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.length() < MAC_LEN) {
                    continue;
                }

                String mac = line.substring(0, MAC_LEN);
                if (checkMac(mac)) {
                    String manufacturer = line.substring(MAC_LEN).trim();
                    if (manufacturer.startsWith("(hex)")) {
                        manufacturer = manufacturer.substring(5).replaceAll("\t", "")
                                .replaceAll("\"", "");
                    }
                    mac = mac.replaceAll("-", ":");
                    mac = mac.toUpperCase();
                    manufacturers.put(mac, manufacturer);
                }
            }
            
            log.debug("Loaded [{}] manufacturers from [{}]", manufacturers.size(), OUI_PATH);
            return true;
        } catch (Exception e) {
            log.error("Failed to parse oui.txt: {}", e.getMessage());
            return false;
        }
    }

    private static boolean checkMac(String mac) {        
        Pattern macPattern = Pattern.compile("([0-9A-Fa-f]{2})(-[0-9A-Fa-f]{2}){2}");
        Matcher macMatcher = macPattern.matcher(mac);
        if (macMatcher.find()) {
            return true;
        }
        return false;
    }
}
