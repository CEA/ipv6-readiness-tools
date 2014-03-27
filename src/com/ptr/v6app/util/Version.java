package com.ptr.v6app.util;

import java.io.IOException;
import java.net.URL;
import java.util.Enumeration;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A utility class for reading v6App version information from MANIFEST.MF. The version is set during
 * the build process.
 */
public class Version {

    // -- Logger
    private static final Logger log = LogManager.getLogger(Version.class.getName());

    // -- v6App version attribute name
    private static final Attributes.Name v6AppVersionAttr = new Attributes.Name("v6App-Version");

    // -- Application version
    private String version = null;

    public Version() {
        loadVersion();
    }

    public String getVersion() {
        return version;
    }

    private void loadVersion() {
        try {

            // load MANIFEST.MF files
            Enumeration<URL> resources = getClass().getClassLoader().getResources(
                    "META-INF/MANIFEST.MF");

            // iterate through files
            while (resources.hasMoreElements()) {
                Manifest manifest = new Manifest(resources.nextElement().openStream());

                // check to see if this is our MANIFEST.MF
                Attributes mainAttr = manifest.getMainAttributes();
                Object versionObj = mainAttr.get(v6AppVersionAttr);
                if (versionObj == null) {
                    continue;
                }

                // set the version and bail
                version = versionObj.toString();
                return;
            }

        } catch (IOException ioe) {
            log.error("Error loading application version", ioe);
        }
    }
}
