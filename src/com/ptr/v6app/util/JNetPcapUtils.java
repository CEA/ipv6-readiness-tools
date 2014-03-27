package com.ptr.v6app.util;

import java.io.File;
import java.io.FilenameFilter;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;

/**
 * Utility class for jNetPcap tasks.
 */
public class JNetPcapUtils {

    // -- Logger
    private static final Logger log = LogManager.getLogger(JNetPcapUtils.class.getName());

    /**
     * Loads a single packet from a .pcap offline file into a PcapPacket object.
     * 
     * @param path
     *            The path of the .pcap file.
     * @return The fully parsed PcapPacket instance.
     */
    public static PcapPacket pcapPacketFromFile(String path) {
        PcapPacket filePacket = new PcapPacket(JMemory.POINTER);
        PcapPacket copyPacket = null;
        StringBuilder errBuf = new StringBuilder();

        // open the pcap file
        final Pcap offlinePcap = Pcap.openOffline(path, errBuf);
        if (offlinePcap == null) {
            log.error("Error parsing [{}]: {}", path, errBuf);
            return null;
        }

        // read one packet and deep copy from JNI mapped memory to JVM memory
        if (offlinePcap.nextEx(filePacket) == Pcap.NEXT_EX_OK) {
            copyPacket = new PcapPacket(filePacket);
        }

        // close the capture and return
        offlinePcap.close();
        return copyPacket;
    }

    /**
     * Helper utility that returns a list of .pcap filename in a given directory.
     * 
     * @param dir
     *            The directory path to search for pcap files
     * @return An array of pcap filename that includes directory path, or null if no pcap files are
     *         found.
     */
    public static String[] getPcapFilenames(String dir) {
        File directory = new File(dir);

        // get the pcap filenames in the specified directory
        String files[] = directory.list(new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                return name.endsWith(".pcap");
            }
        });

        if (files == null) {
            return null;
        }

        // we're interested in the path
        String[] paths = new String[files.length];
        for (int i = 0; i < files.length; i++) {
            paths[i] = dir + "/" + files[i];
        }
        return paths;
    }
}
