package com.ptr.v6app.main;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.RegistryHeaderErrors;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.ptr.v6app.Ipv6Ready;
import com.ptr.v6app.Ipv6ReadyResult;
import com.ptr.v6app.NetworkDiscovery;
import com.ptr.v6app.util.V6AppProperties;
import com.ptr.v6app.util.Version;

/**
 * This class is the main launch point for the v6App. Startup scripts should execute this class when
 * launching the v6App.
 */
public class V6App {

    // -- Logger
    private static final Logger log = LogManager.getLogger(V6App.class.getName());

    // -- Constants
    public static final String XML_FILE = "v6app-results.xml";

    public static boolean parseXmlResults(Date start, Ipv6ReadyResult ipv6Result,
            NetworkDiscovery netDiscovery) {
        boolean xmlSuccess = true;
        log.info("Parsing XML results to [{}]...", XML_FILE);

        try {
            // create XML results document
            DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder docBuilder = docFactory.newDocumentBuilder();

            // root element
            Document doc = docBuilder.newDocument();
            Element root = doc.createElement("v6App");
            doc.appendChild(root);

            // version
            Version v6AppVersion = new Version();
            Element version = doc.createElement("version");
            version.appendChild(doc.createTextNode("" + v6AppVersion.getVersion()));
            root.appendChild(version);

            // date
            SimpleDateFormat df = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss z");
            Element date = doc.createElement("date");
            date.appendChild(doc.createTextNode("" + df.format(start)));
            root.appendChild(date);

            // lib version
            Element libVersion = doc.createElement("pcapLib");
            libVersion.appendChild(doc.createTextNode("" + Pcap.libVersion()));
            root.appendChild(libVersion);

            // add IPv6 readiness result
            try {
                xmlSuccess &= ipv6Result.parseXmlResults(doc, root);
            } catch (Exception e) {
                log.error("Error parsing IPv6 readiness result", e);
                xmlSuccess = false;
            }

            // add network discovery results
            try {
                xmlSuccess &= netDiscovery.parseXmlResults(doc, root);
            } catch (Exception e) {
                log.error("Error parsing network discovery results", e);
                xmlSuccess = false;
            }

            // write XML to file
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
            DOMSource source = new DOMSource(doc);
            StreamResult result = new StreamResult(new File(XML_FILE));
            transformer.transform(source, result);

        } catch (ParserConfigurationException pce) {
            log.error("Error creating XML configuration", pce);
            xmlSuccess = false;
        } catch (TransformerException te) {
            log.error("Error writing XML to file", te);
            xmlSuccess = false;
        }

        return xmlSuccess;
    }

    /**
     * Main method for launching v6App.
     * 
     * @param args
     * @throws RegistryHeaderErrors
     */
    public static void main(String[] args) throws RegistryHeaderErrors {
        log.info("Starting v6App...");
        Date start = new Date();
        boolean networkTest = false;
        boolean xmlSuccess = false;

        try {
            
            // start IPv6 readiness test
            Ipv6Ready ipv6Ready = new Ipv6Ready();
            Ipv6ReadyResult ipv6Result = ipv6Ready.testIpv6Readiness();

            // determine network discovery duration
            int durationSecs = V6AppProperties.getNetworkDiscoverySecs();

            // start network discovery
            NetworkDiscovery netDiscovery = new NetworkDiscovery();
            networkTest = netDiscovery.startNetworkDiscovery(durationSecs * 1000);

            // save XML results
            xmlSuccess = parseXmlResults(start, ipv6Result, netDiscovery);

        } catch (UnsatisfiedLinkError ule) {
            log.error("Error locating dependent libraries.  Is WinPcap (Windows) or libpcap (Linux) installed?");
        }

        log.info("Exiting v6App [{}].", (networkTest && xmlSuccess) ? "SUCCESS" : "ERROR");
    }
}
