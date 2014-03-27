package com.ptr.v6app.jnetpcap.packet;

import java.nio.ByteBuffer;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip6;

import com.ptr.v6app.util.NetUtils;
import com.ptr.v6app.util.Unsigned;

/**
 * JNetPcap header implementation for an ICMPv6 packet.
 */
@Header(length = 4)
public class Icmp6 extends JHeader {

    // -- Logger
    private static final Logger log = LogManager.getLogger(Icmp6.class.getName());

    @Field(offset = 0, length = 8, format = "%d", description = "ICMPv6 Type")
    public int type() {
        return super.getUByte(0);
    }

    public void type(int type) {
        setUByte(0, type);
    }

    @Field(offset = 8, length = 8, format = "%d", description = "ICMPv6 Code")
    public int code() {
        return super.getUByte(1);
    }

    public void code(int code) {
        setUByte(1, code);
    }

    @Field(offset = 16, length = 16, format = "%d", description = "ICMPv6 Checksum")
    public int checksum() {
        return super.getUShort(2);
    }

    public void checksum(int checksum) {
        setUShort(2, checksum);
    }

    public int calculateChecksum() {
        // start by zeroing out current checksum
        checksum(0);

        // get Ip6 header
        Ip6 ip6 = new Ip6();
        if (!getPacket().hasHeader(ip6)) {
            log.error("Error calculating ICMPv6 checksum, can't find IPv6 header");
            return -1;
        }

        // build our buffer for checksum calculation
        ByteBuffer buf = ByteBuffer.allocate(16 + 16 + 4 + 4 + ip6.getPayloadLength());
        buf.put(ip6.source());
        buf.put(ip6.destination());
        Unsigned.putUnsignedInt(buf, (long) ip6.getPayloadLength());
        Unsigned.putUnsignedInt(buf, (long) ip6.next());
        buf.put(ip6.getPayload());

        // calculate checksum
        int checksum = (int) NetUtils.calculateChecksum(buf.array());

        // update checksum
        checksum(checksum);
        return checksum;
    }

    @Bind(to = Ip6.class)
    public static boolean bindToIp6(JPacket packet, Ip6 ip) {
        return ip.next() == 58;
    }

    @Bind(to = Ethernet.class)
    public static boolean bindToEthernet(JPacket packet, Ethernet eth) {
        return eth.type() == 0x86dd;
    }
}
