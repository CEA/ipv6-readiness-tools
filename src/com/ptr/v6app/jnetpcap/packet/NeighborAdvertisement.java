package com.ptr.v6app.jnetpcap.packet;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip6;

/**
 * JNetPcap header implementation for an ICMPv6 Neighbor Advertisement packet.
 */
@Header(length = 20)
public class NeighborAdvertisement extends JHeader {

    @Field(offset = 0, length = 1, format = "%d", description = "R Flag")
    public int rFlag() {
        return (getUByte(0) & 0x80) >> 7;
    }

    @Field(offset = 1, length = 1, format = "%d", description = "S Flag")
    public int sFlag() {
        return (getUByte(0) & 0x40) >> 6;
    }

    @Field(offset = 2, length = 1, format = "%d", description = "O Flag")
    public int oFlag() {
        return (getUByte(0) & 0x20) >> 5;
    }

    @Field(offset = 0, length = 32, format = "%d", description = "Flags")
    public long flags() {
        return getUInt(0);
    }
    
    public void flags(long flags) {
        setUInt(0, flags);
    }

    @Field(offset = 32, length = 128, format = "%d", description = "Target Address")
    public byte[] targetAddress() {
        return getByteArray(4, 16);
    }
    
    public void targetAddress(byte[] targetAddress) {
        setByteArray(4, targetAddress);
    }

    @Bind(to = Ethernet.class)
    public static boolean bindToEthernet(JPacket packet, Ethernet eth) {
        return eth.type() == 0x86dd;
    }

    @Bind(to = Ip6.class)
    public static boolean bindToIp6(JPacket packet, Ip6 ip) {
        return ip.next() == 58;
    }

    @Bind(to = Icmp6.class)
    public static boolean bindToIcmp6(JPacket packet, Icmp6 icmp) {
        return icmp.type() == 136;
    }
}
