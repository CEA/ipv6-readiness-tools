package com.ptr.v6app.jnetpcap.packet;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip6;

/**
 * JNetPcap header implementation for an ICMPv6 Router Advertisement packet.
 */
@Header(length = 12)
public class RouterAdvertisement extends JHeader {

    @Field(offset = 0, length = 8, format = "%d", description = "Cur Hop Limit")
    public int hopLimit() {
        return getUByte(0);
    }
    
    public void hopLimit(int hopLimit) {
        setUByte(0, hopLimit);
    }
    
    @Field(offset = 8, length = 8, format = "%d", description = "Flags")
    public int flags() {
        return getUByte(8);
    }
    
    public void flags(int flags) {
        setUByte(8, flags);
    }
    
    @Field(offset = 16, length = 16, format = "%d", description = "Router Lifetime")
    public int lifetime() {
        return getUShort(16);
    }
    
    public void lifetime(int lifetime) {
        setUShort(16, lifetime);
    }
    
    @Field(offset = 32, length = 32, format = "%l", description = "Reachable Time")
    public long reachable() {
        return getUInt(32);
    }
    
    public void reachable(long reachable) {
        setUInt(32, reachable);
    }
    
    @Field(offset = 64, length = 32, format = "%l", description = "Retrans Timer")
    public long retrans() {
        return getUInt(64);
    }
    
    public void retrans(long retrans) {
        setUInt(64, retrans);
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
        return icmp.type() == 134;
    }
}
