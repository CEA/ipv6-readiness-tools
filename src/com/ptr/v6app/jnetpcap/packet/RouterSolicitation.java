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
@Header(length = 4)
public class RouterSolicitation extends JHeader {

    @Field(offset = 0, length = 32, format = "%d", description = "Reserved")
    public long reserved() {
        return getUInt(0);
    }
    
    public void reserved(int reserved) {
        setUInt(0, reserved);
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
        return icmp.type() == 133;
    }
}
