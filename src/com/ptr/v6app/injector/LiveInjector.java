package com.ptr.v6app.injector;

import org.jnetpcap.packet.JPacket;

public interface LiveInjector {

    public void addInjectionPacket(JPacket packet);
}
