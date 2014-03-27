package com.ptr.v6app.plugin;

import org.jnetpcap.PcapIf;

/**
 * The PcapPlugin interface is the base interface for all injector/listener plugins.
 */
public interface PcapPlugin {

    /**
     * Returns the display name of the plugin.
     * 
     * @return Human-readable name String of the plugin.
     */
    public String getName();

    /**
     * Initializes a plugin.
     * 
     * @param pcapIf
     *            The PcapIf device that will be used by the plugin for listening/injecting.
     */
    public void initialize(PcapIf pcapIf);
}
