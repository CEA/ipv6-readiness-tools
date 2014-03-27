package com.ptr.v6app.plugin;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jnetpcap.PcapIf;

public class PluginManager {

    // -- Logger
    private static final Logger log = LogManager.getLogger(PluginManager.class.getName());

    // -- Singleton instance
    private static PluginManager instance;

    // -- Listener plugins
    private List<ListenerPlugin> listenerPlugins = new ArrayList<ListenerPlugin>();

    // -- Injector plugins
    private List<InjectorPlugin> injectorPlugins = new ArrayList<InjectorPlugin>();

    // -- Plugin classes
    private String[] pluginClasses = { 
            "com.ptr.v6app.plugin.impl.Icmp4Plugin",
            "com.ptr.v6app.plugin.impl.Icmp6Plugin", 
            "com.ptr.v6app.plugin.impl.NeighborDiscoveryPlugin",
            "com.ptr.v6app.plugin.impl.Ping6Plugin", 
            "com.ptr.v6app.plugin.impl.RouterDiscoveryPlugin",
            "com.ptr.v6app.plugin.impl.Udp4Plugin", 
            "com.ptr.v6app.plugin.impl.Udp6Plugin"
            };

    /* Do not instantiate */
    private PluginManager() {
    }

    public static PluginManager getInstance() {
        if (instance == null) {
            log.debug("Creating PluginManager singleton instance");
            instance = new PluginManager();
            instance.loadPlugins();
        }
        return instance;
    }

    public List<ListenerPlugin> getListenerPlugins() {
        return listenerPlugins;
    }

    public List<InjectorPlugin> getInjectorPlugins() {
        return injectorPlugins;
    }
    
    public void initializePlugins(PcapIf pcapIf) {
        if (pcapIf == null) {
            throw new NullPointerException("null PcapIf");
        }
        
        // get the full set of plugins
        Set<PcapPlugin> plugins = new HashSet<PcapPlugin>();
        plugins.addAll(injectorPlugins);
        plugins.addAll(listenerPlugins);
        
        // initialize each plugin
        for (PcapPlugin plugin : plugins) {
            try {
                plugin.initialize(pcapIf);
            } catch (Exception e) {
                log.error("Error initializing plugin [" + plugin.getName() + "]", e);
            }
        }
    }

    private void loadPlugins() {

        for (String pluginClass : pluginClasses) {
            try {
                PcapPlugin plugin = (PcapPlugin) Class.forName(pluginClass).newInstance();
                if (plugin instanceof ListenerPlugin) {
                    listenerPlugins.add((ListenerPlugin) plugin);
                }
                if (plugin instanceof InjectorPlugin) {
                    injectorPlugins.add((InjectorPlugin) plugin);
                }
                log.debug("Plugin loaded [{}]", plugin.getClass().getSimpleName());
            } catch (Exception e) {
                log.warn("Error loading plugin [" + pluginClass + "]", e);
            }
        }
    }
}
