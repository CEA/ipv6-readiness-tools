package com.ptr.v6app.node.data;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.ptr.v6app.node.NodeData;

public class Router4Info implements NodeData {
    
    public static final String ID = Router4Info.class.getSimpleName();

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public void parseXmlData(Document doc, Element root) {
        
        // just note that this node is an IPv4 router for now
        Element router = doc.createElement("ipv4Router");
        root.appendChild(router);
    }
}
