package com.ptr.v6app.node;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

public interface NodeData {

    public String getId();
    
    public void parseXmlData(Document doc, Element root); 
}
