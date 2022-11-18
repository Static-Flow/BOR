package com.staticflow;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;

import javax.swing.*;
import java.util.Collections;
import java.util.List;


/**
 * Custom context menu where one click breakpoints are made. When clicked it generates the URL for the request and adds
 * it as a new interception breakpoint.
 */
public class BorContextMenu implements IContextMenuFactory {

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation iContextMenuInvocation) {
        //check if this extension should display the custom context menu
        if (ExtensionState.getInstance().shouldShowMenu(iContextMenuInvocation.getInvocationContext())) {
            //make the new menu
            JMenuItem menu = new JMenuItem("Create Breakpoint For Request");
            menu.addActionListener(e -> {
                //for every message selected
                for(IHttpRequestResponse message : iContextMenuInvocation.getSelectedMessages()) {
                    //convert IHttpRequestResponse to URL string
                    String potentialBreakpoint = ExtensionState.getInstance().convertToBreakpoint(message);
                    //if this url is not already a breakpoint
                    if( !ExtensionState.getInstance().getBreakpoints().contains(potentialBreakpoint) )
                        //add it to the list of breakpoints
                        ExtensionState.getInstance().getBreakpoints().addElement(potentialBreakpoint);
                    else
                        //else alert user they tried to to add a breakpoint twice
                        JOptionPane.showMessageDialog(ExtensionState.getInstance().getBorExtensionUI(),
                                "Breakpoint for URL: "+potentialBreakpoint+ " already exists.");
                }
            });
            return Collections.singletonList(menu);
        }
        return null;
    }
}
