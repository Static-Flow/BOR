package com.staticflow;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;
import burp.ITab;

import java.awt.*;


/**
 * This extension provides a custom context menu for adding interception "breakpoints" for URLs.
 * The context menus work on any request viewer, i.e. Repeater/Proxy/SiteMap. Current breakpoints
 * are listed in the custom UI tab `BOR`.
 */
public class BreakOnRequestExtension implements IBurpExtender, IExtensionStateListener, ITab {

    /*
        Register all the custom handlers with Burp
     */
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        ExtensionState.getInstance().setCallbacks(iBurpExtenderCallbacks);
        iBurpExtenderCallbacks.registerProxyListener(ExtensionState.getInstance().getProxyListener());
        iBurpExtenderCallbacks.registerContextMenuFactory(ExtensionState.getInstance().getContextMenu());
        iBurpExtenderCallbacks.addSuiteTab(this);
        iBurpExtenderCallbacks.setExtensionName("BOR - Break On Request");
    }

    /*
        Always clean up after yourself
     */
    @Override
    public void extensionUnloaded() {
        ExtensionState.getInstance().getCallbacks().removeProxyListener(ExtensionState.getInstance().getProxyListener());
        ExtensionState.getInstance().getCallbacks().removeContextMenuFactory(ExtensionState.getInstance().getContextMenu());
    }

    @Override
    public String getTabCaption() {
        return "BOR";
    }

    @Override
    public Component getUiComponent() {
        return ExtensionState.getInstance().getBorExtensionUI();
    }
}
