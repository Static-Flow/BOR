package com.staticflow;

import burp.IBurpExtenderCallbacks;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

import javax.swing.*;

/**
 * Singleton class for holding the state of the Extension.
 */
public class ExtensionState {

    //The singleton
    private static ExtensionState state = null;
    //The Burp Suite Callback functions
    private IBurpExtenderCallbacks callbacks;
    // bit vector for the contexts in which this extension should show the custom menu
    private static int validContextMenuBitVector  =
            1<<  IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST |
            1<<  IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST;
    // custom proxy listener to catch requests that match any of the current breakpoints
    private BorProxyListener proxyListener;
    // custom context menu
    private BorContextMenu contextMenu;
    // list model that holds user generated breakpoints
    private DefaultListModel<String> breakpoints;
    // custom ui
    private BorExtensionUI borExtensionUI;

    /*
        Initialize Extension State
     */
    private ExtensionState() {
        breakpoints = new DefaultListModel<>();
        proxyListener = new BorProxyListener();
        contextMenu = new BorContextMenu();
        borExtensionUI = new BorExtensionUI();
        borExtensionUI.getBreakpointList().setModel(breakpoints);
    }

    static ExtensionState getInstance() {
        if (state == null)
            state = new ExtensionState();
        return state;
    }

    IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    void setCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    /*
        Little bit of bit vector magic here to save a bunch of if branches.
        The `validContextMenuBitVector` constant contains a vector of all valid
        context int's that this extension menu should be shown for.
        For example, if valid contexts were 0,3,and 5, then the vector is:
            1 << 0 | 1<< 3 | 1 << 5
        To check if a supplied context int is valid, simply check if the bit is set:
            validContextMenuBitVector & (1 << context)
        If it is set the result will be NON zero.
     */
    boolean shouldShowMenu(int context) {
        return (validContextMenuBitVector & (1 << context)) != 0;
    }

    BorProxyListener getProxyListener() {
        return proxyListener;
    }

    DefaultListModel<String> getBreakpoints() {
        return breakpoints;
    }

    BorContextMenu getContextMenu() {
        return contextMenu;
    }

    /*
        Convert `IHttpRequestResponse` to URL string. Combines the protocol, host, and URL path.
        Note: While it seems like it would work, `getCallbacks().getHelpers().analyzeRequest(requestResponse).getUrl()`
            does not actually return a URL that matches what you would see in the browser and so won't work as a breakpoint.
     */
    String convertToBreakpoint(IHttpRequestResponse requestResponse) {
        IRequestInfo info = callbacks.getHelpers().analyzeRequest(requestResponse);
        return String.format("%s://%s%s",requestResponse.getHttpService().getProtocol(),requestResponse.getHttpService().getHost(),info.getUrl().getPath());
    }

    public BorExtensionUI getBorExtensionUI() {
        return borExtensionUI;
    }
}
