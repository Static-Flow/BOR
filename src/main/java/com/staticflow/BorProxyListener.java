package com.staticflow;

import burp.IInterceptedProxyMessage;
import burp.IProxyListener;

/**
 * Custom proxy listener that sends every outgoing request that matches a breakpoint to the Interceptor for modification
 */
public class BorProxyListener implements IProxyListener {
    @Override
    public void processProxyMessage(boolean isRequest, IInterceptedProxyMessage iInterceptedProxyMessage) {
        //if proxy message is request
        if (isRequest) {
            //and the current list of breakpoints contains the request url
            if (ExtensionState.getInstance().getBreakpoints().contains(
                    ExtensionState.getInstance().convertToBreakpoint(iInterceptedProxyMessage.getMessageInfo())
            )) {
                //mark it for interception
                iInterceptedProxyMessage.setInterceptAction(IInterceptedProxyMessage.ACTION_DO_INTERCEPT);
            }
        }
    }
}
