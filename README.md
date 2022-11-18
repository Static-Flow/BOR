# BOR - Break On Request
BOR is a Burp Suite extension that provides a custom context menu for marking requests to be stopped by the interceptor.

The Burp Suite Proxy Interceptor is a handy tool for catching important/interesting requests for tampering before they are sent to a target. 
When deciding what to intercept you have two options:

A) turn on the global intercept and continuely click "Forward" until you reach the request you want.


B) Setup intecept rules in the Proxy Options tab.

Both have downsides, in the case of option A, it can become very tedious with applications that send a lot of requests and your target request is not first, 
and option B requires hand crafting match rules to ensure you only intercept the request you want.


With BOR the only step required to mark a request for interception is a right click on the request and selecting the `Create Breakpoint For Request` context menu!

# UI Examples
