/**
 * In some cases, proxy configuration by itself won't work. This notably includes Flutter apps (which ignore
 * system/JVM configuration entirely) and plausibly other apps intentionally ignoring proxies. To handle that
 * we hook low-level connection attempts within Network Framework directly, to redirect traffic on all ports
 * to the target.
 *
 * This handles all attempts to connect an outgoing socket, and for all TCP connections opened it will
 * manually replace the nw_connection_create() endpoint parameter so that the socket connects to the proxy
 * instead of the 'real' destination.
 *
 * This doesn't help with certificate trust (you still need some kind of certificate setup) but it does ensure
 * the proxy receives all connections (and so will see if connections don't trust its CA). It's still useful
 * to do proxy config alongside this, as applications may behave a little more 'correctly' if they're aware
 * they're using a proxy rather than doing so unknowingly.
 *
 * Source available at https://github.com/httptoolkit/frida-interception-and-unpinning/
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Tim Perry <tim@httptoolkit.com>
 */

// This is the method we're going to patch:
// https://developer.apple.com/documentation/network/2976677-nw_connection_create (iOS 12+)
const nw_connection_create = Module.findExportByName('libnetwork.dylib', 'nw_connection_create');

// This is the method to make a new endpoint to connect to:
// https://developer.apple.com/documentation/network/2976720-nw_endpoint_create_host (iOS 12+)
const nw_endpoint_create_host = new NativeFunction(
    Module.findExportByName('libnetwork.dylib', 'nw_endpoint_create_host'),
    'pointer', ['pointer', 'pointer']
);

const newHostStr = Memory.allocUtf8String(PROXY_HOST);
const newPortStr = Memory.allocUtf8String(PROXY_PORT.toString());

Interceptor.attach(nw_connection_create, {
    onEnter: function (args) {
        // Replace the endpoint argument entirely with our own:
        args[0] = nw_endpoint_create_host(newHostStr, newPortStr);
    }
});