/**************************************************************************************************
 *
 * The first step in intercepting HTTP & HTTPS traffic is to set the default proxy settings,
 * telling the app that all requests should be sent via our HTTP proxy.
 *
 * In this script, we set that up via a few different mechanisms, which cumulatively should
 * ensure that all connections are sent via the proxy, even if they attempt to use their
 * own custom proxy configurations to avoid this.
 *
 * Despite that, this still only covers well behaved apps - it's still possible for apps
 * to send network traffic directly if they're determined to do so, or if they're built
 * with a framework that does not do this by default (Flutter is notably in this category).
 * To handle those less tidy cases, we manually capture traffic to recognized target ports
 * in the native connect() hook script.
 *
 * Source available at https://github.com/httptoolkit/frida-interception-and-unpinning/
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Tim Perry <tim@httptoolkit.com>
 *
 *************************************************************************************************/

Java.perform(() => {
    // Set default JVM system properties for the proxy address. Notably these are used
    // to initialize WebView configuration.
    Java.use('java.lang.System').setProperty('http.proxyHost', PROXY_HOST);
    Java.use('java.lang.System').setProperty('http.proxyPort', PROXY_PORT.toString());
    Java.use('java.lang.System').setProperty('https.proxyHost', PROXY_HOST);
    Java.use('java.lang.System').setProperty('https.proxyPort', PROXY_PORT.toString());

    Java.use('java.lang.System').clearProperty('http.nonProxyHosts');
    Java.use('java.lang.System').clearProperty('https.nonProxyHosts');

    // Some Android internals attempt to reset these settings to match the device configuration.
    // We block that directly here:
    const controlledSystemProperties = [
        'http.proxyHost',
        'http.proxyPort',
        'https.proxyHost',
        'https.proxyPort',
        'http.nonProxyHosts',
        'https.nonProxyHosts'
    ];
    Java.use('java.lang.System').clearProperty.implementation = function (property) {
        if (controlledSystemProperties.includes(property)) {
            if (DEBUG_MODE) console.log(`Ignoring attempt to clear ${property} system property`);
            return this.getProperty(property);
        }
        return this.clearProperty(...arguments);
    }
    Java.use('java.lang.System').setProperty.implementation = function (property) {
        if (controlledSystemProperties.includes(property)) {
            if (DEBUG_MODE) console.log(`Ignoring attempt to override ${property} system property`);
            return this.getProperty(property);
        }
        return this.setProperty(...arguments);
    }

    // Configure the app's proxy directly, via the app connectivity manager service:
    const ConnectivityManager = Java.use('android.net.ConnectivityManager');
    const ProxyInfo = Java.use('android.net.ProxyInfo');
    ConnectivityManager.getDefaultProxy.implementation = () => ProxyInfo.$new(PROXY_HOST, PROXY_PORT, '');
    // (Not clear if this works 100% - implying there are ConnectivityManager subclasses handling this)

    console.log(`== Proxy system configuration overridden to ${PROXY_HOST}:${PROXY_PORT} ==`);

    // Configure the proxy indirectly, by overriding the return value for all ProxySelectors everywhere:
    const Collections = Java.use('java.util.Collections');
    const ProxyType = Java.use('java.net.Proxy$Type');
    const InetSocketAddress = Java.use('java.net.InetSocketAddress');
    const ProxyCls = Java.use('java.net.Proxy'); // 'Proxy' is reserved in JS

    const targetProxy = ProxyCls.$new(
        ProxyType.HTTP.value,
        InetSocketAddress.$new(PROXY_HOST, PROXY_PORT)
    );
    const getTargetProxyList = () => Collections.singletonList(targetProxy);

    const ProxySelector = Java.use('java.net.ProxySelector');

    // Find every implementation of ProxySelector by quickly scanning method signatures, and
    // then checking whether each match actually implements java.net.ProxySelector:
    const proxySelectorClasses = Java.enumerateMethods('*!select(java.net.URI): java.util.List/s')
        .flatMap((matchingLoader) => matchingLoader.classes
            .map((classData) => Java.use(classData.name))
            .filter((Cls) => ProxySelector.class.isAssignableFrom(Cls.class))
        );

    // Replace the 'select' of every implementation, so they all send traffic to us:
    proxySelectorClasses.forEach(ProxySelectorCls => {
        if (DEBUG_MODE) {
            console.log('Rewriting', ProxySelectorCls.toString());
        }
        ProxySelectorCls.select.implementation = () => getTargetProxyList()
    });

    console.log(`== Proxy configuration overridden to ${PROXY_HOST}:${PROXY_PORT} ==`);
});

