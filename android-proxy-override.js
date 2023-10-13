/**
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
 */

setTimeout(() => {
    Java.perform(() => {
        // Set default JVM system properties for the proxy address:
        Java.use('java.lang.System').setProperty('http.proxyHost', PROXY_HOST);
        Java.use('java.lang.System').setProperty('http.proxyPort', PROXY_PORT.toString());
        Java.use('java.lang.System').setProperty('https.proxyHost', PROXY_HOST);
        Java.use('java.lang.System').setProperty('https.proxyPort', PROXY_PORT.toString());

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
});