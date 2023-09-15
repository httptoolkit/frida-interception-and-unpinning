// Default emulator address for now:
const PROXY_HOST = '192.168.104.248';
const PROXY_PORT = 8000;

setTimeout(() => {
    Java.perform(() => {
        Java.use('java.lang.System').setProperty('http.proxyHost', PROXY_HOST);
        Java.use('java.lang.System').setProperty('http.proxyPort', PROXY_PORT.toString());
        Java.use('java.lang.System').setProperty('https.proxyHost', PROXY_HOST);
        Java.use('java.lang.System').setProperty('https.proxyPort', PROXY_PORT.toString());

        const Collections = Java.use('java.util.Collections');
        const ArrayList = Java.use('java.util.ArrayList');
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
            console.log('Rewriting', ProxySelectorCls.toString());
            ProxySelectorCls.select.implementation = () => getTargetProxyList()
        });

        console.log(
            `Rewrote ${proxySelectorClasses.length} proxy selector classes ` +
            `to send traffic to ${PROXY_HOST}:${PROXY_PORT}`
        );
    });
});