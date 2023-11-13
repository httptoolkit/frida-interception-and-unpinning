/**************************************************************************************************
 *
 * This script defines a large set of targeted certificate unpinning hooks: matching specific
 * methods in certain classes, and transforming their behaviour to ensure that restrictions to
 * TLS trust are disabled.
 *
 * This does not disable TLS protections completely - each hook is designed to disable only
 * *additional* restrictions, and to explicitly trust the certificate provided as CERT_PEM in the
 * config.js configuration file, preserving normal TLS protections wherever possible, even while
 * allowing for controlled MitM of local traffic.
 *
 * The file consists of a few general-purpose methods, then a data structure declaratively
 * defining the classes & methods to match, and how to transform them, and then logic at the end
 * which uses this data structure, applying the transformation for each found match to the
 * target process.
 *
 * For more details on what was matched, and log output when each hooked method is actually used,
 * enable DEBUG_MODE in config.js, and watch the Frida output after running this script.
 *
 * Source available at https://github.com/httptoolkit/frida-interception-and-unpinning/
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Tim Perry <tim@httptoolkit.com>
 *
 *************************************************************************************************/

function buildX509CertificateFromBytes(certBytes) {
    const ByteArrayInputStream = Java.use('java.io.ByteArrayInputStream');
    const CertFactory = Java.use('java.security.cert.CertificateFactory');
    const certFactory = CertFactory.getInstance("X.509");
    return certFactory.generateCertificate(ByteArrayInputStream.$new(certBytes));
}

function getCustomTrustManagerFactory() {
    // This is the one X509Certificate that we want to trust. No need to trust others (we should capture
    // _all_ TLS traffic) and risky to trust _everything_ (risks interception between device & proxy, or
    // worse: some traffic being unintercepted & sent as HTTPS with TLS effectively disabled over the
    // real web - potentially exposing auth keys, private data and all sorts).
    const certBytes = Java.use("java.lang.String").$new(CERT_PEM).getBytes();
    const trustedCACert = buildX509CertificateFromBytes(certBytes);

    // Build a custom TrustManagerFactory with a KeyStore that trusts only this certificate:

    const KeyStore = Java.use("java.security.KeyStore");
    const keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null);
    keyStore.setCertificateEntry("ca", trustedCACert);

    const TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
    const customTrustManagerFactory = TrustManagerFactory.getInstance(
        TrustManagerFactory.getDefaultAlgorithm()
    );
    customTrustManagerFactory.init(keyStore);

    return customTrustManagerFactory;
}

function getCustomX509TrustManager() {
    const customTrustManagerFactory = getCustomTrustManagerFactory();
    const trustManagers = customTrustManagerFactory.getTrustManagers();

    const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');

    const x509TrustManager = trustManagers.find((trustManager) => {
        return trustManager.class.isAssignableFrom(X509TrustManager.class);
    });

    // We have to cast it explicitly before Frida will allow us to use the X509 methods:
    return Java.cast(x509TrustManager, X509TrustManager);
}

// Some standard hook replacements for various cases:
const NO_OP = () => {};
const RETURN_TRUE = () => true;
const CHECK_OUR_TRUST_MANAGER_ONLY = () => {
    const trustManager = getCustomX509TrustManager();
    return (certs, authType) => {
        trustManager.checkServerTrusted(certs, authType);
    };
};

const PINNING_FIXES = {
    // --- Native HttpsURLConnection

    'javax.net.ssl.HttpsURLConnection': [
        {
            methodName: 'setDefaultHostnameVerifier',
            replacement: () => NO_OP
        },
        {
            methodName: 'setSSLSocketFactory',
            replacement: () => NO_OP
        },
        {
            methodName: 'setHostnameVerifier',
            replacement: () => NO_OP
        },
    ],

    // --- Native SSLContext

    'javax.net.ssl.SSLContext': [
        {
            methodName: 'init',
            overload: ['[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'],
            replacement: (targetMethod) => {
                const customTrustManagerFactory = getCustomTrustManagerFactory();

                // When constructor is called, replace the trust managers argument:
                return function (keyManager, _providedTrustManagers, secureRandom) {
                    return targetMethod.call(this,
                        keyManager,
                        customTrustManagerFactory.getTrustManagers(), // Override their trust managers
                        secureRandom
                    );
                }
            }
        }
    ],

    // --- Native Conscrypt CertPinManager

    'com.android.org.conscrypt.CertPinManager': [
        {
            methodName: 'isChainValid',
            replacement: () => RETURN_TRUE
        },
        {
            methodName: 'checkChainPinning',
            replacement: () => NO_OP
        }
    ],

    // --- Native pinning configuration loading (used for configuration by many libraries)

    'android.security.net.config.NetworkSecurityConfig': [
        {
            methodName: '$init',
            overload: '*',
            replacement: (targetMethod) => {
                const PinSet = Java.use('android.security.net.config.PinSet');
                const EMPTY_PINSET = PinSet.EMPTY_PINSET.value;
                return function () {
                    // Always ignore the 2nd 'pins' PinSet argument entirely:
                    arguments[2] = EMPTY_PINSET;
                    targetMethod.call(this, ...arguments);
                }
            }
        }
    ],

    // --- Native HostnameVerification override (n.b. Android contains its own vendored OkHttp v2!)

    'com.android.okhttp.internal.tls.OkHostnameVerifier': [
        {
            methodName: 'verify',
            overload: [
                'java.lang.String',
                'javax.net.ssl.SSLSession'
            ],
            replacement: (targetMethod) => {
                // Our trust manager - this trusts *only* our extra CA
                const trustManager = getCustomX509TrustManager();

                return function (hostname, sslSession) {
                    try {
                        const certs = sslSession.getPeerCertificates();

                        // https://stackoverflow.com/a/70469741/68051
                        const authType = "RSA";

                        // This throws if the certificate isn't trusted (i.e. if it's
                        // not signed by our extra CA specifically):
                        trustManager.checkServerTrusted(certs, authType);

                        // If the cert is from our CA, great! Skip hostname checks entirely.
                        return true;
                    } catch (e) {} // Ignore errors and fallback to default behaviour

                    // We fallback to ensure that connections with other CAs (e.g. direct
                    // connections allowed past the proxy) validate as normal.
                    return targetMethod.call(this, ...arguments);
                }
            }
        }
    ],

    'com.android.okhttp.Address': [
        {
            methodName: '$init',
            overload: [
                'java.lang.String',
                'int',
                'com.android.okhttp.Dns',
                'javax.net.SocketFactory',
                'javax.net.ssl.SSLSocketFactory',
                'javax.net.ssl.HostnameVerifier',
                'com.android.okhttp.CertificatePinner',
                'com.android.okhttp.Authenticator',
                'java.net.Proxy',
                'java.util.List',
                'java.util.List',
                'java.net.ProxySelector'
            ],
            replacement: (targetMethod) => {
                const defaultHostnameVerifier = Java.use("com.android.okhttp.internal.tls.OkHostnameVerifier")
                    .INSTANCE.value;
                const defaultCertPinner = Java.use("com.android.okhttp.CertificatePinner")
                    .DEFAULT.value;

                return function () {
                    // Override arguments, to swap any custom check params (widely used
                    // to add stricter rules to TLS verification) with the defaults instead:
                    arguments[5] = defaultHostnameVerifier;
                    arguments[6] = defaultCertPinner;

                    targetMethod.call(this, ...arguments);
                }
            }
        },
        // Almost identical patch, but for Nougat and older. In these versions, the DNS argument
        // isn't passed here, so the arguments to patch changes slightly:
        {
            methodName: '$init',
            overload: [
                'java.lang.String',
                'int',
                // No DNS param
                'javax.net.SocketFactory',
                'javax.net.ssl.SSLSocketFactory',
                'javax.net.ssl.HostnameVerifier',
                'com.android.okhttp.CertificatePinner',
                'com.android.okhttp.Authenticator',
                'java.net.Proxy',
                'java.util.List',
                'java.util.List',
                'java.net.ProxySelector'
            ],
            replacement: (targetMethod) => {
                const defaultHostnameVerifier = Java.use("com.android.okhttp.internal.tls.OkHostnameVerifier")
                    .INSTANCE.value;
                const defaultCertPinner = Java.use("com.android.okhttp.CertificatePinner")
                    .DEFAULT.value;

                return function () {
                    // Override arguments, to swap any custom check params (widely used
                    // to add stricter rules to TLS verification) with the defaults instead:
                    arguments[4] = defaultHostnameVerifier;
                    arguments[5] = defaultCertPinner;

                    targetMethod.call(this, ...arguments);
                }
            }
        }
    ],

    // --- OkHttp v3

    'okhttp3.CertificatePinner': [
        {
            methodName: 'check',
            overload: ['java.lang.String', 'java.util.List'],
            replacement: () => NO_OP
        },
        {
            methodName: 'check',
            overload: ['java.lang.String', 'java.security.cert.Certificate'],
            replacement: () => NO_OP
        },
        {
            methodName: 'check',
            overload: ['java.lang.String', '[Ljava.security.cert.Certificate;'],
            replacement: () => NO_OP
        },
        {
            methodName: 'check$okhttp',
            replacement: () => NO_OP
        },
    ],

    // --- SquareUp OkHttp (< v3)

    'com.squareup.okhttp.CertificatePinner': [
        {
            methodName: 'check',
            overload: ['java.lang.String', 'java.security.cert.Certificate'],
            replacement: () => NO_OP
        },
        {
            methodName: 'check',
            overload: ['java.lang.String', 'java.util.List'],
            replacement: () => NO_OP
        }
    ],

    // --- Trustkit (https://github.com/datatheorem/TrustKit-Android/)

    'com.datatheorem.android.trustkit.pinning.PinningTrustManager': [
        {
            methodName: 'checkServerTrusted',
            replacement: CHECK_OUR_TRUST_MANAGER_ONLY
        }
    ],

    // --- Appcelerator (https://github.com/tidev/appcelerator.https)

    'appcelerator.https.PinningTrustManager': [
        {
            methodName: 'checkServerTrusted',
            replacement: CHECK_OUR_TRUST_MANAGER_ONLY
        }
    ],

    // --- PhoneGap sslCertificateChecker (https://github.com/EddyVerbruggen/SSLCertificateChecker-PhoneGap-Plugin)

    'nl.xservices.plugins.sslCertificateChecker': [
        {
            methodName: 'execute',
            overload: ['java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext'],
            replacement: () => (_action, _args, context) => {
                context.success("CONNECTION_SECURE");
                return true;
            }
            // This trusts _all_ certs, but that's fine - this is used for checks of independent test
            // connections, rather than being a primary mechanism to secure the app's TLS connections.
        }
    ],

    // --- IBM WorkLight

    'com.worklight.wlclient.api.WLClient': [
        {
            methodName: 'pinTrustedCertificatePublicKey',
            getMethod: (WLClientCls) => WLClientCls.getInstance().pinTrustedCertificatePublicKey,
            overload: '*'
        }
    ],

    'com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning': [
        {
            methodName: 'verify',
            overload: '*',
            replacement: () => NO_OP
        }
        // This covers at least 4 commonly used WorkLight patches. Oddly, most sets of hooks seem
        // to return true for 1/4 cases, which must be wrong (overloads must all have the same
        // return type) but also it's very hard to find any modern (since 2017) references to this
        // class anywhere including WorkLight docs, so it may no longer be relevant anyway.
    ],

    'com.worklight.androidgap.plugin.WLCertificatePinningPlugin': [
        {
            methodName: 'execute',
            overload: '*',
            replacement: () => RETURN_TRUE
        }
    ],

    // --- CWAC-Netsecurity (unofficial back-port pinner for Android<4.2) CertPinManager

    'com.commonsware.cwac.netsecurity.conscrypt.CertPinManager': [
        {
            methodName: 'isChainValid',
            overload: '*',
            replacement: () => RETURN_TRUE
        }
    ],

    // --- Netty

    'io.netty.handler.ssl.util.FingerprintTrustManagerFactory': [
        {
            methodName: 'checkTrusted',
            replacement: () => NO_OP
        }
    ],

    // --- Cordova / PhoneGap Advanced HTTP Plugin (https://github.com/silkimen/cordova-plugin-advanced-http)

    // Modern version:
    'com.silkimen.cordovahttp.CordovaServerTrust': [
        {
            methodName: '$init',
            replacement: (targetMethod) => function () {
                // Ignore any attempts to set trust to 'pinned'. Default settings will trust
                // our cert because of the separate system-certificate injection step.
                if (arguments[0] === 'pinned') {
                    arguments[0] = 'default';
                }

                return targetMethod.call(this, ...arguments);
            }
        }
    ],

    // --- Appmattus Cert Transparency (https://github.com/appmattus/certificatetransparency/)

    'com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyHostnameVerifier': [
        {
            methodName: 'verify',
            replacement: () => RETURN_TRUE
            // This is not called unless the cert passes basic trust checks, so it's safe to blindly accept.
        }
    ],

    'com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor': [
        {
            methodName: 'intercept',
            replacement: () => (a) => a.proceed(a.request())
            // This is not called unless the cert passes basic trust checks, so it's safe to blindly accept.
        }
    ],

    'com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyTrustManager': [
        {
            methodName: 'checkServerTrusted',
            overload: ['[Ljava.security.cert.X509Certificate;', 'java.lang.String'],
            replacement: CHECK_OUR_TRUST_MANAGER_ONLY,
            methodName: 'checkServerTrusted',
            overload: ['[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String'],
            replacement: () => {
                const trustManager = getCustomX509TrustManager();
                return (certs, authType, _hostname) => {
                    // We ignore the hostname - if the certs are good (i.e they're ours), then the
                    // whole chain is good to go.
                    trustManager.checkServerTrusted(certs, authType);
                    return Java.use('java.util.Arrays').asList(certs);
                };
            }
        }
    ]

};

const getJavaClassIfExists = (clsName) => {
    try {
        return Java.use(clsName);
    } catch {
        return undefined;
    }
}

Java.perform(function () {
    if (DEBUG_MODE) console.log('\n    === Disabling all recognized unpinning libraries ===');

    const classesToPatch = Object.keys(PINNING_FIXES);

    classesToPatch.forEach((targetClassName) => {
        const TargetClass = getJavaClassIfExists(targetClassName);
        if (!TargetClass) {
            // We skip patches for any classes that don't seem to be present. This is common
            // as not all libraries we handle are necessarily used.
            if (DEBUG_MODE) console.log(`[ ] ${targetClassName} *`);
            return;
        }

        const patches = PINNING_FIXES[targetClassName];

        let patchApplied = false;

        patches.forEach(({ methodName, getMethod, overload, replacement }) => {
            const namedTargetMethod = getMethod
                ? getMethod(TargetClass)
                : TargetClass[methodName];

            const methodDescription = `${methodName}${
                overload === '*'
                    ? '(*)'
                : overload
                    ? '(' + overload.map((argType) => {
                        // Simplify arg names to just the class name for simpler logs:
                        const argClassName = argType.split('.').slice(-1)[0];
                        if (argType.startsWith('[L')) return `${argClassName}[]`;
                        else return argClassName;
                    }).join(', ') + ')'
                // No overload:
                    : ''
            }`

            let targetMethodImplementations = [];
            try {
                if (namedTargetMethod) {
                    if (!overload) {
                            // No overload specified
                        targetMethodImplementations = [namedTargetMethod];
                    } else if (overload === '*') {
                        // Targetting _all_ overloads
                        targetMethodImplementations = namedTargetMethod.overloads;
                    } else {
                        // Or targetting a specific overload:
                        targetMethodImplementations = [namedTargetMethod.overload(...overload)];
                    }
                }
            } catch (e) {
                // Overload not present
            }


            // We skip patches for any methods that don't seem to be present. This is rarer, but does
            // happen due to methods that only appear in certain library versions or whose signatures
            // have changed over time.
            if (targetMethodImplementations.length === 0) {
                if (DEBUG_MODE) console.log(`[ ] ${targetClassName} ${methodDescription}`);
                return;
            }

            targetMethodImplementations.forEach((targetMethod, i) => {
                const patchName = `${targetClassName} ${methodDescription}${
                    targetMethodImplementations.length > 1 ? ` (${i})` : ''
                }`;

                try {
                    const newImplementation = replacement(targetMethod);
                    if (DEBUG_MODE) {
                        // Log each hooked method as it's called:
                        targetMethod.implementation = function () {
                            console.log(` => ${patchName}`);
                            return newImplementation.apply(this, arguments);
                        }
                    } else {
                        targetMethod.implementation = newImplementation;
                    }

                    if (DEBUG_MODE) console.log(`[+] ${patchName}`);
                    patchApplied = true;
                } catch (e) {
                    // In theory, errors like this should never happen - it means the patch is broken
                    // (e.g. some dynamic patch building fails completely)
                    console.error(`[!] ERROR: ${patchName} failed: ${e}`);
                }
            })
        });

        if (!patchApplied) {
            console.warn(`[!] Matched class ${targetClassName} but could not patch any methods`);
        }
    });

    console.log('== Certificate unpinning completed ==');
});