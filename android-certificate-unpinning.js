const NO_OP = () => {};
const RETURN_TRUE = () => true;

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
                // Parse the certificate from our CERT_PEM config:
                const String = Java.use("java.lang.String");
                const ByteArrayInputStream = Java.use('java.io.ByteArrayInputStream');
                const CertFactory = Java.use('java.security.cert.CertificateFactory');

                const certFactory = CertFactory.getInstance("X.509");
                const certBytes = String.$new(CERT_PEM).getBytes();

                // This is the one X509Certificate that we want to trust. No need to trust others (we should capture
                // _all_ TLS traffic) and risky to trust _everything_ (risks interception between device & proxy, or
                // worse: some traffic being unintercepted & sent as HTTPS with TLS effectively disabled over the
                // real web - potentially exposing auth keys, private data and all sorts).
                const trustedCACert = certFactory.generateCertificate(ByteArrayInputStream.$new(certBytes));

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

    // --- Native TrustManagerImpl

    'com.android.org.conscrypt.TrustManagerImpl': [
        {
            methodName: 'checkTrustedRecursive',
            replacement: () => () => Java.use('java.util.ArrayList').$new()
        },
        {
            methodName: 'verifyChain',
            replacement: () => (untrustedChain) => untrustedChain
        }
    ],

    // --- Native Conscrypt OpenSSLSocketImpl

    'com.android.org.conscrypt.OpenSSLSocketImpl': [
        {
            methodName: 'verifyCertificateChain',
            replacement: () => NO_OP
        }
    ],

    'com.android.org.conscrypt.OpenSSLEngineSocketImpl': [
        {
            methodName: 'verifyCertificateChain',
            overload: ['[Ljava.lang.Long;', 'java.lang.String'],
            replacement: () => NO_OP
        }
    ],

    // --- Native Conscrypt CertPinManager

    'com.android.org.conscrypt.CertPinManager': [
        {
            methodName: 'isChainValid',
            overload: ['java.lang.String', 'java.util.List'],
            replacement: () => RETURN_TRUE
        }
    ],

    // --- Native pinning configuration loading (used for configuration by many libraries)

    'android.security.net.config.NetworkSecurityConfig': [
        {
            methodName: '$init',
            overloads: '*',
            replacement: () => {
                const PinSet = Java.use('android.security.net.config.PinSet');
                const EMPTY_PINSET = PinSet.EMPTY_PINSET.value;
                return function () {
                    // Always ignore the 2nd 'pins' PinSet argument entirely:
                    arguments[2] = EMPTY_PINSET;
                    this.$init(...arguments);
                }
            }
        }
    ],

    // --- Native WebViewClient

    'android.webkit.WebViewClient':  [
        {
            methodName: 'onReceivedSslError',
            overload: ['android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError'],
            replacement: () => NO_OP
        },
        {
            methodName: 'onReceivedSslError',
            overload: ['android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError'],
            replacement: () => NO_OP
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

    'com.squareup.okhttp.internal.tls.OkHostnameVerifier': [
        {
            methodName: 'verify',
            overload: ['java.lang.String', 'java.security.cert.X509Certificate'],
            replacement: () => RETURN_TRUE
        },
        {
            methodName: 'verify',
            overload: ['java.lang.String', 'javax.net.ssl.SSLSession'],
            replacement: () => RETURN_TRUE
        }
    ],

    // --- Trustkit

    'com.datatheorem.android.trustkit.pinning.OkHostnameVerifier': [
        {
            methodName: 'verify',
            overload: ['java.lang.String', 'javax.net.ssl.SSLSession'],
            replacement: () => RETURN_TRUE
        },
        {
            methodName: 'verify',
            overload: ['java.lang.String', 'java.security.cert.X509Certificate'],
            replacement: () => RETURN_TRUE
        }
    ],

    'com.datatheorem.android.trustkit.pinning.PinningTrustManager': [
        {
            methodName: 'checkServerTrusted',
            replacement: () => NO_OP
        }
    ],

    // --- Appcelerator

    'appcelerator.https.PinningTrustManager': [
        {
            methodName: 'checkServerTrusted',
            replacement: NO_OP
        }
    ],

    // --- Apache Harmony version of OpenSSLSocketImpl (v similar to Conscrypt above)

    'org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl': [
        {
            methodName: 'verifyCertificateChain',
            replacement: () => NO_OP
        }
    ],

    // --- PhoneGap sslCertificateChecker (https://github.com/EddyVerbruggen/SSLCertificateChecker-PhoneGap-Plugin)

    'nl.xservices.plugins.sslCertificateChecker': [
        {
            methodName: 'execute',
            overload: ['java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext'],
            replacement: () => RETURN_TRUE
        }
    ],

    // --- IBM WorkLight

    'com.worklight.wlclient.api.WLClient': [
        {
            methodName: 'pinTrustedCertificatePublicKey',
            getMethod: (WLClientCls) => WLClientCls.getInstance().pinTrustedCertificatePublicKey,
            overload: ['java.lang.String'],
            replacement: () => NO_OP
        },
        {
            methodName: 'pinTrustedCertificatePublicKey',
            getMethod: (WLClientCls) => WLClientCls.getInstance().pinTrustedCertificatePublicKey,
            overload: ['[Ljava.lang.String;'],
            replacement: () => NO_OP
        }
    ],

    'com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning': [
        {
            methodName: 'verify',
            overload: ['java.lang.String', 'javax.net.ssl.SSLSocket'],
            replacement: () => NO_OP
        },
        {
            methodName: 'verify',
            overload: ['java.lang.String', 'java.security.cert.X509Certificate'],
            replacement: () => NO_OP
        },
        {
            methodName: 'verify',
            overload: ['java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;'],
            replacement: () => NO_OP
        },
        {
            methodName: 'verify',
            overload: ['java.lang.String', 'javax.net.ssl.SSLSession'],
            replacement: () => RETURN_TRUE
        }
    ],

    'com.worklight.androidgap.plugin.WLCertificatePinningPlugin': [
        {
            methodName: 'execute',
            overload: ['java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext'],
            replacement: () => RETURN_TRUE
        }
    ],

    // --- // CWAC-Netsecurity (unofficial back-port pinner for Android<4.2) CertPinManager

    'com.commonsware.cwac.netsecurity.conscrypt.CertPinManager': [
        {
            methodName: 'isChainValid',
            overload: ['java.lang.String', 'java.util.List'],
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

    // --- Apache Cordova WebViewClient

    'org.apache.cordova.CordovaWebViewClient': [
        // Very similar to native Android WebViewClient
        {
            methodName: 'onReceivedSslError',
            overload: ['android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError'],
            replacement: () => (a, b, c) => c.proceed()
        }
    ],

    // --- Boye AbstractVerifier

    'ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier': [
        {
            methodName: 'verify',
            replacement: () => NO_OP
        }
    ],

    // --- Appmattus

    'com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor': [
        {
            methodName: 'intercept',
            replacement: () => (a) => a.proceed(a.request())
        }
    ],

    'com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyTrustManager': [
        {
            methodName: 'checkServerTrusted',
            overload: ['[Ljava.security.cert.X509Certificate;', 'java.lang.String'],
            replacement: () => NO_OP
        },
        {
            methodName: 'checkServerTrusted',
            overload: ['[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String'],
            replacement: () => () => Java.use('java.util.ArrayList').$new()
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

setTimeout(function () {
    Java.perform(function () {
        if (DEBUG_MODE) console.debug('=== Disablig all recognized unpinning libraries ===');

        Object.keys(PINNING_FIXES).forEach((targetClass) => {
            const Cls = getJavaClassIfExists(targetClass);
            if (!Cls) {
                // We skip patches for any classes that don't seem to be present. This is common
                // as not all libraries we handle are necessarily used.
                if (DEBUG_MODE) console.debug(`[ ] ${targetClass} *`);
            }

            const patches = PINNING_FIXES[targetClass];

            let patchApplied = false;

            patches.forEach(({ methodName, getMethod, overload, replacement }) => {
                const namedTargetMethod = getMethod
                    ? getMethod(targetClass)
                    : targetClass[methodName];

                const methodDescription = `${methodName}${
                    overload
                        ? '(' + overload.map((argType) => {
                            // Simplify arg names to just the class name for simpler logs:
                            const argClassName = argType.split('.').slice(-1)[0];
                            if (argType.startsWith('[L')) return `${argClassName}[]`;
                            else return argClassName;
                        }).join(', ') + ')'
                        : ''
                }`

                const targetMethodImplementations = !namedTargetMethod
                        ? [] // Method not found
                    : !overload
                        ? [namedTargetMethod] // No overload specified
                    : overload === '*'
                        ? namedTargetMethod.overloads // Targetting _all_ overloads
                    // Or targetting a specific overload:
                        : [namedTargetMethod.overload(...overload)];

                if (targetMethodImplementations.length === 0) {
                    // We skip patches for any methods that don't seem to be present. This is
                    // rarer, but happens due to methods that only appear in certain library
                    // versions or whose signatures have changed over time.
                    if (DEBUG_MODE) console.debug(`[ ] ${targetClass} ${methodDescription}`);
                    return;
                }

                try {
                    targetMethodImplementations.forEach((targetMethod) => {
                        targetMethod.implementation = replacement(targetMethod);
                        if (DEBUG_MODE) console.debug(`[+] ${patchName} ${methodDescription}`);
                    })
                    patchApplied = true;
                } catch (e) {
                    // In theory, errors like this should never happen - it means the patch is broken
                    // (e.g. an expected method doesn't exist at all)
                    console.warn(`[!] ERROR: ${patchName} failed: ${e}`);
                }
            });

            console.log(`[!] Matched class ${targetClass} but could not patch any methods`);
        });

    });
});