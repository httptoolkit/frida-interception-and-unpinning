/**************************************************************************************************
 *
 * Once we have captured traffic (once it's being sent to our proxy port) the next step is
 * to ensure any clients using TLS (HTTPS) trust our CA certificate, to allow us to intercept
 * encrypted connections successfully.
 *
 * This script does so by attaching to the internals of Conscrypt (the Android SDK's standard
 * TLS implementation) and pre-adding our certificate to the 'already trusted' cache, so that
 * future connections trust it implicitly. This ensures that all normal uses of Android APIs
 * for HTTPS & TLS will allow interception.
 *
 * This does not handle all standalone certificate pinning techniques - where the application
 * actively rejects certificates that are trusted by default on the system. That's dealt with
 * in the separate certificate unpinning script.
 *
 * Source available at https://github.com/httptoolkit/frida-interception-and-unpinning/
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Tim Perry <tim@httptoolkit.com>
 *
 *************************************************************************************************/

Java.perform(() => {
    // First, we build a JVM representation of our certificate:
    const String = Java.use("java.lang.String");
    const ByteArrayInputStream = Java.use('java.io.ByteArrayInputStream');
    const CertFactory = Java.use('java.security.cert.CertificateFactory');

    let cert;
    try {
        const certFactory = CertFactory.getInstance("X.509");
        const certBytes = String.$new(CERT_PEM).getBytes();
        cert = certFactory.generateCertificate(ByteArrayInputStream.$new(certBytes));
    } catch (e) {
        console.error('Could not parse provided certificate PEM!');
        console.error(e);
        Java.use('java.lang.System').exit(1);
    }

    // Then we hook TrustedCertificateIndex. This is used for caching known trusted certs within Conscrypt -
    // by prepopulating all instances, we ensure that all TrustManagerImpls (and potentially other
    // things) automatically trust our certificate specifically (without disabling validation entirely).
    // This should apply to Android v7+ - previous versions used SSLContext & X509TrustManager.
    [
        'com.android.org.conscrypt.TrustedCertificateIndex',
        'org.conscrypt.TrustedCertificateIndex', // Might be used (com.android is synthetic) - unclear
        'org.apache.harmony.xnet.provider.jsse.TrustedCertificateIndex', // Used in Apache Harmony version of Conscrypt
        'com.google.android.gms.org.conscrypt.TrustedCertificateIndex', // Google Play Services bundled Conscrypt
    ].forEach((TrustedCertificateIndexClassname, i) => {
        let TrustedCertificateIndex;
        try {
            TrustedCertificateIndex = Java.use(TrustedCertificateIndexClassname);
        } catch (e) {
            if (i === 0) {
                throw new Error(`${TrustedCertificateIndexClassname} not found - could not inject system certificate`);
            } else {
                // Other classnames are optional fallbacks
                if (DEBUG_MODE) {
                    console.log(`[ ] Skipped cert injection for ${TrustedCertificateIndexClassname} (not present)`);
                }
                return;
            }
        }

        try {
            // Every read of the index goes through one of its find* methods - the map behind them
            // is private, and nothing outside Conscrypt itself touches it. So we hook those and
            // index our cert in every case before any lookup happens.
            // Note that hook $init instead doesn't work - in some cases (Android 8, where Conscrypt
            // is AOT-compiled ahead of time) we miss some constructions.
            const findMethodNames = new Set(
                TrustedCertificateIndex.class.getDeclaredMethods()
                    .map((method) => method.getName())
                    .filter((methodName) => methodName.startsWith('find'))
            );

            findMethodNames.forEach((methodName) => {
                TrustedCertificateIndex[methodName].overloads
                    .filter((overload) =>
                        overload.argumentTypes.length === 1 &&
                        overload.argumentTypes[0].className === 'java.security.cert.X509Certificate'
                    )
                    .forEach((overload) => {
                        overload.implementation = function () {
                            if (!this.findBySubjectAndPublicKey(cert)) {
                                this.index(cert);
                            }

                            return overload.apply(this, arguments);
                        };
                    });
            });

            if (DEBUG_MODE) console.log(`[+] Injected cert into ${TrustedCertificateIndexClassname}`);
        } catch (e) {
            console.error(`[!] Error hooking system certificates via ${TrustedCertificateIndexClassname}:`);
            console.error(DEBUG_MODE
                ? e
                : '    ' + e.message
            );
        }
    });

    // This effectively adds us to the system certs, and also defeats quite a bit of basic certificate
    // pinning too! It auto-trusts us in any implementation that uses TrustManagerImpl (Conscrypt) as
    // the underlying cert checking component.

    console.log('== System certificate trust injected ==');
});