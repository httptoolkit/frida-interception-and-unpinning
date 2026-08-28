/**************************************************************************************************
 *
 * Once we have captured traffic (once it's being sent to our proxy port) the next step is
 * to ensure any clients using TLS (HTTPS) trust our CA certificate, to allow us to intercept
 * encrypted connections successfully.
 *
 * This script does this, by defining overrides to hook BoringSSL (used by iOS 11+) and Cronet
 * (the Chromium network stack, used by some Android apps including TikTok). This is the primary
 * certificate trust mechanism for iOS, and only a niche addition for Android edge cases.
 *
 * The hooks defined here ensure that normal certificate validation is skipped, and instead any
 * TLS connection using our trusted CA is always trusted. In general use this disables both
 * normal & certificate-pinned TLS/HTTPS validation, so that all connections which use your CA
 * should always succeed.
 *
 * This does not completely disable TLS validation, but it does significantly relax it - it's
 * intended for use with the other scripts in this repo that ensure all traffic is routed directly
 * to your MitM proxy (generally on your local network). You probably don't want to use this for
 * any sensitive traffic sent over public/untrusted networks - it is difficult to intercept, and
 * any attacker would need a copy of the CA certificate you're using, but by its nature as a messy
 * hook around TLS internals it's probably not 100% secure.
 *
 * Since iOS 11 (2017) Apple has used BoringSSL internally to handle all TLS. This code
 * hooks low-level BoringSSL calls, to override all custom certificate validation completely.
 * https://nabla-c0d3.github.io/blog/2019/05/18/ssl-kill-switch-for-ios12/ to the general concept,
 * but note that this script goes further - reimplementing basic TLS cert validation, rather than
 * just returning OK blindly for all connections.
 *
 * Source available at https://github.com/httptoolkit/frida-interception-and-unpinning/
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Tim Perry <tim@httptoolkit.com>
 *
 *************************************************************************************************/

const TARGET_LIBS = [
    { name: 'libboringssl.dylib', hooked: false }, // iOS primary TLS implementation
    { name: 'libsscronet.so', hooked: false }, // Cronet on Android
    { name: 'boringssl', hooked: false }, // Bundled by some apps e.g. TikTok on iOS
    { name: 'libssl.so', hooked: false }, // Native OpenSSL in Android
];

TARGET_LIBS.forEach((targetLib) => {
    waitForModule(targetLib.name, (targetModule) => {
        try {
            patchTargetLib(targetModule, targetLib.name);
            targetLib.hooked = true;
        } catch (e) {
            // Report which library failed & why, but keep going: the remaining libs here, and the
            // scripts after this one, are all independent of this one failing.
            console.log(`\n !!! --- Could not hook TLS in ${targetLib.name}: ${e} --- !!!`);
        }
    });

    if (
        targetLib.name === 'libboringssl.dylib' &&
        Process.platform === 'darwin' &&
        !targetLib.hooked
    ) {
        // On iOS, we expect this to always work immediately, so print a warning if we
        // ever have to skip this TLS patching process.
        console.log(`\n !!! --- Could not load ${targetLib.name} to hook TLS --- !!!`);
    }
});

const MAX_CHAIN_LENGTH_TO_SCAN = 1000;

// Reading a STACK_OF(CRYPTO_BUFFER). BoringSSL exports OPENSSL_sk_num & OPENSSL_sk_value, plus
// sk_num & sk_value as deprecated aliases for them, but Apple's libboringssl.dylib on iOS 26
// exports none of the four, so where they're all missing we read the stack ourselves.
//
// The struct is opaque in BoringSSL's headers, so that does depend on its internal layout:
//
//     struct stack_st { size_t num; void **data; int sorted; size_t num_alloc; ... }
function getStackAccessors(targetModule) {
    const exportedAccessors = [
        ['OPENSSL_sk_num', 'OPENSSL_sk_value'],
        ['sk_num', 'sk_value']
    ].map(([numName, valueName]) => ({
        num: targetModule.findExportByName(numName),
        value: targetModule.findExportByName(valueName)
    })).find(({ num, value }) => num && value);

    if (exportedAccessors) {
        return {
            sk_num: new NativeFunction(exportedAccessors.num, 'size_t', ['pointer']),
            sk_value: new NativeFunction(exportedAccessors.value, 'pointer', ['pointer', 'size_t'])
        };
    }

    return {
        sk_num: (stack) => {
            if (stack.isNull()) return 0;

            const length = stack.readULong();
            if (length > MAX_CHAIN_LENGTH_TO_SCAN) {
                throw new Error(`Implausible certificate chain length (${length})`);
            }
            return length;
        },
        sk_value: (stack, i) => {
            const cert = stack
                .add(Process.pointerSize) // Past the count, to the array of pointers
                .readPointer()
                .add(i * Process.pointerSize)
                .readPointer();

            // Reading from JS throws if this isn't mapped, where handing a bad pointer to the
            // CRYPTO_BUFFER functions below would take the whole app down instead:
            cert.readU8();
            return cert;
        }
    };
}

function patchTargetLib(targetModule, targetName) {
    // Get the peer certificates from an SSL pointer. Returns a pointer to a STACK_OF(CRYPTO_BUFFER)
    // which requires use of the next few methods below to actually access.
    // https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_get0_peer_certificates
    const SSL_get0_peer_certificates = new NativeFunction(
        targetModule.getExportByName('SSL_get0_peer_certificates'),
        'pointer', ['pointer']
    );

    // Stack methods:
    // https://commondatastorage.googleapis.com/chromium-boringssl-docs/stack.h.html
    const { sk_num, sk_value } = getStackAccessors(targetModule);

    // Crypto buffer methods:
    // https://commondatastorage.googleapis.com/chromium-boringssl-docs/pool.h.html
    const crypto_buffer_len = new NativeFunction(
        targetModule.getExportByName('CRYPTO_BUFFER_len'),
        'size_t', ['pointer']
    );

    const crypto_buffer_data = new NativeFunction(
        targetModule.getExportByName('CRYPTO_BUFFER_data'),
        'pointer', ['pointer']
    );

    const SSL_VERIFY_OK = 0x0;
    const SSL_VERIFY_INVALID = 0x1;
    const SSL_VERIFY_RETRY = 0x2;

    // The legacy cert_verify_callback uses the opposite convention to ssl_verify_result_t:
    const LEGACY_VERIFY_OK = 0x1;
    const LEGACY_VERIFY_INVALID = 0x0;

    // Some failures are permanent, and so end up firing on every handshake. We log them
    // with logFailureOnce to track just the first instance of these:
    const loggedFailures = new Set();
    const logFailureOnce = (kind, message) => {
        if (loggedFailures.has(kind)) return;
        loggedFailures.add(kind);
        console.log(`\n !!! --- ${message} --- !!!`);
    };

    // We cache the verification callbacks we create. In general (in testing, 100% of the time) the
    // 'real' callback is always the exact same address, so this is much more efficient than creating
    // a new callback every time.
    const verificationCallbackCache = {};
    const legacyCallbackCache = {};

    const peerCertsIncludeOurCert = (ssl) => {
        const peerCerts = SSL_get0_peer_certificates(ssl);

        const chainLength = Number(sk_num(peerCerts));

        // Loop through every cert in the chain:
        for (let i = 0; i < chainLength; i++) {
            // For each cert, check if it *exactly* matches our configured CA cert:
            const cert = sk_value(peerCerts, i);
            const certDataLength = crypto_buffer_len(cert).toNumber();

            if (certDataLength !== CERT_DER.byteLength) continue;

            const certPointer = crypto_buffer_data(cert);
            const certData = new Uint8Array(certPointer.readByteArray(certDataLength));

            if (certData.every((byte, j) => CERT_DER[j] === byte)) return true;
        }

        return false;
    };

    const buildVerificationCallback = (realCallbackAddr) => {
        if (!verificationCallbackCache[realCallbackAddr]) {
            const realCallback = (realCallbackAddr && !realCallbackAddr.isNull())
                ? new NativeFunction(realCallbackAddr, 'int', ['pointer', 'pointer'])
                : () => SSL_VERIFY_INVALID;

            // We let one thread at a time into the app's callback, as parallel calls seem to
            // crash in some specific scenarios:
            const pendingCheckThreads = new Set();

            const callRealCallback = (ssl, out_alert) => {
                const threadId = Process.getCurrentThreadId();

                // Detect and allow (better than deadlocking) on reentrant calls:
                if (pendingCheckThreads.has(threadId)) return realCallback(ssl, out_alert);

                while (pendingCheckThreads.size > 0) {
                    Thread.sleep(0.01);
                }
                pendingCheckThreads.add(threadId);

                try {
                    return realCallback(ssl, out_alert);
                } finally {
                    pendingCheckThreads.delete(threadId);
                }
            };

            const hookedCallback = new NativeCallback(function (ssl, out_alert) {
                try {
                    return runVerification(ssl, out_alert);
                } catch (e) {
                    // Fail closed if verification throws somehow:
                    logFailureOnce('verification',
                        `${targetName} verification failed unexpectedly: ${e}`);
                    return SSL_VERIFY_INVALID;
                }
            }, 'int', ['pointer','pointer']);

            function runVerification(ssl, out_alert) {
                let realResult = false; // False = not yet called, 0/1 = call result

                if (targetName === 'libsscronet.so') {
                    // Cronet assumes its callback is always called, and crashes if not, so it's
                    // the one library where we call it up front regardless of what we decide.
                    // For Conscrypt (libssl) the callback returns with a pending Java exception
                    // and iOS's BoringSSL rejects bad certs via callback side-effects, so we must
                    // not call the callback in those cases.
                    realResult = callRealCallback(ssl, out_alert);

                    // Retry means the app's own verification is pending, so in this case
                    // we always pass the result back to let that complete properly:
                    if (realResult === SSL_VERIFY_RETRY) return realResult;
                }

                // Extremely dumb certificate validation: we accept any chain where the *exact* CA cert
                // we were given is present. No flexibility for non-trivial cert chains, and no
                // validation beyond presence of the expected CA certificate. BoringSSL does do a
                // fair amount of essential validation independent of the certificate comparison
                // though, so some basics may be covered regardless (see tls13_process_certificate_verify).

                // This *intentionally* does not reject certs with the wrong hostname, expired CA
                // or leaf certs, and lots of other issues. This is significantly better than nothing,
                // but it is not production-ready TLS verification for general use in untrusted envs!

                let ourCertPresent = false;
                try {
                    ourCertPresent = peerCertsIncludeOurCert(ssl);
                } catch (e) {
                    // Failing to read the chain must never mean 'trusted'. Fall through to the real
                    // callback, which is exactly who would have decided this if we weren't here:
                    logFailureOnce('cert-read', `Could not read ${targetName} peer certs: ${e}`);
                }

                if (ourCertPresent) return SSL_VERIFY_OK;

                // No matched peer - fallback to the provided callback instead:
                if (realResult === false) { // Haven't called it yet
                    realResult = callRealCallback(ssl, out_alert);
                }

                return realResult;
            }

            verificationCallbackCache[realCallbackAddr] = hookedCallback;
        }

        return verificationCallbackCache[realCallbackAddr];
    };

    // Older BoringSSL predates SSL_set_custom_verify entirely - notably Android 8's libssl.so,
    // where Conscrypt uses SSL_CTX_set_cert_verify_callback instead. Same idea, but the callback
    // takes an X509_STORE_CTX rather than an SSL, and returns 1 for a trusted chain, not 0.

    // Both resolved below, but only if we actually take the legacy path:
    let sslExDataIndex;
    let X509_STORE_CTX_get_ex_data;

    const buildLegacyVerificationCallback = (realCallbackAddr) => {
        if (!legacyCallbackCache[realCallbackAddr]) {
            const realCallback = (realCallbackAddr && !realCallbackAddr.isNull())
                ? new NativeFunction(realCallbackAddr, 'int', ['pointer', 'pointer'])
                : () => LEGACY_VERIFY_INVALID;

            legacyCallbackCache[realCallbackAddr] = new NativeCallback(function (storeCtx, arg) {
                // Unlike the custom_verify path, we never need to call the real callback here.
                let ourCertPresent = false;
                try {
                    const ssl = X509_STORE_CTX_get_ex_data(storeCtx, sslExDataIndex);
                    if (ssl.isNull()) throw new Error('No SSL attached to X509_STORE_CTX');
                    ourCertPresent = peerCertsIncludeOurCert(ssl);
                } catch (e) {
                    // This will fall through to the real callback if anything goes wrong
                    logFailureOnce('cert-read', `Could not read ${targetName} peer certs: ${e}`);
                }

                if (ourCertPresent) return LEGACY_VERIFY_OK;

                return realCallback(storeCtx, arg);
            }, 'int', ['pointer', 'pointer']);
        }

        return legacyCallbackCache[realCallbackAddr];
    };

    const customVerifyAddrs = [
        targetModule.findExportByName("SSL_set_custom_verify"),
        targetModule.findExportByName("SSL_CTX_set_custom_verify")
    ].filter(Boolean);

    customVerifyAddrs.forEach((set_custom_verify_addr) => {
        const set_custom_verify_fn = new NativeFunction(
            set_custom_verify_addr,
            'void', ['pointer', 'int', 'pointer']
        );

        // When this function is called, ignore the provided callback, and
        // configure our callback instead:
        Interceptor.replace(set_custom_verify_fn, new NativeCallback(function(ssl, mode, providedCallbackAddr) {
            set_custom_verify_fn(ssl, mode, buildVerificationCallback(providedCallbackAddr));
        }, 'void', ['pointer', 'int', 'pointer']));
    });

    // Iff custom_verify is missing, try to fallback to the legacy APIs (never do both):
    const legacyVerifyAddr = customVerifyAddrs.length
        ? null
        : targetModule.findExportByName("SSL_CTX_set_cert_verify_callback");

    if (legacyVerifyAddr) {
        sslExDataIndex = new NativeFunction(
            targetModule.getExportByName('SSL_get_ex_data_X509_STORE_CTX_idx'),
            'int', []
        )();

        X509_STORE_CTX_get_ex_data = new NativeFunction(
            targetModule.getExportByName('X509_STORE_CTX_get_ex_data'),
            'pointer', ['pointer', 'int']
        );

        const set_cert_verify_fn = new NativeFunction(
            legacyVerifyAddr,
            'void', ['pointer', 'pointer', 'pointer']
        );

        // As in the main path: replace any configured cert callback with our own validation
        Interceptor.replace(set_cert_verify_fn, new NativeCallback(function (ctx, providedCallbackAddr, arg) {
            set_cert_verify_fn(ctx, buildLegacyVerificationCallback(providedCallbackAddr), arg);
        }, 'void', ['pointer', 'pointer', 'pointer']));
    }

    const hookedMethodCount = customVerifyAddrs.length + (legacyVerifyAddr ? 1 : 0);

    if (hookedMethodCount) {
        if (DEBUG_MODE) {
            console.log(`[+] Patched ${hookedMethodCount} ${targetName} verification methods${
                legacyVerifyAddr ? ' (legacy cert_verify_callback)' : ''
            }`);
        }
        console.log(`== Hooked native TLS lib ${targetName} ==`);
    } else {
        console.log(`\n !!! Hooking native TLS lib ${targetName} failed - no verification methods found`);
    }

    const get_psk_identity_addr = targetModule.findExportByName("SSL_get_psk_identity");
    if (get_psk_identity_addr) {
        // Hooking this is apparently required for some verification paths which check the
        // result is not 0x0. Any return value should work fine though.
        Interceptor.replace(get_psk_identity_addr, new NativeCallback(function(ssl) {
            return "PSK_IDENTITY_PLACEHOLDER";
        }, 'pointer', ['pointer']));
    } else if (hookedMethodCount) {
        console.log(`Patched ${hookedMethodCount} verification methods, but couldn't find get_psk_identity`);
    }
}

