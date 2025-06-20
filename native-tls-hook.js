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
        patchTargetLib(targetModule, targetLib.name);
        targetLib.hooked = true;
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
    const sk_num = new NativeFunction(
        targetModule.getExportByName('sk_num'),
        'size_t', ['pointer']
    );

    const sk_value = new NativeFunction(
        targetModule.getExportByName('sk_value'),
        'pointer', ['pointer', 'int']
    );

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

    // We cache the verification callbacks we create. In general (in testing, 100% of the time) the
    // 'real' callback is always the exact same address, so this is much more efficient than creating
    // a new callback every time.
    const verificationCallbackCache = {};

    const buildVerificationCallback = (realCallbackAddr) => {
        if (!verificationCallbackCache[realCallbackAddr]) {
            const realCallback = (!realCallbackAddr || realCallbackAddr.isNull())
                ? new NativeFunction(realCallbackAddr, 'int', ['pointer','pointer'])
                : () => SSL_VERIFY_INVALID; // Callback can be null - treat as invalid (=our validation only)

            let pendingCheckThreads = new Set();

            const hookedCallback = new NativeCallback(function (ssl, out_alert) {
                let realResult = false; // False = not yet called, 0/1 = call result

                const threadId = Process.getCurrentThreadId();
                const alreadyHaveLock = pendingCheckThreads.has(threadId);

                // We try to have only one thread running these checks at a time, as parallel calls
                // here on the same underlying callback seem to crash in some specific scenarios
                while (pendingCheckThreads.size > 0 && !alreadyHaveLock) {
                    Thread.sleep(0.01);
                }
                pendingCheckThreads.add(threadId);

                if (targetName !== 'libboringssl.dylib') {
                    // Cronet assumes its callback is always called, and crashes if not. iOS's BoringSSL
                    // meanwhile seems to use some negative checks in its callback, and rejects the
                    // connection independently of the return value here if it's called with a bad cert.
                    // End result: we *only sometimes* proactively call the callback.
                    realResult = realCallback(ssl, out_alert);
                }

                // Extremely dumb certificate validation: we accept any chain where the *exact* CA cert
                // we were given is present. No flexibility for non-trivial cert chains, and no
                // validation beyond presence of the expected CA certificate. BoringSSL does do a
                // fair amount of essential validation independent of the certificate comparison
                // though, so some basics may be covered regardless (see tls13_process_certificate_verify).

                // This *intentionally* does not reject certs with the wrong hostname, expired CA
                // or leaf certs, and lots of other issues. This is significantly better than nothing,
                // but it is not production-ready TLS verification for general use in untrusted envs!

                const peerCerts = SSL_get0_peer_certificates(ssl);

                // Loop through every cert in the chain:
                for (let i = 0; i < sk_num(peerCerts); i++) {
                    // For each cert, check if it *exactly* matches our configured CA cert:
                    const cert = sk_value(peerCerts, i);
                    const certDataLength = crypto_buffer_len(cert).toNumber();

                    if (certDataLength !== CERT_DER.byteLength) continue;

                    const certPointer = crypto_buffer_data(cert);
                    const certData = new Uint8Array(certPointer.readByteArray(certDataLength));

                    if (certData.every((byte, j) => CERT_DER[j] === byte)) {
                        if (!alreadyHaveLock) pendingCheckThreads.delete(threadId);
                        return SSL_VERIFY_OK;
                    }
                }

                // No matched peer - fallback to the provided callback instead:
                if (realResult === false) { // Haven't called it yet
                    realResult = realCallback(ssl, out_alert);
                }

                if (!alreadyHaveLock) pendingCheckThreads.delete(threadId);
                return realResult;
            }, 'int', ['pointer','pointer']);

            verificationCallbackCache[realCallbackAddr] = hookedCallback;
        }

        return verificationCallbackCache[realCallbackAddr];
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

    if (customVerifyAddrs.length) {
        if (DEBUG_MODE) {
            console.log(`[+] Patched ${customVerifyAddrs.length} ${targetName} verification methods`);
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
    } else if (customVerifyAddrs.length) {
        console.log(`Patched ${customVerifyAddrs.length} custom_verify methods, but couldn't find get_psk_identity`);
    }
}

