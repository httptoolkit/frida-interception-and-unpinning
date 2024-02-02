/**************************************************************************************************
 *
 * Once we have captured traffic (once it's being sent to our proxy port) the next step is
 * to ensure any clients using TLS (HTTPS) trust our CA certificate, to allow us to intercept
 * encrypted connections successfully.
 *
 * This script does this, by defining overrides to hook BoringSSL on iOS 11+, so that normal
 * certificate validation is skipped, and instead any TLS connection using our trusted CA is
 * always trusted. In general use this disables both normal & certificate-pinned TLS/HTTPS
 * validation, so that all connections which use your CA should always succeed.
 *
 * This does not completely disable TLS validation, but it does significantly relax it - it's
 * intended for use with the other scripts in this repo that ensure all traffic is routed directly
 * to your MitM proxy (generally on your local network). You probably don't want to use this for
 * any sensitive traffic sent over public/untrusted networks - it is difficult to intercept, and
 * any attacker would need a copy of the CA certifcate you're using, but by its nature as a messy
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

try {
    Module.ensureInitialized("libboringssl.dylib");
} catch (e) {
    try {
	    Module.load("libboringssl.dylib");
    } catch (e) {
        console.log('Could not load BoringSSL to hook TLS');
        if (DEBUG_MODE) console.log(e);
    }
}

// Get the peer certificates from an SSL pointer. Returns a pointer to a STACK_OF(CRYPTO_BUFFER)
// which requires use of the next few methods below to actually access.
// https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_get0_peer_certificates
const SSL_get0_peer_certificates = new NativeFunction(
    Module.findExportByName('libboringssl.dylib', 'SSL_get0_peer_certificates'),
    'pointer', ['pointer']
);

// Stack methods:
// https://commondatastorage.googleapis.com/chromium-boringssl-docs/stack.h.html
const sk_num = new NativeFunction(
    Module.findExportByName('libboringssl.dylib', 'sk_num'),
    'size_t', ['pointer']
);

const sk_value = new NativeFunction(
    Module.findExportByName('libboringssl.dylib', 'sk_value'),
    'pointer', ['pointer', 'int']
);

// Crypto buffer methods:
// https://commondatastorage.googleapis.com/chromium-boringssl-docs/pool.h.html
const crypto_buffer_len = new NativeFunction(
    Module.findExportByName('libboringssl.dylib', 'CRYPTO_BUFFER_len'),
    'size_t', ['pointer']
);

const crypto_buffer_data = new NativeFunction(
    Module.findExportByName('libboringssl.dylib', 'CRYPTO_BUFFER_data'),
    'pointer', ['pointer']
);

const SSL_VERIFY_OK = 0x0;

// We cache the verification callbacks we create. In general (in testing, 100% of the time) the
// 'real' callback is always the exact same address, so this is much more efficient than creating
// a new callback every time.
const verificationCallbackCache = {};

const buildVerificationCallback = (realCallbackAddr) => {
    if (!verificationCallbackCache[realCallbackAddr]) {
        const realCallback = new NativeFunction(realCallbackAddr, 'int', ['pointer','pointer']);

        const hookedCallback = new NativeCallback(function (ssl, out_alert) {
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
                    return SSL_VERIFY_OK;
                }
            }

            // No matched peer - fallback to the provided callback instead:
            return realCallback(ssl, out_alert);
        }, 'int', ['pointer','pointer']);

        verificationCallbackCache[realCallbackAddr] = hookedCallback;
    }

    return verificationCallbackCache[realCallbackAddr];
};

const customVerifyAddrs = [
    Module.findExportByName("libboringssl.dylib", "SSL_set_custom_verify"),
    Module.findExportByName("libboringssl.dylib", "SSL_CTX_set_custom_verify")
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

const get_psk_identity_addr = Module.findExportByName("libboringssl.dylib", "SSL_get_psk_identity");
if (get_psk_identity_addr) {
    // Hooking this is apparently required for some verification paths which check the
    // result is not 0x0. Any return value should work fine though.
    Interceptor.replace(get_psk_identity_addr, new NativeCallback(function(ssl) {
        return "PSK_IDENTITY_PLACEHOLDER";
    }, 'pointer', ['pointer']));
} else if (customVerifyAddrs.length) {
    console.log(`Patched ${customVerifyAddrs.length} custom_verify methods, but couldn't find get_psk_identity`);
}

