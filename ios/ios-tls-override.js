// Since iOS 11 (2017) Apple has used BoringSSL internally to handle all TLS. This code
// hooks low-level BoringSSL calls, to override all custom certificate validation options complete.
// This is a good intro: https://nabla-c0d3.github.io/blog/2019/05/18/ssl-kill-switch-for-ios12/

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

const SSL_VERIFY_NONE = 0x0;

const VerificationCallback = new NativeCallback(function (ssl, out_alert){
	return SSL_VERIFY_NONE;
},'int',['pointer','pointer']);

[
    Module.findExportByName("libboringssl.dylib", "SSL_set_custom_verify"),
    Module.findExportByName("libboringssl.dylib", "SSL_CTX_set_custom_verify")

].filter(Boolean).forEach((set_custom_verify_addr) => {
    const set_custom_verify_fn = new NativeFunction(
        set_custom_verify_addr,
        'void', ['pointer', 'int', 'pointer']
    );

    // When this function is called, ignore the provided callback, and
    // configure our callback instead:
    Interceptor.replace(set_custom_verify_fn, new NativeCallback(function(ssl, mode, _ignoredProvidedCallback) {
        set_custom_verify_fn(ssl, mode, VerificationCallback);
    }, 'void', ['pointer', 'int', 'pointer']));
});

// Hooking this is apparently required for some verification paths which check the
// result is not 0x0. Any return value should work fine though.
const ssl_get_psk_identity = new NativeFunction(
	Module.findExportByName("libboringssl.dylib", "SSL_get_psk_identity"),
	'pointer', ['pointer']
);

Interceptor.replace(ssl_get_psk_identity, new NativeCallback(function(ssl) {
	return "PSK_IDENTITY_PLACEHOLDER";
}, 'pointer', ['pointer']));