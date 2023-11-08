/**************************************************************************************************
 *
 * This file defines various config parameters, used later within the other scripts.
 *
 * In all cases, you'll want to set CERT_PEM and likely PROXY_HOST and PROXY_PORT.
 *
 * Source available at https://github.com/httptoolkit/frida-interception-and-unpinning/
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Tim Perry <tim@httptoolkit.com>
 *
 *************************************************************************************************/

// Put your CA certificate data here in PEM format:
const CERT_PEM = `-----BEGIN CERTIFICATE-----

[!! Put your CA certificate data here, in PEM format !!]

-----END CERTIFICATE-----`;

// Put your intercepting proxy's address here:
const PROXY_HOST = '127.0.0.1';
const PROXY_PORT = 8000;

// If you like, set to to true to enable extra logging:
const DEBUG_MODE = false;

// If you find issues with non-HTTP traffic being captured (due to the
// native connect hook script) you can add ports here to exempt traffic
// on that port from being redirected. Note that this will only affect
// traffic captured by the raw connection hook - for apps using the
// system HTTP proxy settings, traffic on these ports will still be
// sent via the proxy and intercepted despite this setting.
const IGNORED_NON_HTTP_PORTS = [];


// ----------------------------------------------------------------------------
// You don't need to modify any of the below, it just checks and applies some
// of the configuration that you've entered above.
// ----------------------------------------------------------------------------


if (DEBUG_MODE) {
    // Add logging just for clean output & to separate reloads:
    console.log('\n*** Starting scripts ***');
    Java.perform(() => {
        setTimeout(() => console.log('*** Scripts completed ***\n'), 5);
        // (We assume that nothing else will take more than 5ms, but app startup
        // probably will, so this should separate script & runtime logs)
    });
} else {
    console.log(''); // Add just a single newline, for minimal clarity
}

// Check the certificate (without literally including the instruction phrasing
// here, as that can be confusing for some users):
if (CERT_PEM.match(/\[!!.* CA certificate data .* !!\]/)) {
    throw new Error('No certificate was provided' +
        '\n\n' +
        'You need to set CERT_PEM in the Frica config script ' +
        'to the contents of your CA certificate.'
    );
}