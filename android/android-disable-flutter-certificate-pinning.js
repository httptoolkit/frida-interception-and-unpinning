/**************************************************************************************************
 *
 * This script hooks Flutter internal certificate handling, to trust our certificate (and ignore
 * any custom certificate validation - e.g. pinning libraries) for all TLS connections.
 *
 * Unfortunately Flutter is shipped as native code with no exported symbols, so we have to do this
 * by matching individual function signatures by known patterns of assembly instructions. In
 * some cases, this goes further and uses larger functions as anchors - allowing us to find the
 * very short functions correctly, where the patterns would otherwise have false positives.
 *
 * The patterns here have been generated from every non-patch release of Flutter from v2.0.0
 * to v3.32.0 (the latest at the time of writing). They may need updates for new versions
 * in future.
 *
 * Currently this is limited to just Android, but in theory this can be expanded to iOS and
 * desktop platforms in future.
 *
 * Source available at https://github.com/httptoolkit/frida-interception-and-unpinning/
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Tim Perry <tim@httptoolkit.com>
 *
 *************************************************************************************************/

(() => {
    const PATTERNS = {
    "android/x64": {
        "dart::bin::SSLCertContext::CertificateCallback": {
            "signatures": [
                "41 57 41 56 53 48 83 ec 10 b8 01 00 00 00 83 ff 01 0f 84 ?? ?? ?? ?? 48 89 f3",
                "41 57 41 56 41 54 53 48 83 ec 18 b8 01 00 00 00 83 ff 01 0f 84 ?? ?? ?? ?? 48 89 f3"
            ]
        },
        "X509_STORE_CTX_get_current_cert": {
            "signatures": [
                "48 8b 47 50 c3",
                "48 8b 47 60 c3",
                "48 8b 87 a8 00 00 00 c3",
                "48 8b 87 b8 00 00 00 c3"
            ],
            "anchor": "dart::bin::SSLCertContext::CertificateCallback"
        },
        "bssl::x509_to_buffer": {
            "signatures": [
                "41 56 53 50 48 89 f0 48 89 fb 48 89 e6 48 83 26 00 48 89 c7 e8 ?? ?? ?? ?? 85 c0 7e 1b",
                "53 48 83 ec 10 48 89 f0 48 89 fb 48 8d 74 24 08 48 83 26 00 48 89 c7 e8 ?? ?? ?? ?? 85 c0",
                "41 56 53 48 83 ec 18 48 89 f0 48 89 fb 48 8d 74 24 08 48 83 26 00 48 89 c7 e8",
                "41 56 53 48 83 ec 18 48 89 f0 49 89 fe 48 8d 74 24 08 48 83 26 00 48 89 c7 e8",
                "41 57 41 56 53 48 83 ec 10 48 89 f0 49 89 fe 48 89 e6 48 83 26 00 48 89 c7 e8"
            ]
        },
        "i2d_X509": {
            "signatures": [
                "55 41 56 53 48 83 ec 70 48 85 ff 0f 84 ?? ?? ?? ?? 48 89 f3 49 89 fe 48 8d 7c 24 40 6a 40",
                "48 8d 15 ?? ?? ?? ?? e9"
            ],
            "anchor": "bssl::x509_to_buffer"
        }
    },
    "android/x86": {
        "dart::bin::SSLCertContext::CertificateCallback": {
            "signatures": [
                "55 89 e5 53 57 56 83 e4 f0 83 ec 30 e8 ?? ?? ?? ?? 5b 81 c3 ?? ?? ?? ?? bf 01 00 00 00 83 7d 08 01 0f 84"
            ]
        },
        "X509_STORE_CTX_get_current_cert": {
            "signatures": [
                "55 89 e5 83 e4 fc 8b 45 08 8b 40 2c 89 ec 5d c3",
                "55 89 e5 83 e4 fc 8b 45 08 8b 40 34 89 ec 5d c3",
                "55 89 e5 83 e4 fc 8b 45 08 8b 40 5c 89 ec 5d c3",
                "55 89 e5 83 e4 fc 8b 45 08 8b 40 64 89 ec 5d c3"
            ],
            "anchor": "dart::bin::SSLCertContext::CertificateCallback"
        },
        "bssl::x509_to_buffer": {
            "signatures": [
                "55 89 e5 53 57 56 83 e4 f0 83 ec 10 89 ce e8 ?? ?? ?? ?? 5b 81 c3 ?? ?? ?? ?? 8d 44 24 08 83 20 00 83 ec 08 50 52",
                "55 89 e5 53 56 83 e4 f0 83 ec 10 89 ce e8 ?? ?? ?? ?? 5b 81 c3 ?? ?? ?? ?? 8d 44 24 0c 83 20 00 83 ec 08 50 52",
                "55 89 e5 53 57 56 83 e4 f0 83 ec 20 89 ce e8 ?? ?? ?? ?? 5b 81 c3 ?? ?? ?? ?? 8d 44 24 14 83 20 00 89 44 24 04 89 14 24"
            ]
        },
        "i2d_X509": {
            "signatures": [
                "55 89 e5 53 57 56 83 e4 f0 83 ec 40 e8 ?? ?? ?? ?? 5b 81 c3 ?? ?? ?? ?? 8b 7d 08 85 ff 0f 84 ?? ?? ?? ?? 83 ec 08",
                "55 89 e5 53 83 e4 f0 83 ec 10 e8 ?? ?? ?? ?? 5b 81 c3 ?? ?? ?? ?? 83 ec 04 8d 83 ?? ?? ?? ?? 50 ff 75 0c ff 75 08"
            ],
            "anchor": "bssl::x509_to_buffer"
        }
    },

    "android/arm64": {
        "dart::bin::SSLCertContext::CertificateCallback": {
            "signatures": [
                "ff c3 00 d1 fe 57 01 a9 f4 4f 02 a9 1f 04 00 71 c0 07 00 54 f3 03 01 aa ?? ?? ?? 94",
                "ff c3 00 d1 fe 57 01 a9 f4 4f 02 a9 1f 04 00 71 c0 02 00 54 f3 03 01 aa ?? ?? ?? 94"
            ]
        },
        "X509_STORE_CTX_get_current_cert": {
            "signatures": [
                "00 ?? ?? f9 c0 03 5f d6"
            ],
            "anchor": "dart::bin::SSLCertContext::CertificateCallback"
        },
        "bssl::x509_to_buffer": {
            "signatures": [
                "fe 0f 1e f8 f4 4f 01 a9 e1 ?? ?? 91 f3 03 08 aa ff 07 00 f9 ?? ?? ?? 97 1f 04 00 71",
                "fe 0f 1e f8 f4 4f 01 a9 e8 03 01 aa f3 03 00 aa e1 ?? ?? 91 e0 03 08 aa ff 07 00 f9",
                "ff 83 00 d1 fe 4f 01 a9 e1 ?? ?? 91 f3 03 08 aa ff 07 00 f9 ?? ?? ?? 97 1f 00 00 71",
                "ff c3 00 d1 fe 7f 01 a9 f4 4f 02 a9 e1 ?? ?? 91 f3 03 08 aa ?? ?? ?? 97 1f 00 00 71",
                "ff c3 00 d1 fe 7f 01 a9 f4 4f 02 a9 e1 ?? ?? 91 f3 03 08 aa ?? ?? ?? 97 1f 04 00 71"
            ]
        },
        "i2d_X509": {
            "signatures": [
                "ff 43 02 d1 fe 57 07 a9 f4 4f 08 a9 a0 06 00 b4 f4 03 00 aa f3 03 01 aa e0 ?? ?? 91",
                "?2 ?? ?? ?? 42 ?? ?? 91 ?? ?? ?? 17"
            ],
            "anchor": "bssl::x509_to_buffer"
        }
    },
    "android/arm": {
        "dart::bin::SSLCertContext::CertificateCallback": {
            "signatures": [
                "70 b5 84 b0 01 28 02 d1 01 20 04 b0 70 bd 0c 46 ?? f? ?? f? 00 28 4d d0 20 46 ?? f? ?? f? 05 46 ?? f? ?? f",
                "70 b5 84 b0 01 28 02 d1 01 20 04 b0 70 bd 0c 46 ?? f? ?? f? 00 28 52 d0 20 46 ?? f? ?? f? 06 46 ?? f? ?? f",
                "70 b5 84 b0 01 28 02 d1 01 20 04 b0 70 bd 0c 46 ?? f? ?? f? 00 28 50 d0 20 46 ?? f? ?? f? 06 46 ?? f? ?? f"
            ]
        },
        "X509_STORE_CTX_get_current_cert": {
            "signatures": [
                "c0 6a 70 47",
                "40 6b 70 47",
                "c0 6d 70 47",
                "40 6e 70 47"
            ],
            "anchor": "dart::bin::SSLCertContext::CertificateCallback"
        },
        "bssl::x509_to_buffer": {
            "signatures": [
                "bc b5 00 25 0a 46 01 95 01 a9 04 46 10 46 ?? f? ?? f? 01 28 08 db 01 46 01 98 00 22 ?? f? ?? f? 05 46 01 98",
                "bc b5 00 25 0a 46 01 95 01 a9 04 46 10 46 ?? f? ?? f? 00 28 09 dd 01 46 01 98 00 22 ?? f? ?? f? 20 60 01 98",
                "7c b5 00 26 0a 46 01 96 01 a9 04 46 10 46 ?? f? ?? f? 00 28 0e dd 01 46 01 98 00 22 ?? f? ?? f? 05 46 01 98",
                "7c b5 00 26 0a 46 01 96 01 a9 04 46 10 46 ?? f? ?? f? 01 28 0d db 01 46 01 98 00 22 ?? f? ?? f? 05 46 01 98",
                "7c b5 00 26 0a 46 01 96 01 a9 04 46 10 46 ?? f? ?? f? 01 28 0e db 01 46 01 98 00 22 ?? f? ?? f? 05 46 00 90"
            ]
        },
        "i2d_X509": {
            "signatures": [
                "70 b5 8e b0 00 28 4f d0 05 46 08 a8 0c 46 40 21 ?? f? ?? f? 00 28 43 d0 2a 4a 08 a8 02 a9 ?? f? ?? f? e8 b3",
                "01 4a 7a 44 ?? f? ?? b"
            ],
            "anchor": "bssl::x509_to_buffer"
        }
    }
    }


    const MAX_ANCHOR_INSTRUCTIONS_TO_SCAN = 100;

    const CALL_MNEMONICS = ['call', 'bl', 'blx'];

    function scanForSignature(base, size, patterns) {
        const results = [];
        for (const pattern of patterns) {
            const result = Memory.scanSync(base, size, pattern);
            results.push(...result);
        }
        return results;
    }

    function scanForFunction(moduleRXRanges, platformPatterns, functionName, anchorFn) {
        const patternInfo = platformPatterns[functionName];
        const signatures = patternInfo.signatures;

        if (patternInfo.anchor) {
            const maxPatternByteLength = Math.max(...signatures.map(p => (p.length + 1) / 3));

            let addr = ptr(anchorFn);

            for (let i = 0; i < MAX_ANCHOR_INSTRUCTIONS_TO_SCAN; i++) {
                const instr = Instruction.parse(addr);
                addr = instr.next;
                if (CALL_MNEMONICS.includes(instr.mnemonic)) {
                    const callTargetAddr = ptr(instr.operands[0].value);
                    const results = scanForSignature(callTargetAddr, maxPatternByteLength, signatures);
                    if (results.length === 1) {
                        return results[0].address;
                    } else if (results.length > 1) {
                        console.log(`Found multiple matches for ${functionName} anchored by ${anchorFunction}:`, results);
                        throw new Error(`Found multiple matches for ${functionName}`);
                    }
                }
            }

            throw new Error(`Failed to find any match for ${functionName} anchored by ${anchorFn}`);
        } else {
            const results = moduleRXRanges.flatMap((range) => scanForSignature(range.base, range.size, signatures));
            if (results.length !== 1 && signatures.length > 1) {
                console.log(results);
                throw new Error(`Found multiple matches for ${functionName}`);
            }

            return results[0].address;
        }
    }

    function hookFlutter(moduleBase, moduleSize) {
        if (DEBUG_MODE) console.log('\n=== Disabling Flutter certificate pinning ===');

        const relevantRanges = Process.enumerateRanges('r-x').filter(range => {
            return range.base >= moduleBase && range.base < moduleBase.add(moduleSize);
        });

        try {
            const arch = Process.arch;
            const patterns = PATTERNS[`android/${arch}`];

            // This callback is called for all TLS connections. It immediately returns 1 (success) if BoringSSL
            // trusts the cert, or it calls the configured BadCertificateCallback if it doesn't. Note that this
            // is called for every cert in the chain individually - not the whole chain at once.
            const dartCertificateCallback = new NativeFunction(
                scanForFunction(relevantRanges, patterns, 'dart::bin::SSLCertContext::CertificateCallback'),
                'int',
                ['int', 'pointer']
            );

            // We inject code to check the certificate ourselves - getting the cert, converting to DER, and
            // ignoring all validation results if the certificate matches our trusted cert.
            const x509GetCurrentCert = new NativeFunction(
                scanForFunction(relevantRanges, patterns, 'X509_STORE_CTX_get_current_cert', dartCertificateCallback),
                'pointer',
                ['pointer']
            );

            // Just used as an anchor for searching:
            const x509ToBufferAddr = scanForFunction(relevantRanges, patterns, 'bssl::x509_to_buffer');
            const i2d_X509 = new NativeFunction(
                scanForFunction(relevantRanges, patterns, 'i2d_X509', x509ToBufferAddr),
                'int',
                ['pointer', 'pointer']
            );

            Interceptor.attach(dartCertificateCallback, {
                onEnter: function (args) {
                    this.x509Store = args[1];
                },
                onLeave: function (retval) {
                    if (retval.toInt32() === 1) return; // Ignore successful validations

                    // This certificate isn't trusted by BoringSSL or the app's certificate callback. Check it ourselves
                    // and override the result if it exactly matches our cert.
                    try {
                        const x509Cert = x509GetCurrentCert(this.x509Store);

                        const derLength = i2d_X509(x509Cert, NULL);
                        if (derLength <= 0) {
                            throw new Error('Failed to get DER length for X509 cert');
                        }

                        // We create our own target buffer (rather than letting BoringSSL do so, which would
                        // require more hooks to handle cleanup).
                        const derBuffer = Memory.alloc(derLength)
                        const outPtr = Memory.alloc(Process.pointerSize);
                        outPtr.writePointer(derBuffer);

                        const certDataLength = i2d_X509(x509Cert, outPtr)
                        const certData = new Uint8Array(derBuffer.readByteArray(certDataLength));

                        if (certData.every((byte, j) => CERT_DER[j] === byte)) {
                            retval.replace(1); // We trust this certificate, return success
                        }
                    } catch (error) {
                        console.error('[!] Internal error in Flutter certificate unpinning:', error);
                    }
                }
            });

            console.log('=== Flutter certificate pinning disabled ===');
        } catch (error) {
            console.error('[!] Error preparing Flutter certificate pinning hooks:', error);
            throw error;
        }
    }

    let flutter = Process.findModuleByName('libflutter.so');
    if (flutter) {
        hookFlutter(flutter.base, flutter.size);
    } else {
        waitForModule('libflutter.so', function (module) {
            hookFlutter(module.base, module.size);
        });
    }
})();