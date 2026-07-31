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
 * Flutter ships a separate engine build per mode: apps run with `flutter run` bundle the JIT
 * 'debug' engine, while `flutter build --release` bundles a distinct AOT 'release' engine, built
 * with LTO (and, on arm64, the LLVM machine outliner) so that the same functions compile to
 * visibly different code. We therefore carry a separate set of patterns for each, and detect
 * which engine is loaded at runtime.
 *
 * In release builds LTO also inlines X509_STORE_CTX_get_current_cert (a one-line accessor) into
 * its callers, so there is no function left to call. Instead we locate the instruction that reads
 * the field inside CertificateCallback and recover the struct offset from it, then read the
 * certificate out of the store directly.
 *
 * The patterns here have been generated from every non-patch release of Flutter from v2.0.0
 * to v3.44.0 (the latest at the time of writing). They may need updates for new versions
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
                    "41 57 41 56 41 54 53 48 83 ec 18 b8 01 00 00 00 83 ff 01 0f 84 ?? ?? ?? ?? 48 89 f3",
                    "41 57 41 56 53 48 83 ec 10 b8 01 00 00 00 83 ff 01 0f 84 ?? ?? ?? ?? 48 89 f3"
                ]
            },
            "X509_STORE_CTX_get_current_cert": {
                "signatures": [
                    "48 8b 87 b8 00 00 00 c3",
                    "48 8b 47 60 c3",
                    "48 8b 87 a8 00 00 00 c3",
                    "48 8b 47 50 c3"
                ],
                "anchor": "dart::bin::SSLCertContext::CertificateCallback"
            },
            "bssl::x509_to_buffer": {
                "signatures": [
                    "41 57 41 56 53 48 83 ec 10 48 89 f0 49 89 fe 48 89 e6 48 83 26 00 48 89 c7 e8",
                    "41 56 53 50 48 89 f0 48 89 fb 48 89 e6 48 83 26 00 48 89 c7 e8 ?? ?? ?? ?? 85 c0 7e 1b",
                    "53 48 83 ec 10 48 89 f0 48 89 fb 48 8d 74 24 08 48 83 26 00 48 89 c7 e8 ?? ?? ?? ?? 85 c0",
                    "41 56 53 48 83 ec 18 48 89 f0 4? 89 f? 48 8d 74 24 08 48 83 26 00 48 89 c7 e8"
                ]
            },
            "i2d_X509": {
                "signatures": [
                    "48 8d 15 ?? ?? ?? ?? e9",
                    "55 41 56 53 48 83 ec 70 48 85 ff 0f 84 ?? ?? ?? ?? 48 89 f3 49 89 fe 48 8d 7c 24 40 6a 40",
                    "55 41 57 41 56 53 48 83 ec 68 48 85 ff 0f 84 ?? ?? ?? ?? 48 89 f3 49 89 fe 4c 8d 7c 24 08",
                    "55 41 57 41 56 53 48 83 ec 68 48 85 ff 0f 84 ?? ?? ?? ?? 49 89 f6 49 89 ff 48 8d 5c 24 38"
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
                    "55 89 e5 83 e4 fc 8b 45 08 8b 40 64 89 ec 5d c3",
                    "55 89 e5 83 e4 fc 8b 45 08 8b 40 34 89 ec 5d c3",
                    "55 89 e5 83 e4 fc 8b 45 08 8b 40 5c 89 ec 5d c3",
                    "55 89 e5 83 e4 fc 8b 45 08 8b 40 2c 89 ec 5d c3"
                ],
                "anchor": "dart::bin::SSLCertContext::CertificateCallback"
            },
            "bssl::x509_to_buffer": {
                "signatures": [
                    "55 89 e5 53 57 56 83 e4 f0 83 ec 20 89 ce e8 ?? ?? ?? ?? 5b 81 c3 ?? ?? ?? ?? 8d 44 24 14 83 20 00 89 44 24 04 89 14 24",
                    "55 89 e5 53 57 56 83 e4 f0 83 ec 10 89 ce e8 ?? ?? ?? ?? 5b 81 c3 ?? ?? ?? ?? 8d 44 24 08 83 20 00 83 ec 08 50 52",
                    "55 89 e5 53 56 83 e4 f0 83 ec 10 89 ce e8 ?? ?? ?? ?? 5b 81 c3 ?? ?? ?? ?? 8d 44 24 0c 83 20 00 83 ec 08 50 52"
                ]
            },
            "i2d_X509": {
                "signatures": [
                    "55 89 e5 53 83 e4 f0 83 ec 10 e8 ?? ?? ?? ?? 5b 81 c3 ?? ?? ?? ?? 83 ec 04 8d 83 ?? ?? ?? ?? 50 ff 75 0c ff 75 08",
                    "55 89 e5 53 57 56 83 e4 f0 83 ec 40 e8 ?? ?? ?? ?? 5b 81 c3 ?? ?? ?? ?? 8b 7d 08 85 ff 0f 84 ?? ?? ?? ?? 83 ec 08",
                    "55 89 e5 53 57 56 83 e4 f0 83 ec 40 e8 ?? ?? ?? ?? 5b 81 c3 ?? ?? ?? ?? 8b 75 08 83 ec 0c 85 f6 0f 84",
                    "55 89 e5 53 57 56 83 e4 f0 83 ec 40 e8 ?? ?? ?? ?? 5b 81 c3 ?? ?? ?? ?? 83 ec 0c 83 7d 08 00 0f 84"
                ],
                "anchor": "bssl::x509_to_buffer"
            }
        },
        "android/arm64": {
            "dart::bin::SSLCertContext::CertificateCallback": {
                "signatures": [
                    "ff c3 00 d1 fe 57 01 a9 f4 4f 02 a9 1f 04 00 71 ?0 ?? ?? 54 f3 03 01 aa ?? ?? ?? 94 e0 07 00 b4 e0 03 13 aa",
                    "ff c3 00 d1 fe 57 01 a9 f4 4f 02 a9 1f 04 00 71 ?0 ?? ?? 54 f3 03 01 aa ?? ?? ?? 94 c0 09 00 b4 e0 03 13 aa",
                    "ff c3 00 d1 fe 57 01 a9 f4 4f 02 a9 1f 04 00 71 ?0 ?? ?? 54 f3 03 01 aa ?? ?? ?? 94 00 0a 00 b4 e0 03 13 aa"
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
                    "fe 0f 1e f8 f4 4f 01 a9 e8 03 01 aa f3 03 00 aa e1 ?? ?? 91 e0 03 08 aa ff 07 00 f9 ?? ?? ?? 97 1f 04 00 71",
                    "f? ?? ?? ?? f? 4f 01 a9 e1 ?? ?? 91 f3 03 08 aa ff 07 00 f9 ?? ?? ?? 97 1f 0? 00 71 ?? ?? ?? 54 e8 ?? ?? f9",
                    "ff c3 00 d1 fe 7f 01 a9 f4 4f 02 a9 e1 ?? ?? 91 f3 03 08 aa ?? ?? ?? 97 1f 0? 00 71 ?? ?? ?? 54 e8 ?? ?? f9"
                ]
            },
            "i2d_X509": {
                "signatures": [
                    "ff 43 02 d1 fe 57 07 a9 f4 4f 08 a9 a0 06 00 b4 f4 03 00 aa f3 03 01 aa e0 ?? ?? 91 01 08 80 52 ?? ?? ?? 97",
                    "?2 ?? ?? ?? 42 ?? ?? 91 ?? ?? ?? 17",
                    "ff 03 02 d1 fe 33 00 f9 f4 4f 07 a9 40 04 00 b4 ?? ?? ?? 94 e0 03 00 91 01 20 80 52 ?? ?? ?? 97 20 03 00 34",
                    "ff 43 02 d1 fe 57 07 a9 f4 4f 08 a9 00 06 00 b4 f4 03 00 aa e0 ?? ?? 91 f3 03 01 aa ?? ?? ?? 97 e0 ?? ?? 91"
                ],
                "anchor": "bssl::x509_to_buffer"
            }
        },
        "android/arm": {
            "dart::bin::SSLCertContext::CertificateCallback": {
                "signatures": [
                    "70 b5 84 b0 01 28 ?? d1 01 20 04 b0 70 bd 0c 46 ?? f? ?? f? 00 28 ?? d0 20 46 ?? f? ?? f? 0? 46 ??"
                ]
            },
            "X509_STORE_CTX_get_current_cert": {
                "signatures": [
                    "40 6b 70 47",
                    "40 6e 70 47",
                    "c0 6d 70 47",
                    "c0 6a 70 47"
                ],
                "anchor": "dart::bin::SSLCertContext::CertificateCallback"
            },
            "bssl::x509_to_buffer": {
                "signatures": [
                    "?c b5 00 2? 0a 46 01 9? 01 a9 04 46 10 46 ?? f? ?? f? 0? 28 ?? d? 01 46 01 98 00 22 ?? f? ??"
                ]
            },
            "i2d_X509": {
                "signatures": [
                    "70 b5 8e b0 00 28 ?? d0 05 46 08 a8 0c 46 40 21 ?? f? ?? f? 00 28 ?? d0 ?? 4a 08 a8 02 a9 ?? f? ?? f? ?? b3",
                    "?? 4a 7a 44 ?? f? ??",
                    "70 b5 8e b0 ?? b3 08 ae 05 46 0c 46 30 46 ?? f? ?? f? 30 46 40 21 ?? f? ?? f? ?? b3 ?? 4a 08 a8 02 a9",
                    "70 b5 8e b0 ?? b3 02 ae 05 46 0c 46 30 46 ?? f? ?? f? 30 46 4f f4 80 71 ?? f? ?? f? ?? b3 ?? 4a 02 a8 08 a9"
                ],
                "anchor": "bssl::x509_to_buffer"
            }
        },
        "android-release/x64": {
            "dart::bin::SSLCertContext::CertificateCallback": {
                "signatures": [
                    "41 57 41 56 53 48 83 ec 20 b8 01 00 00 00 83 ff 01 0f 84 ?? ?? ?? ?? 48 89 f3",
                    "41 57 41 56 41 54 53 48 83 ec 18 b? 01 00 00 00 83 ff 01 0f 84 ?? ?? ?? ?? 4? 89",
                    "41 57 41 56 41 54 53 48 83 ec 18 41 b? 01 00 00 00 83 ff 01 0f 84 ?? ?? ?? ?? 4? 89"
                ]
            },
            "bssl::x509_to_buffer": {
                "signatures": [
                    "41 56 53 48 83 ec 18 48 89 f0 49 89 fe 48 8d 74 24 08 48 83 26 00 48 89 c7 e8",
                    "41 56 53 50 48 89 f0 48 89 fb 48 89 e6 48 83 26 00 48 89 c7 e8 ?? ?? ?? ?? 85 c0 7e 1b",
                    "41 57 41 56 53 48 83 ec 10 48 89 f0 48 89 fb 48 8d 74 24 08 48 83 26 00 48 89 c7",
                    "53 48 83 ec 10 48 89 f0 48 89 fb 48 8d 74 24 08 48 83 26 00 48 89 c7 e8 ?? ?? ?? ?? 85 c0"
                ]
            },
            "i2d_X509": {
                "signatures": [
                    "48 8d 15 ?? ?? ?? ?? e9",
                    "55 41 56 53 48 81 ec 80 00 00 00 48 85 ff 0f 84 ?? ?? ?? ?? 48 89 f3 49 89 fe",
                    "41 57 41 56 53 48 83 ec 60 48 85 ff 0f 84 ?? ?? ?? ?? 49 89 f6 49 89 ff 48 89 e7",
                    "55 41 57 41 56 41 54 53 48 81 ec a0 00 00 00 48 85 ff 0f 84 ?? ?? ?? ?? 48 89 f3 49 89 fe"
                ],
                "anchor": "bssl::x509_to_buffer"
            },
            "X509_STORE_CTX::current_cert": {
                "anchor": "dart::bin::SSLCertContext::CertificateCallback",
                "anchorMode": "within",
                "signatures": [
                    "4c 8b bb b8 00 00 00",
                    "4d 8b 7e 60",
                    "4d 8b be a8 00 00 00",
                    "4d 8b 7e 50",
                    "49 8b 9e b8 00 00 00",
                    "4c 8b 73 50",
                    "4d 8b be b8 00 00 00"
                ]
            }
        },
        "android-release/arm64": {
            "dart::bin::SSLCertContext::CertificateCallback": {
                "signatures": [
                    "ff 03 01 d1 fe 0b 00 f9 f6 57 02 a9 f4 4f 03 a9 1f 04 00 71 ?0 ?? ?? 54"
                ]
            },
            "bssl::x509_to_buffer": {
                "signatures": [
                    "ff c3 00 d1 fe 7f 01 a9 f4 4f 02 a9 e1 ?? ?? 91 f3 03 08 aa ?? ?? ?? 97 1f 04 00 71 ?b ?? ?? 54 e8 ?? ?? f9",
                    "fe 0f 1e f8 f4 4f 01 a9 ?? ?? ?? 94 ff 07 00 f9 ?? ?? ?? 97 1f 04 00 71 ?b ?? ?? 54 e8 ?? ?? f9 e1 03 00 2a",
                    "ff c3 00 d1 fe 57 01 a9 f4 4f 02 a9 ?? ?? ?? 94 ?? ?? ?? 94 ff 07 00 f9 ?? ?? ?? 97 1f 04 00 71 ?b ?? ?? 54",
                    "f? ?? ?? ?? f? 4f 01 a9 e8 03 01 aa f3 03 00 aa ?? ?? ?? 94 ff 07 00 f9 ?? ?? ?? 97 1f 0? 00 71 ?? ?? ?? 54",
                    "ff c3 00 d1 fe 7f 01 a9 f4 4f 02 a9 ?? ?? ?? 94 e1 ?? ?? 91 e0 03 08 aa ?? ?? ?? 97 1f 0? 00 71 ?? ?? ?? 54"
                ]
            },
            "i2d_X509": {
                "signatures": [
                    "?2 ?? ?? ?? 42 ?? ?? 91 ?? ?? ?? 17",
                    "ff 83 02 d1 fe 57 08 a9 f4 4f 09 a9 a0 06 00 b4 ?? ?? ?? 94 e0 ?? ?? 91 ?? ?? ?? 94 e0 05 00 34 02 02 80 52",
                    "ff 83 02 d1 fe 57 08 a9 f4 4f 09 a9 c0 06 00 b4 ?? ?? ?? 94 e0 ?? ?? 91 ?? ?? ?? 94 00 06 00 34 02 02 80 52",
                    "ff 03 02 d1 fe 33 00 f9 f4 4f 07 a9 c0 03 00 b4 ?? ?? ?? 94 e0 03 00 91 ?? ?? ?? 94 e0 02 00 34 02 02 80 52",
                    "ff 43 03 d1 fe 53 00 f9 f6 57 0b a9 f4 4f 0c a9 60 09 00 b4 00 e4 00 6f ?? ?? ?? 94 ?? ?? ?? 94 e0 09 00 34"
                ],
                "anchor": "bssl::x509_to_buffer"
            },
            "X509_STORE_CTX::current_cert": {
                "anchor": "dart::bin::SSLCertContext::CertificateCallback",
                "anchorMode": "within",
                "signatures": [
                    "74 ?? ?? f9"
                ]
            }
        },
        "android-release/arm": {
            "dart::bin::SSLCertContext::CertificateCallback": {
                "signatures": [
                    "f0 b5 83 b0 01 28 ?? d1 01 20 03 b0 f0 bd ?? 48 0d 46 78 44 00 68 00 28 18 bf 82 f1 64 e9 ?? 48 78 44",
                    "f0 b5 83 b0 01 28 ?? d1 01 20 03 b0 f0 bd ?? 48 0? 46 78 44 00 68 00 28 18 bf ?0 f1 ?? eb ?? 48 78 44",
                    "f0 b5 83 b0 01 28 ?? d1 01 20 03 b0 f0 bd ?? 48 0c 46 78 44 00 68 00 28 18 bf 7? f1 ?? e? ?? 48 78 44",
                    "f0 b5 83 b0 01 28 ?? d1 01 20 03 b0 f0 bd ?? 48 0d 46 78 44 00 68 00 28 18 bf ?? f1 ?0 e? ?? 48 78 44",
                    "?0 b5 8? b0 01 28 ?? d1 01 20 0? b0 ?0 bd ?? 48 0? 46 78 44 ?? f? ?? e? 00 68 00 28 1c bf d0 f8 ?? 0? 00 28",
                    "f0 b5 83 b0 01 28 ?? d1 01 20 03 b0 f0 bd ?? 48 0d 46 78 44 00 68 00 28 18 bf 3? f1 ?? e? ?? 48 78 44"
                ]
            },
            "bssl::x509_to_buffer": {
                "signatures": [
                    "7c b5 00 2? 0a 46 01 9? 01 a9 04 46 10 46 ?? f? ?? f? 0? 28 ?? d? 01 ?? 01 ?? 00 22 ?? ?? ?? f? ?? ??",
                    "?c b5 00 2? 0a 46 01 9? 01 a9 04 46 10 46 ?? f? ?? f? 0? 28 ?? d? 01 46 01 98 00 22 ?? f? ?? f? ?? ??"
                ]
            },
            "i2d_X509": {
                "signatures": [
                    "?? 4a 7a 44 ?? f? ??",
                    "70 b5 90 b0 00 28 ?? d0 05 46 08 a8 0c 46 40 21 ?? f? ?? f? 00 28 ?? d0 ?? 4a 08 a8 02 a9 ?? f? ?? f? 00 28",
                    "b0 b5 8c b0 ?? b3 0c 46 05 46 68 46 4f f4 80 71 ?? f? ?? f? ?? b3 ?? 4a 06 a9 68 46 ?? f? ?? f? ?? b1 06 a8",
                    "f0 b5 95 b0 00 28 ?? d0 05 46 c0 ef 50 00 08 a8 0c 46 00 22 01 46 0d 92 41 f9 cd 0a 0a 60 40 21 ?? f? ??"
                ],
                "anchor": "bssl::x509_to_buffer"
            },
            "X509_STORE_CTX::current_cert": {
                "anchor": "dart::bin::SSLCertContext::CertificateCallback",
                "anchorMode": "within",
                "signatures": [
                    "65 6e 40 68",
                    "6c 6b 40 68",
                    "ec 6d 40 68",
                    "ec 6a 40 68",
                    "6c 6e 40 68",
                    "e5 6a 40 68"
                ]
            }
        }
    }


    // Not a function, but the instruction inside CertificateCallback that reads the field:
    const CURRENT_CERT_FIELD = 'X509_STORE_CTX::current_cert';

    const MAX_ANCHOR_INSTRUCTIONS_TO_SCAN = 100;

    // How much of CertificateCallback we scan to find the inlined field load. Every build
    // we've seen compiles it to well under this.
    const MAX_FUNCTION_BYTES_TO_SCAN = 0x400;

    const CALL_MNEMONICS = ['call', 'bl', 'blx'];

    // On ARM all of this code is Thumb, and both NativeFunction and Instruction.parse need the
    // low bit set to treat an address as Thumb rather than A32.
    const isArm32 = Process.arch === 'arm';
    const asCode = (address) => isArm32 ? address.or(1) : address;

    function scanForSignature(base, size, patterns) {
        const results = [];
        for (const pattern of patterns) {
            const result = Memory.scanSync(base, size, pattern);
            results.push(...result);
        }
        return results;
    }

    /**
     * Finds a function that we're going to call or hook, so its address has to be exactly
     * right: we require one unambiguous match, and fail loudly otherwise.
     *
     * Where the function is anchored, the anchor's call target is the function entry by
     * definition, so we can confirm the address outright: we accept a signature only if it
     * matches at the call target itself, never part-way into it.
     */
    function scanForFunction(moduleRXRanges, platformPatterns, functionName, anchorFn) {
        const patternInfo = platformPatterns[functionName];
        const signatures = patternInfo.signatures;

        if (patternInfo.anchor) {
            const maxPatternByteLength = Math.max(...signatures.map(p => (p.length + 1) / 3));

            let addr = asCode(ptr(anchorFn));

            for (let i = 0; i < MAX_ANCHOR_INSTRUCTIONS_TO_SCAN; i++) {
                const instr = Instruction.parse(addr);
                addr = instr.next;
                if (CALL_MNEMONICS.includes(instr.mnemonic)) {
                    const callTargetAddr = ptr(instr.operands[0].value);
                    const results = scanForSignature(callTargetAddr, maxPatternByteLength, signatures);
                    if (results.some(result => result.address.equals(callTargetAddr))) {
                        return callTargetAddr;
                    }
                }
            }

            throw new Error(`Failed to find any match for ${functionName} anchored by ${anchorFn}`);
        } else {
            const results = moduleRXRanges.flatMap((range) => scanForSignature(range.base, range.size, signatures));

            if (results.length !== 1) {
                // Not necessarily a problem: we scan with each build's patterns in turn, so
                // failing to match here is how we recognise the other kind of build.
                if (DEBUG_MODE) console.log(`Matches for ${functionName}:`, results);
                throw new Error(`Found ${results.length} matches for ${functionName}`);
            }

            return results[0].address;
        }
    }

    /**
     * Finds a function that's only used as a starting point to scan forwards from, never
     * called. That means we don't need its exact entry point, which matters because
     * signatures overlap here: one generated from a build with a shorter prologue also
     * matches part-way into the same function in a build with a longer one.
     *
     * We only tolerate matches that fall inside the extent of the first match, which proves
     * they cover the same code rather than a second, unrelated site.
     */
    function scanForAnchor(moduleRXRanges, platformPatterns, functionName) {
        const signatures = platformPatterns[functionName].signatures;
        const results = moduleRXRanges
            .flatMap((range) => scanForSignature(range.base, range.size, signatures))
            .sort((a, b) => a.address.compare(b.address));

        if (results.length === 0) throw new Error(`Failed to find any match for ${functionName}`);

        const firstMatchEnd = results[0].address.add(results[0].size);
        const overlapping = results.every(result => result.address.compare(firstMatchEnd) < 0);

        if (!overlapping) {
            throw new Error(`Found ${results.length} separate matches for ${functionName}`);
        }

        return results[0].address;
    }

    /**
     * Recovers the offset of X509_STORE_CTX->current_cert. In release builds the accessor is
     * inlined, so we find the single instruction inside CertificateCallback that reads the
     * field and take the displacement straight out of it. That way a future BoringSSL layout
     * change is picked up automatically, rather than silently reading the wrong field.
     */
    function findCurrentCertOffset(platformPatterns, certificateCallbackAddr) {
        const patternInfo = platformPatterns[CURRENT_CERT_FIELD];

        const results = scanForSignature(
            certificateCallbackAddr,
            MAX_FUNCTION_BYTES_TO_SCAN,
            patternInfo.signatures
        );

        if (results.length !== 1) {
            throw new Error(`Found ${results.length} matches for ${CURRENT_CERT_FIELD} - expected exactly one`);
        }

        const instruction = Instruction.parse(asCode(results[0].address));
        const memoryOperand = instruction.operands.find(op => op.type === 'mem');

        if (!memoryOperand) {
            throw new Error(`No memory operand in ${CURRENT_CERT_FIELD} instruction: ${instruction}`);
        }

        const offset = memoryOperand.value.disp;
        if (!offset) {
            throw new Error(`Implausible ${CURRENT_CERT_FIELD} offset ${offset} from: ${instruction}`);
        }

        return offset;
    }

    /**
     * Resolves everything we need to hook, using one specific set of patterns. This has to
     * succeed or fail as a whole: a pattern set for the wrong engine build can match one
     * function by chance, and we want to fall through to the next set if it does, rather
     * than hooking a half-resolved mixture.
     */
    function resolveTargets(moduleRXRanges, patterns) {
        const certificateCallbackAddr = scanForFunction(moduleRXRanges, patterns, 'dart::bin::SSLCertContext::CertificateCallback');

        // Where the accessor still exists we call it; where LTO inlined it (all release
        // builds) we recover the field offset and read the store directly.
        let getCurrentCert;
        if (patterns[CURRENT_CERT_FIELD]) {
            const currentCertOffset = findCurrentCertOffset(patterns, certificateCallbackAddr);
            if (DEBUG_MODE) console.log(`X509_STORE_CTX->current_cert at +0x${currentCertOffset.toString(16)}`);
            getCurrentCert = (storeCtx) => storeCtx.add(currentCertOffset).readPointer();
        } else {
            const x509GetCurrentCert = new NativeFunction(
                asCode(scanForFunction(moduleRXRanges, patterns, 'X509_STORE_CTX_get_current_cert', certificateCallbackAddr)),
                'pointer',
                ['pointer']
            );
            getCurrentCert = (storeCtx) => x509GetCurrentCert(storeCtx);
        }

        // x509_to_buffer is just used as an anchor for searching:
        const x509ToBufferAddr = scanForAnchor(moduleRXRanges, patterns, 'bssl::x509_to_buffer');
        const i2d_X509 = new NativeFunction(
            asCode(scanForFunction(moduleRXRanges, patterns, 'i2d_X509', x509ToBufferAddr)),
            'int',
            ['pointer', 'pointer']
        );

        return { certificateCallbackAddr, getCurrentCert, i2d_X509 };
    }

    /** Works out which engine build is loaded, by seeing whose patterns actually match. */
    function findTargets(moduleRXRanges) {
        // Frida calls 32-bit x86 'ia32', but our patterns are keyed by the name Flutter
        // uses for the same architecture.
        const arch = Process.arch === 'ia32' ? 'x86' : Process.arch;
        const candidates = [`android-release/${arch}`, `android/${arch}`];

        for (const key of candidates) {
            if (!PATTERNS[key]) continue;

            try {
                const targets = resolveTargets(moduleRXRanges, PATTERNS[key]);
                if (DEBUG_MODE) console.log(`Matched Flutter ${key} patterns`);
                return targets;
            } catch (e) {
                // Expected for whichever engine build isn't loaded - we just try the next.
                if (DEBUG_MODE) console.log(`Flutter ${key} patterns don't apply here: ${e.message}`);
            }
        }

        throw new Error(`Could not match any known Flutter patterns for ${Process.arch}`);
    }

    function hookFlutter(moduleBase, moduleSize) {
        if (DEBUG_MODE) console.log('\n=== Disabling Flutter certificate pinning ===');

        const relevantRanges = Process.enumerateRanges('r-x').filter(range => {
            return range.base >= moduleBase && range.base < moduleBase.add(moduleSize);
        });

        try {
            const { certificateCallbackAddr, getCurrentCert, i2d_X509 } = findTargets(relevantRanges);

            // This callback is called for all TLS connections. It immediately returns 1 (success) if BoringSSL
            // trusts the cert, or it calls the configured BadCertificateCallback if it doesn't. Note that this
            // is called for every cert in the chain individually - not the whole chain at once.
            const dartCertificateCallback = new NativeFunction(
                asCode(certificateCallbackAddr),
                'int',
                ['int', 'pointer']
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
                        const x509Cert = getCurrentCert(this.x509Store);

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