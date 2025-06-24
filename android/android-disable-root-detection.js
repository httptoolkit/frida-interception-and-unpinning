/**************************************************************************************************
 *
 * This script defines a large set of root detection bypasses for Android. Hooks included here
 * block detection of many known root indicators, including file paths, package names, commands,
 * notably binaries, and system properties.
 *
 * Enable DEBUG_MODE to see debug output for each bypassed check.
 *
 * Source available at https://github.com/httptoolkit/frida-interception-and-unpinning/
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Tim Perry <tim@httptoolkit.com>
 * SPDX-FileCopyrightText: Riyad Mondal
 *
 *************************************************************************************************/

(() => {
    let loggedRootDetectionWarning = false;
    function logFirstRootDetection() {
        if (!loggedRootDetectionWarning) {
            console.log(" => Blocked possible root detection checks. Enable DEBUG_MODE for more details.");
            loggedRootDetectionWarning = true;
        }
    }

    const LIB_C = Process.findModuleByName("libc.so");

    const BUILD_FINGERPRINT_REGEX = /^([\w.-]+\/[\w.-]+\/[\w.-]+):([\w.]+\/[\w.-]+\/[\w.-]+):(\w+\/[\w,.-]+)$/;

    const CONFIG = {
        secureProps: {
            "ro.secure": "1",
            "ro.debuggable": "0",
            "ro.build.type": "user",
            "ro.build.tags": "release-keys"
        }
    };

    const ROOT_INDICATORS = {
        paths: new Set([
            "/data/local/bin/su",
            "/data/local/su",
            "/data/local/xbin/su",
            "/dev/com.koushikdutta.superuser.daemon/",
            "/sbin/su",
            "/su/bin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/system/sbin/su",
            "/vendor/bin/su",
            "/data/adb/su/bin/su",
            "/system/bin/failsafe/su",
            "/system/bin/.ext/.su",
            "/system/bin/.ext/su",
            "/system/bin/failsafe/su",
            "/system/sd/xbin/su",
            "/system/usr/we-need-root/su",
            "/cache/su",
            "/data/su",
            "/dev/su",
            "/data/adb/magisk",
            "/sbin/.magisk",
            "/cache/.disable_magisk",
            "/dev/.magisk.unblock",
            "/cache/magisk.log",
            "/data/adb/magisk.img",
            "/data/adb/magisk.db",
            "/data/adb/magisk_simple",
            "/init.magisk.rc",
            "/system/app/Superuser.apk",
            "/system/etc/init.d/99SuperSUDaemon",
            "/system/xbin/daemonsu",
            "/system/xbin/ku.sud",
            "/data/adb/ksu",
            "/data/adb/ksud",
            "/system/xbin/busybox",
            "/system/app/Kinguser.apk"
        ]),

        packages: new Set([
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.koushikdutta.rommanager",
            "com.koushikdutta.rommanager.license",
            "com.dimonvideo.luckypatcher",
            "com.chelpus.lackypatch",
            "com.ramdroid.appquarantine",
            "com.ramdroid.appquarantinepro",
            "com.topjohnwu.magisk",
            "me.weishu.kernelsu"
        ]),

        commands: new Set([
            "su",
            "which su",
            "whereis su",
            "locate su",
            "find / -name su",
            "mount",
            "magisk",
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/su/bin/su"
        ]),

        binaries: new Set([
            "su",
            "busybox",
            "magisk",
            "supersu",
            "ksud",
            "daemonsu"
        ])
    };

    function bypassNativeFileCheck() {
        const fopen = LIB_C.findExportByName("fopen");
        if (fopen) {
            Interceptor.attach(fopen, {
                onEnter(args) {
                    this.path = args[0].readUtf8String();
                },
                onLeave(retval) {
                    if (retval.toInt32() !== 0) {
                        const path = this.path.toLowerCase();
                        if (ROOT_INDICATORS.paths.has(this.path) || path.includes("magisk") || path.includes("/su") || path.endsWith("/su")) {
                            if (DEBUG_MODE) {
                                console.log(`Blocked possible root-detection: fopen ${this.path}`);
                            } else logFirstRootDetection();
                            retval.replace(ptr(0x0));
                        }
                    }
                }
            });
        }

        const access = LIB_C.findExportByName("access");
        if (access) {
            Interceptor.attach(access, {
                onEnter(args) {
                    this.path = args[0].readUtf8String();
                },
                onLeave(retval) {
                    if (retval.toInt32() === 0) {
                        const path = this.path.toLowerCase();
                        if (ROOT_INDICATORS.paths.has(this.path) || path.includes("magisk") || path.includes("/su") || path.endsWith("/su")) {
                            if (DEBUG_MODE) {
                                console.debug(`Blocked possible root detection: access ${this.path}`);
                            } else logFirstRootDetection();
                            retval.replace(ptr(-1));
                        }
                    }
                }
            });
        }

        const stat = LIB_C.findExportByName("stat");
        if (stat) {
            Interceptor.attach(stat, {
                onEnter(args) {
                    this.path = args[0].readUtf8String();
                },
                onLeave(retval) {
                    const path = this.path.toLowerCase();
                    if (ROOT_INDICATORS.paths.has(this.path) || path.includes("magisk") || path.includes("/su") || path.endsWith("/su")) {
                        if (DEBUG_MODE) {
                            console.debug(`Blocked possible root detection: stat ${this.path}`);
                        } else logFirstRootDetection();
                        retval.replace(ptr(-1));
                    }
                }
            });
        }

        const lstat = LIB_C.findExportByName("lstat");
        if (lstat) {
            Interceptor.attach(lstat, {
                onEnter(args) {
                    this.path = args[0].readUtf8String();
                },
                onLeave(retval) {
                    const path = this.path.toLowerCase();
                    if (ROOT_INDICATORS.paths.has(this.path) || path.includes("magisk") || path.includes("/su") || path.endsWith("/su")) {
                        if (DEBUG_MODE) {
                            console.debug(`Blocked possible root detection: lstat ${this.path}`);
                        } else logFirstRootDetection();
                        retval.replace(ptr(-1));
                    }
                }
            });
        }
    }

    function bypassJavaFileCheck() {
        function isRootIndicatorFile(file) {
            const path = file.getAbsolutePath();
            const filename = file.getName();
            return ROOT_INDICATORS.paths.has(path) ||
                path.includes("magisk") ||
                filename === "su";
        }

        const UnixFileSystem = Java.use("java.io.UnixFileSystem");
        UnixFileSystem.checkAccess.implementation = function(file, access) {
            if (isRootIndicatorFile(file)) {
                if (DEBUG_MODE) {
                    console.debug(`Blocked possible root detection: filesystem access check for ${file.getAbsolutePath()}`);
                } else logFirstRootDetection();
                return false;
            }
            return this.checkAccess(file, access);
        };

        const File = Java.use("java.io.File");
        File.exists.implementation = function() {
            if (isRootIndicatorFile(this)) {
                if (DEBUG_MODE) {
                    console.debug(`Blocked possible root detection: file exists check for ${this.getAbsolutePath()}`);
                } else logFirstRootDetection();
                return false;
            }
            return this.exists();
        };

        File.length.implementation = function() {
            if (isRootIndicatorFile(this)) {
                if (DEBUG_MODE) {
                    console.debug(`Blocked possible root detection: file length check for ${this.getAbsolutePath()}`);
                } else logFirstRootDetection();
                return 0;
            }
            return this.length();
        };

        const FileInputStream = Java.use("java.io.FileInputStream");
        FileInputStream.$init.overload('java.io.File').implementation = function(file) {
            if (isRootIndicatorFile(file)) {
                if (DEBUG_MODE) {
                    console.debug(`Blocked possible root detection: file stream for ${file.getAbsolutePath()}`);
                } else logFirstRootDetection();
                throw Java.use("java.io.FileNotFoundException").$new(file.getAbsolutePath());
            }
            return this.$init(file);
        };
    }

    function setProp() {
        const Build = Java.use("android.os.Build");

        // We do a little work to make the minimum changes required to hide in the BUILD fingerprint,
        // but otherwise keep matching the real device wherever possible.
        const realFingerprint = Build.FINGERPRINT.value;

        const fingerprintMatch = BUILD_FINGERPRINT_REGEX.exec(realFingerprint);
        let fixedFingerprint;
        if (fingerprintMatch) {
            let [, device, versions, tags] = BUILD_FINGERPRINT_REGEX.exec(realFingerprint);
            tags = 'user/release-keys'; // Should always be the case in production builds
            if (device.includes('generic') || device.includes('sdk') || device.includes('lineage')) {
                device = 'google/raven/raven';
            }

            fixedFingerprint = `${device}:${versions}:${tags}`;
        } else {
            console.warn(`Unexpected BUILD fingerprint format: ${realFingerprint}`);
            // This should never happen in theory (the format is standard), but just in case,
            // we use this fallback fingerprint:
            fixedFingerprint = "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys";
        }

        const fields = {
            "TAGS": "release-keys",
            "TYPE": "user",
            "FINGERPRINT": fixedFingerprint
        };

        Object.entries(fields).forEach(([field, value]) => {
            const fieldObj = Build.class.getDeclaredField(field);
            fieldObj.setAccessible(true);
            fieldObj.set(null, value);
        });

        const system_property_get = LIB_C.findExportByName("__system_property_get");
        if (system_property_get) {
            Interceptor.attach(system_property_get, {
                onEnter(args) {
                    this.key = args[0].readCString();
                    this.ret = args[1];
                },
                onLeave(retval) {
                    const secureValue = CONFIG.secureProps[this.key];
                    if (secureValue !== undefined) {
                        if (DEBUG_MODE) {
                            console.debug(`Blocked possible root detection: system_property_get ${this.key}`);
                        } else logFirstRootDetection();
                        const valuePtr = Memory.allocUtf8String(secureValue);
                        Memory.copy(this.ret, valuePtr, secureValue.length + 1);
                    }
                }
            });
        }

        const Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
            if (cmd.startsWith("getprop ")) {
                const prop = cmd.split(" ")[1];
                if (CONFIG.secureProps[prop]) {
                    if (DEBUG_MODE) {
                        console.debug(`Blocked possible root detection: getprop ${prop}`);
                    } else logFirstRootDetection();
                    return null;
                }
            }
            return this.exec(cmd);
        };
    }

    function bypassRootPackageCheck() {
        const ApplicationPackageManager = Java.use("android.app.ApplicationPackageManager");

        ApplicationPackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(str, i) {
            if (ROOT_INDICATORS.packages.has(str)) {
                if (DEBUG_MODE) {
                    console.debug(`Blocked possible root detection: package info for ${str}`);
                } else logFirstRootDetection();
                str = "invalid.example.nonexistent.package";
            }
            return this.getPackageInfo(str, i);
        };

        ApplicationPackageManager.getInstalledPackages.overload('int').implementation = function(flags) {
            const packages = this.getInstalledPackages(flags);
            const packageList = packages.toArray();
            const filteredPackages = packageList.filter(pkg => !ROOT_INDICATORS.packages.has(pkg.packageName?.value));
            return Java.use("java.util.ArrayList").$new(Java.use("java.util.Arrays").asList(filteredPackages));
        };
    }

    function bypassShellCommands() {
        const ProcessBuilder = Java.use('java.lang.ProcessBuilder');
        ProcessBuilder.command.overload('java.util.List').implementation = function(commands) {
            const cmdArray = commands.toArray();
            if (cmdArray.length > 0) {
                const cmd = cmdArray[0].toString();
                if (ROOT_INDICATORS.commands.has(cmd) || (cmdArray.length > 1 && ROOT_INDICATORS.binaries.has(cmdArray[1].toString()))) {
                    if (DEBUG_MODE) {
                        console.debug(`Blocked possible root detection: ProcessBuilder with ${cmdArray.join(' ')}`);
                    } else logFirstRootDetection();
                    return this.command(Java.use("java.util.Arrays").asList([""]));
                }
            }
            return this.command(commands);
        };

        const Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmdArray) {
            if (cmdArray.length > 0) {
                const cmd = cmdArray[0];
                if (ROOT_INDICATORS.commands.has(cmd) || (cmdArray.length > 1 && ROOT_INDICATORS.binaries.has(cmdArray[1]))) {
                    if (DEBUG_MODE) {
                        console.debug(`Blocked possible root detection: Runtime.exec for ${cmdArray.join(' ')}`);
                    } else logFirstRootDetection();
                    return this.exec([""]);
                }
            }
            return this.exec(cmdArray);
        };

        const ProcessImpl = Java.use("java.lang.ProcessImpl");
        ProcessImpl.start.implementation = function(cmdArray, env, dir, redirects, redirectErrorStream) {
            if (cmdArray.length > 0) {
                const cmd = cmdArray[0].toString();
                const arg = cmdArray.length > 1 ? cmdArray[1].toString() : "";

                if (ROOT_INDICATORS.commands.has(cmd) || ROOT_INDICATORS.binaries.has(arg)) {
                    if (DEBUG_MODE) {
                        console.debug(`Blocked possible root detection: ProcessImpl.start for ${cmdArray.join(' ')}`);
                    } else logFirstRootDetection();
                    return ProcessImpl.start.call(this, [Java.use("java.lang.String").$new("")], env, dir, redirects, redirectErrorStream);
                }
            }
            return ProcessImpl.start.call(this, cmdArray, env, dir, redirects, redirectErrorStream);
        };
    }

    try {
        bypassNativeFileCheck();
        bypassJavaFileCheck();
        setProp();
        bypassRootPackageCheck();
        bypassShellCommands();
        console.log("== Disabled Android root detection ==");
    } catch (error) {
        console.error("\n !!! Error setting up root detection bypass !!!", error);
    }
})();
