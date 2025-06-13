(() => {
    'use strict';

    const CONFIG = {
        fingerprint: "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys",
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

    const Logger = {
        prefix: "RootBypass: ",
        info(message) {
            console.log(`${this.prefix}${message}`);
        },
        error(message, error) {
            console.error(`${this.prefix}ERROR: ${message}`, error || "");
        }
    };

    function bypassNativeFileCheck() {
        const fopen = Module.findExportByName("libc.so", "fopen");
        if (fopen) {
            Interceptor.attach(fopen, {
                onEnter(args) {
                    this.path = args[0].readUtf8String();
                },
                onLeave(retval) {
                    if (retval.toInt32() !== 0) {
                        const path = this.path.toLowerCase();
                        if (ROOT_INDICATORS.paths.has(this.path) || path.includes("magisk") || path.includes("/su") || path.endsWith("/su")) {
                            Logger.info(`Blocked fopen: ${this.path}`);
                            retval.replace(ptr(0x0));
                        }
                    }
                }
            });
        }

        const access = Module.findExportByName("libc.so", "access");
        if (access) {
            Interceptor.attach(access, {
                onEnter(args) {
                    this.path = args[0].readUtf8String();
                },
                onLeave(retval) {
                    if (retval.toInt32() === 0) {
                        const path = this.path.toLowerCase();
                        if (ROOT_INDICATORS.paths.has(this.path) || path.includes("magisk") || path.includes("/su") || path.endsWith("/su")) {
                            Logger.info(`Blocked access: ${this.path}`);
                            retval.replace(ptr(-1));
                        }
                    }
                }
            });
        }

        const stat = Module.findExportByName("libc.so", "stat");
        if (stat) {
            Interceptor.attach(stat, {
                onEnter(args) {
                    this.path = args[0].readUtf8String();
                },
                onLeave(retval) {
                    const path = this.path.toLowerCase();
                    if (ROOT_INDICATORS.paths.has(this.path) || path.includes("magisk") || path.includes("/su") || path.endsWith("/su")) {
                        Logger.info(`Blocked stat: ${this.path}`);
                        retval.replace(ptr(-1));
                    }
                }
            });
        }

        const lstat = Module.findExportByName("libc.so", "lstat");
        if (lstat) {
            Interceptor.attach(lstat, {
                onEnter(args) {
                    this.path = args[0].readUtf8String();
                },
                onLeave(retval) {
                    const path = this.path.toLowerCase();
                    if (ROOT_INDICATORS.paths.has(this.path) || path.includes("magisk") || path.includes("/su") || path.endsWith("/su")) {
                        Logger.info(`Blocked lstat: ${this.path}`);
                        retval.replace(ptr(-1));
                    }
                }
            });
        }
    }

    function bypassJavaFileCheck() {
        const UnixFileSystem = Java.use("java.io.UnixFileSystem");
        UnixFileSystem.checkAccess.implementation = function(file, access) {
            const filename = file.getAbsolutePath();
            if (ROOT_INDICATORS.paths.has(filename) || filename.includes("magisk") || filename.includes("su")) {
                Logger.info(`Blocked file access check: ${filename}`);
                return false;
            }
            return this.checkAccess(file, access);
        };

        const File = Java.use("java.io.File");
        File.exists.implementation = function() {
            const filename = this.getAbsolutePath();
            if (ROOT_INDICATORS.paths.has(filename) || filename.includes("magisk") || filename.includes("su")) {
                Logger.info(`Blocked file exists check: ${filename}`);
                return false;
            }
            return this.exists();
        };

        File.length.implementation = function() {
            const filename = this.getAbsolutePath();
            if (ROOT_INDICATORS.paths.has(filename) || filename.includes("magisk") || filename.includes("su")) {
                Logger.info(`Blocked file length check: ${filename}`);
                return 0;
            }
            return this.length();
        };

        const FileInputStream = Java.use("java.io.FileInputStream");
        FileInputStream.$init.overload('java.io.File').implementation = function(file) {
            const filename = file.getAbsolutePath();
            if (ROOT_INDICATORS.paths.has(filename) || filename.includes("magisk") || filename.includes("su")) {
                Logger.info(`Blocked FileInputStream creation: ${filename}`);
                throw new Java.use("java.io.FileNotFoundException").$new(filename);
            }
            return this.$init(file);
        };
    }

    function setProp() {
        try {
            const Build = Java.use("android.os.Build");
            const fields = {
                "TAGS": "release-keys",
                "TYPE": "user",
                "FINGERPRINT": CONFIG.fingerprint
            };

            Object.entries(fields).forEach(([field, value]) => {
                const fieldObj = Build.class.getDeclaredField(field);
                fieldObj.setAccessible(true);
                fieldObj.set(null, value);
            });

            const system_property_get = Module.findExportByName("libc.so", "__system_property_get");
            if (system_property_get) {
                Interceptor.attach(system_property_get, {
                    onEnter(args) {
                        this.key = args[0].readCString();
                        this.ret = args[1];
                    },
                    onLeave(retval) {
                        const secureValue = CONFIG.secureProps[this.key];
                        if (secureValue !== undefined) {
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
                        Logger.info(`Blocked getprop command: ${cmd}`);
                        return null;
                    }
                }
                return this.exec(cmd);
            };
        } catch (error) {
            Logger.error("Error setting up build properties bypass", error);
        }
    }

    function bypassRootPackageCheck() {
        const ApplicationPackageManager = Java.use("android.app.ApplicationPackageManager");
                
        ApplicationPackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(str, i) {
            if (ROOT_INDICATORS.packages.has(str)) {
                Logger.info(`Blocked package check: ${str}`);
                str = "com.nonexistent.package";
            }
            return this.getPackageInfo(str, i);
        };

        ApplicationPackageManager.getInstalledPackages.overload('int').implementation = function(flags) {
            const packages = this.getInstalledPackages(flags);
            const packageList = packages.toArray();
            const filteredPackages = packageList.filter(pkg => !ROOT_INDICATORS.packages.has(pkg.packageName.value));
            return Java.use("java.util.ArrayList").$new(filteredPackages);
        };
    }

    function bypassShellCommands() {
        try {
            const ProcessBuilder = Java.use('java.lang.ProcessBuilder');
            ProcessBuilder.command.overload('java.util.List').implementation = function(commands) {
                const cmdList = commands.toArray();
                if (cmdList.length > 0) {
                    const cmd = cmdList[0].toString();
                    if (ROOT_INDICATORS.commands.has(cmd) || (cmdList.length > 1 && ROOT_INDICATORS.binaries.has(cmdList[1].toString()))) {
                        Logger.info(`Blocked ProcessBuilder command: ${cmdList.join(' ')}`);
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
                        Logger.info(`Blocked Runtime.exec command array: ${cmdArray.join(' ')}`);
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
                        Logger.info(`Blocked ProcessImpl command: ${cmdArray.join(' ')}`);
                        return ProcessImpl.start.call(this, [Java.use("java.lang.String").$new("")], env, dir, redirects, redirectErrorStream);
                    }
                }
                return ProcessImpl.start.call(this, cmdArray, env, dir, redirects, redirectErrorStream);
            };
        } catch (error) {
            Logger.error("Error setting up shell command bypass", error);
        }
    }

    Logger.info("Initializing root detection bypass...");
    bypassNativeFileCheck();
    bypassJavaFileCheck();
    setProp();
    bypassRootPackageCheck();
    bypassShellCommands();
    Logger.info("Root detection bypass initialized successfully");
})();
