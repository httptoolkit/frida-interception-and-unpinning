# Frida Mobile Interception Scripts

> _Part of [HTTP Toolkit](https://httptoolkit.com/android): powerful tools for building, testing & debugging HTTP(S)_

This repo contains a set of Frida scripts designed to do everything required for fully automated HTTPS MitM interception on mobile devices.

They can be used all together, to handle interception, manage certificate trust & disabling certificate pinning & transparency checks, for MitM interception of HTTP(S) traffic on Android (iOS coming soon!), or they can be used and tweaked independently to hook just specific features.

The scripts can automatically handle:

* Redirection of traffic to an HTTP(S) proxy - modifying both system settings & directly redirecting all socket connections
* Injecting a given CA certificate into the system trust stores
* Disabling all known certificate pinning tools
* Fallback detection of remaining pinning failures, to provide auth-patching of obfuscated certificate pinning (in fully obfuscated apps, the first request may fail, but this will trigger additional patching so that all subsequent requests work correctly)

To get started:

1. Start your MitM proxy (e.g. [HTTP Toolkit](https://httptoolkit.com/android/)), and set up your rooted Android device or emulator, connected to ADB.
2. Find your MitM proxy's port (e.g. 8000) and its CA certificate in PEM format (should start with `-----BEGIN CERTIFICATE-----`).
3. Open `config.js`, and add those details:
    * `CERT_PEM`: your CA certificate in PEM format
    * `PROXY_PORT`: the proxy's port
    * `PROXY_HOST`: the address of your proxy, from the perspective of your device (or use `adb reverse tcp:$PORT tcp:$PORT` to forward the port over ADB, and use `127.0.0.1` as the host)
4. Install & start Frida on your device (e.g. download the relevant server from [github.com/frida/frida](https://github.com/frida/frida/releases/latest), extract it, `adb push` it to your device, and then run it with `adb shell`, `su`, `chmod +x /.../frida-server`, `/.../frida-server`).
5. Find the package id for the app you're interested in (for a quick test, try using [github.com/httptoolkit/android-ssl-pinning-demo](https://github.com/httptoolkit/android-ssl-pinning-demo) - the package id is `tech.httptoolkit.pinning_demo`)
6. Use Frida to launch the app you're interested in with the scripts injected (starting with `config.js`). Which scripts to use is up to you, but for Android a good command to start with is:
    ```bash
    frida -U \
        -l ./config.js \
        -l ./native-connect-hook.js \
        -l ./android/android-proxy-override.js \
        -l ./android/android-system-certificate-injection.js \
        -l ./android/android-certificate-unpinning.js \
        -l ./android/android-certificate-unpinning-fallback.js \
        -f $PACKAGE_ID
    ```
7. Explore, examine & modify all the traffic you're interested in! If you have any problems, please [open an issue](https://github.com/httptoolkit/frida-android-unpinning/issues/new) and help make these scripts even better.
