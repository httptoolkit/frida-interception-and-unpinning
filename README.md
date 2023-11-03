# Frida Mobile Interception Scripts [![Funded by NLnet - NGI Zero Entrust](https://img.shields.io/badge/Funded%20by%20NLnet-NGI%20Zero%20Entrust-98bf00?logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNjcuNCAxNjguMiI%2BPHBhdGggZD0iTTEyNyA0NC45YzEuNC0xMS0xLjMtMjAuOC04LjEtMjkuNVMxMDMuMiAxLjcgOTIuMi40cy0yMC43IDEuMi0yOS40IDhBMzggMzggMCAwIDAgNDggMzIuNmwtLjQgMi41LS4yIDIuNWEzOS4zIDM5LjMgMCAwIDAgOC40IDI3QTM4IDM4IDAgMCAwIDgwIDc5LjNsMi40LjQgMS4zLjJhNDQgNDQgMCAwIDEgNS4yLTEyLjQgMzguMSAzOC4xIDAgMCAxLTQuNy0uMUg4NEEyNi41IDI2LjUgMCAwIDEgNjUuNyA1NyAyNi41IDI2LjUgMCAwIDEgNjAgNDJhMjcuOCAyNy44IDAgMCAxIC4yLTUuM3YtLjJjMS03LjUgNC40LTEzLjUgMTAuNC0xOC4xYTI2IDI2IDAgMCAxIDIwLjItNS42IDI2IDI2IDAgMCAxIDE4LjMgMTAuMyAyNyAyNyAwIDAgMSA0LjcgMjUuMWM0LjItMS4zIDguNi0yIDEzLjItMmwuMi0xLjN6bTUuMyA2LjYtMi41LS4zYTM5LjQgMzkuNCAwIDAgMC0yNyA4LjVBMzguNCAzOC40IDAgMCAwIDg4IDgzLjhjNC4zLjggOC4zIDIgMTIgMy45YTI2LjUgMjYuNSAwIDAgMSAxMC4zLTE4LjFjNC42LTMuNiA5LjYtNS42IDE1LTZhMjcuOCAyNy44IDAgMCAxIDUuNC4zaC4xYzcuNSAxIDEzLjUgNC40IDE4LjIgMTAuNGEyNiAyNiAwIDAgMSA1LjYgMjAuMiAyNy4zIDI3LjMgMCAwIDEtMzAuNSAyNGMuOSA0IDEuMSA4LjMuOCAxMi43IDEwIC42IDE5LTIuMiAyNy04LjVBMzguNiAzOC42IDAgMCAwIDE2NyA5Ni4xYzEuNC0xMS0xLjQtMjAuOC04LjItMjkuNS02LjMtOC0xNC4zLTEzLTI0LjEtMTQuN2wtMi41LS40ek0xMjkgNzguN2MtMy40LS40LTYuNS41LTkuMiAyLjZzLTQuMyA1LTQuNyA4LjNjLS41IDMuNS40IDYuNSAyLjUgOS4zczUgNC4zIDguNCA0LjdjMy40LjQgNi40LS40IDkuMi0yLjZzNC4zLTQuOSA0LjctOC4zYy40LTMuNC0uNC02LjUtMi42LTkuMnMtNC45LTQuMy04LjMtNC44em0tMTE2LTVjLjktNy42IDQuMy0xMy44IDEwLjMtMTguNCA2LTQuNyAxMi43LTYuNiAyMC4xLTUuNmE0NC4zIDQ0LjMgMCAwIDEtLjgtMTIuNyAzOCAzOCAwIDAgMC0yNyA4LjRDNi44IDUyLjIgMS44IDYxLjEuNSA3Mi4xczEuMyAyMC43IDguMSAyOS41YTM4IDM4IDAgMCAwIDI0LjIgMTQuN2wyLjQuNCAyLjUuMmM0LjYuMyA5LS4xIDEzLjItMS4zQTQxLjYgNDEuNiAwIDAgMCA3NSA5Ni44YTM4IDM4IDAgMCAwIDQuNC0xMi41Yy00LjMtLjctOC4zLTItMTItMy44YTI2LjUgMjYuNSAwIDAgMS0xMC4zIDE4LjEgMjYuNiAyNi42IDAgMCAxLTIwLjMgNS43aC0uMmMtNy40LTEtMTMuNS00LjUtMTguMS0xMC40LTQuNy02LTYuNi0xMi44LTUuNy0yMC4zek0zMi40IDY3YTEyIDEyIDAgMCAwLTQuOCA4LjQgMTIgMTIgMCAwIDAgMi42IDkuMSAxMiAxMiAwIDAgMCA4LjMgNC44IDEyLjUgMTIuNSAwIDAgMCAxNC0xMC45Yy40LTMuNC0uNC02LjUtMi42LTkuMmExMS45IDExLjkgMCAwIDAtOC4zLTQuN2MtMy41LS41LTYuNS40LTkuMiAyLjV6bTY0LjgtMzQuOGExMiAxMiAwIDAgMC04LjQtNC43Yy0zLjQtLjQtNi41LjQtOS4xIDIuNmExMS44IDExLjggMCAwIDAtNC44IDguM2MtLjQgMy40LjUgNi41IDIuNiA5LjIgMi4xIDIuNyA0LjkgNC4zIDguMyA0LjggMy40LjMgNi40LS41IDkuMi0yLjYgMi43LTIuMiA0LjMtNSA0LjctOC4zLjQtMy41LS40LTYuNi0yLjUtOS4zek04NSA4OC40bC0xLjMtLjFhNDIuMyA0Mi4zIDAgMCAxLTUuMSAxMi4zYzEuNSAwIDMuMSAwIDQuNy4yaC4yYTI2LjQgMjYuNCAwIDAgMSAxOC4zIDEwLjRjMy42IDQuNSA1LjUgOS41IDUuOCAxNWEyNy45IDI3LjkgMCAwIDEtLjIgNS4zdi4yYy0xIDcuNC00LjQgMTMuNS0xMC4zIDE4LjEtNiA0LjctMTIuOCA2LjUtMjAuMyA1LjZzLTEzLjYtNC40LTE4LjMtMTAuM2EyNi4zIDI2LjMgMCAwIDEtNC42LTI1LjJjLTQuMiAxLjQtOC42IDItMTMuMiAybC0uMiAxLjRhMzguNCAzOC40IDAgMCAwIDguMiAyOS40YzYuOCA4LjcgMTUuNyAxMy44IDI2LjYgMTUuMXMyMC43LTEuNCAyOS41LTguMmM4LTYuMyAxMy0xNC4zIDE0LjctMjQuMWwuNC0yLjUuMi0yLjRhMzkuNSAzOS41IDAgMCAwLTMyLjYtNDEuOGwtMi41LS40em01IDMyYTEyLjEgMTIuMSAwIDAgMC04LjQtNC43IDEyIDEyIDAgMCAwLTkuMSAyLjYgMTIuMSAxMi4xIDAgMCAwLTQuOCA4LjMgMTIgMTIgMCAwIDAgMi42IDkuMmMyLjEgMi44IDQuOSA0LjMgOC4zIDQuN2ExMi40IDEyLjQgMCAwIDAgMTMuOS0xMC45Yy40LTMuNC0uNC02LjQtMi41LTkuMnoiLz48L3N2Zz4%3D&labelColor=ffffff)](https://nlnet.nl/project/AppInterception/)

> _Part of [HTTP Toolkit](https://httptoolkit.com/android): powerful tools for building, testing & debugging HTTP(S)_

**This repo contains Frida scripts designed to do everything required for fully automated HTTPS MitM interception on mobile devices.**

This set of scripts can be used all together, to handle interception, manage certificate trust & disabling certificate pinning & transparency checks, for MitM interception of HTTP(S) traffic on Android (iOS coming soon!) or they can be used and tweaked independently to hook just specific features.

The scripts can automatically handle:

* Redirection of traffic to an HTTP(S) proxy - modifying both system settings & directly redirecting all socket connections.
* Injecting a given CA certificate into the system trust stores.
* Patching all known certificate pinning and certificate transparency tools to allow interception by the same CA certificate.
* As a fallback: auto-detection of remaining pinning failures, to attempt auto-patching of obfuscated certificate pinning (in fully obfuscated apps, the first request may fail, but this will trigger additional patching so that all subsequent requests work correctly).

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

## The Scripts

The command above uses all the scripts, but you can generally use any subset you like, although in almost all cases you will want to include `config.js` as the first script (this defines some variables that are used by other scripts).

For example, to do unpinning alone, when handling proxy & certificate configuration elsewhere and without obfuscation fallbacks, you could just run:

```bash
frida -U \
    -l ./config.js \
    -l ./android/android-certificate-unpinning.js
    -f $PACKAGE_ID
```

Each script includes detailed documentation on what it does and how it works in a large comment section at the top. The scripts are:

* `config.js`

    This defines variables used by other scripts:

    * `CERT_PEM` - the extra CA certificate to trust, in PEM format
    * `PROXY_HOST` - the IP address (IPv4) of the proxy server to use (not required if you're only unpinning)
    * `PROXY_PORT` - the port of the proxy server to use (not required if you're only unpinning)
    * `DEBUG_MODE` - defaults to `false`, but switching this to `true` will enable lots of extra output that can be useful for debugging and reverse engineering any issues.

    This should be listed on the command line before any other scripts.

* `native-connect-hook.js`

    A low-level hook for all network connections. This ensures that all connections are forcibly redirected to the target proxy server, even those which ignore proxy settings or make other raw socket connections.

* `android/`

    * `android-proxy-override.js`

        Overrides the Android proxy settings for the target app, ensuring that all well-behaved traffic is redirected via the proxy server and intercepted.

    * `android-system-certificate-injection.js`

        Modifies the native Android APIs to ensure that all trust stores trust your extra CA certificate by default, allowing encrypted TLS traffic to be captured.

    * `android-certificate-unpinning.js`

        Modifies or disables many common known techniques for additional certificate restrictions, including certificate pinning (accepting only a small set of recognized certificates, rather than all certificates trusted on the system) and certificate transparency (validating that all used certificates have been registered in public certificate logs).

    * `android-certificate-unpinning-fallback.js`

        Detects unhandled certificate validation failures, and attempts to handle unknown unrecognized cases with auto-generated fallback patches. This is more experimental and could be slightly unpredictable, but is very helpful for obfuscated cases, and in general will either fix pinning issues (after one initial failure) or will at least highlight code for further reverse engineering in the Frida log output.

---

These scripts are part of [a broader HTTP Toolkit project](https://httptoolkit.com/blog/frida-mobile-interception-funding/), funded through the [NGI Zero Entrust Fund](https://nlnet.nl/entrust), established by [NLnet](https://nlnet.nl) with financial support from the European Commission's [Next Generation Internet](https://ngi.eu) program. Learn more on the [NLnet project page](https://nlnet.nl/project/F3-AppInterception#ack).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
[<img src="https://nlnet.nl/image/logos/NGI0Entrust_tag.svg" alt="NGI Zero Entrust Logo" width="20%" />](https://nlnet.nl/entrust)
