# Frida Mobile Interception Scripts

> _Part of [HTTP Toolkit](https://httptoolkit.com/android): powerful tools for building, testing & debugging HTTP(S)_

This repo contains a selection of Frida scripts that can be used independently, or as a set for interception of HTTP(S) traffic on Android & iOS.

The scripts are:

## `android-proxy-override.js`

A script to override the proxy configuration of a target application, allowing capture of HTTP traffic without changing device settings, using a VPN, or any other techniques.

Note that this only works for plain HTTP - you will also need a method to trust your CA certificate (either device-wide or using another script) if you would like to intercept HTTPS.

## `android-certificate-unpinning.js`

A script to defeat SSL certificate pinning in a target application, by hooking & disabling all commonly known pinning techniques. For more information and detailed setup instructions for unpinning specifically, take a look at https://httptoolkit.com/blog/frida-certificate-pinning/

---

Each of these scripts can be used with [HTTP Toolkit](https://httptoolkit.com/android) or any other HTTP debugging proxies to capture traffic.
