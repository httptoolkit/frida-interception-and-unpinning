#!/bin/bash
set -e

# Assumes: Android emulator/device is available via ADB and Frida CLI is installed on computer
# Wait for device, install APK, and set up Frida server (all idempotent)

# Wait for emulator/device to be available
adb wait-for-device
adb shell 'while [[ -z $(getprop sys.boot_completed) ]]; do sleep 1; done;'
echo "Emulator/device booted."

# Download and install the demo app, unless this exact version is installed already
APK_VERSION="1.7.1"
APK_PATH="/tmp/pinning-demo-$APK_VERSION.apk"
APK_URL="https://github.com/httptoolkit/android-ssl-pinning-demo/releases/download/v${APK_VERSION}/pinning-demo.apk"
PACKAGE="tech.httptoolkit.pinning_demo"

INSTALLED_VERSION=$(
  adb shell "dumpsys package $PACKAGE | grep -m1 versionName" | tr -d '\r' | cut -d= -f2
) || true

if [ "$INSTALLED_VERSION" != "$APK_VERSION" ]; then
  if [ ! -f $APK_PATH ]; then
    wget -q $APK_URL -O $APK_PATH
  fi
  # A locally built (or otherwise differently signed) copy of the app can't be upgraded in
  # place, so if the install is rejected we replace it outright:
  if ! adb install -r $APK_PATH; then
    adb uninstall $PACKAGE
    adb install $APK_PATH
  fi
  echo "APK v$APK_VERSION installed (previously: ${INSTALLED_VERSION:-not installed})."
else
  echo "APK v$APK_VERSION already installed."
fi

# Set up Frida server, matching the local Frida CLI version & the device architecture
FRIDA_VERSION=$(frida --version)
DEVICE_ABI=$(adb shell getprop ro.product.cpu.abi | tr -d '\r')
case $DEVICE_ABI in
  x86_64)      FRIDA_ARCH="x86_64" ;;
  x86)         FRIDA_ARCH="x86" ;;
  arm64-v8a)   FRIDA_ARCH="arm64" ;;
  armeabi-v7a) FRIDA_ARCH="arm" ;;
  *) echo "Unrecognized device ABI: $DEVICE_ABI" >&2; exit 1 ;;
esac

FRIDA_SERVER_URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-${FRIDA_ARCH}.xz"
FRIDA_SERVER_LOCAL="/tmp/frida-server-$FRIDA_VERSION-$FRIDA_ARCH"
FRIDA_SERVER_REMOTE="/data/local/tmp/frida-server-$FRIDA_VERSION"

# Frida server needs root, and so does seeing it in the process list at all (as /proc hides
# other users' processes) so we always take root first, before looking for it:
adb root > /dev/null || true
sleep 1 # Give adbd a moment to actually drop the connection, before we wait for the new one
adb wait-for-device

# The client refuses to talk to a mismatched server, so any other version is no use to us:
if ! adb shell "ps -A | grep '[f]rida-server-$FRIDA_VERSION'" > /dev/null; then
  if [ ! -f $FRIDA_SERVER_LOCAL ]; then
    wget -q $FRIDA_SERVER_URL -O $FRIDA_SERVER_LOCAL.xz
    unxz -f $FRIDA_SERVER_LOCAL.xz
    chmod +x $FRIDA_SERVER_LOCAL
  fi

  # Bracketed, so the pattern doesn't match the shell that's running pkill itself:
  adb shell "pkill -f '[f]rida-server'" || true

  adb push $FRIDA_SERVER_LOCAL $FRIDA_SERVER_REMOTE
  adb shell "chmod 755 $FRIDA_SERVER_REMOTE"
  adb shell "nohup $FRIDA_SERVER_REMOTE >/dev/null 2>&1 &"

  # Starting the server is async, so we wait for it to actually accept connections:
  for _ in $(seq 30); do
    if frida-ps -U > /dev/null 2>&1; then break; fi
    sleep 1
  done
  frida-ps -U > /dev/null

  echo "Frida server $FRIDA_VERSION started on device."
else
  echo "Frida server $FRIDA_VERSION already running."
fi
