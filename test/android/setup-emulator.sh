#!/bin/bash
set -e

# Assumes: Android emulator/device is available via ADB and Frida CLI is installed on computer
# Wait for device, install APK, and set up Frida server (all idempotent)

# Wait for emulator/device to be available
adb wait-for-device
adb shell 'while [[ -z $(getprop sys.boot_completed) ]]; do sleep 1; done;'
echo "Emulator/device booted."

# Download and install APK if not already installed
APK_VERSION="v1.6.0"
APK_PATH="/tmp/pinning-demo.apk"
APK_URL="https://github.com/httptoolkit/android-ssl-pinning-demo/releases/download/${APK_VERSION}/pinning-demo.apk"
PACKAGE="tech.httptoolkit.pinning_demo"
if ! adb shell pm list packages | grep -q "$PACKAGE"; then
  wget -q $APK_URL -O $APK_PATH
  adb install -r $APK_PATH
  echo "APK installed."
else
  echo "APK already installed."
fi

# Set up Frida server
FRIDA_VERSION=$(frida --version)
FRIDA_SERVER_URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-x86_64.xz"
FRIDA_SERVER_LOCAL="/tmp/frida-server"
FRIDA_SERVER_REMOTE="/data/local/tmp/frida-server"

if ! adb shell "ps -A | grep '[f]rida-server'" > /dev/null; then
  if [ ! -f $FRIDA_SERVER_LOCAL ]; then
    wget -q $FRIDA_SERVER_URL -O /tmp/frida-server.xz
    unxz -f /tmp/frida-server.xz
    chmod +x $FRIDA_SERVER_LOCAL
  fi
  adb root || true
  sleep 1
  adb push $FRIDA_SERVER_LOCAL $FRIDA_SERVER_REMOTE
  echo 'Pushed'
  adb shell "chmod 755 $FRIDA_SERVER_REMOTE"
  echo 'chmoded'
  adb shell "ls -l $FRIDA_SERVER_REMOTE"
  adb shell "$FRIDA_SERVER_REMOTE" &
  echo "Frida server started on device."
else
  echo "Frida server already running."
fi
