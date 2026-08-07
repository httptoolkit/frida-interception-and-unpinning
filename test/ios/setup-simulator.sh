#!/bin/bash
set -e

# Assumes: macOS with Xcode & an iOS simulator runtime installed, and frida-tools installed (which
# is where we get the ObjC bridge from - see below).
#
# Boots a simulator, builds & installs the test app, and puts a working Frida gadget inside it,
# ready for the tests to inject. All idempotent, so it can be rerun freely.

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$TEST_DIR/tmp"

APP_NAME="TestApp"
BUNDLE_ID="tech.httptoolkit.frida_test_app"

# Recent gadgets crash on the iOS 26 simulator: 17.16.4 segfaults during its own initialisation,
# with nothing of ours loaded at all, and 17.16.0 survives that but dies as soon as it runs a
# script. Rather than pinning a version and waiting for somebody to notice when that's fixed, we
# walk back from the newest until one works, which self-heals & reports where the problem is.
GADGET_VERSIONS="${GADGET_VERSIONS:-17.16.4 17.16.0 17.15.0 17.14.0 17.12.0 17.10.0 17.8.0 17.6.0 17.4.0 17.2.0 17.0.0 16.7.19}"

mkdir -p "$BUILD_DIR"

# --- The simulator ------------------------------------------------------------------------------

# Reuse whatever's already booted, so that a local run doesn't boot a second simulator every time:
UDID=$(xcrun simctl list devices booted -j | python3 -c "
import json, sys
for runtime, devices in sorted(json.load(sys.stdin)['devices'].items()):
    for device in devices:
        if 'iPhone' in device['name']:
            print(device['udid'])
            sys.exit(0)
")

if [ -z "$UDID" ]; then
  UDID=$(xcrun simctl list devices available -j | python3 -c "
import json, sys
for runtime, devices in sorted(json.load(sys.stdin)['devices'].items()):
    for device in devices:
        if 'iPhone' in device['name']:
            print(device['udid'])
            sys.exit(0)
sys.exit('No iPhone simulator is available')
")
  xcrun simctl boot "$UDID"
fi

xcrun simctl bootstatus "$UDID"
xcrun simctl list devices booted | grep "$UDID"

# --- The app ------------------------------------------------------------------------------------

APP="$BUILD_DIR/$APP_NAME.app"
rm -rf "$APP"
mkdir -p "$APP/Frameworks"

sed -e "s/__APP_NAME__/$APP_NAME/g" -e "s/__BUNDLE_ID__/$BUNDLE_ID/g" \
  "$TEST_DIR/app/Info.plist" > "$APP/Info.plist"
plutil -lint "$APP/Info.plist"

# Built for the simulator we just booted, which runs this machine's own architecture:
xcrun --sdk iphonesimulator swiftc \
  -sdk "$(xcrun --sdk iphonesimulator --show-sdk-path)" \
  -target "$(uname -m)-apple-ios15.0-simulator" \
  -swift-version 5 \
  -o "$APP/$APP_NAME" \
  "$TEST_DIR/app/main.swift"

# Ad-hoc signing, which is all the simulator asks for:
codesign --force --sign - "$APP"

xcrun simctl install "$UDID" "$APP"
# Confirms the simulator accepted the bundle, rather than finding out at launch:
xcrun simctl listapps "$UDID" | grep -q "$BUNDLE_ID"

BUNDLE_DIR="$(xcrun simctl get_app_container "$UDID" "$BUNDLE_ID" app)"
DATA_DIR="$(xcrun simctl get_app_container "$UDID" "$BUNDLE_ID" data)"
echo "App installed at: $BUNDLE_DIR"

# Before injecting anything: otherwise a broken app and a broken injection are indistinguishable,
# since both look like nothing happening at all.
#
# N.b. checked by pid: matching the app by name would also match our own simctl commands.
xcrun simctl launch "$UDID" "$BUNDLE_ID" | tee "$BUILD_DIR/baseline.log"
sleep 5
ps -p "$(awk '{print $2}' "$BUILD_DIR/baseline.log")" > /dev/null
xcrun simctl terminate "$UDID" "$BUNDLE_ID"
echo "The app runs uninjected."

# --- The gadget ---------------------------------------------------------------------------------

# A script that does nothing but prove it ran, to test each gadget with. N.b. a file rather than
# console output, because the gadget's console output doesn't reach the simulator log at all.
cat > "$BUNDLE_DIR/Frameworks/gadget-check.js" <<EOF
const file = new File("$DATA_DIR/gadget-check.txt", "w");
file.write("ran\n");
file.close();
EOF

# Script mode, so the gadget runs a script at startup rather than pausing the app to wait for a
# client to attach. That's the mode the tests need, and the mode that recent gadgets break in:
printf '%s\n' \
  "{ \"interaction\": { \"type\": \"script\", \"path\": \"$BUNDLE_DIR/Frameworks/gadget-check.js\", \"on_change\": \"ignore\" } }" \
  > "$BUNDLE_DIR/Frameworks/FridaGadget.config"

WORKING=""
for VERSION in $GADGET_VERSIONS; do
  echo
  echo "### Frida $VERSION"

  CACHED_GADGET="$BUILD_DIR/frida-gadget-$VERSION.dylib"

  if [ ! -f "$CACHED_GADGET" ]; then
    if ! curl -sSfL -o "$CACHED_GADGET.xz" \
      "https://github.com/frida/frida/releases/download/$VERSION/frida-gadget-$VERSION-ios-simulator-universal.dylib.xz"
    then
      echo "  no simulator gadget published for this version"
      rm -f "$CACHED_GADGET.xz"
      continue
    fi
    unxz -f "$CACHED_GADGET.xz"
  fi

  cp "$CACHED_GADGET" "$BUNDLE_DIR/Frameworks/FridaGadget.dylib"
  codesign --force --sign - "$BUNDLE_DIR" # The bundle's contents just changed

  xcrun simctl terminate "$UDID" "$BUNDLE_ID" > /dev/null 2>&1 || true
  rm -f "$DATA_DIR/gadget-check.txt" # Otherwise a previous version's marker would count

  # DYLD_INSERT_LIBRARIES via SIMCTL_CHILD_ injects into the app with no modification to the app
  # itself - no repackaging, and no re-signing beyond the ad-hoc signature above:
  if ! SIMCTL_CHILD_DYLD_INSERT_LIBRARIES="$BUNDLE_DIR/Frameworks/FridaGadget.dylib" \
    xcrun simctl launch "$UDID" "$BUNDLE_ID" > "$BUILD_DIR/attempt.log" 2>&1
  then
    echo "  launch refused: $(cat "$BUILD_DIR/attempt.log")"
    continue
  fi

  PID="$(awk '{print $2}' "$BUILD_DIR/attempt.log")"
  sleep 10

  if ! ps -p "$PID" > /dev/null 2>&1; then
    echo "  the app crashed (pid $PID)"
    continue
  fi

  if [ ! -f "$DATA_DIR/gadget-check.txt" ]; then
    echo "  the app survived, but the gadget never ran the script (pid $PID)"
    continue
  fi

  echo "  the app survived & ran our script (pid $PID)"
  WORKING="$VERSION"
  xcrun simctl terminate "$UDID" "$BUNDLE_ID" > /dev/null 2>&1 || true
  break
done

if [ -z "$WORKING" ]; then
  echo
  echo "No gadget version could run a script in this simulator at all" >&2
  exit 1
fi

echo
echo "Using Frida gadget $WORKING"

# --- The ObjC bridge ----------------------------------------------------------------------------

# Frida 17 unbundled the language bridges, and they're now supplied by the host tool rather than
# the runtime. The gadget has no host to ask and doesn't carry them itself, so a script using ObjC
# (as ios-disable-detection.js does) fails with a ReferenceError unless we supply the bridge
# ourselves. This is the same prebuilt bundle that `frida -l` would have handed it.
python3 - "$BUILD_DIR/objc-bridge.js" <<'EOF'
import pathlib, shutil, sys

try:
    import frida_tools
except ImportError:
    sys.exit('frida-tools is not installed, so the ObjC bridge is not available')

bridge = pathlib.Path(frida_tools.__file__).parent / 'bridges' / 'objc.js'
if not bridge.exists():
    sys.exit(f'This frida-tools has no ObjC bridge at {bridge}')

shutil.copy(bridge, sys.argv[1])
EOF

echo "Simulator ready to test."
