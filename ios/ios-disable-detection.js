/**************************************************************************************************
 *
 * Some iOS apps attempt to detect jailbroken devices and similar. This script disables these
 * detections to ensure you can freely manage your device and modify your apps.
 *
 * Source available at https://github.com/httptoolkit/frida-interception-and-unpinning/
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Tim Perry <tim@httptoolkit.com>
 *
 *************************************************************************************************/

if (ObjC.available) {
    try {
        const JailMonkey = ObjC.classes.JailMonkey;
        if (JailMonkey) {
            const isJailBroken = JailMonkey["- isJailBroken"];
            Interceptor.attach(isJailBroken.implementation, {
                onLeave: function(retval) {
                    if (DEBUG_MODE) console.log("JailMonkey isJailBroken check hooked & skipped");
                    retval.replace(ptr("0x0"));
                }
            });

            console.log('== Hooked JailMonkey detection ==');
        } else {
            if (DEBUG_MODE) console.log('Skipping JailMonkey hook - not present');
        }
    } catch (err) {
        console.error(`[!] ERROR: JailMonkey isJailBroken hook failed: ${err}`);
    }
}