/**
 * This script can be useful as part of a pre-setup or automated configuration process,
 * where you don't know why IP address is best used to reach your proxy server from the
 * target device. You can run this script first with a list of IP addresses, and wait for
 * the 'connected' message to confirm the working IP (or 'connection-failed' if none work)
 * before then injecting the config script and the rest of your script code.
 *
 * Source available at https://github.com/httptoolkit/frida-interception-and-unpinning/
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Tim Perry <tim@httptoolkit.com>
 */

// Modify this to specify the addresses you'd like to test:
const IP_ADDRESSES_TO_TEST = [
];

const TARGET_PORT = 0;




// ----------------------------------------------------------------------------
// You don't need to modify any of the below - this is the logic that does the
// checks themselves.
// ----------------------------------------------------------------------------

if (IP_ADDRESSES_TO_TEST.length === 0) {
    throw new Error('No IP addresses provided to check - please modify IP_ADDRESSES_TO_TEST');
}

if (TARGET_PORT === 0) {
    throw new Error('No target port provided to check - please modify TARGET_PORT');
}

async function testAddress(ip, port) {
    try {
        const socket = await Socket.connect({ host: ip, port });
        socket.close();
        return true;
    } catch (e) {
        return false;
    }
}

let completed = false;
let testsCompleted = 0;
IP_ADDRESSES_TO_TEST.forEach(async (ip) => {
    const result = await testAddress(ip, TARGET_PORT);
    testsCompleted += 1;

    if (completed) return; // Ignore results after the first connection

    if (result) {
        completed = true;
        send({
            type: 'connected',
            ip,
            port: TARGET_PORT
        });
    }

    if (testsCompleted === IP_ADDRESSES_TO_TEST.length && !completed) {
        completed = true;
        send({
            type: 'connection-failed'
        });
    }
});