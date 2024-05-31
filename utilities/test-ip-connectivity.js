/**
 * This script is a little different from the others, and is designed to help with setup,
 * particularly in automated scenarios, rather than supporting interception/unpinning/etc.
 *
 * Using this script, you can provide a list of IP addresses and a port, and the script will
 * send messages back to your Frida client for each IP:PORT address that is reachable from
 * the target device. When your proxy is running on a remote device from the target host,
 * this can be useful to work out which proxy IP address should be used.
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

IP_ADDRESSES_TO_TEST.forEach(async (ip) => {
    const result = await testAddress(ip, TARGET_PORT);
    send({
        type: 'connectivity-result',
        ip,
        port: TARGET_PORT,
        result
    });
});