/**
 * In some cases, proxy configuration by itself won't work. This notably includes Flutter apps (which ignore
 * system/JVM configuration entirely) and plausibly other apps intentionally ignoring proxies. To handle that
 * we hook native connect() calls directly, to redirect traffic on all ports to the target.
 *
 * This handles all attempts to connect an outgoing socket, and for all TCP connections opened it will
 * manually replace the connect() parameters so that the socket connects to the proxy instead of the
 * 'real' destination.
 *
 * This doesn't help with certificate trust (you still need some kind of certificate setup) but it does ensure
 * the proxy receives all connections (and so will see if connections don't trust its CA). It's still useful
 * to do proxy config alongside this, as applications may behave a little more 'correctly' if they're aware
 * they're using a proxy rather than doing so unknowingly.
 *
 * Source available at https://github.com/httptoolkit/frida-interception-and-unpinning/
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Tim Perry <tim@httptoolkit.com>
 */

(() => {
    const PROXY_HOST_IPv4_BYTES = PROXY_HOST.split('.').map(part => parseInt(part, 10));
    const IPv6_MAPPING_PREFIX_BYTES = [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff];
    const PROXY_HOST_IPv6_BYTES = IPv6_MAPPING_PREFIX_BYTES.concat(PROXY_HOST_IPv4_BYTES);

    // Flags for fcntl():
    const F_GETFL = 3;
    const F_SETFL = 4;
    const O_NONBLOCK = (Process.platform === 'darwin')
        ? 4
        : 2048; // Linux/Android

    let fcntl, send, recv, conn;
    try {
        const systemModule = Process.findModuleByName('libc.so') ?? // Android
                             Process.findModuleByName('libc.so.6') ?? // Linux
                             Process.findModuleByName('libsystem_c.dylib'); // iOS

        if (!systemModule) throw new Error("Could not find libc or libsystem_c");

        fcntl = new NativeFunction(systemModule.getExportByName('fcntl'), 'int', ['int', 'int', 'int']);
        send = new NativeFunction(systemModule.getExportByName('send'), 'ssize_t', ['int', 'pointer', 'size_t', 'int']);
        recv = new NativeFunction(systemModule.getExportByName('recv'), 'ssize_t', ['int', 'pointer', 'size_t', 'int']);

        conn = systemModule.getExportByName('connect')
    } catch (e) {
        console.error("Failed to set up native hooks:", e.message);
        console.warn('Could not initialize system functions to to hook raw traffic');
        return;
    }

    Interceptor.attach(conn, {
        onEnter(args) {
            const fd = this.sockFd = args[0].toInt32();
            const sockType = Socket.type(fd);

            const addrPtr = ptr(args[1]);
            const addrLen = args[2].toInt32();
            const addrData = addrPtr.readByteArray(addrLen);

            const isTCP = sockType === 'tcp' || sockType === 'tcp6';
            const isUDP = sockType === 'udp' || sockType === 'udp6';
            const isIPv6 = sockType === 'tcp6' || sockType === 'udp6';

            if (isTCP || isUDP) {
                const portAddrBytes = new DataView(addrData.slice(2, 4));
                const port = portAddrBytes.getUint16(0, false); // Big endian!

                const shouldBeIgnored = IGNORED_NON_HTTP_PORTS.includes(port);
                const shouldBeBlocked = BLOCK_HTTP3 && !shouldBeIgnored && isUDP && port === 443;

                // N.b for now we only support TCP interception - UDP direct should be doable,
                // but SOCKS5 UDP would require a whole different flow. Rarely relevant, especially
                // if you're blocking HTTP/3.
                const shouldBeIntercepted = isTCP && !shouldBeIgnored && !shouldBeBlocked;

                const hostBytes = isIPv6
                    // 16 bytes offset by 8 (2 for family, 2 for port, 4 for flowinfo):
                    ? new Uint8Array(addrData.slice(8, 8 + 16))
                    // 4 bytes, offset by 4 (2 for family, 2 for port)
                    : new Uint8Array(addrData.slice(4, 4 + 4));

                const isIntercepted = port === PROXY_PORT && areArraysEqual(hostBytes,
                    isIPv6
                        ? PROXY_HOST_IPv6_BYTES
                        : PROXY_HOST_IPv4_BYTES
                );

                if (isIntercepted) return;

                if (shouldBeBlocked) {
                    if (isIPv6) {
                        // Skip 8 bytes: 2 family, 2 port, 4 flowinfo, then write :: (all 0s)
                        for (let i = 0; i < 16; i++) {
                            addrPtr.add(8 + i).writeU8(0);
                        }
                    } else {
                        // Skip 4 bytes: 2 family, 2 port, then write 0.0.0.0
                        addrPtr.add(4).writeU32(0);
                    }

                    console.debug(`Blocking QUIC connection to ${getReadableAddress(hostBytes, isIPv6)}:${port}`);
                    this.state = 'Blocked';
                } else if (shouldBeIntercepted) {
                    // Otherwise, it's an unintercepted connection that should be captured:
                    this.state = 'intercepting';

                    // For SOCKS, we preserve the original destionation to use in the SOCKS handshake later
                    // and we temporarily set the socket to blocking mode to do the handshake itself.
                    if (PROXY_SUPPORTS_SOCKS5) {
                        this.originalDestination = { host: hostBytes, port, isIPv6 };
                        this.originalFlags = fcntl(this.sockFd, F_GETFL, 0);
                        this.isNonBlocking = (this.originalFlags & O_NONBLOCK) !== 0;
                        if (this.isNonBlocking) {
                            fcntl(this.sockFd, F_SETFL, this.originalFlags & ~O_NONBLOCK);
                        }
                    }

                    console.log(`Manually intercepting ${sockType} connection to ${getReadableAddress(hostBytes, isIPv6)}:${port}`);

                    // Overwrite the port with the proxy port:
                    portAddrBytes.setUint16(0, PROXY_PORT, false); // Big endian
                    addrPtr.add(2).writeByteArray(portAddrBytes.buffer);

                    // Overwrite the address with the proxy address:
                    if (isIPv6) {
                        // Skip 8 bytes: 2 family, 2 port, 4 flowinfo
                        addrPtr.add(8).writeByteArray(PROXY_HOST_IPv6_BYTES);
                    } else {
                        // Skip 4 bytes: 2 family, 2 port
                        addrPtr.add(4).writeByteArray(PROXY_HOST_IPv4_BYTES);
                    }
                } else {
                    // Explicitly being left alone
                    if (DEBUG_MODE) {
                        console.debug(`Allowing unintercepted ${sockType} connection to port ${port}`);
                    }
                    this.state = 'ignored';
                }
            } else {
                // Should just be unix domain sockets - UDP & TCP are covered above
                if (DEBUG_MODE) console.log(`Ignoring ${sockType} connection`);
                this.state = 'ignored';
            }
        },
        onLeave: function (retval) {
            if (this.state === 'ignored') return;

            if (this.state === 'intercepting' && PROXY_SUPPORTS_SOCKS5) {
                const connectSuccess = retval.toInt32() === 0;

                let handshakeSuccess = false;

                const { host, port, isIPv6 } = this.originalDestination;
                if (connectSuccess) {
                    handshakeSuccess = performSocksHandshake(this.sockFd, host, port, isIPv6);
                } else {
                    console.error(`SOCKS: Failed to connect to proxy at ${PROXY_HOST}:${PROXY_PORT}`);
                }

                if (this.isNonBlocking) {
                    fcntl(this.sockFd, F_SETFL, this.originalFlags);
                }

                if (handshakeSuccess) {
                    const readableHost = getReadableAddress(host, isIPv6);
                    if (DEBUG_MODE) console.debug(`SOCKS redirect successful for fd ${this.sockFd} to ${readableHost}:${port}`);
                    retval.replace(0);
                } else {
                    if (DEBUG_MODE) console.error(`SOCKS redirect FAILED for fd ${this.sockFd}`);
                    retval.replace(-1);
                }
            } else if (DEBUG_MODE) {
                const fd = this.sockFd;
                const sockType = Socket.type(fd);
                const address = Socket.peerAddress(fd);
                console.debug(
                    `${this.state} ${sockType} fd ${fd} to ${JSON.stringify(address)} (${retval.toInt32()})`
                );
            }
        }
    });

    console.log(`== Redirecting ${
        IGNORED_NON_HTTP_PORTS.length === 0
        ? 'all'
        : 'all unrecognized'
    } TCP connections to ${PROXY_HOST}:${PROXY_PORT} ==`);

    const getReadableAddress = (
        /** @type {Uint8Array} */ hostBytes,
        /** @type {boolean} */ isIPv6
    ) => {
        if (!isIPv6) {
            // Return simple a.b.c.d IPv4 format:
            return [...hostBytes].map(x => x.toString()).join('.');
        }

        if (
            hostBytes.slice(0, 10).every(b => b === 0) &&
            hostBytes.slice(10, 12).every(b => b === 255)
        ) {
            // IPv4-mapped IPv6 address - print as IPv4 for readability
            return '::ffff:'+[...hostBytes.slice(12)].map(x => x.toString()).join('.');
        }

        else {
            // Real IPv6:
            return `[${[...hostBytes].map(x => x.toString(16)).join(':')}]`;
        }
    };

    const areArraysEqual = (arrayA, arrayB) => {
        if (arrayA.length !== arrayB.length) return false;
        return arrayA.every((x, i) => arrayB[i] === x);
    };

    function performSocksHandshake(sockfd, targetHostBytes, targetPort, isIPv6) {
        const hello = Memory.alloc(3).writeByteArray([0x05, 0x01, 0x00]);
        if (send(sockfd, hello, 3, 0) < 0) {
            console.error("SOCKS: Failed to send hello");
            return false;
        }

        const response = Memory.alloc(2);
        if (recv(sockfd, response, 2, 0) < 0) {
            console.error("SOCKS: Failed to receive server choice");
            return false;
        }

        if (response.readU8() !== 0x05 || response.add(1).readU8() !== 0x00) {
            console.error("SOCKS: Server rejected auth method");
            return false;
        }

        let req = [0x05, 0x01, 0x00]; // VER, CMD(CONNECT), RSV

        if (isIPv6) {
            req.push(0x04); // ATYP: IPv6
        } else { // IPv4
            req.push(0x01); // ATYP: IPv4
        }

        req.push(...targetHostBytes, (targetPort >> 8) & 0xff, targetPort & 0xff);
        const reqBuf = Memory.alloc(req.length).writeByteArray(req);

        if (send(sockfd, reqBuf, req.length, 0) < 0) {
            console.error("SOCKS: Failed to send connection request");
            return false;
        }

        const replyHeader = Memory.alloc(4);
        if (recv(sockfd, replyHeader, 4, 0) < 0) {
            console.error("SOCKS: Failed to receive reply header");
            return false;
        }

        const replyCode = replyHeader.add(1).readU8();
        if (replyCode !== 0x00) {
            console.error(`SOCKS: Server returned error code ${replyCode}`);
            return false;
        }

        const atyp = replyHeader.add(3).readU8();
        let remainingBytes = 0;
        if (atyp === 0x01) remainingBytes = 4 + 2; // IPv4 + port
        else if (atyp === 0x04) remainingBytes = 16 + 2; // IPv6 + port
        if (remainingBytes > 0) recv(sockfd, Memory.alloc(remainingBytes), remainingBytes, 0);

        return true;
    }
})();