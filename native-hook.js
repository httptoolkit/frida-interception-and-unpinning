/**
 * In some cases, proxy configuration by itself won't work. This notably includes Flutter apps (which ignore
 * system/JVM configuration entirely) and plausibly other apps intentionally ignoring proxies. To handle that
 * we hook libc's connect() directly to redirect traffic on all recognized ports.
 *
 * This handles all calls to connect an outgoing socket, and for all TCP connections opened on recognized ports,
 * it will manually replace the connect parameters, so that the socket connects to the proxy instead of the
 * 'real' destination.
 *
 * This doesn't help with certificate trust (you still need some kind of certificate setup) but it does ensure
 * the proxy receives all connections (and so will see if connections don't trust its CA). It's still useful
 * to do proxy config alongside this, primarily to capture traffic that might be sent on any non-standard ports.
 */

// Ports which we recognize, and forcibly redirect to capture, if not captured already.
const RECOGNIZED_PORTS = [
    80,
    443,
    4443,
    8000,
    8080,
    8443,
    8888,
    9000
];

const PROXY_HOST_IPv4_BYTES = PROXY_HOST.split('.').map(part => parseInt(part, 10));
const IPv6_MAPPING_PREFIX_BYTES = [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff];
const PROXY_HOST_IPv6_BYTES = IPv6_MAPPING_PREFIX_BYTES.concat(PROXY_HOST_IPv4_BYTES);

const connectFn = (
    Module.findExportByName('libc.so', 'connect') ?? // Android
    Module.findExportByName('libc.so.6', 'connect') // Linux
);

if (!connectFn) { // Should always be set, but just in case
    console.warn('Could not find libc connect() function to hook raw traffic');
} else {
    Interceptor.attach(connectFn, {
        onEnter(args) {
            const fd = this.sockFd = args[0].toInt32();
            const sockType = Socket.type(fd);

            const addrPtr = ptr(args[1]);
            const addrLen = args[2].toInt32(); // TODO: Probably not right?
            const addrData = addrPtr.readByteArray(addrLen);

            if (sockType === 'tcp' || sockType === 'tcp6') {
                const portAddrBytes = new DataView(addrData.slice(2, 4));
                const port = portAddrBytes.getUint16(0, false); // Big endian!

                const shouldBeIntercepted = RECOGNIZED_PORTS.includes(port);

                const isIPv6 = sockType === 'tcp6';

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

                if (!shouldBeIntercepted) {
                    // Not intercecpted, sent to unrecognized port - probably not HTTP(S)
                    if (DEBUG_MODE) {
                        console.debug(`Allowing unintercepted connection to unrecognized port ${port}`);
                    }
                    return;
                }

                // Otherwise, it's an unintercepted connection that should be captured:

                console.log(`Manually intercepting connection to ${
                    isIPv6
                        ? `[${[...hostBytes].map(x => x.toString(16)).join(':')}]`
                        : [...hostBytes].map(x => x.toString()).join('.')
                }:${port}`);

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
            } else if (DEBUG_MODE) {
                console.log(`Ignoring ${sockType} connection`);
                this.ignored = true;
            }

            // N.b. we ignore all non-TCP connections: both UDP and Unix streams
        },
        onLeave: function (result) {
            if (!DEBUG_MODE || this.ignored) return;

            const fd = this.sockFd;
            const sockType = Socket.type(fd);
            const address = Socket.peerAddress(fd);
            console.debug(
                `Connected ${sockType} fd ${fd} to ${JSON.stringify(address)} (${result.toInt32()})`
            );
        }
    });

    console.log(`Hooked connect() at ${connectFn}`);
}

const areArraysEqual = (arrayA, arrayB) => {
    if (arrayA.length !== arrayB.length) return false;
    return arrayA.every((x, i) => arrayB[i] === x);
};

