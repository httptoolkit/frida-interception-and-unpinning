/**
 * Loads the real config.js & native-connect-hook.js into a throwaway process, and makes
 * socket calls inside it, so the connect hook can be tested directly on this machine.
 *
 * The process itself does nothing at all: Frida calls socket(), connect() and friends
 * through libc for us, so there's no test-only native code to build or maintain.
 */

import * as frida from 'frida';
import * as fs from 'fs/promises';
import * as path from 'path';
import { fileURLToPath } from 'url';

const SCRIPTS = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

// config.js refuses to load without one, and the connect hook never looks at it:
const PLACEHOLDER_CERT = [
    '-----BEGIN CERTIFICATE-----',
    'MIIBkTCB+w==',
    '-----END CERTIFICATE-----'
].join('\n');

export interface ConnectResult {
    /** What connect() returned to the application: 0 for success. */
    result: number;
    /** The errno the application sees alongside that result. */
    errno: number;
    /** How long connect() blocked for, which is what a stalled proxy costs the app. */
    durationMs: number;
    /** Whether the socket is non-blocking now, i.e. whether we put it back as we found it. */
    nonBlocking: boolean;
}

// Everything we need to do inside the target process. Written as a plain string, as it runs
// in Frida's runtime rather than Node's:
const AGENT = `
const libc = Process.getModuleByName('libc.so.6');
const native = (name, ret, args) =>
    new NativeFunction(libc.getExportByName(name), ret, args);

const socketFn = native('socket', 'int', ['int', 'int', 'int']);
const connectFn = native('connect', 'int', ['int', 'pointer', 'int']);
const sendFn = native('send', 'ssize_t', ['int', 'pointer', 'size_t', 'int']);
const recvFn = native('recv', 'ssize_t', ['int', 'pointer', 'size_t', 'int']);
const fcntlFn = native('fcntl', 'int', ['int', 'int', 'int']);
const errnoLocation = native('__errno_location', 'pointer', []);

const AF_INET = 2, AF_INET6 = 10, SOCK_STREAM = 1;
const F_GETFL = 3, F_SETFL = 4, O_NONBLOCK = 2048;

let fd = -1;

// Builds a sockaddr_in, or a sockaddr_in6 holding the IPv4-mapped form of the same address
// (::ffff:a.b.c.d) - which is what Android apps produce for almost every connection:
function buildAddress(ipv4Bytes, port, useIPv6) {
    const portBytes = [(port >> 8) & 0xff, port & 0xff];

    if (!useIPv6) {
        const addr = Memory.alloc(16);
        addr.writeU16(AF_INET);
        addr.add(2).writeByteArray(portBytes);
        addr.add(4).writeByteArray(ipv4Bytes);
        return { pointer: addr, length: 16 };
    }

    const addr = Memory.alloc(28);
    addr.writeU16(AF_INET6);
    addr.add(2).writeByteArray(portBytes);
    addr.add(8).writeByteArray(
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff].concat(ipv4Bytes)
    );
    return { pointer: addr, length: 28 };
}

rpc.exports = {
    connect(ipv4Bytes, port, useIPv6, nonBlocking) {
        fd = socketFn(useIPv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
        if (nonBlocking) fcntlFn(fd, F_SETFL, fcntlFn(fd, F_GETFL, 0) | O_NONBLOCK);

        const address = buildAddress(ipv4Bytes, port, useIPv6);
        errnoLocation().writeInt(0);

        const started = Date.now();
        const result = connectFn(fd, address.pointer, address.length);
        const durationMs = Date.now() - started;

        return {
            result: result,
            errno: errnoLocation().readInt(),
            durationMs: durationMs,
            nonBlocking: (fcntlFn(fd, F_GETFL, 0) & O_NONBLOCK) !== 0
        };
    },

    // Sends some data & reads whatever comes back, to check the tunnel begins cleanly:
    echo(text) {
        const buffer = Memory.alloc(256);
        sendFn(fd, Memory.allocUtf8String(text), text.length, 0);
        const received = recvFn(fd, buffer, 256, 0).toNumber();
        return received > 0 ? buffer.readUtf8String(received) : null;
    }
};
`;

export class HookedProcess {

    /** Everything the scripts have logged, in order. */
    readonly logs: string[] = [];

    private pid: number;
    private script: frida.Script;

    private constructor(pid: number, script: frida.Script) {
        this.pid = pid;
        this.script = script;
    }

    static async start(settings: { [setting: string]: string } = {}) {
        // Spawned through Frida rather than started ourselves and attached to: its helper
        // then owns the process, where ptrace_scope=1 (the default on most CI runners)
        // would otherwise refuse to let us attach to a process we merely started.
        const pid = await frida.spawn([
            process.execPath, '-e', 'setInterval(() => {}, 1000)'
        ]);

        try {
            const session = await frida.attach(pid);
            const source = await HookedProcess.buildSource(settings);

            const script = await session.createScript(source);
            const hooked = new HookedProcess(pid, script);
            script.logHandler = (_level, text) => { hooked.logs.push(text); };
            await script.load();
            await frida.resume(pid);
            return hooked;
        } catch (e) {
            await frida.kill(pid).catch(() => {});
            throw e;
        }
    }

    private static async buildSource(settings: { [setting: string]: string }) {
        let config = await fs.readFile(path.join(SCRIPTS, 'config.js'), 'utf8');
        config = config.replace(/(?<=const CERT_PEM = `)[^`]+(?=`)/s, PLACEHOLDER_CERT);

        Object.entries(settings).forEach(([setting, value]) => {
            const definition = new RegExp(`(?<=const ${setting} = )[^;]+(?=;)`);
            // Otherwise a renamed setting would silently not be applied, and the test would
            // quietly stop testing what it says it does:
            if (!definition.test(config)) {
                throw new Error(`Config setting ${setting} was not found`);
            }
            config = config.replace(definition, value);
        });

        const hook = await fs.readFile(path.join(SCRIPTS, 'native-connect-hook.js'), 'utf8');

        // Evaluated separately, as Frida's CLI does, so that the scripts share globals while
        // each still sees itself as its own file:
        return [
            `Script.evaluate('config.js', ${JSON.stringify(config)});`,
            `Script.evaluate('native-connect-hook.js', ${JSON.stringify(hook)});`,
            AGENT
        ].join('\n');
    }

    async connect(options: {
        host?: string,
        port: number,
        ipv6?: boolean,
        nonBlocking?: boolean
    }): Promise<ConnectResult> {
        const host = options.host ?? '93.184.216.34'; // Somewhere the hook will redirect
        return this.script.exports.connect(
            host.split('.').map(Number),
            options.port,
            options.ipv6 ?? false,
            options.nonBlocking ?? false
        ) as Promise<ConnectResult>;
    }

    async echo(text: string) {
        return this.script.exports.echo(text) as Promise<string | null>;
    }

    async stop() {
        await frida.kill(this.pid).catch(() => {});
    }
}
