/**
 * A minimal SOCKS5 server that can be told to misbehave in each of the ways a real proxy
 * plausibly might, so we can check the connect hook fails cleanly rather than hanging or
 * corrupting the connection.
 *
 * After a successful handshake it echoes everything it receives, which lets a test confirm
 * that the tunnel starts exactly where it should: any handshake bytes left unread would
 * arrive at the application as if the server had sent them.
 */

import * as net from 'net';

export type SocksMode =
    | 'normal'
    | 'dribble'        // Replies one byte at a time, forcing short reads
    | 'silent'         // Accepts the connection, then never replies at all
    | 'stalls'         // Replies to the greeting, then never replies to the request
    | 'refuses'        // Replies to the request with a failure code
    | 'demands-auth'   // Requires an auth method we don't offer
    | 'names-itself';  // Replies with a hostname (ATYP 3) rather than an address

export interface SocksRequest {
    addressType: number;
    address: string;
    port: number;
}

const [VERSION, NO_AUTH, NO_ACCEPTABLE_AUTH] = [0x05, 0x00, 0xFF];
const [IPV4, HOSTNAME, IPV6] = [0x01, 0x03, 0x04];

export class SocksServer {

    /** Every destination a client has asked us to connect to. */
    readonly requests: SocksRequest[] = [];

    private server: net.Server;
    private mode: SocksMode;

    private constructor(mode: SocksMode) {
        this.mode = mode;
        this.server = net.createServer((socket) => this.handle(socket));
    }

    static async start(mode: SocksMode = 'normal') {
        const server = new SocksServer(mode);
        await new Promise<void>((resolve) =>
            server.server.listen(0, '127.0.0.1', resolve));
        return server;
    }

    get port() {
        return (this.server.address() as net.AddressInfo).port;
    }

    async stop() {
        await new Promise((resolve) => this.server.close(resolve));
    }

    private write(socket: net.Socket, data: Buffer) {
        if (this.mode !== 'dribble') return socket.write(data);

        // One byte at a time, with a gap, so that a reader that assumes it gets everything
        // it asked for in one go will see only part of the message:
        let sent = 0;
        const timer = setInterval(() => {
            if (sent >= data.length || socket.destroyed) return clearInterval(timer);
            socket.write(data.subarray(sent, sent + 1));
            sent += 1;
        }, 5);
    }

    private handle(socket: net.Socket) {
        let stage: 'greeting' | 'request' | 'tunnelling' = 'greeting';
        let buffer = Buffer.alloc(0);

        socket.on('error', () => {}); // Clients hang up mid-handshake constantly here
        socket.on('data', (chunk) => {
            buffer = Buffer.concat([buffer, chunk]);

            if (stage === 'greeting') {
                // VER, NMETHODS, then that many method bytes:
                if (buffer.length < 2 || buffer.length < 2 + buffer[1]) return;
                if (buffer[0] !== VERSION) return socket.destroy();
                buffer = buffer.subarray(2 + buffer[1]);
                stage = 'request';

                if (this.mode === 'silent') return;
                if (this.mode === 'demands-auth') {
                    return this.write(socket, Buffer.from([VERSION, NO_ACCEPTABLE_AUTH]));
                }
                this.write(socket, Buffer.from([VERSION, NO_AUTH]));
                return;
            }

            if (stage === 'request') {
                const request = this.parseRequest(buffer);
                if (!request) return; // Not all here yet
                this.requests.push(request);
                buffer = Buffer.alloc(0);
                stage = 'tunnelling';

                if (this.mode === 'stalls') return;
                if (this.mode === 'refuses') {
                    return this.write(socket, this.reply(0x05)); // Connection refused
                }
                this.write(socket, this.reply(0x00));
                return;
            }

            socket.write(buffer); // Echo, so the tunnel's first bytes can be checked
            buffer = Buffer.alloc(0);
        });
    }

    private parseRequest(buffer: Buffer): SocksRequest | undefined {
        if (buffer.length < 4) return;
        const addressType = buffer[3];

        const addressLength =
            addressType === IPV4 ? 4 :
            addressType === IPV6 ? 16 :
            addressType === HOSTNAME ? (buffer.length >= 5 ? buffer[4] : undefined) :
            undefined;
        if (addressLength === undefined) return;

        const addressStart = addressType === HOSTNAME ? 5 : 4;
        if (buffer.length < addressStart + addressLength + 2) return;

        const addressBytes = buffer.subarray(addressStart, addressStart + addressLength);
        const address =
            addressType === IPV4 ? [...addressBytes].join('.') :
            addressType === IPV6 ? [...addressBytes].map((b) => b.toString(16).padStart(2, '0')).join('') :
            addressBytes.toString();

        return {
            addressType,
            address,
            port: buffer.readUInt16BE(addressStart + addressLength)
        };
    }

    private reply(status: number) {
        if (this.mode === 'names-itself') {
            const name = Buffer.from('proxy.example');
            return Buffer.concat([
                Buffer.from([VERSION, status, 0x00, HOSTNAME, name.length]),
                name,
                Buffer.from([0x00, 0x00])
            ]);
        }

        // A blank IPv4 bound address, which is what a proxy that never makes an outgoing
        // connection of its own has to report:
        return Buffer.from([VERSION, status, 0x00, IPV4, 0, 0, 0, 0, 0, 0]);
    }
}
