/**
 * Tests for native-connect-hook.js, run against a SOCKS server we can make misbehave.
 *
 * These run here rather than on a device because none of this is reachable from an app: a
 * real proxy either works or it doesn't, where the interesting cases are the ones where it
 * half-works. The Android suite covers that the hook intercepts real traffic; this covers
 * what happens when the thing on the other end stops cooperating.
 */

import { expect } from 'chai';

import { HookedProcess } from './hooked-process.ts';
import { SocksServer, type SocksMode } from './socks-server.ts';

const DESTINATION = '93.184.216.34';
const DESTINATION_PORT = 443;

describe('The native connect hook', function () {

    this.timeout(30_000);

    let proxy: SocksServer | undefined;
    let app: HookedProcess | undefined;

    afterEach(async () => {
        await app?.stop();
        await proxy?.stop();
        app = proxy = undefined;
    });

    // Starts a SOCKS proxy in the given mode, with the hook pointed at it:
    const givenSocksProxy = async (mode: SocksMode = 'normal') => {
        proxy = await SocksServer.start(mode);
        app = await HookedProcess.start({
            PROXY_HOST: `'127.0.0.1'`,
            PROXY_PORT: proxy.port.toString(),
            PROXY_SUPPORTS_SOCKS5: 'true'
        });
        return { proxy, app };
    };

    describe('given a working SOCKS proxy', () => {

        it('tunnels connections, and the tunnel carries data cleanly', async () => {
            const { app, proxy } = await givenSocksProxy();

            const result = await app.connect({ port: DESTINATION_PORT });

            expect(result.result).to.equal(0);
            expect(proxy.requests).to.deep.equal([
                { addressType: 1, address: DESTINATION, port: DESTINATION_PORT }
            ]);
            // The proxy echoes what it receives, so anything the handshake left unread
            // would turn up in front of this:
            expect(await app.echo('HELLO')).to.equal('HELLO');
        });

        it('sends IPv4-mapped destinations as plain IPv4', async () => {
            // Android apps open AF_INET6 sockets for IPv4 destinations almost universally,
            // so this is the common case rather than an edge case. The 16-byte form is
            // handled inconsistently by SOCKS servers - mockttp rejects it outright.
            const { app, proxy } = await givenSocksProxy();

            const result = await app.connect({ port: DESTINATION_PORT, ipv6: true });

            expect(result.result).to.equal(0);
            expect(proxy.requests).to.deep.equal([
                { addressType: 1, address: DESTINATION, port: DESTINATION_PORT }
            ]);
            expect(await app.echo('HELLO')).to.equal('HELLO');
        });

        it('leaves a non-blocking socket non-blocking', async () => {
            // We clear O_NONBLOCK to run the handshake. Not putting it back would leave the
            // app's socket blocking for the rest of its life.
            const { app } = await givenSocksProxy();

            const result = await app.connect({
                port: DESTINATION_PORT,
                nonBlocking: true
            });

            expect(result.result).to.equal(0);
            expect(result.nonBlocking).to.equal(true);
        });

        it('handles a proxy that replies one byte at a time', async () => {
            // recv() returns as soon as any data is available, so a reply split across
            // packets is misparsed by anything that assumes otherwise - and the leftovers
            // are then delivered to the application as if the server had sent them.
            const { app } = await givenSocksProxy('dribble');

            const result = await app.connect({ port: DESTINATION_PORT });

            expect(result.result).to.equal(0);
            expect(await app.echo('HELLO')).to.equal('HELLO');
        });

    });

    describe('given a proxy that stops cooperating', () => {

        // The everyday version of this is the USB cable coming out. There's nothing to
        // recover, so all we want is a prompt, clearly reported failure.

        it('gives up on a proxy that never replies', async () => {
            const { app } = await givenSocksProxy('silent');

            const result = await app.connect({ port: DESTINATION_PORT });

            expect(result.result).to.equal(-1);
            expect(result.durationMs).to.be.lessThan(20_000);
        });

        it('gives up on a proxy that stalls mid-handshake', async () => {
            const { app } = await givenSocksProxy('stalls');

            const result = await app.connect({ port: DESTINATION_PORT });

            expect(result.result).to.equal(-1);
            expect(result.durationMs).to.be.lessThan(20_000);
        });

        it('reports a proxy refusing the connection as a failed connect', async () => {
            const { app } = await givenSocksProxy('refuses');

            const result = await app.connect({ port: DESTINATION_PORT });

            expect(result.result).to.equal(-1);
            expect(app.logs.join('\n')).to.include('SOCKS: Server returned error code 5');
        });

        it('fails cleanly when the proxy demands an auth method we do not offer', async () => {
            const { app } = await givenSocksProxy('demands-auth');

            const result = await app.connect({ port: DESTINATION_PORT });

            expect(result.result).to.equal(-1);
            expect(app.logs.join('\n')).to.include('SOCKS: Server rejected auth method');
        });

        it('refuses a hostname reply rather than misreading the stream', async () => {
            // ATYP 3 is legal, but nothing we proxy through replies with one. Failing beats
            // guessing at how many bytes of address to consume.
            const { app } = await givenSocksProxy('names-itself');

            const result = await app.connect({ port: DESTINATION_PORT });

            expect(result.result).to.equal(-1);
            expect(app.logs.join('\n')).to.include('unsupported address type 3');
        });

        it('reports a failure the application can interpret', async () => {
            // -1 with errno left at 0 isn't a failure any application knows how to handle.
            const { app } = await givenSocksProxy('silent');

            const result = await app.connect({ port: DESTINATION_PORT });

            expect(result.result).to.equal(-1);
            expect(result.errno).to.equal(111); // ECONNREFUSED
        });

        it('leaves a non-blocking socket non-blocking even when the handshake fails', async () => {
            const { app } = await givenSocksProxy('silent');

            const result = await app.connect({
                port: DESTINATION_PORT,
                nonBlocking: true
            });

            expect(result.result).to.equal(-1);
            expect(result.nonBlocking).to.equal(true);
        });

    });

    describe('given no SOCKS support', () => {

        it('redirects connections to the proxy', async () => {
            proxy = await SocksServer.start();
            app = await HookedProcess.start({
                PROXY_HOST: `'127.0.0.1'`,
                PROXY_PORT: proxy.port.toString(),
                PROXY_SUPPORTS_SOCKS5: 'false'
            });

            // No SOCKS handshake, so the proxy sees a raw connection rather than a request,
            // but the connection itself lands on the proxy rather than the destination:
            const result = await app.connect({ port: DESTINATION_PORT });

            expect(result.result).to.equal(0);
            expect(proxy.requests).to.deep.equal([]);
        });

        it('leaves connections to the proxy itself alone', async () => {
            proxy = await SocksServer.start();
            app = await HookedProcess.start({
                PROXY_HOST: `'127.0.0.1'`,
                PROXY_PORT: proxy.port.toString(),
                PROXY_SUPPORTS_SOCKS5: 'true'
            });

            // Already going where we'd send it, so it must be left completely untouched -
            // rewriting it would send our own SOCKS handshake into the proxy twice.
            const result = await app.connect({
                host: '127.0.0.1',
                port: proxy.port,
                nonBlocking: true
            });

            // A non-blocking connect() reports EINPROGRESS, which is exactly what proves we
            // kept out of the way: had we touched it we'd have made it blocking and returned
            // a result of our own.
            expect(result.result).to.equal(-1);
            expect(result.errno).to.equal(115); // EINPROGRESS
            expect(result.nonBlocking).to.equal(true);
            expect(proxy.requests).to.deep.equal([]);
        });

        it('leaves an exempted port unintercepted', async () => {
            proxy = await SocksServer.start();
            app = await HookedProcess.start({
                PROXY_HOST: `'127.0.0.1'`,
                PROXY_PORT: proxy.port.toString(),
                IGNORED_NON_HTTP_PORTS: '[9]'
            });

            // Port 9 is exempted, so this goes to the real (dead) destination and fails,
            // where without the exemption it would be redirected to our proxy and succeed:
            const result = await app.connect({ host: '127.0.0.1', port: 9 });

            expect(result.result).to.equal(-1);
        });

    });

});
