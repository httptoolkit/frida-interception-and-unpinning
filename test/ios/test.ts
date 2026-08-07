import * as fs from 'fs/promises';
import * as path from 'path';
import * as mockttp from 'mockttp';
import { expect } from 'chai';

import { SimulatorApp, type RequestResult, type Script } from './simulator.ts';

const BUNDLE_ID = 'tech.httptoolkit.frida_test_app'; // Matching setup-simulator.sh
const BUILD_DIR = path.join(import.meta.dirname, 'tmp');
const REPO_ROOT = path.join(import.meta.dirname, '..', '..');

// The simulator shares its host's network stack, so the proxy is simply on localhost:
const PROXY_HOST = '127.0.0.1';

// Every request the test app makes, as it names them itself (see app/main.swift):
const HTTPS_REQUEST = 'https';
const HTTP_REQUEST = 'http';
const RAW_SOCKET_REQUEST = 'raw'; // Over a BSD socket, i.e. not via Network framework at all
const ALL_REQUESTS = [HTTPS_REQUEST, HTTP_REQUEST, RAW_SOCKET_REQUEST];

const MOCK_RESPONSE = 'Mocked response';

const app = new SimulatorApp(BUNDLE_ID, BUILD_DIR);

describe('Test iOS interception', function () {

    this.timeout(4 * 60_000);

    let proxyServer: mockttp.Mockttp;
    let interceptedUrls: string[] = [];
    let rejectedTlsHosts: string[] = [];

    // The scripts, as the README's iOS command lists them, but each is loaded only where the
    // scenario below asks for it:
    let scripts: { [name: string]: Script };

    before(async () => {
        await app.connect();

        const [cert, key] = await Promise.all([
            fs.readFile(path.join(BUILD_DIR, 'ca.crt'), 'utf8'),
            fs.readFile(path.join(BUILD_DIR, 'ca.key'), 'utf8')
        ]).catch(async () => {
            // If the files don't exist, generate a new CA cert
            const ca = await mockttp.generateCACertificate();
            await fs.mkdir(BUILD_DIR, { recursive: true });
            await fs.writeFile(path.join(BUILD_DIR, 'ca.crt'), ca.cert);
            await fs.writeFile(path.join(BUILD_DIR, 'ca.key'), ca.key);
            return [ca.cert, ca.key];
        });

        proxyServer = mockttp.getLocal({
            recordTraffic: false,
            https: { cert, key },
            socks: true,
            passthrough: ['unknown-protocol'],
            http2: true
        });

        await proxyServer.start();

        const readScript = async (relativePath: string): Promise<Script> => ({
            name: relativePath,
            source: await fs.readFile(path.join(REPO_ROOT, relativePath), 'utf8')
        });

        // The proxy's own CA & port, so that intercepting anything at all is a real test of the
        // scripts, exactly as a user would configure them:
        const configSource = (await fs.readFile(path.join(REPO_ROOT, 'config.js'), 'utf8'))
            .replace(/(?<=const CERT_PEM = `)[^`]+(?=`)/s, cert.trim())
            .replace(/(?<=const PROXY_HOST = ')[^']+(?=')/, PROXY_HOST)
            .replace(/(?<=const PROXY_PORT = )\d+(?=;)/, proxyServer.port.toString());

        scripts = Object.fromEntries((await Promise.all([
            app.objcBridge(),
            Promise.resolve({ name: 'config.js', source: configSource }),
            readScript('ios/ios-connect-hook.js'),
            readScript('ios/ios-disable-detection.js'),
            readScript('native-tls-hook.js'),
            readScript('native-connect-hook.js')
        ])).map((script) => [script.name, script]));
    });

    after(async () => {
        await app.terminate();
        if (proxyServer) await proxyServer.stop();
    });

    beforeEach(async () => {
        proxyServer.reset();
        interceptedUrls = [];
        rejectedTlsHosts = [];

        await proxyServer.on('request', (req) => {
            console.log(` - Intercepted request to ${req.url}`);
            interceptedUrls.push(req.url);
        });

        await proxyServer.on('tls-client-error', (event) => {
            console.log(` - TLS interception rejected for ${event.tlsMetadata.sniHostname}`);
            rejectedTlsHosts.push(event.tlsMetadata.sniHostname!);
        });

        await proxyServer.forAnyRequest().thenReply(200, MOCK_RESPONSE);
    });

    afterEach(async function (this: Mocha.Context) {
        if (this.currentTest?.state === 'failed') {
            console.log('Test failed. Our scripts logged:');
            console.log(await app.gadgetLog() || '(nothing at all - they never ran)');
        }

        await app.terminate();
    });

    // Launch the app with the given scripts injected via the gadget, and wait for it to report
    // every request it makes:
    const runWithScripts = async (scriptNames: string[]) => {
        await app.injectScripts(scriptNames.map((name) => scripts[name]));
        await app.launch({ withGadget: true });
        return app.waitForResults(ALL_REQUESTS);
    };

    describe("given no interception", () => {

        let results: { [name: string]: RequestResult };

        beforeEach(async () => {
            // No gadget at all, so nothing of ours is loaded into the app:
            await app.launch({ withGadget: false });
            results = await app.waitForResults(ALL_REQUESTS);
        });

        it("all requests should go directly to the real server", async () => {
            for (const request of ALL_REQUESTS) {
                expect(results[request].error, `${request} request failed`).to.equal(undefined);
                expect(results[request].status, `${request} request`).to.equal(200);
                // I.e. this came from example.com itself, not from our proxy:
                expect(results[request].body, `${request} request`)
                    .not.to.include(MOCK_RESPONSE);
            }

            // Without this, an app that quietly reached the proxy anyway would still pass every
            // check above, and every scenario below would be meaningless:
            expect(interceptedUrls).to.deep.equal([]);
        });

    });

    describe("given connection redirection but no certificate trust", () => {

        let results: { [name: string]: RequestResult };

        beforeEach(async () => {
            results = await runWithScripts([
                'config.js',
                // Redirect connections, but don't touch certificate trust:
                'ios/ios-connect-hook.js',
                'native-connect-hook.js'
            ]);
        });

        it("only the unencrypted requests should be intercepted successfully", async () => {
            expect(results[HTTP_REQUEST].body, 'HTTP request').to.equal(MOCK_RESPONSE);
            expect(results[RAW_SOCKET_REQUEST].body, 'raw socket request').to.equal(MOCK_RESPONSE);

            // HTTPS reaches the proxy too, but the app doesn't trust it, so it goes no further:
            expect(results[HTTPS_REQUEST].error, 'HTTPS request').not.to.equal(undefined);
            expect(rejectedTlsHosts).to.include('example.com');
        });

    });

    describe("given full interception", () => {

        let results: { [name: string]: RequestResult };

        beforeEach(async () => {
            results = await runWithScripts([
                // The bridge first, since ios-disable-detection.js uses ObjC as it loads:
                'the ObjC bridge',
                // Then the standard scripts, in the order the README's iOS command uses:
                'config.js',
                'ios/ios-connect-hook.js',
                'ios/ios-disable-detection.js',
                'native-tls-hook.js',
                'native-connect-hook.js'
            ]);
        });

        it("every request should be intercepted successfully", async () => {
            for (const request of ALL_REQUESTS) {
                expect(results[request].error, `${request} request failed`).to.equal(undefined);
                expect(results[request].status, `${request} request`).to.equal(200);
                expect(results[request].body, `${request} request`).to.equal(MOCK_RESPONSE);
            }

            expect(interceptedUrls).to.include.members([
                'https://example.com/https-request',
                'http://example.com/http-request',
                'http://example.com/raw-request'
            ]);
        });

        it("every script should load & hook what it's aiming at", async () => {
            const log = await app.gadgetLog();

            // N.b. these match the scripts' success messages specifically - 'libboringssl.dylib'
            // alone would also match the message logged when hooking it fails:
            expect(log).to.include('== Hooked native TLS lib libboringssl.dylib ==');
            expect(log).to.include(
                `== Redirecting all TCP connections to ${PROXY_HOST}:${proxyServer.port} ==`
            );
            expect(log).to.include(
                `== Redirecting Network framework connections to ` +
                `${PROXY_HOST}:${proxyServer.port} ==`
            );

            // Last, so that a script that fails halfway is reported as the specific hook that's
            // missing above, rather than just as an incomplete run:
            expect(log, 'not all scripts ran to completion').to.include('ALL SCRIPTS LOADED');
        });

    });

});
