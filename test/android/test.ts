import * as fs from 'fs/promises';
import * as mockttp from 'mockttp';
import { expect } from 'chai';
import * as ChildProcess from 'child_process';

import { DeviceApp, delay, readUi } from './device.ts';

const APP_ID = 'tech.httptoolkit.pinning_demo';

const app = new DeviceApp(APP_ID);

type Result = 'Success' | 'Failed';

// The address the device should use to reach the proxy these tests run. On an emulator that's
// 10.0.2.2 (the emulator's alias for its host's loopback) but if the tests run elsewhere, e.g.
// in a container beside the emulator, that needs to be this machine's address instead:
const PROXY_HOST = process.env.TEST_PROXY_HOST || '10.0.2.2';

describe('Test Android unpinning', function () {

    this.timeout(4 * 60_000);

    let fridaSession: ChildProcess.ChildProcess | undefined;
    let proxyServer: mockttp.Mockttp;

    before(async () => {
        const [cert, key] = await Promise.all([
            fs.readFile('./tmp/ca.crt', 'utf8'),
            fs.readFile('./tmp/ca.key', 'utf8')
        ]).catch(async () => {
            // If the files don't exist, generate a new CA cert
            const ca = await mockttp.generateCACertificate();
            await fs.mkdir('./tmp');
            await fs.writeFile('./tmp/ca.crt', ca.cert);
            await fs.writeFile('./tmp/ca.key', ca.key);
            return [ca.cert, ca.key];
        });

        proxyServer = mockttp.getLocal({
            recordTraffic: false,
            https: {
                cert,
                key
            },
            socks: true,
            passthrough: ['unknown-protocol'],
            http2: true
        });

        await proxyServer.start();

        const configBase = await fs.readFile('../../config.js', 'utf8');
        const config = configBase
            .replace(/(?<=const CERT_PEM = `)[^`]+(?=`)/s, cert.trim())
            .replace(/(?<=const PROXY_HOST = ')[^']+(?=')/, PROXY_HOST)
            .replace(/(?<=const PROXY_PORT = )\d+(?=;)/, proxyServer.port.toString());
        await fs.writeFile('./tmp/config.js', config);
    });

    after(async () => {
        if (proxyServer) {
            await proxyServer.stop();
        }
    });

    beforeEach(async () => {
        proxyServer.reset();

        await proxyServer.on('request', (req) => {
            console.log(` - Intercepted request to ${req.url}`);
        });

        await proxyServer.on('tls-client-error', (event) => {
            console.log(` - TLS interception rejected for ${event.tlsMetadata.sniHostname}`);
        });

        await proxyServer.forAnyRequest().thenCallback((req) => {
            return { statusCode: 200, body: 'Mocked response' };
        });
    });

    afterEach(async function (this: Mocha.Context) {
        if (this.currentTest?.state === 'failed') {
            const buttons = await readUi().then((ui) => app.buttons(ui)).catch(() => []);
            console.log('Test failed with these buttons on screen:', buttons.length
                ? buttons.map(({ text, description }) => `${text}: ${description || '(no result)'}`)
                : '(none - the app was not on screen)'
            );
        }

        await stopFrida();
    });

    // Frida exits by itself in various cases (notably if the app is killed) and 'exit' never
    // fires twice, so we have to check before waiting for it, or we'd wait forever:
    const stopFrida = async () => {
        if (!fridaSession) return;
        const session = fridaSession;
        fridaSession = undefined;

        if (session.exitCode === null && session.signalCode === null) {
            session.kill('SIGUSR1');
            await new Promise(resolve => session.once('exit', resolve));
        }
    };

    async function launchFrida(scripts: string[]) {
        {
            // N.b. no retries here: launching is reliable now that the scripts don't delay startup
            // significantly, so a failure to launch means something is actually wrong, and CI runs
            // the tests with --retries anyway.

            // Start from a clean slate, so we can't mistake a leftover instance for our launch:
            await app.forceStop();
            await app.clearLogs();

            const session = fridaSession = ChildProcess.spawn('frida', [
                '-U',
                ...(
                    scripts.map((script) => ['-l', script]).flat()
                ),
                '-f', APP_ID
            ], {
                cwd: '../..',
                stdio: 'pipe'
            });

            let fridaOutput = '';
            let spawnError: Error | undefined;
            session.stdout!.on('data', (d) => { fridaOutput += d.toString(); });
            session.stderr!.on('data', (d) => { fridaOutput += d.toString(); });
            session.stdout?.pipe(process.stdout);
            session.stderr?.pipe(process.stderr);
            // Without this listener, a Frida that can't be run at all (e.g. it's not installed)
            // raises an unhandled error event, killing the entire test run:
            session.on('error', (e) => { spawnError = e });

            console.log('Waiting for app to load...');
            const failure = await waitForApp(session, () => fridaOutput);

            if (!failure) {
                console.log('App loaded');
                return;
            }

            await stopFrida();

            if (spawnError) throw spawnError;

            // Whatever went wrong, Android usually logged why, and that's far more useful than
            // our own view of it:
            const androidLogs = await app.recentFailureLogs();

            throw new Error(
                `The app did not start: ${failure}.` +
                (androidLogs ? `\nAndroid logged:\n${androidLogs}` : '') +
                `\nFrida output:\n${fridaOutput}`
            );
        }

        // Returns a description of what went wrong, or undefined once the app is up:
        async function waitForApp(
            session: ChildProcess.ChildProcess,
            output: () => string
        ): Promise<string | undefined> {
            const startTime = Date.now();

            while (Date.now() - startTime < 60_000) {
                // Frida exits if Android kills the app during startup (or if it fails to start it
                // at all) and there's nothing left to wait for if so:
                if (session.exitCode !== null || session.signalCode !== null) {
                    return 'Frida exited before the app appeared';
                }

                const ui = await readUi();

                // A crash or ANR dialog covers the app, so report that rather than just timing out:
                const systemError = app.systemErrorDialog(ui);
                if (systemError) return `Android reported: "${systemError}"`;

                // The previous instance's window can linger on screen briefly after it's killed,
                // so we wait for Frida to confirm the launch, not just for the app to be visible:
                if (
                    output().includes(`Spawned \`${APP_ID}\``) &&
                    app.hasText(ui, 'SSL Pinning Demo')
                ) return undefined;

                // N.b. this must await something on every pass, or we'd starve the event loop and
                // never receive Frida's output at all:
                await delay(500);
            }

            return 'Timed out waiting for the app to appear';
        }
    }

    const testButton = async (text: string, expected: Result) => {
        // Not every button fits on screen, so we scroll each one into view before using it:
        const button = await app.scrollIntoView(text);

        console.log(`Testing button: ${text} (expected: ${expected})`);
        await app.tap(button);

        // Requests here either complete or fail within a few seconds, so this is generous, but
        // capped so that one stuck button reports itself rather than eating the test's timeout:
        const description = await app.waitForButtonResult(text, {
            timeout: 30_000,
            retryTapAfter: 15_000
        });

        expect(description).to.be.a('string', `Button ${text} did not respond`);

        // Matching the app's exact wording, so that a failure whose error message happens to
        // mention success can't be read as one:
        expect(description).to.include(
            expected === 'Success' ? ' - Success' : ' - Failed with error:',
            `Button ${text} was not ${expected}:`
        );
    };

    // Test every button in the app, expecting the given result for each, except for the buttons
    // named as exceptions, which should do the opposite:
    const testAllButtons = async (
        expected: Result,
        { exceptions = [] }: { exceptions?: string[] } = {}
    ) => {
        // If the app dies mid-test we see only its absence, so we say what Android saw too:
        const buttons = await app.findAllButtons().catch(async (e) => {
            const androidLogs = await app.recentFailureLogs();
            throw new Error(
                `${e.message}` +
                (await app.isRunning() ? '' : '. The app is no longer running') +
                (androidLogs ? `.\nAndroid logged:\n${androidLogs}` : '')
            );
        });

        console.log(`Testing ${buttons.length} buttons: ${buttons.join(', ')}`);

        // Without this, a scenario with no exceptions would pass having tested nothing at all:
        expect(buttons).not.to.be.empty;

        // If the app's buttons are renamed or dropped, the expectations below are no longer
        // saying what they think they are, so we check them against the app itself:
        expect(exceptions.filter((exception) => !buttons.includes(exception)))
            .to.deep.equal([], 'Expected buttons were not present');

        await app.scrollToTop();

        for (let button of buttons) {
            await testButton(button, exceptions.includes(button)
                ? (expected === 'Success' ? 'Failed' : 'Success')
                : expected
            );
        }
    };

    // We run this 100% failure test first, to warm everything up
    describe("with proxy config but no certificate trust", () => {

        beforeEach(async () => {
            await launchFrida([
                './test/android/tmp/config.js', // Our custom config
                // Redirect traffic but don't configure the cert - everything should fail:
                './android/android-proxy-override.js'
            ]);
        });

        it("all TLS requests should fail", async () => {
            await testAllButtons('Failed', {
                exceptions: [
                    // Plain HTTP isn't affected by cert trust at all - it's proxied & mocked fine:
                    'PLAIN HTTP REQUEST',
                    'PLAIN IGNORE-PROXY HTTP REQUEST',
                    // Flutter doesn't use the proxy settings this script sets, so it connects
                    // directly, untouched:
                    'FLUTTER REQUEST',
                    // Raw sockets ignore the proxy settings too, so this connects directly to the
                    // real server, whose certificate it pins successfully:
                    'RAW CUSTOM-PINNED REQUEST'
                ]
            });
        });

    });

    describe("given no interception", () => {

        beforeEach(async () => {
            await launchFrida([]);
        });

        it('all buttons should succeed initially', async () => {
            await testAllButtons('Success');
        });

    });

    describe("given basic interception", () => {

        beforeEach(async () => {
            await launchFrida([
                './test/android/tmp/config.js', // Our custom config
                // Otherwise just the basic Android settings injection scripts to set the
                // system cert & system proxy:
                './android/android-proxy-override.js',
                './android/android-system-certificate-injection.js'
            ]);
        });

        it("everything should succeed except the explicitly pinned requests", async () => {
            await testAllButtons('Success', {
                exceptions: [
                    // These pin specific certificates (by hash, or via the network security
                    // config) so trusting our CA isn't enough - only unpinning fixes these:
                    'CONFIG-PINNED REQUEST',
                    'OKHTTP PINNED REQUEST',
                    'TRUSTKIT PINNED REQUEST'
                ]
            });
        });

    });

    describe("given full unpinned interception", () => {

        beforeEach(async () => {
            await launchFrida([
                './test/android/tmp/config.js', // Our custom config
                // Otherwise the standard scripts, as in the README:
                './native-connect-hook.js',
                './native-tls-hook.js',
                './android/android-proxy-override.js',
                './android/android-system-certificate-injection.js',
                './android/android-certificate-unpinning.js',
                './android/android-certificate-unpinning-fallback.js',
                './android/android-disable-root-detection.js',
                './android/android-disable-flutter-certificate-pinning.js',
            ]);
        });

        it("all buttons should succeed, except the known unsupported cases", async () => {
            await testAllButtons('Success', {
                exceptions: [
                    // This checks the certificate itself, by hand, at the lowest level. Unpinning
                    // it requires reverse engineering the app - see the demo app's README.
                    'RAW CUSTOM-PINNED REQUEST',
                    // The Flutter hooks find their targets by scanning for byte patterns, and
                    // those don't match the Flutter version this app now ships, so Flutter
                    // traffic is not unpinned at all here:
                    'FLUTTER REQUEST'
                ]
            });
        });

    });

});
