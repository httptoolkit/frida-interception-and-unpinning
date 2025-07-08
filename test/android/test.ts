import * as fs from 'fs/promises';
import * as mockttp from 'mockttp';
import * as appium from 'appium';
import { remote } from 'webdriverio';
import { expect } from 'chai';
import * as ChildProcess from 'child_process';

const IGNORED_BUTTONS = [
    'RAW CUSTOM-PINNED REQUEST',
];

const waitForContentDescription = async (button: WebdriverIO.Element, options: { timeout?: number } = {}): Promise<string> =>
    button.waitUntil(
        () => button.getAttribute('content-desc'),
        { timeout: options.timeout ?? 20_000 }
    );

const clickButton = async (button: WebdriverIO.Element) => {
    const text = await button.getText();
    button.click();

    // The webview buttons seem flaky in testing - sometimes they just don't respond (some kind of webview initialization
    // race?) so if they do nothing, we click them again before the main timeout (20s) expires.
    if (text.includes('WEBVIEW')) {
        waitForContentDescription(button, { timeout: 10_000 })
            .catch((e) => {
                button.click().catch(() => {});
            });
    }
}

describe('Test Android unpinning', function () {

    this.timeout(60_000);

    let appiumServer: any;
    let driver: WebdriverIO.Browser;
    let fridaSession: ChildProcess.ChildProcess;
    let proxyServer: mockttp.Mockttp;

    let seenRequests: mockttp.CompletedRequest[] = [];
    let tlsFailures: mockttp.TlsConnectionEvent[] = [];

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
            .replace(/(?<=const DEBUG = `)false/s, 'true')
            .replace(/(?<=const CERT_PEM = `)[^`]+(?=`)/s, cert.trim())
            .replace(/(?<=const PROXY_HOST = ')[^']+(?=')/, '10.0.2.2') // Android emulator localhost IP
            .replace(/(?<=const PROXY_PORT = )\d+(?=;)/, proxyServer.port.toString());
        await fs.writeFile('./tmp/config.js', config);
    });

    before(async () => {
        appiumServer = await appium.main({
            loglevel: 'warn'
        });
    });

    after(async () => {
        if (appiumServer) {
            await appiumServer.closeAllConnections();
            await appiumServer.close();
            await appiumServer.unref();
        }

        if (proxyServer) {
            await proxyServer.stop();
        }
    });

    beforeEach(async () => {
        proxyServer.reset();

        let reqCount = 0;
        await proxyServer.forAnyRequest().thenCallback((req) => {
            console.log(`Intercepted request ${reqCount++}: ${req.method} ${req.url}`);
            return { statusCode: 200, body: 'Mocked response' };
        });

        seenRequests = [];
        tlsFailures = [];
        await proxyServer.on('request', (req) => seenRequests.push(req));
        await proxyServer.on('tls-client-error', (event) => tlsFailures.push(event));
    });

    async function launchFrida(scripts: string[]) {
        fridaSession = ChildProcess.spawn('frida', [
            '-U',
            ...(
                scripts.map((script) => ['-l', script]).flat()
            ),
            '-f', 'tech.httptoolkit.pinning_demo'
        ], {
            cwd: '../..',
            stdio: 'pipe'
        });

        fridaSession.stdout?.pipe(process.stdout);
        fridaSession.stderr?.pipe(process.stderr);

        // Wait for Frida to start the app successfully
        await new Promise<void>((resolve, reject) => {
            fridaSession!.on('error', reject);
            fridaSession!.stdout?.on('data', (d) => {
                if (d.toString().includes('Spawned `tech.httptoolkit.pinning_demo`')) {
                    resolve();
                }
                if (d.toString().includes('Error: ')) {
                    reject(new Error(`Frida error: ${d.toString()}`));
                }
            })
        });

        driver = await remote({
            port: 4723,
            logLevel: 'warn',
            capabilities: {
                platformName: 'android',
                'appium:automationName': 'UiAutomator2',
                'appium:noReset': true,
                'appium:fullReset': false,
            }
        });
    }

    afterEach(async function (this: Mocha.Context) {
        if (this.currentTest?.state === 'failed') {
            if (driver) {
                const source = await driver.getPageSource().catch((e) => e.message);
                console.log('Test failed in this state:', source);
            } else {
                console.log('Test failed but no driver available to log state');
            }
        }
    });


    afterEach(async () => {
        if (driver) {
            await driver.deleteSession();
        }

        if (fridaSession) {
            fridaSession.kill('SIGUSR1');
            await new Promise(resolve => fridaSession!.on('exit', resolve));
        }
    });

    // We run this 100% failure test first, to warm everything up
    describe("without proxy config but no certificate trust", () => {

        beforeEach(async () => {
            await launchFrida([
                './test/android/tmp/config.js', // Our custom config
                // Redirect traffic but don't configure the cert - everything should fail:
                './android/android-proxy-override.js'
            ]);
        });

        it("all requests should fail", async () => {
            const buttons = await driver.$$('android=new UiSelector().className("android.widget.Button")');
            expect(buttons).to.have.lengthOf(13, 'Expected buttons were not present');

            buttons.map(clickButton);
            await Promise.all(await buttons.map(async (button) => {
                const buttonText = await button.getText();
                if (!IGNORED_BUTTONS.includes(buttonText.toUpperCase())) {
                    expect(await waitForContentDescription(button)).to.include('Failed');
                }
            }));

            expect(seenRequests).to.have.lengthOf(0, 'Expected all requests to fail');
            expect(tlsFailures).to.have.lengthOf(13, 'Expected TLS failures for all requests');
        });

    });

    describe("given no interception", () => {

        beforeEach(async () => {
            await launchFrida([]);
        });

        it('all buttons should succeed initially', async () => {
            const buttons = await driver.$$('android=new UiSelector().className("android.widget.Button")');
            expect(buttons).to.have.lengthOf(13, 'Expected buttons were not present');

            buttons.map(clickButton);
            await Promise.all(await buttons.map(async (button) => {
                const buttonText = await button.getText();
                if (!IGNORED_BUTTONS.includes(buttonText.toUpperCase())) {
                    expect(await waitForContentDescription(button)).to.include('Success');
                }
            }));

            expect(seenRequests).to.have.lengthOf(0, 'Expected no requests to be intercepted');
            expect(tlsFailures).to.have.lengthOf(0, 'Expected no TLS failures');
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

        it("all unpinned requests should succeed, all others should fail", async () => {
            const buttons = await driver.$$('android=new UiSelector().className("android.widget.Button")');
            expect(buttons).to.have.lengthOf(13, 'Expected buttons were not present');

            buttons.map(clickButton);
            await Promise.all(await buttons.map(async (button) => {
                const buttonText = await button.getText();
                if (buttonText.toUpperCase().startsWith('UNPINNED')) {
                    expect(await waitForContentDescription(button)).to.include('Success');
                }
                // Some pinnned requests will still pass because the basic cert
                // injection is just *that* good.
            }));

            expect(seenRequests).to.have.lengthOf.at.least(3, 'Expected unpinned requests to be intercepted');
            expect(tlsFailures).to.have.lengthOf.at.least(5, 'Expected most pinned requests to fail');
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
            ]);
        });

        it("all buttons except 'Raw custom-pinned request' should succeed", async () => {
            const buttons = await driver.$$('android=new UiSelector().className("android.widget.Button")');
            expect(buttons).to.have.lengthOf(13, 'Expected buttons were not present');

            buttons.map(clickButton);
            await Promise.all(await buttons.map(async (button) => {
                const buttonText = await button.getText();
                if (!IGNORED_BUTTONS.includes(buttonText.toUpperCase())) {
                    expect(await waitForContentDescription(button)).to.include('Success');
                }
            }));

            expect(seenRequests).to.have.lengthOf(14, 'Expected all requests to be intercepted');
            expect(tlsFailures).to.have.lengthOf(1, 'Expected only raw request to fail');
        });

    });

});