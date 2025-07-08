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
        { timeout: options.timeout ?? 30_000 }
    );

describe('Test Android unpinning', function () {

    this.timeout(60_000);

    let appiumServer: any;
    let driver: WebdriverIO.Browser;
    let fridaSession: ChildProcess.ChildProcess;
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
            if (driver) {
                const source = await driver.getPageSource().catch((e) => e.message);
                console.log('Test failed in this state:', source);
            } else {
                console.log('Test failed but no driver available to log state');
            }
        }

        if (driver) {
            await driver.deleteSession();
        }

        if (fridaSession) {
            fridaSession.kill('SIGUSR1');
            await new Promise(resolve => fridaSession!.on('exit', resolve));
        }
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

        // Wait until the app UI is actually loaded & visible on screen:
        console.log("Waiting for app to load...");
        const titleText = driver.$('android=new UiSelector().text("SSL Pinning Demo")')
        await titleText.waitForExist()
        console.log("App loaded:", await titleText.getText());
    }

    const testButton = async (button: WebdriverIO.Element, expected: 'Success' | 'Failed' | '?') => {
        const text = await button.getText();
        console.log(`Testing button: ${text} (expected: ${expected})`);

        await button.click();

        let description: string | undefined;

        // Webview buttons can need a kick to start up, and then end up sending 2x requests, eugh
        if (text.includes('WEBVIEW')) {
            waitForContentDescription(button, { timeout: 10_000 })
                .catch((e) => {
                    if (!description) {
                        console.log(`Retrying webview button ${text} (${e.message})`);
                        button.click().catch(() => {});
                    }
                });
        }

        description = await waitForContentDescription(button);
        if (expected !== '?') {
            expect(description).to.include(expected, `Button ${text} was not ${expected}:`);
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

        it("all requests should fail", async () => {
            const buttons = await driver.$$('android=new UiSelector().className("android.widget.Button")');
            expect(buttons).to.have.lengthOf(13, 'Expected buttons were not present');

            for (let button of buttons) {
                await testButton(button, 'Failed');
            }
        });

    });

    describe("given no interception", () => {

        beforeEach(async () => {
            await launchFrida([]);
        });

        it('all buttons should succeed initially', async () => {
            const buttons = await driver.$$('android=new UiSelector().className("android.widget.Button")');
            expect(buttons).to.have.lengthOf(13, 'Expected buttons were not present');

            for (let button of buttons) {
                const buttonText = await button.getText();
                const ignored = IGNORED_BUTTONS.includes(buttonText.toUpperCase());
                await testButton(button, ignored ? '?' : 'Success');
            }
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

        it("all unpinned requests should succeed, most others should fail", async () => {
            const buttons = await driver.$$('android=new UiSelector().className("android.widget.Button")');
            expect(buttons).to.have.lengthOf(13, 'Expected buttons were not present');

            for (let button of buttons) {
                const buttonText = await button.getText();
                const shouldSucceed = buttonText.toUpperCase().includes('UNPINNED');
                await testButton(button, shouldSucceed ? 'Success' : '?');
            }
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

            for (let button of buttons) {
                const buttonText = await button.getText();
                const ignored = IGNORED_BUTTONS.includes(buttonText.toUpperCase());
                await testButton(button, ignored ? '?' : 'Success');
            }
        });

    });

});