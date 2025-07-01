import * as appium from 'appium';
import { remote } from 'webdriverio';
import { expect } from 'chai';
import { delay } from '@httptoolkit/util';

describe('Test Android unpinning', function () {

    this.timeout(60_000);

    let appiumServer: any;
    let driver: WebdriverIO.Browser;

    before(async () => {
        appiumServer = await appium.main({
            loglevel: 'warn'
        });

        driver = await remote({
            port: 4723,
            capabilities: {
                platformName: 'android',
                'appium:appPackage': 'tech.httptoolkit.pinning_demo',
                'appium:automationName': 'UiAutomator2',
                'appium:appActivity': '.MainActivity'
            }
        });
    });

    after(async () => {
        if (driver) await driver.deleteSession();
        if (appiumServer) await appiumServer.close();
    })

    it('should run a test', async () => {
        const button = driver.$('android=new UiSelector().text("UNPINNED REQUEST")');
        await button.click();

        let contentDescription: string | undefined;
        while (!contentDescription) {
            await delay(500);
            contentDescription = await button.getAttribute('content-desc');
        }

        expect(contentDescription).to.include('Success');
    });

});