/**
 * A minimal Android UI driver, built directly on ADB.
 *
 * Everything these tests need from a device is: read the UI, tap things, and scroll. UIAutomator's
 * own `dump` gives us the first (in one shot, including the content descriptions the demo app uses
 * to report results) and `input` gives us the rest, so we do it directly rather than pulling in
 * Appium & WebdriverIO (and their ~800 transitive dependencies, and a device-side server) for it.
 */

import * as ChildProcess from 'child_process';
import { promisify } from 'util';
import { XMLParser } from 'fast-xml-parser';

const execFile = promisify(ChildProcess.execFile);

export const adb = (...args: string[]) =>
    execFile('adb', args, { maxBuffer: 32 * 1024 * 1024 }).then(({ stdout }) => stdout);

export const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export interface UiNode {
    text: string;
    description: string;
    className: string;
    packageName: string;
    scrollable: boolean;
    bounds: readonly [left: number, top: number, right: number, bottom: number];
}

const xmlParser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '' });

const parseNodes = (xml: string) => {
    const nodes: UiNode[] = [];

    const collect = (node: any) => {
        if (!node || typeof node !== 'object') return;
        if (Array.isArray(node)) return node.forEach(collect);

        if (node.class && node.bounds) {
            const [, ...bounds] = /\[(\d+),(\d+)]\[(\d+),(\d+)]/.exec(node.bounds) ?? [];
            if (bounds.length === 4) {
                nodes.push({
                    text: node.text ?? '',
                    description: node['content-desc'] ?? '',
                    className: node.class,
                    packageName: node.package ?? '',
                    scrollable: node.scrollable === 'true',
                    bounds: bounds.map(Number) as unknown as UiNode['bounds']
                });
            }
        }

        // Children live under a 'node' key, but walking everything keeps this robust to changes:
        Object.values(node).forEach(collect);
    };
    collect(xmlParser.parse(xml).hierarchy);

    return nodes;
};

/**
 * Read the entire visible UI. Note that only on-screen views appear at all - anything scrolled
 * out of view is simply not in the hierarchy.
 */
export const readUi = async (): Promise<UiNode[]> => {
    // Dumping is rejected while the UI is busy or wedged. That's worth waiting out rather than
    // failing immediately: if the app has hung, Android puts an ANR dialog up within a few
    // seconds, and reporting that is far more useful than reporting a failed dump.
    const ATTEMPTS = 20;

    for (let attempt = 1; ; attempt++) {
        // Dumping to /dev/tty streams the XML straight back to us, avoiding a second round trip
        // via a file on the device:
        const output = await adb('exec-out', 'uiautomator', 'dump', '/dev/tty')
            .catch((e): string => `dump failed: ${e.message}`);

        const xml = output.slice(output.indexOf('<?xml'), output.lastIndexOf('>') + 1);
        if (xml.includes('<hierarchy')) {
            try {
                return parseNodes(xml);
            } catch (e: any) {
                if (attempt >= ATTEMPTS) throw new Error(`Could not parse UI dump: ${e.message}`);
            }
        } else if (attempt >= ATTEMPTS) {
            throw new Error(
                `Could not read the device UI for ${(ATTEMPTS * 500) / 1000}s, which normally ` +
                `means the screen is not responding: ${output.trim()}`
            );
        }

        await delay(500);
    }
};

const contains = (outer: UiNode['bounds'], inner: UiNode['bounds']) =>
    inner[0] >= outer[0] && inner[1] >= outer[1] && inner[2] <= outer[2] && inner[3] <= outer[3];

/**
 * A summary of what's on screen & where, so we can tell whether a scroll actually moved anything.
 */
const positionSummary = (nodes: UiNode[]) =>
    nodes.map(({ text, bounds }) => `${text}@${bounds.join(',')}`).join(';');

export class DeviceApp {

    // N.b. no parameter properties - Node's type stripping only erases types, it can't
    // generate the assignment those imply:
    private appId: string;

    constructor(appId: string) {
        this.appId = appId;
    }

    async apiLevel() {
        return parseInt(await adb('shell', 'getprop', 'ro.build.version.sdk'), 10);
    }

    /**
     * Anything Android itself logged about the app crashing or hanging. When something goes wrong
     * this usually explains it far better than the symptoms we can see from outside.
     */
    async recentFailureLogs() {
        const logs = (await adb('logcat', '-d').catch(() => '')).split('\n');

        const failures = logs.flatMap((line, i) => {
            const isAnr = line.includes('ANR in') && line.includes(this.appId);
            const isCrash = line.includes('FATAL EXCEPTION') &&
                // The app is named on the line after this one, not on the line itself:
                logs.slice(i, i + 3).some((next) => next.includes(this.appId));

            // The lines that follow say why (the ANR's reason, or the exception itself):
            return isAnr || isCrash ? logs.slice(i, i + 3) : [];
        });

        return failures.slice(0, 9).join('\n');
    }

    async clearLogs() {
        // So that the logs we report on failure only cover this run:
        await adb('logcat', '-c').catch(() => {});
    }

    async isRunning() {
        return !!(await adb('shell', 'pidof', this.appId).catch(() => '')).trim();
    }

    async forceStop() {
        await adb('shell', 'am', 'force-stop', this.appId);
        // Anything else on top of the app (e.g. a notification shade pulled down by a stray
        // swipe) would hide it from every query we make, so we clear that too:
        await adb('shell', 'cmd', 'statusbar', 'collapse');
        while (await this.isRunning()) await delay(500);
    }

    private ownNodes(nodes: UiNode[]) {
        return nodes.filter((node) => node.packageName === this.appId);
    }

    buttons(nodes: UiNode[]) {
        return this.ownNodes(nodes).filter((node) => node.className === 'android.widget.Button');
    }

    hasText(nodes: UiNode[], text: string) {
        return this.ownNodes(nodes).some((node) => node.text === text);
    }

    /**
     * Android's own crash & ANR dialogs. These cover the app, hiding it from everything we query,
     * so without this a crash looks like a button that never responded.
     */
    systemErrorDialog(nodes: UiNode[]) {
        return nodes.find((node) =>
            node.packageName === 'android' &&
            /isn't responding|keeps stopping|has stopped/i.test(node.text)
        )?.text;
    }

    private assertNotCrashed(nodes: UiNode[]) {
        const error = this.systemErrorDialog(nodes);
        if (error) throw new Error(`Android reported a problem with the app: "${error}"`);
    }

    private scrollable(nodes: UiNode[]) {
        const scrollable = this.ownNodes(nodes).find((node) => node.scrollable);
        if (!scrollable) throw new Error(`No scrollable view found in ${this.appId}`);
        return scrollable;
    }

    private async swipe(nodes: UiNode[], direction: 'up' | 'down') {
        const [left, top, right, bottom] = this.scrollable(nodes).bounds;

        // We swipe within the middle of the view, to stay clear of the system gesture areas at
        // the very top & bottom of the screen:
        const x = Math.round((left + right) / 2);
        const quarter = Math.round((bottom - top) / 4);
        const [from, to] = direction === 'up'
            ? [top + (quarter * 3), top + quarter]
            : [top + quarter, top + (quarter * 3)];

        await adb('shell', 'input', 'swipe', `${x}`, `${from}`, `${x}`, `${to}`, '300');
    }

    async scrollToTop() {
        let previousPosition = '';

        for (let i = 0; i < 30; i++) {
            const nodes = await readUi();
            const position = positionSummary(nodes);
            if (position === previousPosition) return;

            previousPosition = position;
            await this.swipe(nodes, 'down');
        }
    }

    /**
     * Every button in the app, top to bottom. The app's buttons change from release to release,
     * so we read them from the app itself rather than hardcoding a list.
     */
    async findAllButtons() {
        await this.scrollToTop();

        const buttons: string[] = [];
        let previousPosition = '';
        let unchangedPages = 0;

        // We're at the end once scrolling stops changing what's on screen. Two unchanged pages
        // are required, so a single swipe that doesn't register can't quietly cut the list short:
        for (let i = 0; i < 30 && unchangedPages < 2; i++) {
            const nodes = await readUi();

            for (const button of this.buttons(nodes)) {
                if (button.text && !buttons.includes(button.text)) buttons.push(button.text);
            }

            const position = positionSummary(nodes);
            unchangedPages = position === previousPosition ? unchangedPages + 1 : 0;
            previousPosition = position;

            await this.swipe(nodes, 'up');
        }

        return buttons;
    }

    /**
     * Scroll a button into view (fully, so that we can safely tap its centre) and return it.
     */
    async scrollIntoView(text: string) {
        let previousPosition = '';
        let direction: 'up' | 'down' = 'up';

        for (let i = 0; i < 40; i++) {
            const nodes = await readUi();
            this.assertNotCrashed(nodes);

            const button = this.buttons(nodes).find((b) => b.text === text);
            if (button && contains(this.scrollable(nodes).bounds, button.bounds)) return button;

            // If we've hit the end of the list without finding it, turn around and search back:
            const position = positionSummary(nodes);
            if (position === previousPosition) direction = direction === 'up' ? 'down' : 'up';
            previousPosition = position;

            await this.swipe(nodes, direction);
        }

        throw new Error(`Could not scroll to button '${text}'`);
    }

    async tap({ bounds: [left, top, right, bottom] }: UiNode) {
        await adb('shell', 'input', 'tap',
            `${Math.round((left + right) / 2)}`,
            `${Math.round((top + bottom) / 2)}`
        );
    }

    /**
     * Wait for a button's content description, which is how the demo app reports each request's
     * result. Buttons with their own engines to spin up (WebView, Flutter) can miss a first tap
     * entirely, so we re-tap once before giving up.
     */
    async waitForButtonResult(text: string, options: { timeout: number, retryTapAfter: number }) {
        const startTime = Date.now();
        let retapped = false;

        while (true) {
            const nodes = await readUi();
            this.assertNotCrashed(nodes);

            const button = this.buttons(nodes).find((b) => b.text === text);
            if (button?.description) return button.description;

            const elapsed = Date.now() - startTime;
            if (elapsed > options.timeout) {
                // Note that a button that's missing entirely (rather than present with no result)
                // means it wasn't in the UI at all, e.g. it was covered or scrolled away:
                console.log(`Timed out waiting for '${text}'. The UI showed:`, this.buttons(
                    await readUi()
                ).map((b) => `${b.text}${b.description ? ` => ${b.description}` : ' (no result)'}`));

                // Crash & ANR dialogs are detected above, but they can be disabled device-wide,
                // so we check Android's own logs too - they explain a missing result far better
                // than anything we can see from out here:
                const failureLogs = await this.recentFailureLogs();
                if (failureLogs) console.log(`Android logged:\n${failureLogs}`);

                return undefined;
            }

            if (button && !retapped && elapsed > options.retryTapAfter) {
                console.log(`Re-tapping button ${text}`);
                await this.tap(button);
                retapped = true;
            }
        }
    }

}
