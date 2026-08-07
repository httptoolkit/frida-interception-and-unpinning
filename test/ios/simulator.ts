/**
 * A minimal driver for an app running in the iOS simulator, built directly on simctl.
 *
 * Unlike the Android tests, which attach Frida to the app over ADB and drive its UI, everything
 * here goes through Frida's gadget: a dylib inserted into the app at launch, which loads a single
 * script as the process starts. That's the only way to run our scripts on iOS without a jailbreak,
 * so it's what we test. setup-simulator.sh puts a working gadget inside the app's bundle; this
 * assembles the scripts for it & reads back what happened.
 */

import * as ChildProcess from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';

const execFile = promisify(ChildProcess.execFile);

export const simctl = (...args: string[]) =>
    execFile('xcrun', ['simctl', ...args], { maxBuffer: 32 * 1024 * 1024 })
        .then(({ stdout }) => stdout);

export const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** One request made by the test app, as it reports them itself. */
export interface RequestResult {
    case: string;
    status?: number;
    body?: string;
    error?: string;
}

export interface Script {
    name: string;
    source: string;
}

/**
 * Combine the scripts into the single script the gadget loads, exactly as the README's iOS
 * command combines them for the Frida CLI, plus the logging the gadget doesn't give us.
 */
const buildInjectedScript = (scripts: Script[], logPath: string) => {
    // The gadget's console output doesn't reach the simulator log at all, so without this our
    // scripts would run entirely silently. We tee it to a file in the app's own data container,
    // which we can read back from here:
    const preamble = `
const TEST_LOG_PATH = ${JSON.stringify(logPath)};

function testLog(line) {
    try {
        const file = new File(TEST_LOG_PATH, "a");
        file.write(line + "\\n");
        file.close();
    } catch (e) {}
}

console.log = function () { testLog(Array.prototype.join.call(arguments, " ")); };
console.warn = console.log;
console.error = console.log;
console.debug = console.log;
`;

    // Each script announces itself, so that a failure can be placed even if it happens before the
    // script has logged anything of its own:
    const body = scripts
        .map(({ name, source }) => `testLog("RUNNING: ${name}");\n${source}`)
        .join('\n');

    // N.b. one try block around all of them, not one each: the scripts are written to share a
    // single top-level scope, and a block per script would hide each script's declarations from
    // the next. This still reports the error, which the gadget otherwise swallows entirely.
    return `${preamble}
try {
${body}
testLog("ALL SCRIPTS LOADED");
} catch (error) {
    testLog("SCRIPT FAILED: " + error + "\\n" + (error && error.stack));
}
`;
};

export class SimulatorApp {

    // N.b. no parameter properties - Node's type stripping only erases types, it can't generate
    // the assignment those imply:
    private bundleId: string;
    private buildDir: string;

    private udid!: string;
    private bundleDir!: string;
    private dataDir!: string;

    private launchedPid: string | undefined;

    constructor(bundleId: string, buildDir: string) {
        this.bundleId = bundleId;
        this.buildDir = buildDir;
    }

    /**
     * Find the simulator & the installed app that setup-simulator.sh prepared. Everything here
     * depends on that having run, so we say so explicitly rather than failing later in pieces.
     */
    async connect() {
        const setupFirst = 'Run test/ios/setup-simulator.sh first';

        const booted = JSON.parse(await simctl('list', 'devices', 'booted', '-j')).devices;
        const devices: any[] = Object.values(booted).flat();
        const device = devices.find((device) => device.name.includes('iPhone'));
        if (!device) throw new Error(`No iPhone simulator is booted. ${setupFirst}`);

        this.udid = device.udid;
        console.log(`Testing on ${device.name} (${this.udid})`);

        const container = (type: 'app' | 'data') =>
            simctl('get_app_container', this.udid, this.bundleId, type)
                .then((output) => output.trim())
                .catch(() => {
                    throw new Error(`${this.bundleId} is not installed. ${setupFirst}`);
                });

        [this.bundleDir, this.dataDir] = await Promise.all([container('app'), container('data')]);

        await fs.access(this.gadgetPath).catch(() => {
            throw new Error(`The app has no Frida gadget inside it. ${setupFirst}`);
        });
    }

    private get gadgetPath() {
        return path.join(this.bundleDir, 'Frameworks', 'FridaGadget.dylib');
    }

    private get scriptPath() {
        return path.join(this.bundleDir, 'Frameworks', 'injected.js');
    }

    private get logPath() {
        return path.join(this.dataDir, 'gadget.log');
    }

    private get resultsPath() {
        return path.join(this.dataDir, 'Documents', 'results.jsonl');
    }

    /**
     * The ObjC bridge, which the gadget doesn't supply. See setup-simulator.sh, which extracts
     * this from frida-tools, and IMPROVEMENTS.md for why it's needed at all.
     */
    async objcBridge(): Promise<Script> {
        const bridge = await fs.readFile(path.join(this.buildDir, 'objc-bridge.js'), 'utf8')
            .catch(() => {
                throw new Error('No ObjC bridge was extracted. Run test/ios/setup-simulator.sh');
            });

        // Wrapped, rather than dropped in as-is, because the bundle defines the bridge as a local
        // named `bridge` and expects its host to expose it:
        return {
            name: 'the ObjC bridge',
            source: `(() => {\n${bridge}\nglobalThis.ObjC = bridge;\n})();`
        };
    }

    /**
     * Write the script the gadget will load at the next launch. Kept inside the app's own bundle,
     * which is where a gadget would normally be shipped, and so is somewhere the app can
     * definitely read from.
     */
    async injectScripts(scripts: Script[]) {
        const script = buildInjectedScript(scripts, this.logPath);

        await fs.writeFile(this.scriptPath, script);
        // Also kept where a failing run can be inspected, since the copy above disappears with
        // the app on reinstall:
        await fs.writeFile(path.join(this.buildDir, 'injected.js'), script);

        await fs.writeFile(path.join(this.bundleDir, 'Frameworks', 'FridaGadget.config'),
            JSON.stringify({
                // Script mode: the gadget runs our script as the app starts, rather than pausing
                // the app to wait for a client to attach to it.
                interaction: { type: 'script', path: this.scriptPath, on_change: 'ignore' }
            })
        );

        // The bundle's contents just changed, and its signature covers them:
        await execFile('codesign', ['--force', '--sign', '-', this.bundleDir]);
    }

    /**
     * Launch the app, with the gadget injected unless told otherwise, and wait for it to be up.
     * Note that this deliberately does not wait for our scripts: whether they run at all is one
     * of the things the tests are checking.
     */
    async launch(options: { withGadget: boolean }) {
        await this.terminate();

        // So that everything we read back afterwards is definitely from this launch:
        await Promise.all([
            fs.rm(this.logPath, { force: true }),
            fs.rm(this.resultsPath, { force: true })
        ]);

        const environment = options.withGadget
            ? { ...process.env, SIMCTL_CHILD_DYLD_INSERT_LIBRARIES: this.gadgetPath }
            : process.env;

        // N.b. the launch is what tells us the app was accepted at all, so a failure here is
        // reported as-is rather than waiting for the symptoms:
        const output = await execFile('xcrun',
            ['simctl', 'launch', '--terminate-running-process', this.udid, this.bundleId],
            { env: environment }
        ).then(({ stdout }) => stdout).catch((e) => {
            throw new Error(`Could not launch the app: ${e.stderr || e.message}`);
        });

        // e.g. 'tech.httptoolkit.frida_test_app: 54321'
        this.launchedPid = output.trim().split(' ').pop();

        // A launch that's immediately fatal (a gadget that segfaults, most likely) still reports
        // a pid, so we check the process actually exists before going any further:
        await delay(1000);
        if (!await this.isRunning()) {
            throw await this.explainFailure('The app did not survive launch');
        }
    }

    async isRunning() {
        if (!this.launchedPid) return false;
        return execFile('ps', ['-p', this.launchedPid]).then(() => true, () => false);
    }

    async terminate() {
        await simctl('terminate', this.udid, this.bundleId).catch(() => {});
        this.launchedPid = undefined;
    }

    /** Everything our scripts have logged from inside the app. */
    async gadgetLog() {
        return fs.readFile(this.logPath, 'utf8').catch(() => '');
    }

    /** Every request the app has reported so far, oldest first. */
    async results(): Promise<RequestResult[]> {
        const contents = await fs.readFile(this.resultsPath, 'utf8').catch(() => '');

        return contents.split('\n')
            .filter((line) => line.trim())
            // The app appends as it goes, so the last line can be half-written when we read it:
            .flatMap((line) => {
                try {
                    return [JSON.parse(line) as RequestResult];
                } catch (e) {
                    return [];
                }
            });
    }

    /**
     * Wait for the app to report the given requests, and return the first result for each. The
     * app repeats them, but the results are cleared at launch, so these are always from this run.
     */
    async waitForResults(cases: string[], timeout = 60_000) {
        const startTime = Date.now();

        while (true) {
            const results = await this.results();
            const found = cases.map((name) => results.find((result) => result.case === name));

            if (found.every((result) => result !== undefined)) {
                return Object.fromEntries(
                    found.map((result) => [result!.case, result!])
                ) as { [name: string]: RequestResult };
            }

            if (Date.now() - startTime > timeout) {
                const missing = cases.filter((name, i) => !found[i]);
                throw await this.explainFailure(
                    `The app did not report ${missing.join(', ')} within ${timeout / 1000}s`
                );
            }

            if (!await this.isRunning()) {
                throw await this.explainFailure('The app stopped running mid-test');
            }

            await delay(500);
        }
    }

    /**
     * Everything we can say about why the app isn't doing what it should. Our scripts' own output
     * usually explains it, and if the app died instead then only iOS's crash report can.
     */
    async explainFailure(problem: string) {
        const [log, crashes] = await Promise.all([this.gadgetLog(), this.recentCrashes()]);

        return new Error(
            problem +
            (await this.isRunning() ? '' : '. The app is no longer running') +
            (log
                ? `.\nOur scripts logged:\n${log}`
                : '.\nOur scripts logged nothing at all, so they never ran'
            ) +
            (crashes ? `\niOS reported a crash:\n${crashes}` : '')
        );
    }

    /**
     * A summary of any recent crash reports. These are the only explanation available when the
     * app dies during launch, which is exactly how a broken gadget shows up.
     */
    private async recentCrashes() {
        const reportDir = path.join(os.homedir(), 'Library', 'Logs', 'DiagnosticReports');

        const reports = await fs.readdir(reportDir).catch((): string[] => []);
        const ourReports = reports.filter((name) => name.endsWith('.ips'));

        const summaries = await Promise.all(ourReports.map(async (name) => {
            const reportPath = path.join(reportDir, name);

            const stats = await fs.stat(reportPath);
            if (Date.now() - stats.mtimeMs > 5 * 60_000) return '';

            // These are two JSON documents in one file: a metadata header line, which we've
            // already got, and then the report itself:
            const contents = await fs.readFile(reportPath, 'utf8').catch(() => '');
            const report = (() => {
                try {
                    return JSON.parse(contents.slice(contents.indexOf('\n')));
                } catch (e) {
                    return undefined;
                }
            })();
            if (!report) return '';

            const images: any[] = report.usedImages ?? [];
            const frames: any[] = report.threads?.[report.faultingThread]?.frames ?? [];

            return [
                `--- ${name}`,
                `  ${JSON.stringify(report.exception ?? report.termination ?? {})}`,
                ...frames.slice(0, 10).map((frame) => {
                    const image = images[frame.imageIndex] ?? {};
                    return `    ${image.name ?? image.path ?? '?'} + ${frame.imageOffset}` +
                        ` ${frame.symbol ?? ''}`;
                })
            ].join('\n');
        }));

        return summaries.filter((summary) => summary).join('\n');
    }

}
