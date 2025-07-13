import { launch } from "puppeteer";
import path from "path";
import config from "./config.js";

let lastBotRun = 0;
const botCooldown = 30 * 1000; // 30 seconds
let botIsRunning = false;
let shouldGiveFlag = false;

// extension path resolving
const studentMonitoringExtensionPath = path.join(process.cwd(), "studentmonitoring");
const webFilteringExtensionPath = path.join(process.cwd(), "webfiltering");

function sleep(ms){
    return new Promise(resolve => setTimeout(resolve, ms));
}

export async function runBot(url) {
    if (botIsRunning) {
        return;
    }
    botIsRunning = true;
    lastBotRun = Date.now();

    const browser = await launch({
            headless: process.env.HEADLESS || false,
            defaultViewport: null,
            pipe: true,
            args: ['--no-sandbox', '--disable-setuid-sandbox',
            '--enable-benchmarking',
            '--js-flags=--jitless,--noexpose_wasm',
            // note: these flags may require chrome for testing which is default in newer puppeteer versions
            '--unsafely-treat-insecure-origin-as-secure=http://' + config.host + ':' + config.port + ",http:" + config.host,
            '--enable-logging=stderr',
            '--enable-unsafe-swiftshader',
            ],
            dumpio: true,
            enableExtensions: [
                studentMonitoringExtensionPath,
                webFilteringExtensionPath
            ]
        });
    console.log(await browser.version());

    try {
        const page = await browser.newPage();
        await page.goto(url, { waitUntil: 'networkidle0', timeout: 5000 });
        try{
            await page.click("#free-click", {delay: 1}); // free user activation thing
        }catch(ex){
            console.warn("No button found, continuing without it.");
        }

        // sleep
        await sleep(15000); // wait for 15 seconds so the extension takes notice

        // execute verification that site is stable
        let pageUrl = await page.url();
        let currentUrl = new URL(pageUrl);
        // find extension worker and trigger a final tick
        const extensionWorkerTargets = browser.targets().filter(target => target.url().startsWith("chrome-extension://"));
        if(extensionWorkerTargets.length == 0){
            console.log("No extension workers found???");
            return;
        }
        for(let target of extensionWorkerTargets){
            const worker = await target.worker();
            if(!worker){
                // false positive when extension page is loaded
                console.log("No worker found for target:", target.url());
                continue;
            }
            const result = await Promise.race([worker.evaluate(async () => {
                if(this.tick){
                    await this.tick();
                    return true;
                }
                return false;
            }), sleep(100)]);
            console.log(target.url(), "tick result:", result);
        }

        // check if the site is still up
        pageUrl = await page.url();
        currentUrl = new URL(pageUrl);
        if((currentUrl.origin == ("http://" + config.host) || currentUrl.origin == ("http://" + config.host + ":" + config.port)) && !page.isClosed()){
            console.log("Flag conditions met.", currentUrl, page.isClosed());
            shouldGiveFlag = true;
        } else {
            // for your local debugging pleasure
            console.log("Bot did not reach the expected host without tab being closed:", currentUrl.host, pageUrl);
        }
    } catch (ex) {
        console.error(ex);
    }

    await browser.close();

    botIsRunning = false; // we suggest new instances anyways because of some odd chrome bugs
}

export function canRunBot() {
    const now = Date.now();
    if (now - lastBotRun < botCooldown) {
        return [false, "Wait " + (botCooldown - (now - lastBotRun)) / 1000 + " seconds before running again"];
    }
    if(botIsRunning){
        return [false, "Bot is currently running."];
    }
    return [true, "Conditions passed."];
}

export function shouldFlag() {
    return shouldGiveFlag;
}