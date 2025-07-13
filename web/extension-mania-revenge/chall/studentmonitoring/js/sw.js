// simplified example
// I also added types =)

/**
 * async wrapper for chrome.tabs.query
 * @param {chrome.tabs.QueryInfo} queryInfo
 * @return {Promise<chrome.tabs.Tab[]>} 
 */
function queryAsync(queryInfo) {
    return new Promise((resolve, reject) => {
        chrome.tabs.query(queryInfo, (result) => {
            if (chrome.runtime.lastError) {
                reject(chrome.runtime.lastError);
            } else {
                resolve(result);
            }
        });
    });
}


async function tick(){
    const tabs = await queryAsync({});
    for(let tab of tabs){
        if(tab.url){
            const url = new URL(tab.url);
            if(url.hostname === "coolctfgames.localhost"){
                // student is off task =O =O =O
                console.log("Closing tab:", tab.url);
                await chrome.tabs.update(tab.id, {url: "about:blank"}); // apparently auto tab closing might have been broken in docker wtf
                await chrome.tabs.remove(tab.id);
                console.log("Tab closed:", tab.id);
                chrome.notifications.create("",{
                    type: "basic",
                    title: "Good Guardian",
                    message: "Tab was closed.",
                    priority: 2,
                });
            }
        }
    }
}

// simplified version of more fancy logic just for this chal
async function tickLoop(){
    await tick();
    setTimeout(tickLoop, 250 + Math.random() * 1000);
}

chrome.runtime.onStartup.addListener( () => {
    console.log("[StudentMonitoring] Ready");

    // mock init time
    setTimeout(() => {
        tickLoop();
    }, 2500 + Math.random() * 500);
});