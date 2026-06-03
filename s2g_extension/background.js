chrome.runtime.onInstalled.addListener(() => {
    // Turn off by default on install
    chrome.storage.local.set({ proxyEnabled: false });
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'setProxy') {
        const enabled = request.enabled;
        const config = {
            mode: enabled ? "fixed_servers" : "system",
            rules: {
                singleProxy: {
                    scheme: "http",
                    host: "127.0.0.1",
                    port: 8080
                },
                bypassList: ["localhost", "127.0.0.1"]
            }
        };

        chrome.proxy.settings.set(
            { value: config, scope: 'regular' },
            function () {
                if (chrome.runtime.lastError) {
                    console.error('Error setting proxy:', chrome.runtime.lastError);
                    sendResponse({ success: false, error: chrome.runtime.lastError });
                } else {
                    // Save state
                    chrome.storage.local.set({ proxyEnabled: enabled });
                    sendResponse({ success: true });
                }
            }
        );

        return true; // Keep message channel open for async response
    }
});
