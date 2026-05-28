const API_BASE_URL = "http://127.0.0.1:8000";

// Install-time setup
chrome.runtime.onInstalled.addListener(() => {
  // Create Context Menu Item for scanning specific links
  chrome.contextMenus.create({
    id: "scanLink",
    title: "Scan link with Phishing Detector",
    contexts: ["link"]
  });
  
  // Set default settings
  chrome.storage.local.set({
    apiUrl: API_BASE_URL,
    autoScan: true
  });
  
  console.log("Phishing Detector AI Extension installed and initialized.");
});

// Listener for context menu clicks
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "scanLink" && info.linkUrl) {
    scanSingleLink(info.linkUrl);
  }
});

// Listener for Tab Updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    handleUrlChange(changeInfo.url, tabId);
  }
});

// Listener for Active Tab Switch
chrome.tabs.onActivated.addListener((activeInfo) => {
  chrome.tabs.get(activeInfo.tabId, (tab) => {
    if (tab && tab.url) {
      handleUrlChange(tab.url, activeInfo.tabId);
    }
  });
});

// Core logic for handling URL changes
function handleUrlChange(url, tabId) {
  // Filter out internal browser pages
  if (
    !url || 
    url.startsWith("chrome://") || 
    url.startsWith("chrome-extension://") || 
    url.startsWith("about:") || 
    url.startsWith("view-source:") ||
    url.startsWith("edge://")
  ) {
    chrome.action.setBadgeText({ text: "", tabId: tabId });
    chrome.storage.local.set({ [`tab_${tabId}`]: { status: "system", url: url } });
    return;
  }

  // Retrieve current settings
  chrome.storage.local.get(["apiUrl", "autoScan"], (settings) => {
    const apiUrl = settings.apiUrl || API_BASE_URL;
    const autoScan = settings.autoScan !== false;

    if (!autoScan) {
      chrome.action.setBadgeText({ text: "OFF", tabId: tabId });
      chrome.action.setBadgeBackgroundColor({ color: "#6c757d", tabId: tabId });
      return;
    }

    // Set temporary scanning state
    chrome.action.setBadgeText({ text: "...", tabId: tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#17a2b8", tabId: tabId });

    // Send URL to FastAPI
    fetch(`${apiUrl}/api/scan/url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    })
      .then(response => {
        if (!response.ok) throw new Error("API server responded with error");
        return response.json();
      })
      .then(data => {
        // Cache result for popup use
        chrome.storage.local.set({ [`tab_${tabId}`]: { status: "scanned", data: data, url: url } });
        
        // Update Badge based on threat rating
        updateBadge(tabId, data.risk_level);
        
        // If dangerous, send notification or message to content script
        if (data.risk_level === "danger") {
          notifyUserDanger(url, data.threat_score);
          // Let content script show an overlay banner
          chrome.tabs.sendMessage(tabId, { action: "showDangerBanner", data: data }).catch(err => {
            // Content script might not be loaded yet or active, ignore error
          });
        }
      })
      .catch(error => {
        console.error("Error scanning URL:", error);
        chrome.action.setBadgeText({ text: "?", tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#6c757d", tabId: tabId });
        chrome.storage.local.set({ 
          [`tab_${tabId}`]: { status: "error", error: "Backend server offline", url: url } 
        });
      });
  });
}

// Update Chrome badge text & color based on threat risk level
function updateBadge(tabId, riskLevel) {
  let badgeText = "SAFE";
  let badgeColor = "#28a745"; // Green

  if (riskLevel === "danger") {
    badgeText = "RISK";
    badgeColor = "#dc3545"; // Red
  } else if (riskLevel === "suspicious") {
    badgeText = "WARN";
    badgeColor = "#ffc107"; // Yellow
  }

  chrome.action.setBadgeText({ text: badgeText, tabId: tabId });
  chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId: tabId });
}

// Trigger browser notifications
function notifyUserDanger(url, score) {
  chrome.notifications.create({
    type: "basic",
    iconUrl: "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%23dc3545' width='48' height='48'><path d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z'/></svg>",
    title: "⚠️ Phishing Alert!",
    message: `Warning: This site is flagged as high-risk (${Math.round(score * 100)}% phishing probability). Proceed with caution.`,
    contextMessage: url,
    priority: 2
  });
}

// Scan a single link from context menus
function scanSingleLink(linkUrl) {
  chrome.storage.local.get(["apiUrl"], (settings) => {
    const apiUrl = settings.apiUrl || API_BASE_URL;
    
    // Show notification that scanning started
    chrome.notifications.create("scan_start", {
      type: "basic",
      iconUrl: "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%2317a2b8' width='48' height='48'><path d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z'/></svg>",
      title: "Scanning Link...",
      message: `Analyzing: ${linkUrl.substring(0, 45)}...`,
      priority: 0
    });

    fetch(`${apiUrl}/api/scan/url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: linkUrl })
    })
      .then(response => response.json())
      .then(data => {
        // Clear previous scanning notice
        chrome.notifications.clear("scan_start");
        
        let title = "✅ Link is Safe";
        let message = `Score: ${Math.round(data.threat_score * 100)}%. No major threats detected.`;
        let icon = "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%2328a745' width='48' height='48'><path d='M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z'/></svg>";

        if (data.risk_level === "danger") {
          title = "🚨 DANGER: Phishing Link!";
          message = `Threat level is extremely high (${Math.round(data.threat_score * 100)}%). Do NOT open this link.`;
          icon = "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%23dc3545' width='48' height='48'><path d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z'/></svg>";
        } else if (data.risk_level === "suspicious") {
          title = "⚠️ Suspicious Link";
          message = `Warning: Threat score is ${Math.round(data.threat_score * 100)}%. Triggers: ${data.all_triggers.slice(0,2).join(', ')}`;
          icon = "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%23ffc107' width='48' height='48'><path d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z'/></svg>";
        }

        chrome.notifications.create({
          type: "basic",
          iconUrl: icon,
          title: title,
          message: message,
          contextMessage: linkUrl,
          priority: 2
        });
      })
      .catch(err => {
        chrome.notifications.clear("scan_start");
        chrome.notifications.create({
          type: "basic",
          iconUrl: "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%236c757d' width='48' height='48'><path d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z'/></svg>",
          title: "Scan Failed",
          message: "Could not reach the Phishing Detector API. Make sure backend is running.",
          priority: 1
        });
      });
  });
}

// Runtime message listener for communication from Popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "refreshTab" && message.tabId && message.url) {
    handleUrlChange(message.url, message.tabId);
    sendResponse({ status: "refreshed" });
  }
  return true;
});

