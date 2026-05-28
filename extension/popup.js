const API_BASE_URL = "http://127.0.0.1:8000";
const CIRCUMFERENCE = 364.42; // 2 * PI * r (r=58)

document.addEventListener("DOMContentLoaded", () => {
  // Navigation Tabs Toggle
  const tabBtns = document.querySelectorAll(".tab-btn");
  const tabPanels = document.querySelectorAll(".tab-panel");

  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetTab = btn.getAttribute("data-tab");
      
      tabBtns.forEach(b => b.classList.remove("active"));
      tabPanels.forEach(p => p.classList.remove("active"));
      
      btn.classList.add("active");
      document.getElementById(targetTab).classList.add("active");
    });
  });

  // Check API Server Health
  checkApiHealth();

  // Retrieve Current Page Scan Details
  loadCurrentTabAnalysis();

  // Bind Manual URL Scan Events
  document.getElementById("btn-scan-url").addEventListener("click", performManualUrlScan);
  document.getElementById("manual-url-input").addEventListener("keypress", (e) => {
    if (e.key === "Enter") performManualUrlScan();
  });

  // Bind Manual Email Scan Events
  document.getElementById("btn-scan-email").addEventListener("click", performEmailScan);

  // Bind Protection Toggle Settings
  setupProtectionToggle();
});

// 1. Connection Health Monitor
function checkApiHealth() {
  chrome.storage.local.get(["apiUrl"], (settings) => {
    const apiUrl = settings.apiUrl || API_BASE_URL;
    
    const dot = document.getElementById("api-status-dot");
    const label = document.getElementById("api-status-text");

    fetch(`${apiUrl}/api/health`)
      .then(response => {
        if (!response.ok) throw new Error();
        return response.json();
      })
      .then(data => {
        dot.className = "status-dot online";
        label.innerText = "AI Shield Online";
      })
      .catch(() => {
        dot.className = "status-dot offline";
        label.innerText = "Backend Offline";
      });
  });
}

// 2. Load cached analysis for active browser tab
function loadCurrentTabAnalysis() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs.length === 0) return;
    const activeTab = tabs[0];
    const tabId = activeTab.id;
    const urlDisplay = document.getElementById("current-url-display");
    
    // Set URL header
    urlDisplay.innerText = activeTab.url || "New Tab";
    urlDisplay.title = activeTab.url;

    // Pull from local storage cache
    chrome.storage.local.get([`tab_${tabId}`], (result) => {
      const cached = result[`tab_${tabId}`];
      
      if (cached && cached.status === "scanned") {
        renderCurrentTabStats(cached.data);
      } else if (cached && cached.status === "system") {
        renderSystemPage(cached.url);
      } else if (cached && cached.status === "error") {
        renderScanError(cached.error);
      } else {
        // Fallback: If no cache, attempt scanning it now
        triggerImmediateScan(activeTab.url, tabId);
      }
    });
  });
}

// Immediately trigger scan on popup open if cache is missing
function triggerImmediateScan(url, tabId) {
  if (!url || url.startsWith("chrome://") || url.startsWith("about:")) {
    renderSystemPage(url);
    return;
  }
  
  chrome.storage.local.get(["apiUrl"], (settings) => {
    const apiUrl = settings.apiUrl || API_BASE_URL;
    
    fetch(`${apiUrl}/api/scan/url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    })
      .then(res => res.json())
      .then(data => {
        // Cache and render
        chrome.storage.local.set({ [`tab_${tabId}`]: { status: "scanned", data: data, url: url } });
        renderCurrentTabStats(data);
      })
      .catch(() => {
        renderScanError("Backend offline. Start FastAPI backend.");
      });
  });
}

// Render dynamic elements for active URL report
function renderCurrentTabStats(data) {
  const scorePercent = document.getElementById("current-score-percent");
  const scoreCircle = document.getElementById("current-score-circle");
  const riskBadge = document.getElementById("current-risk-badge");
  const triggersList = document.getElementById("current-triggers-list");

  // Math percentage score
  const scoreVal = Math.round(data.threat_score * 100);
  scorePercent.innerText = `${scoreVal}%`;

  // Draw Radial Progress Ring
  const offset = CIRCUMFERENCE - (data.threat_score * CIRCUMFERENCE);
  scoreCircle.style.strokeDashoffset = offset;

  // Color stroke and risk label
  riskBadge.className = "risk-badge";
  if (data.risk_level === "danger") {
    scoreCircle.style.stroke = "#ef4444";
    riskBadge.classList.add("risk-danger");
    riskBadge.innerText = "DANGER";
  } else if (data.risk_level === "suspicious") {
    scoreCircle.style.stroke = "#f59e0b";
    riskBadge.classList.add("risk-suspicious");
    riskBadge.innerText = "SUSPICIOUS";
  } else {
    scoreCircle.style.stroke = "#10b981";
    riskBadge.classList.add("risk-safe");
    riskBadge.innerText = "SAFE";
  }

  // Render Triggers
  triggersList.innerHTML = "";
  data.all_triggers.forEach(trigger => {
    const li = document.createElement("li");
    li.innerText = trigger;
    
    // Style trigger classification color coding
    if (data.risk_level === "danger") {
      li.classList.add("danger-trigger");
    } else if (data.risk_level === "suspicious") {
      li.classList.add("warn-trigger");
    } else {
      li.classList.add("safe-trigger");
    }
    triggersList.appendChild(li);
  });
}

// Draw UI when on system-related screens
function renderSystemPage(url) {
  document.getElementById("current-score-percent").innerText = "0%";
  document.getElementById("current-score-circle").style.strokeDashoffset = CIRCUMFERENCE;
  document.getElementById("current-score-circle").style.stroke = "#8794af";
  
  const riskBadge = document.getElementById("current-risk-badge");
  riskBadge.className = "risk-badge risk-safe";
  riskBadge.innerText = "SECURE SYSTEM";

  const triggersList = document.getElementById("current-triggers-list");
  triggersList.innerHTML = `
    <li class="safe-trigger">Internal browser or extension page.</li>
    <li class="safe-trigger">These pages are protected by default sandbox layers.</li>
  `;
}

// Draw UI on backend errors
function renderScanError(errText) {
  document.getElementById("current-score-percent").innerText = "ERR";
  document.getElementById("current-score-circle").style.strokeDashoffset = CIRCUMFERENCE;
  document.getElementById("current-score-circle").style.stroke = "#ef4444";
  
  const riskBadge = document.getElementById("current-risk-badge");
  riskBadge.className = "risk-badge risk-danger";
  riskBadge.innerText = "ERROR";

  const triggersList = document.getElementById("current-triggers-list");
  triggersList.innerHTML = `
    <li class="danger-trigger">${errText}</li>
    <li class="warn-trigger">Check API status. Make sure python FastAPI script is running on localhost.</li>
  `;
}

// 3. Perform manual URL scanning
function performManualUrlScan() {
  const urlInput = document.getElementById("manual-url-input");
  const url = urlInput.value.trim();
  const btn = document.getElementById("btn-scan-url");
  const resultBox = document.getElementById("url-scan-result");

  if (!url) return;

  btn.disabled = true;
  btn.innerText = "...";
  
  chrome.storage.local.get(["apiUrl"], (settings) => {
    const apiUrl = settings.apiUrl || API_BASE_URL;

    fetch(`${apiUrl}/api/scan/url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    })
      .then(res => {
        if (!res.ok) throw new Error("Server error");
        return res.json();
      })
      .then(data => {
        resultBox.classList.remove("hidden");
        
        document.getElementById("url-res-domain").innerText = data.domain;
        document.getElementById("url-res-score").innerText = `${Math.round(data.threat_score * 100)}%`;
        
        // Badges
        const rBadge = document.getElementById("url-res-risk-badge");
        rBadge.className = "risk-badge";
        if (data.risk_level === "danger") {
          rBadge.classList.add("risk-danger");
          rBadge.innerText = "DANGER";
        } else if (data.risk_level === "suspicious") {
          rBadge.classList.add("risk-suspicious");
          rBadge.innerText = "SUSPICIOUS";
        } else {
          rBadge.classList.add("risk-safe");
          rBadge.innerText = "SAFE";
        }

        // Triggers
        const list = document.getElementById("url-res-triggers");
        list.innerHTML = "";
        data.all_triggers.forEach(tr => {
          const li = document.createElement("li");
          li.innerText = tr;
          if (data.risk_level === "danger") {
            li.className = "danger-trigger";
          } else if (data.risk_level === "suspicious") {
            li.className = "warn-trigger";
          } else {
            li.className = "safe-trigger";
          }
          list.appendChild(li);
        });
      })
      .catch(() => {
        alert("Failed to scan URL. Verify backend server connection.");
      })
      .finally(() => {
        btn.disabled = false;
        btn.innerText = "Scan";
      });
  });
}

// 4. Perform manual email text analysis
function performEmailScan() {
  const input = document.getElementById("email-text-input");
  const text = input.value.trim();
  const btn = document.getElementById("btn-scan-email");
  const resultBox = document.getElementById("email-scan-result");

  if (!text) return;

  btn.disabled = true;
  btn.innerText = "Analyzing...";

  chrome.storage.local.get(["apiUrl"], (settings) => {
    const apiUrl = settings.apiUrl || API_BASE_URL;

    fetch(`${apiUrl}/api/scan/email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: text })
    })
      .then(res => {
        if (!res.ok) throw new Error();
        return res.json();
      })
      .then(data => {
        resultBox.classList.remove("hidden");
        
        document.getElementById("email-res-score").innerText = `${Math.round(data.threat_score * 100)}%`;
        
        const rBadge = document.getElementById("email-res-risk-badge");
        rBadge.className = "risk-badge";
        if (data.risk_level === "danger") {
          rBadge.classList.add("risk-danger");
          rBadge.innerText = "PHISHING";
        } else if (data.risk_level === "suspicious") {
          rBadge.classList.add("risk-suspicious");
          rBadge.innerText = "SUSPICIOUS";
        } else {
          rBadge.classList.add("risk-safe");
          rBadge.innerText = "SAFE";
        }

        const list = document.getElementById("email-res-triggers");
        list.innerHTML = "";
        data.triggers.forEach(tr => {
          const li = document.createElement("li");
          li.innerText = tr;
          if (data.risk_level === "danger") {
            li.className = "danger-trigger";
          } else if (data.risk_level === "suspicious") {
            li.className = "warn-trigger";
          } else {
            li.className = "safe-trigger";
          }
          list.appendChild(li);
        });
      })
      .catch(() => {
        alert("Failed to analyze email. Verify backend server connection.");
      })
      .finally(() => {
        btn.disabled = false;
        btn.innerText = "Analyze Email Content";
      });
  });
}

// 5. Toggle Live Protection Mode
function setupProtectionToggle() {
  const toggleBtn = document.getElementById("btn-toggle-scan");
  
  chrome.storage.local.get(["autoScan"], (settings) => {
    let autoScan = settings.autoScan !== false;
    updateToggleButtonUI(toggleBtn, autoScan);
  });

  toggleBtn.addEventListener("click", () => {
    chrome.storage.local.get(["autoScan"], (settings) => {
      const current = settings.autoScan !== false;
      const next = !current;
      
      chrome.storage.local.set({ autoScan: next }, () => {
        updateToggleButtonUI(toggleBtn, next);
        
        // Refresh active tab badge configuration
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          if (tabs.length > 0 && tabs[0].url) {
            // Signal service worker to re-process current tab URL
            chrome.runtime.sendMessage({ action: "refreshTab", tabId: tabs[0].id, url: tabs[0].url });
            // Re-load popup content
            setTimeout(loadCurrentTabAnalysis, 100);
          }
        });
      });
    });
  });
}

function updateToggleButtonUI(btn, autoScan) {
  if (autoScan) {
    btn.innerText = "Protection: ON";
    btn.classList.remove("disabled");
  } else {
    btn.innerText = "Protection: OFF";
    btn.classList.add("disabled");
  }
}
