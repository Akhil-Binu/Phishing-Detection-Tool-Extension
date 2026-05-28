// Content script for real-time DOM checking and alerts
console.log("Phishing Detector content script injected.");

// 1. Client-Side Link Spoofing Detector
function inspectLinks() {
  const links = document.querySelectorAll("a");
  const popularBrands = [
    'google', 'paypal', 'microsoft', 'apple', 'amazon', 'facebook', 
    'netflix', 'chase', 'wellsfargo', 'github', 'instagram', 'linkedin'
  ];

  links.forEach(link => {
    const text = link.innerText.trim().toLowerCase();
    const href = link.href.trim().toLowerCase();
    
    // Check if the link contains a brand keyword in text but the href does not
    if (href && href.startsWith("http")) {
      for (const brand of popularBrands) {
        if (text.includes(brand)) {
          try {
            const urlObj = new URL(href);
            // If the brand is mentioned in text, but isn't part of the href domain
            if (!urlObj.hostname.includes(brand)) {
              highlightSuspiciousLink(link, brand, urlObj.hostname);
            }
          } catch (e) {
            // Invalid URL format, skip
          }
        }
      }
    }
  });
}

// Visual indicator for spoofed links
function highlightSuspiciousLink(linkElement, brand, actualDomain) {
  linkElement.style.border = "2px dashed #dc3545";
  linkElement.style.padding = "2px";
  linkElement.style.backgroundColor = "rgba(220, 53, 69, 0.15)";
  linkElement.style.cursor = "help";
  linkElement.title = `⚠️ Suspicious Link Spoofing:\nText references '${brand}' but leads to '${actualDomain}'!`;
}

// 2. Danger Banner Overlay Injector
function injectDangerBanner(score, triggers) {
  // Check if warning banner already exists
  if (document.getElementById("phishing-detector-danger-banner")) return;

  const banner = document.createElement("div");
  banner.id = "phishing-detector-danger-banner";
  
  // Custom styled CSS embedded directly
  Object.assign(banner.style, {
    position: "fixed",
    top: "0",
    left: "0",
    width: "100%",
    backgroundColor: "#1c0d0f",
    color: "#f8d7da",
    borderBottom: "4px solid #dc3545",
    padding: "16px 24px",
    zIndex: "2147483647", // Top-most priority layering
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
    fontSize: "15px",
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    boxShadow: "0 8px 30px rgba(0, 0, 0, 0.5)",
    transition: "all 0.3s ease-in-out"
  });

  const leftContent = document.createElement("div");
  leftContent.style.display = "flex";
  leftContent.style.alignItems = "center";
  leftContent.style.gap = "12px";

  // Warning icon
  const icon = document.createElement("span");
  icon.innerHTML = "🚨";
  icon.style.fontSize = "24px";

  const messageText = document.createElement("div");
  messageText.innerHTML = `
    <strong style="color: #dc3545; font-size: 16px;">Phishing Warning!</strong> 
    This page has been flagged as highly malicious (${Math.round(score * 100)}% risk). 
    <span style="color: #abb2bf; font-size: 13px; display: block; margin-top: 4px;">
      Triggers matched: ${triggers.join(" | ")}
    </span>
  `;

  leftContent.appendChild(icon);
  leftContent.appendChild(messageText);

  // Actions Container
  const actions = document.createElement("div");
  actions.style.display = "flex";
  actions.style.gap = "12px";

  const backBtn = document.createElement("button");
  backBtn.innerText = "Get Me Out of Here";
  Object.assign(backBtn.style, {
    backgroundColor: "#dc3545",
    color: "#fff",
    border: "none",
    padding: "8px 16px",
    borderRadius: "6px",
    fontWeight: "600",
    cursor: "pointer",
    fontSize: "14px",
    transition: "background 0.2s"
  });
  backBtn.onmouseover = () => backBtn.style.backgroundColor = "#c82333";
  backBtn.onmouseout = () => backBtn.style.backgroundColor = "#dc3545";
  backBtn.onclick = () => {
    window.history.back();
    setTimeout(() => {
      window.location.href = "https://www.google.com"; // Fallback if no history back possible
    }, 500);
  };

  const ignoreBtn = document.createElement("button");
  ignoreBtn.innerText = "Ignore & Proceed";
  Object.assign(ignoreBtn.style, {
    backgroundColor: "transparent",
    color: "#abb2bf",
    border: "1px solid #abb2bf",
    padding: "8px 16px",
    borderRadius: "6px",
    cursor: "pointer",
    fontSize: "13px",
    transition: "all 0.2s"
  });
  ignoreBtn.onmouseover = () => {
    ignoreBtn.style.color = "#fff";
    ignoreBtn.style.borderColor = "#fff";
  };
  ignoreBtn.onmouseout = () => {
    ignoreBtn.style.color = "#abb2bf";
    ignoreBtn.style.borderColor = "#abb2bf";
  };
  ignoreBtn.onclick = () => {
    banner.style.transform = "translateY(-100%)";
    setTimeout(() => banner.remove(), 300);
    // Push page offset back
    document.body.style.marginTop = "0px";
  };

  actions.appendChild(ignoreBtn);
  actions.appendChild(backBtn);

  banner.appendChild(leftContent);
  banner.appendChild(actions);

  document.body.appendChild(banner);

  // Shift page content down to prevent overlap with navbar
  document.body.style.marginTop = `${banner.offsetHeight}px`;
  document.body.style.position = "relative";
}

// Listen for push events from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "showDangerBanner" && message.data) {
    injectDangerBanner(message.data.threat_score, message.data.all_triggers);
  }
});

// Run DOM scan on page load
if (document.readyState === "complete" || document.readyState === "interactive") {
  inspectLinks();
} else {
  window.addEventListener("DOMContentLoaded", inspectLinks);
}
