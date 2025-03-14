// Import the UCI Phishing Websites model
importScripts("model/phishing_model_uci.js");

// Cache for checked URLs
let phishingDatabase = {};

// Track warning page redirections to prevent loops
let redirectedTabsMap = new Map();

// Load the model and initial settings
chrome.runtime.onInstalled.addListener(async () => {
  try {
    console.log("Phishing Detector has been installed and initialized");
    console.log("UCI ML model loaded successfully");

    // Initialize storage for statistics
    await chrome.storage.local.set({
      totalChecked: 0,
      totalBlocked: 0,
      lastReset: Date.now(),
    });
  } catch (error) {
    console.error("Error initializing extension:", error);
  }
});

// Monitor user navigation
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // First, check if real-time protection is enabled
  const settings = await loadSettings();
  if (!settings.enableRealTimeProtection) {
    return; // Exit early if real-time protection is disabled
  }

  // Check only the main frame
  if (details.frameId !== 0) return;

  const url = details.url;
  const tabId = details.tabId;

  // Extract domain from URL
  let domain;
  try {
    domain = new URL(url).hostname;
  } catch (e) {
    domain = "";
  }

  // Check if domain is in whitelist
  if (
    settings.whitelist &&
    settings.whitelist.some((item) => domain.includes(item))
  ) {
    console.log("Site is in whitelist, skipping check:", domain);
    return; // Skip phishing check for whitelisted domains
  }

  // Ignore navigations to the warning page
  if (url.includes("warning.html")) return;

  // Check if this URL has already been approved by the user
  if (redirectedTabsMap.has(tabId) && redirectedTabsMap.get(tabId) === url) {
    // User chose to proceed - don't show warning again for this navigation
    redirectedTabsMap.delete(tabId);
    return;
  }

  // Check if URL is valid for analysis
  if (!isValidUrl(url)) return;

  try {
    // Check if the URL is potentially phishing
    const result = await checkPhishingUrl(url);

    if (result.isPhishing) {
      console.log("Phishing site detected!");
      // Redirect to warning page
      chrome.tabs.update(tabId, {
        url: chrome.runtime.getURL(
          `warning/warning.html?target=${encodeURIComponent(url)}&score=${
            result.score
          }`
        ),
      });

      // Update statistics
      const stats = await chrome.storage.local.get([
        "totalChecked",
        "totalBlocked",
      ]);
      await chrome.storage.local.set({
        totalChecked: (stats.totalChecked || 0) + 1,
        totalBlocked: (stats.totalBlocked || 0) + 1,
      });
    } else {
      // Only update statistics for checked sites
      const stats = await chrome.storage.local.get(["totalChecked"]);
      await chrome.storage.local.set({
        totalChecked: (stats.totalChecked || 0) + 1,
      });
    }
  } catch (error) {
    console.error("Error checking URL:", error);
  }
});

// Function to check URL using the UCI ML model
async function checkPhishingUrl(url) {
  // Load settings to get custom threshold
  const settings = await loadSettings();
  const threshold = settings.detectionThreshold || 0.5;

  // Check local cache
  if (phishingDatabase[url] !== undefined) {
    return {
      ...phishingDatabase[url],
      isPhishing: phishingDatabase[url].score > threshold,
    };
  }

  // Extract features and predict
  const features = extractUCIFeatures(url);
  const prediction = predictPhishing(features);

  // Apply custom threshold
  const result = {
    isPhishing: prediction.score > threshold,
    score: prediction.score,
    timestamp: Date.now(),
    features: features,
  };

  // Save in cache
  phishingDatabase[url] = result;

  return result;
}

// Add a message handler
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "checkUrl") {
    checkPhishingUrl(message.url)
      .then((result) => sendResponse(result))
      .catch((error) => sendResponse({ error: error.message }));
    return true; // Indicates that the response will be sent asynchronously
  }

  if (message.action === "analyzeContent") {
    // Integrate DOM features into our analysis
    if (phishingDatabase[message.url]) {
      const currentFeatures = phishingDatabase[message.url].features;
      const enhancedFeatures = { ...currentFeatures, ...message.features };

      // Recalculate the score with enhanced features
      const enhancedPrediction = predictPhishing(enhancedFeatures);

      // Update the result in cache
      phishingDatabase[message.url].score = enhancedPrediction.score;
      phishingDatabase[message.url].isPhishing = enhancedPrediction.isPhishing;
      phishingDatabase[message.url].features = enhancedFeatures;
    }

    sendResponse({ received: true });
    return true;
  }

  if (message.action === "proceedAnyway") {
    const tabId = message.tabId;
    const targetUrl = message.url;

    // Mark this tab as approved for the dangerous URL
    redirectedTabsMap.set(tabId, targetUrl);

    // Navigate to the requested URL
    chrome.tabs.update(tabId, { url: targetUrl });

    // Update statistics
    chrome.storage.local.get(["proceedCount"], function (result) {
      const currentCount = result.proceedCount || 0;
      chrome.storage.local.set({ proceedCount: currentCount + 1 });
    });

    sendResponse({ success: true });
    return true;
  }
});

function debugURL(url) {
  console.log("=== URL DEBUG INFO ===");
  console.log("URL:", url);

  // Extract features using your existing extractor
  const features = extractUCIFeatures(url);
  console.log("Extracted Features:", features);

  // Add additional context for debugging
  try {
    const urlObj = new URL(url);
    console.log("URL parts:");
    console.log("- Protocol:", urlObj.protocol);
    console.log("- Hostname:", urlObj.hostname);
    console.log("- Path:", urlObj.pathname);
    console.log("- Search:", urlObj.search);

    // Check for specific suspicious patterns
    const suspicious = [];

    if (features.double_slash_redirecting)
      suspicious.push("Double slash redirect");

    if (features.having_sub_domain > 0.5)
      suspicious.push("Multiple subdomains");

    if (features.sslfinal_state === 1) suspicious.push("Missing HTTPS");

    if (features.prefix_suffix === 1) suspicious.push("Hyphen in domain");

    if (urlObj.hostname.includes("secure") || urlObj.hostname.includes("bank"))
      suspicious.push("Suspicious keywords in hostname");

    if (suspicious.length > 0) {
      console.log("Suspicious patterns detected:", suspicious.join(", "));
    }
  } catch (e) {
    console.error("Error parsing URL:", e);
  }

  // Use your existing prediction function
  const prediction = predictPhishing(features);
  console.log("Prediction:", prediction);
  console.log("=====================");

  return prediction;
}

// Load settings from storage
async function loadSettings() {
  try {
    const data = await chrome.storage.local.get("settings");
    return {
      detectionThreshold: 0.5,
      enableRealTimeProtection: true,
      showExtendedInfo: true,
      whitelist: [],
      ...(data.settings || {}),
    };
  } catch (error) {
    console.error("Error loading settings:", error);
    return {
      detectionThreshold: 0.5,
      enableRealTimeProtection: true,
      showExtendedInfo: true,
      whitelist: [],
    };
  }
}

// Check if URL is valid for analysis
function isValidUrl(url) {
  // Skip browser internal pages and file URLs
  if (
    url.startsWith("chrome://") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("file://") ||
    url.startsWith("about:") ||
    url.startsWith("edge://") ||
    url.startsWith("firefox://")
  ) {
    return false;
  }

  return true;
}
