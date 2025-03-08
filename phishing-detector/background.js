// Import the UCI Phishing Websites model
importScripts('model/phishing_model_uci.js');

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
      lastReset: Date.now()
    });
  } catch (error) {
    console.error("Error initializing extension:", error);
  }
});

// Monitor user navigation
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Check only the main frame
  if (details.frameId !== 0) return;
  
  const url = details.url;
  const tabId = details.tabId;
  
  // Ignore navigations to the warning page
  if (url.includes('warning.html')) return;
  
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
        url: chrome.runtime.getURL(`warning/warning.html?target=${encodeURIComponent(url)}&score=${result.score}`)
      });
      
      // Update statistics
      const stats = await chrome.storage.local.get(['totalChecked', 'totalBlocked']);
      await chrome.storage.local.set({
        totalChecked: (stats.totalChecked || 0) + 1,
        totalBlocked: (stats.totalBlocked || 0) + 1
      });
    } else {
      // Only update statistics for checked sites
      const stats = await chrome.storage.local.get(['totalChecked']);
      await chrome.storage.local.set({
        totalChecked: (stats.totalChecked || 0) + 1
      });
    }
  } catch (error) {
    console.error("Error checking URL:", error);
  }
});

// Function to check URL using the UCI ML model
async function checkPhishingUrl(url) {
  // Check local cache
  if (phishingDatabase[url] !== undefined) {
    return phishingDatabase[url];
  }
  
  // Extract URL features using the improved function from the UCI model
  const features = extractUCIFeatures(url);
  
  // Additional context: Look for suspicious patterns in the URL
  const lowerUrl = url.toLowerCase();
  
  // Suspicious TLD check (some TLDs are more commonly used in phishing)
  const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work'];
  if (suspiciousTLDs.some(tld => lowerUrl.endsWith(tld))) {
    features.suspicious_tld = 1;
  }
  
  // Suspicious URL patterns
  const patterns = [
    { pattern: /secure.*bank|bank.*secure/, weight: 0.5 },
    { pattern: /login.*confirm|confirm.*login/, weight: 0.4 },
    { pattern: /account.*verify|verify.*account/, weight: 0.4 },
    { pattern: /update.*password|password.*update/, weight: 0.3 },
    { pattern: /[-_.]{3,}/, weight: 0.3 } // Multiple special characters
  ];
  
  for (const { pattern, weight } of patterns) {
    if (pattern.test(lowerUrl)) {
      features.suspicious_pattern = (features.suspicious_pattern || 0) + weight;
    }
  }
  
  // Use the improved model for prediction
  const prediction = predictPhishing(features);
  
  // Save the result in cache
  phishingDatabase[url] = {
    isPhishing: prediction.isPhishing,
    score: prediction.score,
    timestamp: Date.now(),
    features: features
  };
  
  // Log for debugging
  console.log("URL check:", url);
  console.log("Features:", features);
  console.log("Score:", prediction.score, "Is Phishing:", prediction.isPhishing);
  
  return phishingDatabase[url];
}

// Add a message handler
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'checkUrl') {
    checkPhishingUrl(message.url)
      .then(result => sendResponse(result))
      .catch(error => sendResponse({ error: error.message }));
    return true; // Indicates that the response will be sent asynchronously
  }
  
  if (message.action === 'analyzeContent') {
    // Integrate DOM features into our analysis
    if (phishingDatabase[message.url]) {
      const currentFeatures = phishingDatabase[message.url].features;
      const enhancedFeatures = {...currentFeatures, ...message.features};
      
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
  
  if (message.action === 'proceedAnyway') {
    const tabId = message.tabId;
    const targetUrl = message.url;
    
    // Mark this tab as approved for the dangerous URL
    redirectedTabsMap.set(tabId, targetUrl);
    
    // Navigate to the requested URL
    chrome.tabs.update(tabId, { url: targetUrl });
    
    // Update statistics
    chrome.storage.local.get(['proceedCount'], function(result) {
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
    
    if (features.sslfinal_state === 1) 
      suspicious.push("Missing HTTPS");
    
    if (features.prefix_suffix === 1) 
      suspicious.push("Hyphen in domain");
    
    if (urlObj.hostname.includes('secure') || urlObj.hostname.includes('bank')) 
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