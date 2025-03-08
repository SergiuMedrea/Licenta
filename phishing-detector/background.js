// Import the UCI Phishing Websites model
importScripts('model/phishing_model_uci.js');

// Cache for checked URLs
let phishingDatabase = {};

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
  
  try {
    // Check if the URL is potentially phishing
    const result = await checkPhishingUrl(url);
    
    if (result.isPhishing) {
      console.log("Phishing site detected!");
      // Warn the user
      chrome.tabs.update(tabId, {
        url: `warning.html?target=${encodeURIComponent(url)}&score=${result.score}`
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
  
  // Extract URL features using the function from the UCI model
  const features = extractUCIFeatures(url);
  
  // Use the model for prediction
  const prediction = predictPhishing(features);
  
  // Save the result in cache
  phishingDatabase[url] = {
    isPhishing: prediction.isPhishing,
    score: prediction.score,
    timestamp: Date.now(),
    features: features
  };
  
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
    // Update statistics
    chrome.storage.local.get(['proceedCount'], function(result) {
      const currentCount = result.proceedCount || 0;
      chrome.storage.local.set({ proceedCount: currentCount + 1 });
    });
    sendResponse({ success: true });
    return true;
  }
});