// Feature descriptions for displaying to users
const featureDescriptions = {
  having_IP_Address: "IP address used in domain",
  URL_Length: "Unusually long URL",
  Shortining_Service: "URL shortening service detected",
  having_At_Symbol: "@ symbol in URL",
  double_slash_redirecting: "Double slash redirect",
  Prefix_Suffix: "Hyphen prefix/suffix in domain",
  having_Sub_Domain: "Multiple subdomains",
  SSLfinal_State: "Missing HTTPS/SSL",
  Domain_registeration_length: "Recently registered domain",
  Favicon: "Favicon loaded from external domain",
  port: "Non-standard port used",
  HTTPS_token: "HTTPS in domain part",
  Request_URL: "External content requests",
  URL_of_Anchor: "Suspicious link targets",
  Links_in_tags: "External links in tags",
  SFH: "Suspicious form action",
  submitting_to_email: "Form submits to email",
  Abnormal_URL: "Abnormal URL structure",
  Redirect: "Multiple redirects",
  on_mouseover: "Status bar manipulation",
  RightClick: "Right-click disabled",
  popUpWindow: "Uses pop-up windows",
  Iframe: "Contains hidden iframes",
  age_of_domain: "Recently created domain",
  DNSRecord: "Missing DNS records",
  web_traffic: "Low website traffic",
  Page_Rank: "Low page rank",
  Google_Index: "Not indexed by Google",
  Links_pointing_to_page: "Few external links"
};

// Icons for feature display
const featureIcons = {
  default: "❗",
  having_IP_Address: "🌐",
  URL_Length: "📏",
  Shortining_Service: "🔗",
  having_At_Symbol: "@",
  HTTPS_token: "🔒",
  Redirect: "↪️",
  popUpWindow: "📃",
  Iframe: "📦",
  SFH: "📝"
};

// Status indicators for different risk levels
const statusData = {
  safe: {
    className: "safe",
    icon: "✓",
    text: "Site is safe"
  },
  warning: {
    className: "warning",
    icon: "⚠️",
    text: "Potentially suspicious"
  },
  danger: {
    className: "danger",
    icon: "⛔",
    text: "Phishing detected!"
  },
  unknown: {
    className: "unknown",
    icon: "❓",
    text: "Unknown status"
  }
};

// Settings default values
const defaultSettings = {
  detectionThreshold: 0.5, // Default threshold for classifying as phishing
  showExtendedInfo: true,  // Show detailed feature information
  enableRealTimeProtection: true, // Enable real-time protection
};

// Initialize the popup
document.addEventListener('DOMContentLoaded', async () => {
  console.log("Popup initialized");
  
  // Set up fallback image for logo
  setupLogoFallback();
  
  // Hide main content, show loader
  document.getElementById('mainContent').style.display = 'none';
  document.getElementById('loaderSection').style.display = 'flex';
  
  // Load settings
  const settings = await loadSettings();
  
  // Get current tab
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const currentTab = tabs[0];
    const url = currentTab.url;
    
    // Display URL
    document.getElementById('currentUrl').textContent = url;
    
    // Check if URL is valid for analysis
    if (!isValidUrl(url)) {
      updateStatus('unknown');
      showMessage("Cannot analyze this page");
      hideLoader();
      return;
    }
    
    // Only analyze if real-time protection is enabled
    if (settings.enableRealTimeProtection) {
      try {
        // Request URL check from background script
        const result = await new Promise((resolve, reject) => {
          chrome.runtime.sendMessage(
            { action: 'checkUrl', url: url },
            response => {
              if (chrome.runtime.lastError) {
                console.error("Communication error:", chrome.runtime.lastError);
                reject(chrome.runtime.lastError);
              } else {
                console.log("Response received:", response);
                resolve(response);
              }
            }
          );
        });
        
        // Process and display the result
        processResult(result, settings);
      } catch (error) {
        console.error("Error checking URL:", error);
        updateStatus('unknown');
        showMessage("Error analyzing the site");
      }
    } else {
      // Show that real-time protection is disabled
      updateStatus('unknown');
      showMessage("Real-time protection is disabled. Click 'Scan Now' to analyze this page.");
    }
    
    // Load statistics
    loadStats();
  } catch (error) {
    console.error("Error getting current tab:", error);
    updateStatus('unknown');
    showMessage("Error getting current tab");
  }
  
  // Hide loader, show content
  hideLoader();
  
  // Set up event listeners
  setupEventListeners();
});

// Set up fallback for logo image
function setupLogoFallback() {
  const logoElement = document.getElementById('headerLogo');
  
  logoElement.addEventListener('error', function() {
    this.src = 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="white"><path d="M12 22C6.477 22 2 17.523 2 12S6.477 2 12 2s10 4.477 10 10-4.477 10-10 10zm0-2a8 8 0 1 0 0-16 8 8 0 0 0 0 16zm-1-5h2v2h-2v-2zm0-8h2v6h-2V7z"/></svg>';
  });
}

// Process the phishing detection result
function processResult(result, settings) {
  if (result.error) {
    updateStatus('unknown');
    showMessage("Error: " + result.error);
    return;
  }
  
  // Get the score, features, and phishing status
  const score = result.score || 0;
  const isPhishing = result.isPhishing;
  const features = result.features || {};
  
  // Update risk meter
  updateRiskMeter(score);
  
  // Update status based on score and threshold
  if (isPhishing) {
    updateStatus('danger');
  } else if (score > 0.3) {
    updateStatus('warning');
  } else {
    updateStatus('safe');
  }
  
  // Display detected features if there are any
  const activeFeatures = getActiveFeatures(features);
  if (activeFeatures.length > 0) {
    displayFeatures(activeFeatures);
  }
}

// Update the risk meter display
function updateRiskMeter(score) {
  const riskScoreElement = document.getElementById('riskScore');
  const meterFillElement = document.getElementById('meterFill');
  
  // Update score text
  riskScoreElement.textContent = (score * 100).toFixed(0) + '%';
  
  // Update meter fill width
  meterFillElement.style.width = (score * 100) + '%';
}

// Update status indicators
function updateStatus(status) {
  const statusCardElement = document.getElementById('statusCard');
  const statusIconElement = document.getElementById('statusIcon');
  const statusTextElement = document.getElementById('statusText');
  const meterFillElement = document.getElementById('meterFill');
  
  // Get status data
  const data = statusData[status];
  
  // Remove all status classes
  statusCardElement.classList.remove('safe', 'warning', 'danger', 'unknown');
  meterFillElement.classList.remove('safe', 'warning', 'danger', 'unknown');
  
  // Add current status class
  statusCardElement.classList.add(data.className);
  meterFillElement.classList.add(data.className);
  
  // Update status text and icon
  statusIconElement.textContent = data.icon;
  statusTextElement.textContent = data.text;
}

// Get active features from the features object
function getActiveFeatures(features) {
  const activeFeatures = [];
  
  for (const [feature, value] of Object.entries(features)) {
    // Consider a feature active if it's true, 1, or greater than 0.5
    if (value === true || value === 1 || (typeof value === 'number' && value > 0.5)) {
      activeFeatures.push({
        name: feature,
        value: value
      });
    }
  }
  
  return activeFeatures;
}

// Display detected features
function displayFeatures(features) {
  const featuresSection = document.getElementById('featuresSection');
  const featuresList = document.getElementById('featuresList');
  
  // Show features section
  featuresSection.style.display = 'block';
  
  // Clear previous features
  featuresList.innerHTML = '';
  
  // Add each feature
  features.forEach(feature => {
    const featureItem = document.createElement('div');
    featureItem.className = 'feature-item';
    
    // Get icon for this feature or use default
    const icon = featureIcons[feature.name] || featureIcons.default;
    
    // Get description for this feature or use the feature name
    const description = featureDescriptions[feature.name] || 
                       feature.name.replace(/_/g, ' ').replace(/([A-Z])/g, ' $1').trim();
    
    featureItem.innerHTML = `
      <span class="feature-icon">${icon}</span>
      <span>${description}</span>
    `;
    
    featuresList.appendChild(featureItem);
  });
}

// Show message in place of features list
function showMessage(message) {
  const featuresSection = document.getElementById('featuresSection');
  const featuresList = document.getElementById('featuresList');
  
  // Show features section
  featuresSection.style.display = 'block';
  
  // Clear previous features
  featuresList.innerHTML = '';
  
  // Add message
  const messageItem = document.createElement('div');
  messageItem.className = 'feature-item';
  messageItem.style.textAlign = 'center';
  messageItem.textContent = message;
  
  featuresList.appendChild(messageItem);
}

// Load statistics from storage
async function loadStats() {
  try {
    const stats = await chrome.storage.local.get(['totalChecked', 'totalBlocked']);
    
    document.getElementById('totalChecked').textContent = stats.totalChecked || 0;
    document.getElementById('totalBlocked').textContent = stats.totalBlocked || 0;
  } catch (error) {
    console.error("Error loading statistics:", error);
  }
}

// Load settings from storage
async function loadSettings() {
  try {
    const data = await chrome.storage.local.get('settings');
    return { ...defaultSettings, ...(data.settings || {}) };
  } catch (error) {
    console.error("Error loading settings:", error);
    return defaultSettings;
  }
}

// Set up event listeners
function setupEventListeners() {
  // Toggle features visibility
  const toggleBtn = document.getElementById('toggleFeatures');
  const featuresContainer = document.getElementById('featuresContainer');
  
  toggleBtn.addEventListener('click', () => {
    const isVisible = featuresContainer.style.display !== 'none';
    
    featuresContainer.style.display = isVisible ? 'none' : 'block';
    toggleBtn.textContent = isVisible ? 'Show Details' : 'Hide Details';
  });
  
  // Scan button
  document.getElementById('scanBtn').addEventListener('click', async () => {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const currentTab = tabs[0];
      const url = currentTab.url;
      
      // Show loader
      document.getElementById('mainContent').style.display = 'none';
      document.getElementById('loaderSection').style.display = 'flex';
      
      // Request URL check from background script (always perform when manually requested)
      try {
        const result = await new Promise((resolve, reject) => {
          chrome.runtime.sendMessage(
            { action: 'checkUrl', url: url },
            response => {
              if (chrome.runtime.lastError) {
                console.error("Communication error:", chrome.runtime.lastError);
                reject(chrome.runtime.lastError);
              } else {
                console.log("Response received:", response);
                resolve(response);
              }
            }
          );
        });
        
        // Process and display the result
        const settings = await loadSettings();
        processResult(result, settings);
        
        // Hide loader, show content
        hideLoader();
      } catch (error) {
        console.error("Error checking URL:", error);
        updateStatus('unknown');
        showMessage("Error analyzing the site");
        hideLoader();
      }
    } catch (error) {
      console.error("Error scanning page:", error);
    }
  });
  
  // Settings button
  document.getElementById('settingsBtn').addEventListener('click', () => {
    // Open options page
    chrome.runtime.openOptionsPage();
  });
  
  // About link
  document.getElementById('aboutLink').addEventListener('click', (e) => {
    e.preventDefault();
    
    // Show about information
    alert(
      "Phishing Detector v1.0\n\n" +
      "This extension uses the UCI ML Phishing Websites dataset " +
      "to detect and protect against phishing websites.\n\n" +
      "Model accuracy: ~96%\n" +
      "Features: 30\n\n" +
      "Built with ❤️ for online safety."
    );
  });
}

// Hide loader and show main content
function hideLoader() {
  document.getElementById('loaderSection').style.display = 'none';
  document.getElementById('mainContent').style.display = 'block';
}

// Check if URL is valid for analysis
function isValidUrl(url) {
  // Skip browser internal pages and file URLs
  if (url.startsWith('chrome://') || 
      url.startsWith('chrome-extension://') || 
      url.startsWith('file://') ||
      url.startsWith('about:') ||
      url.startsWith('edge://') ||
      url.startsWith('firefox://')) {
    return false;
  }
  
  return true;
}