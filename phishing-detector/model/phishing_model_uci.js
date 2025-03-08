// Phishing detection model automatically generated from UCI ML dataset
const phishingModel = {
  "feature_names": [
    "having_ip_address",
    "url_length",
    "shortining_service",
    "having_at_symbol",
    "double_slash_redirecting",
    "prefix_suffix",
    "having_sub_domain",
    "sslfinal_state",
    "domain_registration_length",
    "favicon",
    "port",
    "https_token",
    "request_url",
    "url_of_anchor",
    "links_in_tags",
    "sfh",
    "submitting_to_email",
    "abnormal_url",
    "redirect",
    "on_mouseover",
    "rightclick",
    "popupwindow",
    "iframe",
    "age_of_domain",
    "dnsrecord",
    "web_traffic",
    "page_rank",
    "google_index",
    "links_pointing_to_page",
    "statistical_report"
  ],
  "n_estimators": 100,
  "max_depth": 20,
  "feature_importances": {
    "having_ip_address": 0.009939122385008489,
    "url_length": 0.006472748850453865,
    "prefix_suffix": 0.04011182521219297,
    "having_sub_domain": 0.06378244456477829,
    "sslfinal_state": 0.3484183750085123,
    "domain_registration_length": 0.013965844547302588,
    "https_token": 0.0051636835627633165,
    "request_url": 0.017129296650179898,
    "url_of_anchor": 0.2657971512080538,
    "links_in_tags": 0.04014857226348678,
    "sfh": 0.01862578168798766,
    "age_of_domain": 0.010731509669089645,
    "dnsrecord": 0.009714681010001227,
    "web_traffic": 0.07400043668217646,
    "page_rank": 0.008544006521524266,
    "google_index": 0.010434310071705564,
    "links_pointing_to_page": 0.01381496829182754
  }
};


// Function for prediction in JavaScript
function predictPhishing(features) {
  // Calculate score based on feature importance
  let score = 0;
  let totalWeight = 0;
  
  // Normalize feature names to lowercase for case-insensitive matching
  const normalizedFeatures = {};
  for (const [key, value] of Object.entries(features)) {
    normalizedFeatures[key.toLowerCase()] = value;
  }
  
  // Check each feature from the model's importance list
  for (const [feature, weight] of Object.entries(phishingModel.feature_importances)) {
    const featureLower = feature.toLowerCase();
    
    if (normalizedFeatures[featureLower] !== undefined) {
      // Get the feature value
      const value = normalizedFeatures[featureLower];
      
      // Calculate weighted score
      score += weight * value;
      totalWeight += weight;
    }
  }
  
  // Normalize score
  if (totalWeight > 0) {
    score = score / totalWeight;
  }
  
  // Additional scoring for suspicious URL patterns
  // These are common in phishing sites but might not be in the original feature set
  if (normalizedFeatures['double_slash_redirecting'] === 1) {
    score += 0.1;
  }
  
  if (normalizedFeatures['prefix_suffix'] === 1 || normalizedFeatures['prefix_suffix'] === 1) {
    score += 0.1;
  }
  
  if (features.hasOwnProperty('sslfinal_state') && features['sslfinal_state'] === 1) {
    score += 0.15; // Missing HTTPS is a strong phishing indicator
  }
  
  // Check for suspicious keywords in the URL
  const url = features.url || '';
  const suspiciousTerms = ['login', 'secure', 'bank', 'account', 'confirm', 'verify', 'update'];
  let termCount = 0;
  
  for (const term of suspiciousTerms) {
    if (url.toLowerCase().includes(term)) {
      termCount++;
    }
  }
  
  if (termCount >= 2) {
    score += 0.1 * Math.min(termCount, 3); // Cap the bonus at 3 terms
  }
  
  // Cap score at 1.0
  score = Math.min(score, 1.0);
  
  // Final prediction (with threshold of 0.5)
  return {
    score: score,
    isPhishing: score > 0.5,
    confidence: score
  };
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

// Define a function for mapping UCI ML features to JavaScript features
function extractUCIFeatures(url, domContent = null) {
  // Check if URL is valid for analysis
  if (!isValidUrl(url)) {
    return {};
  }

  // Initialize all model features with default values
  const features = {};
  
  // Store the original URL for additional checks
  features.url = url;
  
  // Set all features to 0 initially
  for (const feature of phishingModel.feature_names) {
    features[feature.toLowerCase()] = 0;
  }
  
  try {
    const urlObj = new URL(url);
    
    // ===== Address Bar Based Features =====
    
    // Feature 1: having_IP_Address
    features['having_ip_address'] = /^\d+\.\d+\.\d+\.\d+$/.test(urlObj.hostname) ? 1 : 0;
    
    // Feature 2: URL_Length
    features['url_length'] = url.length > 54 ? 1 : (url.length > 30 ? 0.5 : 0);
    
    // Feature 3: Shortining_Service
    const shortURLServices = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'tiny.cc', 'ow.ly'];
    features['shortining_service'] = shortURLServices.some(service => 
      url.includes(service)) ? 1 : 0;
    
    // Feature 4: having_At_Symbol
    features['having_at_symbol'] = url.includes('@') ? 1 : 0;
    
    // Feature 5: double_slash_redirecting
    const lastDoubleSlash = url.lastIndexOf('//');
    features['double_slash_redirecting'] = lastDoubleSlash > 7 ? 1 : 0;
    
    // Feature 6: Prefix_Suffix
    features['prefix_suffix'] = urlObj.hostname.includes('-') ? 1 : 0;
    
    // Feature 7: having_Sub_Domain
    const dotCount = urlObj.hostname.split('.').length - 1;
    if (dotCount == 1) {
      features['having_sub_domain'] = 0; // Legitimate
    } else if (dotCount == 2) {
      features['having_sub_domain'] = 0.5; // Suspicious
    } else {
      features['having_sub_domain'] = 1; // Phishing
    }
    
    // Feature 8: SSLfinal_State
    features['sslfinal_state'] = urlObj.protocol === 'https:' ? 0 : 1;
    
    // Feature 12: HTTPS_token
    features['https_token'] = urlObj.hostname.includes('https') ? 1 : 0;
    
    // Enhanced detection: Check if URL contains bank-related keywords
    const suspiciousHostPatterns = [
      /bank/, /secure/, /login/, /signin/, /verify/, /confirm/, /update/, /account/
    ];
    
    if (suspiciousHostPatterns.some(pattern => pattern.test(urlObj.hostname))) {
      // If hostname contains suspicious keywords but isn't a major bank domain
      const majorBankDomains = ['chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com'];
      if (!majorBankDomains.some(domain => urlObj.hostname.endsWith(domain))) {
        features['abnormal_url'] = 1;
      }
    }
    
    // Check for redirect in path
    if (urlObj.pathname.includes('redirect') || urlObj.pathname.includes('forward') || 
        urlObj.pathname.includes('goto') || urlObj.pathname.includes('return')) {
      features['redirect'] = 1;
    }
    
    // Check for unusual number of dots or special characters in hostname
    const specialCharCount = urlObj.hostname.replace(/[a-zA-Z0-9.]/g, '').length;
    if (specialCharCount > 1) {
      features['abnormal_url'] = Math.max(features['abnormal_url'] || 0, 0.5);
    }
    
  } catch (error) {
    console.error("Error extracting features:", error);
  }
  
  return features;
}

// Export functions for use in the extension
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    model: phishingModel,
    predict: predictPhishing,
    extractFeatures: extractUCIFeatures
  };
}
