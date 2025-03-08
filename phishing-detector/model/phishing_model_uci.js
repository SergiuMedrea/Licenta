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
  
  // Check if all necessary features exist
  for (const [feature, weight] of Object.entries(phishingModel.feature_importances)) {
    if (features[feature] !== undefined) {
      // Normalize numerical features to values between 0 and 1
      // Binary features (0/1) remain unchanged
      const value = features[feature];
      
      // Calculate weighted score
      score += weight * value;
      totalWeight += weight;
    }
  }
  
  // Normalize score
  if (totalWeight > 0) {
    score = score / totalWeight;
  }
  
  // Final prediction (with threshold of 0.5)
  return {
    score: score,
    isPhishing: score > 0.5,
    confidence: score
  };
}

// Define a function for mapping UCI ML features to JavaScript features
function extractUCIFeatures(url, domContent = null) {
  // Initialize all model features with default values
  const features = {};
  
  // Set all features to 0 initially
  for (const feature of phishingModel.feature_names) {
    features[feature] = 0;
  }
  
  try {
    const urlObj = new URL(url);
    
    // ===== Address Bar Based Features =====
    
    // Feature 1: having_IP_Address
    features['having_IP_Address'] = /^\d+\.\d+\.\d+\.\d+$/.test(urlObj.hostname) ? 1 : 0;
    
    // Feature 2: URL_Length
    features['URL_Length'] = url.length > 54 ? 1 : 0;
    
    // Feature 3: Shortining_Service
    const shortURLServices = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd'];
    features['Shortining_Service'] = shortURLServices.some(service => 
      url.includes(service)) ? 1 : 0;
    
    // Feature 4: having_At_Symbol
    features['having_At_Symbol'] = url.includes('@') ? 1 : 0;
    
    // Feature 5: double_slash_redirecting
    const lastDoubleSlash = url.lastIndexOf('//');
    features['double_slash_redirecting'] = lastDoubleSlash > 7 ? 1 : 0;
    
    // Feature 6: Prefix_Suffix
    features['Prefix_Suffix'] = urlObj.hostname.includes('-') ? 1 : 0;
    
    // Feature 7: having_Sub_Domain
    const dotCount = urlObj.hostname.split('.').length - 1;
    if (dotCount == 1) {
      features['having_Sub_Domain'] = 0; // Legitimate
    } else if (dotCount == 2) {
      features['having_Sub_Domain'] = 0.5; // Suspicious
    } else {
      features['having_Sub_Domain'] = 1; // Phishing
    }
    
    // Feature 8: SSLfinal_State
    features['SSLfinal_State'] = urlObj.protocol === 'https:' ? 0 : 1;
    
    // Feature 12: HTTPS_token
    features['HTTPS_token'] = urlObj.hostname.includes('https') ? 1 : 0;
    
    // Other features can be implemented similarly
    
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
