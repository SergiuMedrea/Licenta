// Function to analyze page content according to UCI ML features
function analyzePageContent() {
  const url = window.location.href;
  const domainName = window.location.hostname;
  
  // Initialize features object
  const features = {};
  
  try {
    // Request_URL - Check if external objects are loaded from other domains
    let externalResources = 0;
    let totalResources = 0;
    
    document.querySelectorAll('img, script, link').forEach(el => {
      const src = el.getAttribute('src') || el.getAttribute('href');
      if (src) {
        totalResources++;
        if (src.startsWith('http') && !src.includes(domainName)) {
          externalResources++;
        }
      }
    });
    
    features.Request_URL = totalResources > 0 ? 
                          (externalResources / totalResources >= 0.22 ? 1 : 0) : 0;
    
    // URL_of_Anchor - Check <a> tags with different domains or no link
    let suspiciousAnchors = 0;
    let totalAnchors = document.querySelectorAll('a').length;
    
    document.querySelectorAll('a').forEach(a => {
      const href = a.getAttribute('href');
      if (!href || href === '#' || href.startsWith('javascript:')) {
        suspiciousAnchors++;
      } else if (href.startsWith('http') && !href.includes(domainName)) {
        suspiciousAnchors++;
      }
    });
    
    features.URL_of_Anchor = totalAnchors > 0 ? 
                           (suspiciousAnchors / totalAnchors >= 0.31 ? 1 : 0) : 0;
    
    // SFH (Server Form Handler) - Check forms for suspicious actions
    features.SFH = 0; // Default legitimate
    
    document.querySelectorAll('form').forEach(form => {
      const action = form.getAttribute('action');
      if (!action || action === '' || action === 'about:blank') {
        features.SFH = 1; // Phishing
      } else if (action.startsWith('http') && !action.includes(domainName)) {
        features.SFH = 0.5; // Suspicious
      }
    });
    
    // submitting_to_email - Check if forms submit data via email
    features.submitting_to_email = document.body.innerHTML.includes('mailto:') ||
                                 document.body.innerHTML.includes('mail(') ? 1 : 0;
    
    // Iframe - Check for iframe usage
    features.Iframe = document.querySelectorAll('iframe').length > 0 ? 1 : 0;
    
    // web_forwarding - Number of redirects
    // This feature is just an estimate in content script
    features.web_forwarding = document.body.innerHTML.includes('window.location.replace') ||
                             document.body.innerHTML.includes('window.location.href') ? 1 : 0;
    
    // on_mouseover - Check for status bar customization
    features.on_mouseover = document.body.innerHTML.includes('onmouseover') &&
                           document.body.innerHTML.includes('status') ? 1 : 0;
    
    // RightClick - Check for right-click disabling
    features.RightClick = document.body.innerHTML.includes('oncontextmenu="return false"') ||
                        document.body.innerHTML.includes('event.button==2') ? 1 : 0;
    
    // popUpWindow - Check for pop-up windows
    features.popUpWindow = document.body.innerHTML.includes('window.open') ? 1 : 0;
    
    // Send features to background script
    chrome.runtime.sendMessage({
      action: 'analyzeContent',
      url: window.location.href,
      features: features
    });
    
    return features;
  } catch (error) {
    console.error("Error analyzing page content:", error);
    return {};
  }
}

// Run analysis after page has fully loaded
window.addEventListener('load', () => {
  // Small delay to allow dynamic elements to load completely
  setTimeout(analyzePageContent, 1500);
});