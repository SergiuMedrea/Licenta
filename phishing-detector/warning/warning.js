document.addEventListener('DOMContentLoaded', function() {
  // Get URL parameters
  const urlParams = new URLSearchParams(window.location.search);
  const targetUrl = urlParams.get('target');
  const riskScore = urlParams.get('score');
  
  // Display the dangerous URL and risk score
  const urlDisplay = document.getElementById('dangerousUrl');
  if (urlDisplay && targetUrl) {
    urlDisplay.textContent = targetUrl;
  }
  
  const scoreDisplay = document.getElementById('riskScore');
  if (scoreDisplay && riskScore) {
    // Convert score to percentage and round to 2 decimal places
    const percentage = (parseFloat(riskScore) * 100).toFixed(2);
    scoreDisplay.textContent = `${percentage}%`;
  }
  
  // Back button functionality
  const backButton = document.getElementById('backButton');
  if (backButton) {
    backButton.addEventListener('click', function() {
      // Go back to the previous page or to a safe default
      window.history.back();
    });
  }
  
  // Proceed button functionality
  const proceedButton = document.getElementById('proceedButton');
  if (proceedButton && targetUrl) {
    proceedButton.addEventListener('click', function() {
      // Get the current tab ID correctly
      chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        const currentTabId = tabs[0].id;
        
        // Inform the background script that the user wants to proceed
        chrome.runtime.sendMessage({
          action: 'proceedAnyway',
          url: targetUrl,
          tabId: currentTabId
        }, function(response) {
          if (response && response.success) {
            // The background script will handle the navigation
          }
        });
      });
    });
  }
});