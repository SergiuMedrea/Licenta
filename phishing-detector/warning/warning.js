document.addEventListener('DOMContentLoaded', function() {
  // Get the dangerous URL and score from parameters
  const urlParams = new URLSearchParams(window.location.search);
  const dangerousUrl = urlParams.get('target');
  const riskScore = urlParams.get('score');
  
  // Display the URL and score
  document.getElementById('dangerousUrl').textContent = dangerousUrl || 'Unknown URL';
  
  // Check if the score exists and is valid
  if (riskScore && !isNaN(parseFloat(riskScore))) {
    document.getElementById('riskScore').textContent = (parseFloat(riskScore) * 100).toFixed(1) + '%';
  } else {
    document.getElementById('riskScore').textContent = 'Unknown';
  }
  
  // Back to safety button
  document.getElementById('backButton').onclick = function() {
    window.history.back();
  };
  
  // Proceed anyway button
  document.getElementById('proceedButton').onclick = function() {
    // Record the user's decision to proceed
    try {
      chrome.runtime.sendMessage({
        action: 'proceedAnyway',
        url: dangerousUrl
      });
    } catch (error) {
      console.error("Error sending message:", error);
    }
    
    // Redirect to the dangerous site
    if (dangerousUrl) {
      window.location.href = dangerousUrl;
    } else {
      window.history.back();
    }
  };
});