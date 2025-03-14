// Default settings
const defaultSettings = {
    detectionThreshold: 0.5,
    enableRealTimeProtection: true,
    showExtendedInfo: true,
    whitelist: [],
    updateFrequency: 'weekly',
    collectAnonymousStats: true,
    lastReset: Date.now()
  };
  
  // Initialize the options page
  document.addEventListener('DOMContentLoaded', async () => {
    // Handle fallback icon if the logo image fails to load
    setupLogoFallback();
    
    // Load saved settings
    const settings = await loadSettings();
    
    // Apply settings to form
    applySettingsToForm(settings);
    
    // Set up event listeners
    setupEventListeners();
  });
  
  // Set up fallback for logo image
  function setupLogoFallback() {
    const logoImage = document.getElementById('logoImage');
    const fallbackIcon = document.getElementById('fallbackIcon');
    
    if (logoImage && fallbackIcon) {
      logoImage.addEventListener('error', function() {
        // Hide the broken image
        logoImage.style.display = 'none';
        // Show the fallback SVG icon
        fallbackIcon.style.display = 'block';
      });
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
  
  // Save settings to storage
  async function saveSettings(settings) {
    try {
      await chrome.storage.local.set({ settings });
      return true;
    } catch (error) {
      console.error("Error saving settings:", error);
      return false;
    }
  }
  
  // Apply loaded settings to the form
  function applySettingsToForm(settings) {
    // Detection threshold
    const thresholdInput = document.getElementById('detectionThreshold');
    const thresholdValue = document.getElementById('thresholdValue');
    
    thresholdInput.value = settings.detectionThreshold;
    thresholdValue.textContent = settings.detectionThreshold;
    
    // Toggle switches
    document.getElementById('enableRealTimeProtection').checked = settings.enableRealTimeProtection;
    document.getElementById('showExtendedInfo').checked = settings.showExtendedInfo;
    document.getElementById('collectAnonymousStats').checked = settings.collectAnonymousStats;
    
    // Whitelist
    const whitelistArea = document.getElementById('whitelist');
    whitelistArea.value = settings.whitelist.join('\n');
    
    // Update frequency
    const updateFrequencySelect = document.getElementById('updateFrequency');
    updateFrequencySelect.value = settings.updateFrequency;
  }
  
  // Get settings from form
  function getSettingsFromForm() {
    // Get values from form elements
    const detectionThreshold = parseFloat(document.getElementById('detectionThreshold').value);
    const enableRealTimeProtection = document.getElementById('enableRealTimeProtection').checked;
    const showExtendedInfo = document.getElementById('showExtendedInfo').checked;
    const collectAnonymousStats = document.getElementById('collectAnonymousStats').checked;
    
    // Process whitelist
    const whitelistText = document.getElementById('whitelist').value;
    const whitelist = whitelistText
      .split('\n')
      .map(domain => domain.trim())
      .filter(domain => domain.length > 0);
    
    // Get update frequency
    const updateFrequency = document.getElementById('updateFrequency').value;
    
    // Return settings object
    return {
      detectionThreshold,
      enableRealTimeProtection,
      showExtendedInfo,
      whitelist,
      updateFrequency,
      collectAnonymousStats,
      lastUpdated: Date.now()
    };
  }
  
  // Show notification message
  function showNotification(message, type = 'success') {
    const notification = document.getElementById('notification');
    
    // Set notification type
    notification.className = 'notification';
    notification.classList.add(`notification-${type}`);
    
    // Set notification message
    notification.textContent = message;
    
    // Show notification
    notification.style.display = 'block';
    
    // Hide notification after 5 seconds
    setTimeout(() => {
      notification.style.display = 'none';
    }, 5000);
  }
  
  // Set up event listeners
  function setupEventListeners() {
    // Detection threshold slider
    const thresholdInput = document.getElementById('detectionThreshold');
    const thresholdValue = document.getElementById('thresholdValue');
    
    thresholdInput.addEventListener('input', () => {
      thresholdValue.textContent = thresholdInput.value;
    });
    
    // Save button
    document.getElementById('saveBtn').addEventListener('click', async () => {
      // Get settings from form
      const settings = getSettingsFromForm();
      
      // Save settings
      const success = await saveSettings(settings);
      
      if (success) {
        showNotification('Settings saved successfully!');
      } else {
        showNotification('Error saving settings', 'error');
      }
    });
    
    // Cancel button
    document.getElementById('cancelBtn').addEventListener('click', () => {
      // Reload the page to discard changes
      window.location.reload();
    });
    
    // Reset button
    document.getElementById('resetBtn').addEventListener('click', async () => {
      if (confirm('Are you sure you want to reset all settings to their default values?')) {
        // Save default settings
        const success = await saveSettings(defaultSettings);
        
        if (success) {
          // Apply default settings to form
          applySettingsToForm(defaultSettings);
          
          showNotification('Settings reset to defaults');
        } else {
          showNotification('Error resetting settings', 'error');
        }
      }
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
    
    // Privacy link
    document.getElementById('privacyLink').addEventListener('click', (e) => {
      e.preventDefault();
      
      // Show privacy information
      alert(
        "Privacy Policy\n\n" +
        "Phishing Detector respects your privacy:\n\n" +
        "• We don't collect personal data\n" +
        "• When enabled, anonymous statistics include only detection counts\n" +
        "• No browsing history is stored or shared\n" +
        "• All analysis happens locally on your device\n\n" +
        "You can disable anonymous statistics collection in settings."
      );
    });
  }