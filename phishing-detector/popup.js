document.addEventListener('DOMContentLoaded', async () => {
  console.log("Popup inițializat");
  
  // Obține tab-ul curent
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const currentTab = tabs[0];
    const url = currentTab.url;
    
    // Afișează URL-ul curent
    document.getElementById('currentUrl').textContent = url;
    console.log("URL curent:", url);
    
    try {
      // Verifică URL-ul utilizând funcția din background
      console.log("Trimit cerere către background pentru verificare URL");
      
      const result = await new Promise((resolve, reject) => {
        chrome.runtime.sendMessage(
          { action: 'checkUrl', url: url },
          response => {
            if (chrome.runtime.lastError) {
              console.error("Eroare comunicare:", chrome.runtime.lastError);
              reject(chrome.runtime.lastError);
            } else {
              console.log("Răspuns primit:", response);
              resolve(response);
            }
          }
        );
      });
      
      // Actualizează interfața cu rezultatul
      updateUI(result);
      
      // Obține statisticile
      const stats = await chrome.storage.local.get(['totalChecked', 'totalBlocked']);
      document.getElementById('totalChecked').textContent = stats.totalChecked || 0;
      document.getElementById('totalBlocked').textContent = stats.totalBlocked || 0;
      
    } catch (error) {
      console.error("Eroare la verificarea URL-ului:", error);
      document.getElementById('statusText').textContent = "Eroare la verificare";
      document.getElementById('statusText').style.color = "red";
    }
  } catch (error) {
    console.error("Eroare la obținerea tab-ului curent:", error);
    document.getElementById('statusText').textContent = "Eroare la obținerea tab-ului";
    document.getElementById('statusText').style.color = "red";
  }
});

// Actualizează interfața în funcție de rezultatul verificării
function updateUI(result) {
  const statusIndicator = document.getElementById('statusIndicator');
  const statusText = document.getElementById('statusText');
  const riskScore = document.getElementById('riskScore');
  
  riskScore.textContent = (result.score * 100).toFixed(1) + '%';
  
  if (result.isPhishing) {
    statusIndicator.className = 'status-indicator dangerous';
    statusText.textContent = 'Site periculos detectat!';
    statusText.style.color = 'red';
  } else if (result.score > 0.3) {
    statusIndicator.className = 'status-indicator suspicious';
    statusText.textContent = 'Site potențial suspect';
    statusText.style.color = 'orange';
  } else {
    statusIndicator.className = 'status-indicator safe';
    statusText.textContent = 'Site sigur';
    statusText.style.color = 'green';
  }
}