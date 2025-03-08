// Adaugă un handler pentru mesaje de la content scripts și popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log("Mesaj primit:", message);
  
  if (message.action === 'checkUrl') {
    checkPhishingUrl(message.url)
      .then(result => {
        console.log("Rezultat verificare (din mesaj):", result);
        sendResponse(result);
      })
      .catch(error => {
        console.error("Eroare la verificarea URL-ului (din mesaj):", error);
        sendResponse({ error: error.message });
      });
    return true; // Indică faptul că răspunsul va fi trimis asincron
  }
  
  if (message.action === 'analyzeContent') {
    console.log("Analiza conținutului pentru:", message.url);
    console.log("Caracteristici pagină:", message.features);
    // Aici am putea îmbunătăți scorul de phishing bazat pe conținutul paginii
    sendResponse({ received: true });
    return true;
  }
});
let phishingDatabase = {}; // Cache pentru URL-uri verificate anterior

// Încarcă modelul și setările inițiale
chrome.runtime.onInstalled.addListener(async () => {
  // Inițializare setări și model
  try {
    await loadModel();
    console.log("Phishing Detector a fost instalat și inițializat");
  } catch (error) {
    console.error("Eroare la inițializarea extensiei:", error);
  }
});

// Monitorizează navigarea utilizatorului
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  console.log("Navigare detectată:", details.url);
  
  // Se verifică doar frame-ul principal pentru eficiență
  if (details.frameId !== 0) return;
  
  const url = details.url;
  const tabId = details.tabId;
  
  try {
    // Verifică dacă URL-ul este potențial phishing
    console.log("Verificare URL:", url);
    const result = await checkPhishingUrl(url);
    console.log("Rezultat verificare:", result);
    
    if (result.isPhishing) {
      console.log("Site de phishing detectat!");
      // Avertizează utilizatorul
      chrome.tabs.update(tabId, {
        url: `warning.html?target=${encodeURIComponent(url)}&score=${result.score}`
      });
    }
  } catch (error) {
    console.error("Eroare la verificarea URL-ului:", error);
  }
});

// Funcția pentru verificarea URL-ului
async function checkPhishingUrl(url) {
  console.log("[checkPhishingUrl] Verificare URL:", url);
  
  // Verifică cache-ul local
  if (phishingDatabase[url] !== undefined) {
    console.log("[checkPhishingUrl] URL găsit în cache:", phishingDatabase[url]);
    return phishingDatabase[url];
  }
  
  // Extrage caracteristicile URL-ului
  const features = extractUrlFeatures(url);
  console.log("[checkPhishingUrl] Caracteristici extrase:", features);
  
  // Utilizează modelul pentru predicție
  const prediction = await predictWithModel(features);
  console.log("[checkPhishingUrl] Predicție model:", prediction);
  
  // Salvează rezultatul în cache
  phishingDatabase[url] = {
    isPhishing: prediction.score > 0.7, // Pragul poate fi ajustat
    score: prediction.score,
    timestamp: Date.now()
  };
  
  console.log("[checkPhishingUrl] Rezultat final:", phishingDatabase[url]);
  return phishingDatabase[url];
}

// Funcția pentru încărcarea modelului (placeholder)
async function loadModel() {
  // În prototip, vom folosi o implementare simplificată
  console.log("Modelul a fost încărcat");
  
  // Inițializăm storage-ul pentru statistici
  try {
    await chrome.storage.local.set({
      totalChecked: 0,
      totalBlocked: 0,
      lastReset: Date.now()
    });
    console.log("Storage inițializat cu succes");
  } catch (error) {
    console.error("Eroare la inițializarea storage-ului:", error);
  }
  
  return true;
}

// Funcția pentru extragerea caracteristicilor URL-ului
function extractUrlFeatures(url) {
  try {
    const urlObj = new URL(url);
    
    // Caracteristici simple pentru prototip
    return {
      domainLength: urlObj.hostname.length,
      pathLength: urlObj.pathname.length,
      numDots: (urlObj.hostname.match(/\./g) || []).length,
      numDashes: (urlObj.hostname.match(/-/g) || []).length,
      hasHttps: urlObj.protocol === 'https:',
      numParams: urlObj.searchParams.size,
      hasSubdomain: urlObj.hostname.split('.').length > 2,
      // Caracteristici care ar putea indica phishing
      hasIpAddress: /\d+\.\d+\.\d+\.\d+/.test(urlObj.hostname),
      hasSuspiciousWords: /secure|login|verify|account|update|confirm|bank|paypal|password/i.test(url),
      hasLongSubdomain: urlObj.hostname.split('.')[0].length > 15
    };
  } catch (error) {
    console.error("Eroare la extragerea caracteristicilor URL-ului:", error);
    return {};
  }
}

// Funcția pentru predicția cu modelul (implementare simplificată pentru prototip)
async function predictWithModel(features) {
  // În prototip, folosim o implementare simplă bazată pe reguli
  // Într-o implementare reală, aici ar fi utilizat un model ML antrenat
  
  let score = 0;
  
  // Reguli simple pentru detectarea phishing-ului
  if (features.hasIpAddress) score += 0.4;
  if (features.hasSuspiciousWords) score += 0.3;
  if (features.hasLongSubdomain) score += 0.2;
  if (!features.hasHttps) score += 0.3;
  if (features.numDashes > 2) score += 0.2;
  if (features.domainLength > 30) score += 0.2;
  
  // Normalizează scorul între 0 și 1
  score = Math.min(1, score);
  
  return { score };
}
