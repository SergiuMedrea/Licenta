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