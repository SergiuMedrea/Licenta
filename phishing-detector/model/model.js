// Funcția pentru antrenarea modelului (exemplu simplificat)
async function trainModel(trainingData) {
  console.log("Antrenare model cu", trainingData.length, "exemple");

  // Într-o implementare reală, aici ar fi antrenarea unui model ML
  // Pentru prototip, stocăm doar regulile și ponderea lor
  const model = {
    features: {
      hasIpAddress: 0.45, // URL conține o adresă IP
      hasSuspiciousWords: 0.35, // URL conține cuvinte suspecte
      hasLongSubdomain: 0.3, // Subdomen foarte lung
      notUsingHttps: 0.4, // Nu folosește HTTPS
      excessiveDashes: 0.25, // Multe caracterele "-" în URL
      longDomainName: 0.25, // Nume de domeniu foarte lung
      redirectUrl: 0.3, // URL de redirecționare
      abnormalFormAction: 0.5, // Formular cu acțiune suspectă
      hasPopup: 0.2, // Pagina deschide pop-up-uri
      iframeRedirect: 0.4, // Folosește iframe-uri pentru redirecționare
      hiddenElements: 0.35, // Elemente ascunse care colectează date
      faviconMismatch: 0.25, // Favicon diferit de domeniu
      disablsRightClick: 0.15, // Dezactivează click dreapta
      requiresExcessiveInfo: 0.35, // Cere informații excesive
    },
    threshold: 0.7, // Pragul pentru clasificare ca phishing
    version: "1.0.0",
    lastUpdated: Date.now(),
  };

  return model;
}

// Funcția pentru extragerea caracteristicilor avansate din URL și conținut
function extractFeatures(url, pageContent = null) {
  try {
    const urlObj = new URL(url);

    // Caracteristici din URL
    const urlFeatures = {
      domainLength: urlObj.hostname.length,
      pathLength: urlObj.pathname.length,
      numDots: (urlObj.hostname.match(/\./g) || []).length,
      numDashes: (urlObj.hostname.match(/-/g) || []).length,
      hasHttps: urlObj.protocol === "https:",
      notUsingHttps: urlObj.protocol !== "https:",
      numParams: urlObj.searchParams.size,
      hasSubdomain: urlObj.hostname.split(".").length > 2,
      hasIpAddress: /^\d+\.\d+\.\d+\.\d+$/.test(urlObj.hostname),
      hasSuspiciousWords:
        /secure|login|verify|account|update|confirm|bank|paypal|password/i.test(
          url
        ),
      hasLongSubdomain: urlObj.hostname.split(".")[0].length > 15,
      excessiveDashes: (urlObj.hostname.match(/-/g) || []).length > 2,
      longDomainName: urlObj.hostname.length > 30,
      redirectUrl:
        url.includes("redirect") ||
        url.includes("url=") ||
        url.includes("goto="),
    };

    // Caracteristici din conținutul paginii (dacă este disponibil)
    const contentFeatures = pageContent
      ? {
          hasPasswordField: /<input[^>]*type=["']password["'][^>]*>/i.test(
            pageContent
          ),
          hasLoginForm:
            /<form[^>]*>/i.test(pageContent) &&
            (pageContent.toLowerCase().includes("login") ||
              pageContent.toLowerCase().includes("sign in")),
          hasBrandLogo: /<img[^>]*logo[^>]*>/i.test(pageContent),
          abnormalFormAction:
            /<form[^>]*action=["'](?!https:)[^"']*["'][^>]*>/i.test(
              pageContent
            ),
          hasPopup: /window\.open|popup|alert\(/i.test(pageContent),
          iframeRedirect: /<iframe[^>]*>/i.test(pageContent),
          hiddenElements: /<[^>]*hidden[^>]*>/i.test(pageContent),
          faviconMismatch: false, // Necesită analiză mai complexă
          disablesRightClick: /oncontextmenu\s*=\s*["']return false["']/i.test(
            pageContent
          ),
          requiresExcessiveInfo:
            (pageContent.match(/<input/g) || []).length > 7,
        }
      : {};

    // Combinăm caracteristicile
    return { ...urlFeatures, ...contentFeatures };
  } catch (error) {
    console.error("Eroare la extragerea caracteristicilor:", error);
    return {};
  }
}

// Funcția pentru predicție folosind modelul
function predictWithModel(features, model) {
  let score = 0;
  let activeFeatures = [];

  // Calculăm scorul pentru fiecare caracteristică
  for (const [feature, weight] of Object.entries(model.features)) {
    if (features[feature] === true) {
      score += weight;
      activeFeatures.push(feature);
    }
  }

  // Normalizăm scorul între 0 și 1 pentru cazuri extreme
  score = Math.min(1, score);

  return {
    score: score,
    isPhishing: score >= model.threshold,
    activeFeatures: activeFeatures,
  };
}

// Funcția pentru actualizarea modelului (ar putea folosi un API extern)
async function updateModel() {
  try {
    // În prototip, simulăm o actualizare
    console.log("Verificare actualizări model...");

    // Într-o implementare reală, aici ar fi o cerere către un server
    // pentru a obține cele mai recente date de antrenament

    // Generăm date de antrenament mock
    const mockTrainingData = [
      { url: "https://secure-bank-login.example.com", isPhishing: true },
      { url: "http://paypal.secure.mydomain.example", isPhishing: true },
      { url: "https://login.microsoft.com", isPhishing: false },
      { url: "https://secure.chase.com", isPhishing: false },
    ];

    // Antrenăm modelul cu datele noi
    const updatedModel = await trainModel(mockTrainingData);

    // Salvăm modelul
    chrome.storage.local.set({ phishingModel: updatedModel });
    console.log("Model actualizat cu succes:", updatedModel);

    return updatedModel;
  } catch (error) {
    console.error("Eroare la actualizarea modelului:", error);
    return null;
  }
}

// Exportăm funcțiile pentru utilizare în background.js
export { extractFeatures, predictWithModel, updateModel, trainModel };
