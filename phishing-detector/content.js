// Analizează conținutul paginii pentru a detecta semne de phishing
function analyzePageContent() {
  // Caracteristici care pot indica un site de phishing
  const features = {
    hasPasswordField: document.querySelectorAll('input[type="password"]').length > 0,
    hasLoginForm: document.querySelectorAll('form').length > 0 && 
                 (document.body.innerHTML.toLowerCase().includes('login') || 
                  document.body.innerHTML.toLowerCase().includes('sign in')),
    hasBrandLogos: document.querySelectorAll('img[src*="logo"]').length > 0,
    hasSuspiciousRedirects: Array.from(document.querySelectorAll('a')).some(a => 
      a.href.includes('redirect') || a.href.includes('redir') || a.href.includes('url=')),
    poorDesign: document.querySelectorAll('*[style]').length < 10, // Estimare simplificată
    // Se pot adăuga mai multe caracteristici pentru analiza DOM și conținut
  };
  
  // Trimite caracteristicile către background script pentru analiză
  chrome.runtime.sendMessage({
    action: 'analyzeContent',
    features: features,
    url: window.location.href
  });
}

// Rulează analiza după ce pagina s-a încărcat complet
window.addEventListener('load', () => {
  // Întârziere mică pentru a permite încărcarea completă a elementelor dinamice
  setTimeout(analyzePageContent, 1500);
});