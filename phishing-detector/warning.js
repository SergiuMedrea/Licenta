document.addEventListener('DOMContentLoaded', function() {
    // Obține URL-ul periculos și scorul din parametrii
    const urlParams = new URLSearchParams(window.location.search);
    const dangerousUrl = urlParams.get('target');
    const riskScore = urlParams.get('score');
    
    // Afișează URL-ul și scorul
    document.getElementById('dangerousUrl').textContent = dangerousUrl || 'URL necunoscut';
    
    // Verificăm dacă scorul există și este valid
    if (riskScore && !isNaN(parseFloat(riskScore))) {
      document.getElementById('riskScore').textContent = (parseFloat(riskScore) * 100).toFixed(1) + '%';
    } else {
      document.getElementById('riskScore').textContent = 'Necunoscut';
    }
    
    // Butonul pentru întoarcere în siguranță
    document.getElementById('backButton').onclick = function() {
      window.history.back();
    };
    
    // Butonul pentru continuare în ciuda avertismentului
    document.getElementById('proceedButton').onclick = function() {
      // Înregistrează decizia utilizatorului de a continua
      try {
        chrome.runtime.sendMessage({
          action: 'proceedAnyway',
          url: dangerousUrl
        });
      } catch (error) {
        console.error("Eroare la trimiterea mesajului:", error);
      }
      
      // Redirecționează către site-ul periculos
      if (dangerousUrl) {
        window.location.href = dangerousUrl;
      } else {
        window.history.back();
      }
    };
  });