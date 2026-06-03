document.addEventListener('DOMContentLoaded', () => {
  const toggle = document.getElementById('proxyToggle');
  const statusIndicator = document.getElementById('statusDot');
  const statusText = document.getElementById('statusText');
  const setupBtn = document.getElementById('setupBtn');

  // Load current state
  chrome.storage.local.get(['proxyEnabled'], (result) => {
    const isEnabled = result.proxyEnabled || false;
    toggle.checked = isEnabled;
    updateUI(isEnabled);
  });

  // Handle toggle change
  toggle.addEventListener('change', (e) => {
    const isEnabled = e.target.checked;
    
    // Send message to background script to update proxy
    chrome.runtime.sendMessage(
      { action: 'setProxy', enabled: isEnabled },
      (response) => {
        if (response && response.success) {
          updateUI(isEnabled);
        } else {
          // Revert toggle if failed
          toggle.checked = !isEnabled;
          alert("Failed to update proxy settings.");
        }
      }
    );
  });

  // Setup button
  setupBtn.addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('setup.html') });
  });

  function updateUI(isEnabled) {
    if (isEnabled) {
      statusIndicator.classList.add('active');
      statusText.textContent = 'Firewall Active';
      statusText.style.color = '#00e676';
    } else {
      statusIndicator.classList.remove('active');
      statusText.textContent = 'Firewall Inactive';
      statusText.style.color = '#f44336';
    }
  }
});
