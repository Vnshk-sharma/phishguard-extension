/**
 * PhishGuard — content.js
 * Content script injected into every page.
 * Listens for messages from background/popup to show warning banner.
 */

// Listen for messages from background worker
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'SHOW_PHISHING_BANNER') {
    showBanner();
    sendResponse({ ok: true });
  }
  if (msg.type === 'HIDE_PHISHING_BANNER') {
    const banner = document.getElementById('phishguard-banner');
    if (banner) banner.remove();
    sendResponse({ ok: true });
  }
});

/**
 * Injects a persistent warning banner at the top of the page.
 */
function showBanner() {
  // Prevent duplicates
  if (document.getElementById('phishguard-banner')) return;

  // Inject animation keyframes
  const style = document.createElement('style');
  style.id = 'phishguard-style';
  style.textContent = `
    @keyframes pg-slide-in {
      from { transform: translateY(-100%); opacity: 0; }
      to   { transform: translateY(0);     opacity: 1; }
    }
    @keyframes pg-pulse {
      0%, 100% { box-shadow: 0 2px 20px rgba(239,68,68,0.4); }
      50%       { box-shadow: 0 2px 40px rgba(239,68,68,0.7); }
    }
    #phishguard-banner {
      animation: pg-slide-in 0.35s ease, pg-pulse 2.5s ease 0.5s infinite;
    }
    #phishguard-close:hover {
      background: rgba(255,255,255,0.25) !important;
    }
  `;
  document.head.appendChild(style);

  const banner = document.createElement('div');
  banner.id = 'phishguard-banner';
  Object.assign(banner.style, {
    position: 'fixed',
    top: '0',
    left: '0',
    width: '100%',
    zIndex: '2147483647',
    background: 'linear-gradient(135deg, #450a0a 0%, #991b1b 50%, #7f1d1d 100%)',
    color: '#ffffff',
    fontFamily: "'IBM Plex Mono', 'Courier New', monospace",
    fontSize: '13px',
    lineHeight: '1.4',
    padding: '12px 20px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: '16px',
    borderBottom: '2px solid #ef4444',
  });

  // Icon + text
  const left = document.createElement('div');
  Object.assign(left.style, {
    display: 'flex', alignItems: 'center', gap: '12px',
  });
  left.innerHTML = `
    <span style="font-size:20px;flex-shrink:0;">⚠️</span>
    <div>
      <div style="font-weight:700;letter-spacing:0.06em;font-size:13px;">PHISHING WARNING — PhishGuard</div>
      <div style="opacity:0.8;font-size:11px;margin-top:2px;">
        This site may be attempting to steal your credentials or personal data. Proceed with extreme caution.
      </div>
    </div>
  `;

  // Action buttons
  const right = document.createElement('div');
  Object.assign(right.style, { display: 'flex', gap: '8px', flexShrink: '0' });

  const leaveBtn = document.createElement('button');
  leaveBtn.textContent = '← Go Back';
  Object.assign(leaveBtn.style, {
    background: '#ef4444', border: 'none', color: '#fff',
    fontFamily: 'inherit', fontSize: '11px', fontWeight: '600',
    padding: '6px 12px', borderRadius: '6px', cursor: 'pointer',
  });
  leaveBtn.addEventListener('click', () => window.history.back());

  const closeBtn = document.createElement('button');
  closeBtn.id = 'phishguard-close';
  closeBtn.textContent = 'Dismiss';
  Object.assign(closeBtn.style, {
    background: 'rgba(255,255,255,0.15)',
    border: '1px solid rgba(255,255,255,0.35)',
    color: '#fff', fontFamily: 'inherit', fontSize: '11px',
    padding: '6px 12px', borderRadius: '6px', cursor: 'pointer',
    transition: 'background 0.15s',
  });
  closeBtn.addEventListener('click', () => {
    banner.remove();
    const s = document.getElementById('phishguard-style');
    if (s) s.remove();
  });

  right.appendChild(leaveBtn);
  right.appendChild(closeBtn);
  banner.appendChild(left);
  banner.appendChild(right);
  document.body.prepend(banner);
}
