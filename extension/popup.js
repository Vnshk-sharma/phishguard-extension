/**
 * PhishGuard — popup.js
 * Handles UI rendering, API communication, and history management.
 */

/* ══════════════════════════════════════════════════════════════
   CONFIG
   ══════════════════════════════════════════════════════════════ */
const CONFIG = {
  API_URL: 'http://127.0.0.1:8000/predict',
  TIMEOUT_MS: 8000,
  MAX_HISTORY: 50,
};

/* ══════════════════════════════════════════════════════════════
   DOM REFS
   ══════════════════════════════════════════════════════════════ */
const $ = (id) => document.getElementById(id);

const el = {
  currentUrl:       $('currentUrl'),
  loadingState:     $('loadingState'),
  safeState:        $('safeState'),
  phishingState:    $('phishingState'),
  disabledState:    $('disabledState'),
  confidenceSection:$('confidenceSection'),
  confValue:        $('confValue'),
  progressBar:      $('progressBar'),
  confNote:         $('confNote'),
  featuresSection:  $('featuresSection'),
  featuresGrid:     $('featuresGrid'),
  explanationSection:$('explanationSection'),
  explanationText:  $('explanationText'),
  actionsRow:       $('actionsRow'),
  warnBtn:          $('warnBtn'),
  recheckBtn:       $('recheckBtn'),
  enableToggle:     $('enableToggle'),
  historyBtn:       $('historyBtn'),
  backBtn:          $('backBtn'),
  clearHistoryBtn:  $('clearHistoryBtn'),
  mainView:         $('mainView'),
  historyView:      $('historyView'),
  historyList:      $('historyList'),
  historyEmpty:     $('historyEmpty'),
  footerStatus:     $('footerStatus'),
};

/* ══════════════════════════════════════════════════════════════
   STATE
   ══════════════════════════════════════════════════════════════ */
let currentTabUrl = '';
let lastResult    = null;
let isEnabled     = true;

/* ══════════════════════════════════════════════════════════════
   INIT
   ══════════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', async () => {
  await loadSettings();
  bindEvents();
  await checkCurrentTab();
});

async function loadSettings() {
  const data = await chromeGet(['enabled']);
  isEnabled = data.enabled !== false; // default true
  el.enableToggle.checked = isEnabled;
}

/* ══════════════════════════════════════════════════════════════
   EVENT BINDINGS
   ══════════════════════════════════════════════════════════════ */
function bindEvents() {
  // Toggle enable/disable
  el.enableToggle.addEventListener('change', async () => {
    isEnabled = el.enableToggle.checked;
    await chrome.storage.local.set({ enabled: isEnabled });
    if (isEnabled) {
      await checkCurrentTab();
    } else {
      showState('disabled');
      hideResultSections();
    }
  });

  // Re-check
  el.recheckBtn.addEventListener('click', () => checkCurrentTab(true));

  // Inject warning banner
  el.warnBtn.addEventListener('click', injectWarningBanner);

  // History panel
  el.historyBtn.addEventListener('click', showHistoryPanel);
  el.backBtn.addEventListener('click', showMainPanel);
  el.clearHistoryBtn.addEventListener('click', clearHistory);
}

/* ══════════════════════════════════════════════════════════════
   MAIN FLOW — Get tab URL → Analyze → Render
   ══════════════════════════════════════════════════════════════ */
async function checkCurrentTab(force = false) {
  if (!isEnabled) { showState('disabled'); return; }

  // Get the active tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) return;

  currentTabUrl = tab.url;
  el.currentUrl.textContent = shortenUrl(currentTabUrl);

  // Check cache (skip API call if we have a recent result and not forcing)
  if (!force) {
    const cached = await getCachedResult(currentTabUrl);
    if (cached) {
      renderResult(cached);
      return;
    }
  }

  showState('loading');
  hideResultSections();

  const result = await analyzeUrl(currentTabUrl);
  lastResult = result;

  // Cache result
  await cacheResult(currentTabUrl, result);

  // Save to history
  await saveToHistory(currentTabUrl, result);

  renderResult(result);
}

/* ══════════════════════════════════════════════════════════════
   API CALL (with fallback to local JS analysis)
   ══════════════════════════════════════════════════════════════ */
async function analyzeUrl(url) {
  // Try FastAPI backend first
  try {
    updateFooterStatus('checking', 'Checking…');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), CONFIG.TIMEOUT_MS);

    const resp = await fetch(CONFIG.API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    updateFooterStatus('online', 'Connected');
    return data;
  } catch (err) {
    // Backend unavailable → fall back to local JS heuristics
    console.warn('[PhishGuard] Backend unavailable, using local analysis:', err.message);
    updateFooterStatus('offline', 'Offline mode');
    return localAnalysis(url);
  }
}

/* ══════════════════════════════════════════════════════════════
   LOCAL JS ANALYSIS (fallback — no Python backend needed)
   This replicates the backend feature extraction in JavaScript.
   ══════════════════════════════════════════════════════════════ */
function localAnalysis(url) {
  let parsedUrl, hostname = '', path = '';
  try {
    parsedUrl = new URL(url);
    hostname = parsedUrl.hostname.toLowerCase();
    path = parsedUrl.pathname + parsedUrl.search;
  } catch { hostname = url; }

  /* ── Feature Extraction ── */
  const urlLength     = url.length;
  const hasAtSymbol   = url.includes('@');
  const hasIPAddress  = /\d{1,3}(\.\d{1,3}){3}/.test(hostname);
  const numDots       = (hostname.match(/\./g) || []).length;
  const hasHttps      = url.startsWith('https://');
  const numHyphens    = (hostname.match(/-/g) || []).length;
  const numSlashes    = (url.match(/\//g) || []).length;
  const hasDoubleSlash= url.indexOf('//') > 6;
  const domainLength  = hostname.length;
  const hasPort       = /:\d+/.test(hostname);
  const queryLength   = parsedUrl ? parsedUrl.search.length : 0;
  const numSubdomains = numDots > 1 ? numDots - 1 : 0;

  const suspiciousKeywords = [
    'login','signin','account','verify','update','secure','banking',
    'paypal','ebay','amazon','apple','microsoft','google','confirm',
    'password','credential','suspend','alert','urgent','free','win',
  ];
  const foundKeywords = suspiciousKeywords.filter(k =>
    url.toLowerCase().includes(k)
  );

  const tldList     = ['.tk','.ml','.ga','.cf','.gq','.xyz','.top','.work','.click','.zip'];
  const hasBadTLD   = tldList.some(t => hostname.endsWith(t));
  const hasRedirect = url.toLowerCase().includes('redirect') || url.toLowerCase().includes('url=http');

  /* ── Scoring ── */
  let score = 0;
  if (hasAtSymbol)          score += 25;
  if (hasIPAddress)         score += 30;
  if (urlLength > 100)      score += 15;
  else if (urlLength > 75)  score += 8;
  if (numDots > 4)          score += 15;
  if (numHyphens > 3)       score += 10;
  if (!hasHttps)            score += 10;
  if (hasBadTLD)            score += 20;
  if (hasPort)              score += 15;
  if (hasDoubleSlash)       score += 10;
  if (hasRedirect)          score += 15;
  if (foundKeywords.length) score += Math.min(foundKeywords.length * 8, 30);
  if (domainLength > 30)    score += 10;

  score = Math.min(score, 100);
  const confidence = score / 100;
  const isPhishing = score >= 40;

  /* ── Features List ── */
  const features = [
    {
      name: 'URL Length',
      value: urlLength > 100 ? 'Very Long' : urlLength > 75 ? 'Long' : 'Normal',
      risk: urlLength > 100 ? 'high' : urlLength > 75 ? 'medium' : 'low',
    },
    {
      name: 'Contains @',
      value: hasAtSymbol ? 'Yes' : 'No',
      risk: hasAtSymbol ? 'high' : 'low',
    },
    {
      name: 'IP Address',
      value: hasIPAddress ? 'Yes' : 'No',
      risk: hasIPAddress ? 'high' : 'low',
    },
    {
      name: 'HTTPS',
      value: hasHttps ? 'Yes' : 'No',
      risk: hasHttps ? 'low' : 'medium',
    },
    {
      name: 'Subdomains',
      value: numSubdomains === 0 ? 'None' : `${numSubdomains}`,
      risk: numSubdomains > 2 ? 'high' : numSubdomains > 1 ? 'medium' : 'low',
    },
    {
      name: 'Suspicious TLD',
      value: hasBadTLD ? 'Yes' : 'No',
      risk: hasBadTLD ? 'high' : 'low',
    },
    {
      name: 'Keywords',
      value: foundKeywords.length > 0 ? foundKeywords[0] : 'None',
      risk: foundKeywords.length > 1 ? 'high' : foundKeywords.length === 1 ? 'medium' : 'low',
    },
    {
      name: 'Hyphens',
      value: numHyphens > 0 ? numHyphens : 'None',
      risk: numHyphens > 3 ? 'high' : numHyphens > 1 ? 'medium' : 'low',
    },
  ];

  /* ── Explanation ── */
  const reasons = [];
  if (hasAtSymbol)        reasons.push('contains "@" symbol which can obscure the real domain');
  if (hasIPAddress)       reasons.push('uses a raw IP address instead of a domain name');
  if (hasBadTLD)          reasons.push(`uses a suspicious TLD commonly associated with phishing`);
  if (foundKeywords.length) reasons.push(`contains deceptive keyword(s): "${foundKeywords.slice(0,2).join('", "')}"`);
  if (!hasHttps)          reasons.push('does not use HTTPS encryption');
  if (numSubdomains > 2)  reasons.push(`has ${numSubdomains} subdomains which may mimic legitimate sites`);
  if (urlLength > 100)    reasons.push('URL is unusually long, often used to obscure the real destination');

  const explanation = isPhishing
    ? `This URL was flagged because it ${reasons.length ? reasons.join('; and ') : 'matches multiple phishing patterns'}.`
    : 'No significant phishing indicators were found. The URL appears to follow standard domain conventions.';

  return {
    url,
    label: isPhishing ? 'phishing' : 'safe',
    confidence: parseFloat(confidence.toFixed(3)),
    score,
    features,
    explanation,
    source: 'local',
  };
}

/* ══════════════════════════════════════════════════════════════
   RENDER RESULT
   ══════════════════════════════════════════════════════════════ */
function renderResult(result) {
  const { label, confidence, features, explanation } = result;
  const pct = Math.round(confidence * 100);
  const isPhishing = label === 'phishing';

  // Show verdict card
  showState(isPhishing ? 'phishing' : 'safe');

  // Update extension icon badge via background
  chrome.runtime.sendMessage({
    type: 'UPDATE_BADGE',
    label,
    tabId: null,
  });

  // Confidence bar
  el.confidenceSection.classList.remove('hidden');
  el.confValue.textContent = `${pct}%`;
  el.confNote.textContent = isPhishing
    ? `Model is ${pct}% confident this is phishing`
    : `Model is ${pct}% confident this is safe`;

  requestAnimationFrame(() => {
    el.progressBar.style.width = `${pct}%`;
    el.progressBar.className = 'progress-bar ' + (
      pct >= 70 ? 'danger-bar' :
      pct >= 45 ? 'warn-bar'   : 'safe-bar'
    );
  });

  // Feature chips
  if (features && features.length) {
    el.featuresSection.classList.remove('hidden');
    el.featuresGrid.innerHTML = '';
    features.forEach(f => {
      const chipClass = f.risk === 'high' ? 'risky' : f.risk === 'medium' ? 'neutral' : 'good';
      const badgeClass = f.risk === 'high' ? 'badge-red' : f.risk === 'medium' ? 'badge-yellow' : 'badge-green';
      el.featuresGrid.insertAdjacentHTML('beforeend', `
        <div class="feature-chip ${chipClass}">
          <span class="chip-name">${escHtml(f.name)}</span>
          <span class="chip-badge ${badgeClass}">${escHtml(String(f.value))}</span>
        </div>
      `);
    });
  }

  // Explanation
  el.explanationSection.classList.remove('hidden');
  el.explanationText.textContent = explanation || '—';

  // Actions
  el.actionsRow.classList.remove('hidden');
  if (isPhishing) {
    el.warnBtn.classList.remove('hidden');
  } else {
    el.warnBtn.classList.add('hidden');
  }
}

/* ══════════════════════════════════════════════════════════════
   STATE HELPER
   ══════════════════════════════════════════════════════════════ */
function showState(state) {
  el.loadingState.classList.add('hidden');
  el.safeState.classList.add('hidden');
  el.phishingState.classList.add('hidden');
  el.disabledState.classList.add('hidden');

  if (state === 'loading')   el.loadingState.classList.remove('hidden');
  if (state === 'safe')      el.safeState.classList.remove('hidden');
  if (state === 'phishing')  el.phishingState.classList.remove('hidden');
  if (state === 'disabled')  el.disabledState.classList.remove('hidden');
}

function hideResultSections() {
  el.confidenceSection.classList.add('hidden');
  el.featuresSection.classList.add('hidden');
  el.explanationSection.classList.add('hidden');
  el.actionsRow.classList.add('hidden');
  el.warnBtn.classList.add('hidden');
}

/* ══════════════════════════════════════════════════════════════
   INJECT WARNING BANNER (content script)
   ══════════════════════════════════════════════════════════════ */
async function injectWarningBanner() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;
  try {
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: injectBannerFn,
    });
  } catch (err) {
    console.error('[PhishGuard] Script injection failed:', err);
  }
}

// This function runs in the page context
function injectBannerFn() {
  if (document.getElementById('phishguard-banner')) return;

  const banner = document.createElement('div');
  banner.id = 'phishguard-banner';
  Object.assign(banner.style, {
    position: 'fixed',
    top: '0',
    left: '0',
    width: '100%',
    zIndex: '2147483647',
    background: 'linear-gradient(135deg, #7f1d1d, #991b1b)',
    color: '#fff',
    fontFamily: "'IBM Plex Mono', monospace",
    fontSize: '13px',
    padding: '10px 20px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: '12px',
    boxShadow: '0 2px 20px rgba(239,68,68,0.5)',
    borderBottom: '2px solid #ef4444',
    animation: 'phishguard-slide 0.35s ease',
  });

  const style = document.createElement('style');
  style.textContent = `
    @keyframes phishguard-slide {
      from { transform: translateY(-100%); opacity: 0; }
      to   { transform: translateY(0);     opacity: 1; }
    }
  `;
  document.head.appendChild(style);

  banner.innerHTML = `
    <span style="display:flex;align-items:center;gap:10px;">
      <span style="font-size:18px;">⚠️</span>
      <span>
        <strong style="letter-spacing:0.06em;">PHISHING WARNING</strong>
        <span style="opacity:0.85;margin-left:8px;">PhishGuard detected this site may be unsafe</span>
      </span>
    </span>
    <button id="phishguard-close" style="
      background:rgba(255,255,255,0.15);border:1px solid rgba(255,255,255,0.3);
      color:#fff;font-size:12px;padding:4px 10px;border-radius:6px;cursor:pointer;
      font-family:inherit;
    ">Dismiss</button>
  `;

  document.body.prepend(banner);
  document.getElementById('phishguard-close').addEventListener('click', () => banner.remove());
}

/* ══════════════════════════════════════════════════════════════
   HISTORY
   ══════════════════════════════════════════════════════════════ */
async function saveToHistory(url, result) {
  const data = await chromeGet(['history']);
  const history = data.history || [];
  const entry = {
    url,
    label: result.label,
    confidence: result.confidence,
    timestamp: Date.now(),
  };
  // Avoid duplicate consecutive entries for same URL
  if (history.length && history[0].url === url) return;
  history.unshift(entry);
  if (history.length > CONFIG.MAX_HISTORY) history.pop();
  await chrome.storage.local.set({ history });
}

async function showHistoryPanel() {
  el.mainView.classList.add('hidden');
  el.historyView.classList.remove('hidden');

  const data = await chromeGet(['history']);
  const history = data.history || [];
  el.historyList.innerHTML = '';

  if (!history.length) {
    el.historyEmpty.classList.remove('hidden');
    return;
  }
  el.historyEmpty.classList.add('hidden');

  history.forEach(entry => {
    const isPhish = entry.label === 'phishing';
    const pct = Math.round((entry.confidence || 0) * 100);
    const time = formatRelativeTime(entry.timestamp);

    const item = document.createElement('div');
    item.className = `history-item ${isPhish ? 'hist-phish' : 'hist-safe'}`;
    item.innerHTML = `
      <div class="hist-dot ${isPhish ? 'phishing' : 'safe'}"></div>
      <div class="hist-info">
        <div class="hist-url">${escHtml(shortenUrl(entry.url))}</div>
        <div class="hist-meta">
          <span class="hist-verdict ${isPhish ? 'phishing' : 'safe'}">${isPhish ? 'PHISHING' : 'SAFE'}</span>
          <span class="hist-time">${time}</span>
        </div>
      </div>
      <div class="hist-conf">${pct}%</div>
    `;
    el.historyList.appendChild(item);
  });
}

function showMainPanel() {
  el.historyView.classList.add('hidden');
  el.mainView.classList.remove('hidden');
}

async function clearHistory() {
  await chrome.storage.local.set({ history: [] });
  el.historyList.innerHTML = '';
  el.historyEmpty.classList.remove('hidden');
}

/* ══════════════════════════════════════════════════════════════
   CACHE (5 minute TTL)
   ══════════════════════════════════════════════════════════════ */
async function getCachedResult(url) {
  const data = await chromeGet(['urlCache']);
  const cache = data.urlCache || {};
  const entry = cache[url];
  if (!entry) return null;
  if (Date.now() - entry.ts > 5 * 60 * 1000) return null; // expired
  return entry.result;
}

async function cacheResult(url, result) {
  const data = await chromeGet(['urlCache']);
  const cache = data.urlCache || {};
  cache[url] = { result, ts: Date.now() };
  await chrome.storage.local.set({ urlCache: cache });
}

/* ══════════════════════════════════════════════════════════════
   UTILITIES
   ══════════════════════════════════════════════════════════════ */
function chromeGet(keys) {
  return new Promise(resolve => chrome.storage.local.get(keys, resolve));
}

function shortenUrl(url) {
  try {
    const u = new URL(url);
    return u.hostname + (u.pathname.length > 30 ? u.pathname.slice(0, 30) + '…' : u.pathname);
  } catch { return url.slice(0, 60); }
}

function escHtml(str) {
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function formatRelativeTime(ts) {
  const diff = (Date.now() - ts) / 1000;
  if (diff < 60)   return 'just now';
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  return `${Math.floor(diff/86400)}d ago`;
}

function updateFooterStatus(state, text) {
  el.footerStatus.textContent = text;
  el.footerStatus.className = 'footer-status ' + state;
}
