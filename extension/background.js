/**
 * PhishGuard — background.js (Service Worker)
 * Handles badge color updates, real-time tab monitoring, and messaging.
 */

/* ══════════════════════════════════════════════════════════════
   CONSTANTS
   ══════════════════════════════════════════════════════════════ */
const API_URL    = 'http://127.0.0.1:8000/predict';
const TIMEOUT_MS = 8000;
const CACHE_TTL  = 5 * 60 * 1000; // 5 minutes

/* ══════════════════════════════════════════════════════════════
   INSTALL / UPDATE
   ══════════════════════════════════════════════════════════════ */
chrome.runtime.onInstalled.addListener(() => {
  console.log('[PhishGuard] Extension installed');
  chrome.storage.local.set({ enabled: true, history: [], urlCache: {} });
  setBadgeDefault();
});

/* ══════════════════════════════════════════════════════════════
   MESSAGE HANDLER (from popup.js)
   ══════════════════════════════════════════════════════════════ */
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'UPDATE_BADGE') {
    chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
      if (tab) updateBadge(tab.id, msg.label);
    });
  }
  return false;
});

/* ══════════════════════════════════════════════════════════════
   TAB NAVIGATION LISTENER
   Automatically check URL when user navigates to a new page.
   ══════════════════════════════════════════════════════════════ */
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete') return;
  if (!tab.url || tab.url.startsWith('chrome://')) return;

  const { enabled } = await chromeGet(['enabled']);
  if (!enabled) {
    setBadgeDisabled(tabId);
    return;
  }

  setBadgeChecking(tabId);

  try {
    const result = await analyzeUrlBackground(tab.url);
    updateBadge(tabId, result.label);

    // Auto-inject banner if phishing (optional — only if auto-warn enabled)
    const { autoWarn } = await chromeGet(['autoWarn']);
    if (autoWarn && result.label === 'phishing') {
      await injectWarningInTab(tabId);
    }
  } catch (err) {
    console.warn('[PhishGuard] Background analysis failed:', err.message);
    setBadgeDefault(tabId);
  }
});

/* ══════════════════════════════════════════════════════════════
   ANALYSIS (background context)
   ══════════════════════════════════════════════════════════════ */
async function analyzeUrlBackground(url) {
  const cached = await getCachedResult(url);
  if (cached) return cached;

  const result = localAnalysisBackground(url);
  await cacheResult(url, result);
  return result;
}

/* ══════════════════════════════════════════════════════════════
   LOCAL ANALYSIS (background — simplified scoring)
   ══════════════════════════════════════════════════════════════ */
function localAnalysisBackground(url) {
  let hostname = '';
  try { hostname = new URL(url).hostname.toLowerCase(); } catch { hostname = url; }

  let score = 0;
  if (url.includes('@'))               score += 25;
  if (/\d{1,3}(\.\d{1,3}){3}/.test(hostname)) score += 30;
  if (url.length > 100)                score += 15;
  if ((hostname.match(/\./g)||[]).length > 4) score += 15;
  if (!url.startsWith('https://'))     score += 10;
  if (['.tk','.ml','.ga','.cf','.gq'].some(t => hostname.endsWith(t))) score += 20;

  const kw = ['login','signin','verify','secure','account','password','banking'];
  if (kw.some(k => url.toLowerCase().includes(k))) score += 15;

  score = Math.min(score, 100);
  return {
    url,
    label: score >= 40 ? 'phishing' : 'safe',
    confidence: parseFloat((score / 100).toFixed(3)),
    score,
    features: [],
    explanation: '',
    source: 'local-bg',
  };
}

/* ══════════════════════════════════════════════════════════════
   BADGE MANAGEMENT
   ══════════════════════════════════════════════════════════════ */
function updateBadge(tabId, label) {
  if (label === 'phishing') {
    setBadgeDanger(tabId);
  } else {
    setBadgeSafe(tabId);
  }
}

function setBadgeSafe(tabId) {
  chrome.action.setBadgeText({ text: '✓', tabId });
  chrome.action.setBadgeBackgroundColor({ color: '#10b981', tabId });
}

function setBadgeDanger(tabId) {
  chrome.action.setBadgeText({ text: '!', tabId });
  chrome.action.setBadgeBackgroundColor({ color: '#ef4444', tabId });
}

function setBadgeChecking(tabId) {
  chrome.action.setBadgeText({ text: '…', tabId });
  chrome.action.setBadgeBackgroundColor({ color: '#6366f1', tabId });
}

function setBadgeDisabled(tabId) {
  chrome.action.setBadgeText({ text: '', tabId });
}

function setBadgeDefault(tabId) {
  const args = tabId ? { text: '', tabId } : { text: '' };
  chrome.action.setBadgeText(args);
}

/* ══════════════════════════════════════════════════════════════
   INJECT BANNER
   ══════════════════════════════════════════════════════════════ */
async function injectWarningInTab(tabId) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        if (document.getElementById('phishguard-banner')) return;
        const b = document.createElement('div');
        b.id = 'phishguard-banner';
        Object.assign(b.style, {
          position:'fixed', top:'0', left:'0', width:'100%',
          zIndex:'2147483647', background:'linear-gradient(135deg,#7f1d1d,#991b1b)',
          color:'#fff', fontFamily:'monospace', fontSize:'13px',
          padding:'10px 20px', display:'flex', alignItems:'center',
          justifyContent:'space-between', boxShadow:'0 2px 20px rgba(239,68,68,0.5)',
          borderBottom:'2px solid #ef4444',
        });
        b.innerHTML = `<span>⚠️ <strong>PHISHING WARNING</strong> — PhishGuard detected this site may be unsafe</span>
          <button onclick="this.parentNode.remove()" style="
            background:rgba(255,255,255,0.15);border:1px solid rgba(255,255,255,0.3);
            color:#fff;font-size:12px;padding:4px 10px;border-radius:6px;cursor:pointer;">×</button>`;
        document.body.prepend(b);
      },
    });
  } catch (err) {
    console.warn('[PhishGuard] Banner injection failed:', err.message);
  }
}

/* ══════════════════════════════════════════════════════════════
   CACHE
   ══════════════════════════════════════════════════════════════ */
async function getCachedResult(url) {
  const data = await chromeGet(['urlCache']);
  const cache = data.urlCache || {};
  const entry = cache[url];
  if (!entry || Date.now() - entry.ts > CACHE_TTL) return null;
  return entry.result;
}

async function cacheResult(url, result) {
  const data = await chromeGet(['urlCache']);
  const cache = data.urlCache || {};
  cache[url] = { result, ts: Date.now() };
  // Prune cache if too large
  const keys = Object.keys(cache);
  if (keys.length > 200) {
    const oldest = keys.sort((a,b) => cache[a].ts - cache[b].ts).slice(0, 50);
    oldest.forEach(k => delete cache[k]);
  }
  await chrome.storage.local.set({ urlCache: cache });
}

function chromeGet(keys) {
  return new Promise(resolve => chrome.storage.local.get(keys, resolve));
}
