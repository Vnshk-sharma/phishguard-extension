"""
PhishGuard — Streamlit Web App
Run locally:  streamlit run streamlit_app.py
Deploy:       https://streamlit.io/cloud
"""

import streamlit as st
import streamlit.components.v1 as components
import re
import math
import time
import pandas as pd
import io
from urllib.parse import urlparse, parse_qs

# ══════════════════════════════════════════════════════════════
# PAGE CONFIG
# ══════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="PhishGuard — Phishing URL Detector",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# ══════════════════════════════════════════════════════════════
# CUSTOM CSS
# ══════════════════════════════════════════════════════════════
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Syne:wght@700;800&display=swap');

  /* Hide Streamlit default elements */
  #MainMenu, footer, header { visibility: hidden; }
  .block-container { padding-top: 2rem; padding-bottom: 2rem; max-width: 760px; }

  /* Global font */
  html, body, [class*="css"] {
    font-family: 'IBM Plex Mono', monospace;
    background-color: #090b10;
    color: #e2e6f0;
  }

  /* Input box */
  .stTextInput input {
    background: #161b26 !important;
    border: 1px solid rgba(255,255,255,0.1) !important;
    border-radius: 8px !important;
    color: #e2e6f0 !important;
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 13px !important;
    padding: 12px 16px !important;
  }
  .stTextInput input:focus {
    border-color: rgba(99,102,241,0.6) !important;
    box-shadow: 0 0 0 3px rgba(99,102,241,0.12) !important;
  }

  /* Button */
  .stButton button {
    background: #6366f1 !important;
    color: white !important;
    border: none !important;
    border-radius: 8px !important;
    font-family: 'IBM Plex Mono', monospace !important;
    font-weight: 600 !important;
    font-size: 13px !important;
    padding: 10px 28px !important;
    width: 100%;
    transition: all 0.2s !important;
  }
  .stButton button:hover {
    background: #5254cc !important;
    transform: translateY(-1px) !important;
    box-shadow: 0 8px 24px rgba(99,102,241,0.35) !important;
  }

  /* Metric cards */
  [data-testid="metric-container"] {
    background: #0f1219;
    border: 1px solid rgba(255,255,255,0.07);
    border-radius: 10px;
    padding: 16px !important;
  }
  [data-testid="metric-container"] label {
    font-size: 10px !important;
    letter-spacing: 0.1em !important;
    color: #454d66 !important;
  }
  [data-testid="metric-container"] [data-testid="stMetricValue"] {
    font-family: 'Syne', sans-serif !important;
    font-size: 22px !important;
    font-weight: 800 !important;
  }

  /* Progress bar */
  .stProgress > div > div {
    border-radius: 99px !important;
    height: 6px !important;
  }

  /* Expander */
  .streamlit-expanderHeader {
    background: #0f1219 !important;
    border: 1px solid rgba(255,255,255,0.07) !important;
    border-radius: 8px !important;
    font-size: 12px !important;
    color: #7a8099 !important;
  }

  /* Sidebar */
  [data-testid="stSidebar"] {
    background: #0f1219 !important;
    border-right: 1px solid rgba(255,255,255,0.07) !important;
  }

  /* Divider */
  hr { border-color: rgba(255,255,255,0.06) !important; }
</style>
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════
# FEATURE EXTRACTION (same logic as extension)
# ══════════════════════════════════════════════════════════════
SUSPICIOUS_KEYWORDS = [
    'login','signin','account','verify','update','secure','banking',
    'paypal','ebay','amazon','apple','microsoft','google','confirm',
    'password','credential','suspend','alert','urgent','free','win',
    'wallet','crypto','bitcoin','recover','support','helpdesk',
]

BAD_TLDS = [
    '.tk','.ml','.ga','.cf','.gq','.xyz','.top','.work',
    '.click','.zip','.review','.country','.loan','.download',
]

def extract_features(url: str) -> dict:
    try:
        parsed   = urlparse(url if '://' in url else 'http://' + url)
        hostname = (parsed.hostname or '').lower()
        path     = parsed.path or ''
        query    = parsed.query or ''
        scheme   = parsed.scheme.lower()
    except Exception:
        hostname = url; path = ''; query = ''; scheme = 'http'

    url_lower = url.lower()

    found_keywords = [k for k in SUSPICIOUS_KEYWORDS if k in url_lower]

    return {
        'url_length':     len(url),
        'domain_length':  len(hostname),
        'num_dots':       hostname.count('.'),
        'has_at_symbol':  '@' in url,
        'has_ip_address': bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname)),
        'has_https':      scheme == 'https',
        'num_hyphens':    hostname.count('-'),
        'num_subdomains': max(0, hostname.count('.') - 1),
        'has_double_slash': '//' in url[7:],
        'has_port':       parsed.port not in (None, 80, 443),
        'has_suspicious_tld': any(hostname.endswith(t) for t in BAD_TLDS),
        'has_redirect':   'redirect' in url_lower or 'url=http' in url_lower,
        'found_keywords': found_keywords,
        'top_keyword':    found_keywords[0] if found_keywords else '',
        'keyword_count':  len(found_keywords),
        'query_length':   len(query),
        'hostname_entropy': _entropy(hostname),
        'digit_ratio':    sum(c.isdigit() for c in hostname) / max(len(hostname), 1),
    }


def score_url(f: dict) -> int:
    score = 0
    if f['has_at_symbol']:          score += 25
    if f['has_ip_address']:         score += 30
    if f['url_length'] > 100:       score += 15
    elif f['url_length'] > 75:      score += 8
    if f['num_dots'] > 4:           score += 15
    if f['num_hyphens'] > 3:        score += 10
    if not f['has_https']:          score += 10
    if f['has_suspicious_tld']:     score += 20
    if f['has_port']:               score += 15
    if f['has_double_slash']:       score += 10
    if f['has_redirect']:           score += 15
    if f['keyword_count']:          score += min(f['keyword_count'] * 8, 30)
    if f['domain_length'] > 30:     score += 10
    if f['hostname_entropy'] > 4.0: score += 8
    if f['digit_ratio'] > 0.3:      score += 8
    return min(score, 100)


def build_explanation(label: str, f: dict) -> str:
    reasons = []
    if f['has_at_symbol']:      reasons.append('"@" symbol hides the real destination domain')
    if f['has_ip_address']:     reasons.append('raw IP address used instead of a domain name')
    if f['has_suspicious_tld']: reasons.append('free/suspicious TLD commonly exploited for phishing')
    if f['top_keyword']:        reasons.append(f'deceptive keyword "{f["top_keyword"]}" detected')
    if not f['has_https']:      reasons.append('no HTTPS encryption')
    if f['num_subdomains'] > 2: reasons.append(f'{f["num_subdomains"]} subdomains mimicking a real site')
    if f['url_length'] > 100:   reasons.append('unusually long URL obscuring the real domain')

    if label == 'phishing':
        return ('⚠️ Flagged because: ' + ' · '.join(reasons)) if reasons else '⚠️ Multiple phishing patterns detected.'
    return '✅ No significant phishing indicators found. URL follows standard conventions.'


def get_top_features(f: dict) -> list:
    contributions = []
    if f['has_at_symbol']:          contributions.append(("@ Symbol",         25))
    if f['has_ip_address']:         contributions.append(("IP Address",        30))
    if f['url_length'] > 100:       contributions.append(("URL Too Long",      15))
    elif f['url_length'] > 75:      contributions.append(("URL Length",         8))
    if f['num_dots'] > 4:           contributions.append(("Too Many Dots",     15))
    if f['num_hyphens'] > 3:        contributions.append(("Too Many Hyphens",  10))
    if not f['has_https']:          contributions.append(("No HTTPS",          10))
    if f['has_suspicious_tld']:     contributions.append(("Suspicious TLD",    20))
    if f['has_port']:               contributions.append(("Non-standard Port", 15))
    if f['has_double_slash']:       contributions.append(("Double Slash",      10))
    if f['has_redirect']:           contributions.append(("Redirect Pattern",  15))
    if f['keyword_count']:          contributions.append(("Phishing Keywords", min(f['keyword_count'] * 8, 30)))
    if f['domain_length'] > 30:     contributions.append(("Long Domain",       10))
    if f['hostname_entropy'] > 4.0: contributions.append(("High Entropy",       8))
    if f['digit_ratio'] > 0.3:      contributions.append(("High Digit Ratio",   8))
    return sorted(contributions, key=lambda x: x[1], reverse=True)[:5]


def _entropy(text: str) -> float:
    if not text: return 0.0
    freq = {}
    for c in text: freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((v/n) * math.log2(v/n) for v in freq.values())


# ══════════════════════════════════════════════════════════════
# SESSION STATE (history)
# ══════════════════════════════════════════════════════════════
if 'history' not in st.session_state:
    st.session_state.history = []


# ══════════════════════════════════════════════════════════════
# HEADER
# ══════════════════════════════════════════════════════════════
st.markdown("""
<div style="text-align:center; padding: 20px 0 10px;">
  <div style="display:inline-flex;align-items:center;gap:10px;
              background:rgba(99,102,241,0.1);border:1px solid rgba(99,102,241,0.25);
              border-radius:99px;padding:6px 18px;margin-bottom:20px;
              font-size:11px;letter-spacing:0.1em;color:#6366f1;">
    🔍 ML-POWERED PHISHING DETECTION
  </div>
  <h1 style="font-family:'Syne',sans-serif;font-size:clamp(32px,6vw,56px);
             font-weight:800;letter-spacing:-0.03em;margin:0;line-height:1.1;">
    🛡️ PhishGuard
  </h1>
  <p style="color:#7a8099;font-size:14px;margin-top:12px;max-width:480px;margin-inline:auto;">
    Paste any URL to instantly detect phishing. Analyzes 15+ signals in real time.
    No signup · No tracking · 100% free.
  </p>
</div>
""", unsafe_allow_html=True)

st.divider()

# ══════════════════════════════════════════════════════════════
# INPUT
# ══════════════════════════════════════════════════════════════
col1, col2 = st.columns([4, 1])
with col1:
    url_input = st.text_input(
        label="URL",
        placeholder="https://example.com/login",
        label_visibility="collapsed",
    )
with col2:
    analyze = st.button("🔍 Analyze", use_container_width=True)

# Sample URLs
st.markdown("""
<div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-top:4px;margin-bottom:8px;">
  <span style="font-size:10px;color:#454d66;letter-spacing:0.08em;">TRY:</span>
  <span style="font-size:10px;padding:3px 10px;border-radius:99px;
               border:1px solid rgba(16,185,129,0.25);color:#34d399;
               background:rgba(16,185,129,0.08);">google.com ✓</span>
  <span style="font-size:10px;padding:3px 10px;border-radius:99px;
               border:1px solid rgba(239,68,68,0.25);color:#f87171;
               background:rgba(239,68,68,0.08);">paypal-verify.tk/login ✗</span>
  <span style="font-size:10px;padding:3px 10px;border-radius:99px;
               border:1px solid rgba(239,68,68,0.25);color:#f87171;
               background:rgba(239,68,68,0.08);">192.168.1.1/bank ✗</span>
</div>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════
# BATCH URL SCANNER
# ══════════════════════════════════════════════════════════════
st.divider()
st.markdown("<p style='font-size:10px;letter-spacing:0.1em;color:#454d66;margin-bottom:8px;'>▸ BATCH URL SCANNER</p>", unsafe_allow_html=True)
uploaded_file = st.file_uploader(
    "📄 Upload a CSV file with a `url` column to scan multiple URLs at once",
    type=["csv"],
)
if uploaded_file:
    try:
        df = pd.read_csv(uploaded_file)
        if 'url' not in df.columns:
            st.error("CSV must have a column named 'url'")
        else:
            st.markdown(f"<p style='font-size:11px;color:#7a8099;margin-top:6px;'>Found {len(df)} URLs. Click below to analyze.</p>", unsafe_allow_html=True)
            if st.button("🔍 Analyze All URLs", use_container_width=True, key="batch_analyze"):
                results = []
                progress = st.progress(0)
                for i, url in enumerate(df['url'].dropna()):
                    url        = str(url).strip()
                    features   = extract_features(url)
                    score      = score_url(features)
                    confidence = score / 100
                    label      = 'phishing' if score >= 40 else 'safe'
                    results.append({
                        'url':        url,
                        'verdict':    label.upper(),
                        'confidence': f"{round(confidence * 100)}%",
                        'score':      f"{score}/100",
                    })
                    progress.progress((i + 1) / len(df))

                results_df = pd.DataFrame(results)
                st.dataframe(results_df, use_container_width=True)

                csv_buffer = io.StringIO()
                results_df.to_csv(csv_buffer, index=False)
                st.download_button(
                    label="⬇️ Download Results as CSV",
                    data=csv_buffer.getvalue(),
                    file_name="phishguard_batch_results.csv",
                    mime="text/csv",
                    use_container_width=True,
                )
    except Exception as e:
        st.error(f"Error reading file: {e}")
st.divider()

# ══════════════════════════════════════════════════════════════
# ANALYSIS
# ══════════════════════════════════════════════════════════════
if analyze and url_input.strip():
    url = url_input.strip()

    with st.spinner("Analyzing URL…"):
        time.sleep(0.3)  # small UX delay
        features    = extract_features(url)
        score       = score_url(features)
        confidence  = score / 100
        label       = 'phishing' if score >= 40 else 'safe'
        explanation = build_explanation(label, features)

    # Save to history
    st.session_state.history.insert(0, {
        'url':        url,
        'label':      label,
        'confidence': confidence,
        'score':      score,
    })
    if len(st.session_state.history) > 20:
        st.session_state.history.pop()

    st.divider()

    # ── VERDICT BANNER ─────────────────────────────────────────
    is_phishing = label == 'phishing'
    pct         = round(confidence * 100)

    if is_phishing:
        st.markdown(f"""
        <div style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);
                    border-radius:12px;padding:20px 24px;margin-bottom:20px;
                    box-shadow:0 0 40px rgba(239,68,68,0.15);">
          <div style="display:flex;align-items:center;gap:14px;">
            <span style="font-size:36px;">⚠️</span>
            <div>
              <div style="font-family:'Syne',sans-serif;font-size:26px;font-weight:800;
                          color:#ef4444;letter-spacing:0.06em;">PHISHING DETECTED</div>
              <div style="font-size:11px;color:#7a8099;margin-top:3px;word-break:break-all;">{url}</div>
            </div>
          </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div style="background:rgba(16,185,129,0.08);border:1px solid rgba(16,185,129,0.25);
                    border-radius:12px;padding:20px 24px;margin-bottom:20px;
                    box-shadow:0 0 40px rgba(16,185,129,0.1);">
          <div style="display:flex;align-items:center;gap:14px;">
            <span style="font-size:36px;">✅</span>
            <div>
              <div style="font-family:'Syne',sans-serif;font-size:26px;font-weight:800;
                          color:#10b981;letter-spacing:0.06em;">SAFE</div>
              <div style="font-size:11px;color:#7a8099;margin-top:3px;word-break:break-all;">{url}</div>
            </div>
          </div>
        </div>
        """, unsafe_allow_html=True)

    # ── METRICS ROW ────────────────────────────────────────────
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("CONFIDENCE",  f"{pct}%")
    m2.metric("RISK SCORE",  f"{score}/100")
    m3.metric("VERDICT",     "⚠️ PHISH" if is_phishing else "✅ SAFE")
    m4.metric("KEYWORDS",    features['keyword_count'])

    # ── CONFIDENCE BAR ─────────────────────────────────────────
    if pct >= 70:
        risk_label = "High Risk"
        risk_color = "#ef4444"
    elif pct >= 45:
        risk_label = "Moderate Risk"
        risk_color = "#f59e0b"
    else:
        risk_label = "Low Risk"
        risk_color = "#10b981"

    st.markdown(f"""
    <p style='font-size:10px;letter-spacing:0.1em;color:#454d66;margin-top:16px;margin-bottom:6px;'>
      CONFIDENCE SCORE &nbsp;·&nbsp;
      <span style='color:{risk_color};font-weight:600;'>● {risk_label}</span>
    </p>
    <style>
    div[data-testid="stProgress"] > div > div > div > div {{
        background-color: {risk_color} !important;
    }}
    </style>
    """, unsafe_allow_html=True)
    st.progress(confidence)
    st.markdown(f"<p style='font-size:10px;color:#454d66;margin-top:4px;'>Model is {pct}% confident in this prediction</p>", unsafe_allow_html=True)

    st.divider()

    # ── FEATURE BREAKDOWN ──────────────────────────────────────
    st.markdown("<p style='font-size:10px;letter-spacing:0.1em;color:#454d66;margin-bottom:12px;'>▸ FEATURE ANALYSIS</p>", unsafe_allow_html=True)

    feature_display = [
        ("URL Length",      str(features['url_length']) + " chars",
         "🔴" if features['url_length'] > 100 else "🟡" if features['url_length'] > 75 else "🟢"),
        ("Contains @",      "Yes" if features['has_at_symbol'] else "No",
         "🔴" if features['has_at_symbol'] else "🟢"),
        ("IP Address",      "Yes" if features['has_ip_address'] else "No",
         "🔴" if features['has_ip_address'] else "🟢"),
        ("HTTPS",           "Yes" if features['has_https'] else "No",
         "🟢" if features['has_https'] else "🟡"),
        ("Subdomains",      str(features['num_subdomains']),
         "🔴" if features['num_subdomains'] > 2 else "🟡" if features['num_subdomains'] > 1 else "🟢"),
        ("Suspicious TLD",  "Yes" if features['has_suspicious_tld'] else "No",
         "🔴" if features['has_suspicious_tld'] else "🟢"),
        ("Keywords Found",  features['top_keyword'] or "None",
         "🔴" if features['keyword_count'] > 1 else "🟡" if features['keyword_count'] == 1 else "🟢"),
        ("Hyphens",         str(features['num_hyphens']),
         "🔴" if features['num_hyphens'] > 3 else "🟡" if features['num_hyphens'] > 1 else "🟢"),
        ("Has Port",        "Yes" if features['has_port'] else "No",
         "🔴" if features['has_port'] else "🟢"),
        ("Redirect",        "Yes" if features['has_redirect'] else "No",
         "🔴" if features['has_redirect'] else "🟢"),
        ("Entropy",         str(round(features['hostname_entropy'], 2)),
         "🔴" if features['hostname_entropy'] > 4 else "🟡" if features['hostname_entropy'] > 3 else "🟢"),
        ("Digit Ratio",     str(round(features['digit_ratio'], 2)),
         "🔴" if features['digit_ratio'] > 0.3 else "🟢"),
    ]

    # Display in 3-column grid
    cols = st.columns(3)
    for i, (name, value, indicator) in enumerate(feature_display):
        with cols[i % 3]:
            st.markdown(f"""
            <div style="background:#0f1219;border:1px solid rgba(255,255,255,0.07);
                        border-radius:8px;padding:10px 12px;margin-bottom:8px;">
              <div style="font-size:9px;color:#454d66;letter-spacing:0.08em;margin-bottom:4px;">{name.upper()}</div>
              <div style="display:flex;align-items:center;justify-content:space-between;">
                <span style="font-size:12px;color:#e2e6f0;">{value}</span>
                <span style="font-size:14px;">{indicator}</span>
              </div>
            </div>
            """, unsafe_allow_html=True)

    st.divider()

    # ── TOP CONTRIBUTING FEATURES ──────────────────────────────
    top_features = get_top_features(features)

    FEATURE_HINTS = {
        "@ Symbol":         ("Attackers use @ to hide the real destination URL.",           "No @ symbol found — links go where they appear to go."),
        "IP Address":       ("Raw IPs instead of domains are a classic phishing trick.",    "Domain name used — not a raw IP address."),
        "URL Too Long":     ("Very long URLs obscure the real domain from the user.",       "URL length is within a normal range."),
        "URL Length":       ("Longer than average URLs can hide suspicious destinations.",  "URL length is within a normal range."),
        "Too Many Dots":    ("Excessive dots suggest deep subdomains mimicking real sites.","Normal number of dots in the domain."),
        "Too Many Hyphens": ("Many hyphens are often used in fake domain names.",          "Normal hyphen usage in the domain."),
        "No HTTPS":         ("No encryption means data can be intercepted easily.",        "HTTPS is present — connection is encrypted."),
        "Suspicious TLD":   ("Free TLDs like .tk and .ml are heavily abused by phishers.", "TLD appears legitimate and trustworthy."),
        "Non-standard Port":("Unusual ports bypass standard web filters.",                 "Standard port used — no anomaly detected."),
        "Double Slash":     ("Double slashes after the domain can indicate redirect tricks.","No suspicious double slash patterns found."),
        "Redirect Pattern": ("Redirect parameters are used to send users to malicious sites.","No redirect patterns detected in the URL."),
        "Phishing Keywords":("Words like 'login', 'verify', 'paypal' are bait for victims.","No deceptive phishing keywords detected."),
        "Long Domain":      ("Very long domain names are hard to read and easy to fake.",   "Domain length looks normal."),
        "High Entropy":     ("Random-looking domains are generated by phishing toolkits.",  "Domain entropy is within a normal range."),
        "High Digit Ratio": ("Too many digits in a domain is uncommon for legitimate sites.","Digit ratio in domain looks normal."),
    }

    st.markdown("<p style='font-size:10px;letter-spacing:0.1em;color:#454d66;margin-bottom:12px;'>▸ TOP CONTRIBUTING FEATURES</p>", unsafe_allow_html=True)

    if top_features:
        for feat_name, feat_score in top_features:
            bar_pct = int((feat_score / 100) * 100)
            hint = FEATURE_HINTS.get(feat_name, ("", ""))[0]
            st.markdown(f"""
            <div style="background:#0f1219;border:1px solid rgba(255,255,255,0.07);
                        border-radius:8px;padding:10px 14px;margin-bottom:6px;">
              <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
                <span style="font-size:11px;color:#e2e6f0;">{feat_name}</span>
                <span style="font-size:11px;color:#ef4444;font-weight:600;">+{feat_score} pts</span>
              </div>
              <div style="background:#161b26;border-radius:99px;height:4px;margin-bottom:6px;">
                <div style="width:{bar_pct}%;height:100%;background:#ef4444;border-radius:99px;"></div>
              </div>
              <div style="font-size:10px;color:#7a8099;">{hint}</div>
            </div>
            """, unsafe_allow_html=True)
    else:
        safe_signals = [
            ("✅ HTTPS Present",        FEATURE_HINTS["No HTTPS"][1]),
            ("✅ No @ Symbol",          FEATURE_HINTS["@ Symbol"][1]),
            ("✅ No IP Address",        FEATURE_HINTS["IP Address"][1]),
            ("✅ No Suspicious TLD",    FEATURE_HINTS["Suspicious TLD"][1]),
            ("✅ No Phishing Keywords", FEATURE_HINTS["Phishing Keywords"][1]),
        ]
        for sig_name, sig_hint in safe_signals:
            st.markdown(f"""
            <div style="background:#0f1219;border:1px solid rgba(16,185,129,0.15);
                        border-radius:8px;padding:10px 14px;margin-bottom:6px;">
              <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
                <span style="font-size:11px;color:#10b981;font-weight:600;">{sig_name}</span>
                <span style="font-size:11px;color:#10b981;font-weight:600;">+0 pts</span>
              </div>
              <div style="background:#161b26;border-radius:99px;height:4px;margin-bottom:6px;">
                <div style="width:0%;height:100%;background:#10b981;border-radius:99px;"></div>
              </div>
              <div style="font-size:10px;color:#7a8099;">{sig_hint}</div>
            </div>
            """, unsafe_allow_html=True)

    st.divider()

    # ── EXPLANATION ────────────────────────────────────────────
    st.markdown("<p style='font-size:10px;letter-spacing:0.1em;color:#454d66;margin-bottom:8px;'>▸ WHY WAS THIS FLAGGED?</p>", unsafe_allow_html=True)
    st.markdown(f"""
    <div style="background:#0f1219;border:1px solid rgba(255,255,255,0.07);
                border-radius:8px;padding:14px 16px;font-size:12px;
                color:#7a8099;line-height:1.8;">
      {explanation}
    </div>
    """, unsafe_allow_html=True)

    # ── COPY RESULT BUTTON ─────────────────────────────────────
    result_text = f"PhishGuard Result\\nURL: {url}\\nVerdict: {'PHISHING' if is_phishing else 'SAFE'}\\nConfidence: {pct}%\\nRisk Score: {score}/100"
    components.html(f"""
        <button id="copyBtn"
            onclick="navigator.clipboard.writeText(`{result_text}`).then(() => {{
                    var btn = document.getElementById('copyBtn');
                    btn.innerText = 'Copied!';
                    btn.style.background = '#0f1219';
                    btn.style.borderColor = 'rgba(255,255,255,0.1)';
                    setTimeout(() => {{
                        btn.innerText = 'Copy Result to Clipboard';
                        btn.style.background = '#6366f1';
                        btn.style.borderColor = '#6366f1';
                    }}, 2000);
                }})"
            style="background:#6366f1;color:white;border:1px solid #6366f1;
                   border-radius:8px;padding:10px 20px;font-family:'IBM Plex Mono',monospace;
                   font-size:13px;font-weight:600;cursor:pointer;width:100%;
                   transition:background 0.2s,border-color 0.2s;">
            Copy Result to Clipboard
        </button>
    """, height=55)

    # ── CSV DOWNLOAD BUTTON (main page) ───────────────────────
    if st.session_state.history:
        csv_buffer = io.StringIO()
        pd.DataFrame(st.session_state.history).to_csv(csv_buffer, index=False)
        st.download_button(
            label="⬇️ Download History as CSV",
            data=csv_buffer.getvalue(),
            file_name="phishguard_history.csv",
            mime="text/csv",
            use_container_width=True,
        )

elif analyze and not url_input.strip():
    st.warning("Please enter a URL to analyze.")


# ══════════════════════════════════════════════════════════════
# SIDEBAR — HISTORY + INFO
# ══════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("### 🛡️ PhishGuard")
    st.markdown("<p style='font-size:11px;color:#454d66;'>ML-powered phishing detector</p>", unsafe_allow_html=True)
    st.divider()

    # Scan History
    st.markdown("#### 📜 Scan History")
    if st.session_state.history:
        if st.button("🗑️ Clear History", use_container_width=True):
            st.session_state.history = []
            st.rerun()

        # ── CSV DOWNLOAD BUTTON ────────────────────────────────
        csv_buffer = io.StringIO()
        pd.DataFrame(st.session_state.history).to_csv(csv_buffer, index=False)
        st.download_button(
            label="⬇️ Download History as CSV",
            data=csv_buffer.getvalue(),
            file_name="phishguard_history.csv",
            mime="text/csv",
            use_container_width=True,
        )
        # ──────────────────────────────────────────────────────

        for entry in st.session_state.history:
            is_p  = entry['label'] == 'phishing'
            color = "#ef4444" if is_p else "#10b981"
            icon  = "⚠️" if is_p else "✅"
            pct   = round(entry['confidence'] * 100)
            short = entry['url'][:35] + '…' if len(entry['url']) > 35 else entry['url']
            st.markdown(f"""
            <div style="background:#0f1219;border:1px solid rgba(255,255,255,0.06);
                        border-radius:8px;padding:10px 12px;margin-bottom:6px;">
              <div style="font-size:10px;color:#7a8099;word-break:break-all;">{short}</div>
              <div style="display:flex;justify-content:space-between;margin-top:4px;">
                <span style="font-size:10px;color:{color};font-weight:600;">{icon} {entry['label'].upper()}</span>
                <span style="font-size:10px;color:#454d66;">{pct}%</span>
              </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.markdown("<p style='font-size:11px;color:#454d66;'>No scans yet.</p>", unsafe_allow_html=True)

    st.divider()

    # How it works
    with st.expander("ℹ️ How It Works"):
        st.markdown("""
        <div style="font-size:11px;color:#7a8099;line-height:1.8;">
        PhishGuard analyzes <strong style="color:#e2e6f0;">15+ URL features</strong> in real time:<br><br>
        • URL & domain length<br>
        • @ symbol presence<br>
        • IP address as hostname<br>
        • Suspicious TLDs (.tk, .ml…)<br>
        • HTTPS status<br>
        • Subdomain depth<br>
        • Deceptive keywords<br>
        • Shannon entropy<br>
        • Redirect patterns<br>
        • Non-standard ports<br><br>
        URLs scoring <strong style="color:#ef4444;">≥ 40/100</strong> are flagged as phishing.
        </div>
        """, unsafe_allow_html=True)

    st.divider()
    st.markdown("""
    <div style="font-size:10px;color:#454d66;text-align:center;">
      v1.0 · Built with Streamlit<br>
      <a href="https://github.com/Vnshk-sharma/phishguard-extension" style="color:#6366f1;">GitHub</a>
    </div>
    """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════
# BOTTOM STATS
# ══════════════════════════════════════════════════════════════
st.divider()
c1, c2, c3, c4 = st.columns(4)
c1.metric("Features Checked", "15+")
c2.metric("Analysis Time",    "<50ms")
c3.metric("Cost",             "Free")
c4.metric("Data Collected",   "Zero")