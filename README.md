# 🛡️ PhishGuard — ML-Powered Phishing URL Detector

> A production-grade Chrome Extension that detects phishing URLs in real-time using machine learning. Built for engineers who care about security and code quality.

![PhishGuard Demo](screenshots/demo.png)

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🧠 **ML Detection** | Random Forest / Gradient Boosting model with 23 URL features |
| ⚡ **Real-time** | Analyzes every URL automatically as you browse |
| 📊 **Confidence Score** | Visual progress bar showing model certainty |
| 🔍 **Feature Breakdown** | 10 chip cards showing WHY a URL was flagged |
| ⚠️ **Warning Banner** | Injected page banner for phishing sites |
| 🟢🔴 **Badge Color** | Extension icon turns green (safe) or red (phishing) |
| 📜 **Scan History** | Persistent log of all scanned URLs with timestamps |
| 🔌 **Offline Mode** | Falls back to JS heuristics when API is unavailable |
| ⏸️ **Enable/Disable Toggle** | Pause detection without uninstalling |
| 💾 **5-min Cache** | Avoids redundant API calls for the same URL |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Chrome Extension (MV3)                      │
│                                                                 │
│  ┌─────────────┐    ┌──────────────┐    ┌──────────────────┐   │
│  │  popup.html  │    │ background.js │    │   content.js     │   │
│  │  popup.js    │◄──►│ (SW)          │───►│ (page context)   │   │
│  │  styles.css  │    │ tab listener  │    │ warning banner   │   │
│  └──────┬──────┘    └──────┬───────┘    └──────────────────┘   │
│         │                  │                                     │
│  chrome.storage.local  ────┘  (history, cache, settings)        │
└─────────┼────────────────────────────────────────────────────────┘
          │ POST /predict  { url }
          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FastAPI Backend (Python)                      │
│                                                                 │
│  main.py  ──►  feature_engineering.py  ──►  model.pkl          │
│                                                                 │
│  • 23 features extracted from URL                               │
│  • Random Forest with sklearn Pipeline                          │
│  • Returns: label, confidence, features[], explanation          │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
User navigates to URL
        │
        ▼
background.js detects tab update
        │
        ├──► Check chrome.storage cache (5-min TTL)
        │         │ HIT → use cached result
        │         │
        │         └── MISS → POST to FastAPI /predict
        │                         │
        │                         ├── feature_engineering.py
        │                         │   extracts 23 URL features
        │                         │
        │                         └── model.pkl predicts
        │                             { label, confidence, features }
        │
        ├──► Update extension badge (🟢 / 🔴)
        ├──► Save to history
        └──► popup.js renders result UI
```

---

## 📁 File Structure

```
phishguard/
├── extension/
│   ├── manifest.json          # MV3 manifest
│   ├── popup.html             # Extension popup UI
│   ├── popup.js               # Popup logic, API calls, rendering
│   ├── styles.css             # Dark terminal aesthetic UI
│   ├── background.js          # Service worker, tab listener, badge
│   ├── content.js             # Page-injected warning banner
│   └── icons/
│       ├── icon16.png
│       ├── icon32.png
│       ├── icon48.png
│       └── icon128.png
│
└── backend/
    ├── main.py                # FastAPI app, CORS, endpoints
    ├── feature_engineering.py # 23 URL feature extractors
    ├── train_model.py         # ML training script
    ├── model.pkl              # Trained model (generated)
    └── requirements.txt       # Python dependencies
```

---

## 🚀 Setup Guide

### Prerequisites

- Python 3.10+
- Chrome / Chromium browser
- Node.js (optional, not required)

---

### 1. Backend Setup

```bash
# Clone the project
git clone https://github.com/yourname/phishguard.git
cd phishguard/backend

# Create virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# (Optional) Train the model
python train_model.py           # Generates model.pkl

# Start the API server
uvicorn main:app --reload --port 8000
```

The API will be running at `http://127.0.0.1:8000`

Visit `http://127.0.0.1:8000/docs` for the interactive Swagger UI.

---

### 2. Extension Setup

1. Open Chrome and go to `chrome://extensions/`
2. Enable **Developer Mode** (toggle, top-right)
3. Click **"Load unpacked"**
4. Select the `extension/` folder
5. Pin **PhishGuard** to your toolbar

---

### 3. Verify It Works

- Navigate to any website — the badge should turn green or red
- Click the extension icon to see the full analysis popup
- Try `http://paypal-verify.tk/login` to see the phishing detection

---

## 📡 API Reference

### `POST /predict`

**Request:**
```json
{
  "url": "http://paypal-verify-update.tk/login"
}
```

**Response:**
```json
{
  "url": "http://paypal-verify-update.tk/login",
  "label": "phishing",
  "confidence": 0.932,
  "score": 85,
  "features": [
    { "name": "URL Length",      "value": "42 chars",  "risk": "low"    },
    { "name": "Contains @",      "value": "No",        "risk": "low"    },
    { "name": "IP as Host",      "value": "No",        "risk": "low"    },
    { "name": "HTTPS",           "value": "No",        "risk": "medium" },
    { "name": "Subdomains",      "value": 0,           "risk": "low"    },
    { "name": "Suspicious TLD",  "value": "Yes",       "risk": "high"   },
    { "name": "Keyword",         "value": "verify",    "risk": "medium" },
    { "name": "Hyphens",         "value": 2,           "risk": "medium" },
    { "name": "Has Port",        "value": "No",        "risk": "low"    },
    { "name": "Redirect",        "value": "No",        "risk": "low"    }
  ],
  "explanation": "Flagged because this URL uses a free/suspicious TLD frequently exploited for phishing; contains deceptive keyword \"verify\"; does not use HTTPS encryption.",
  "source": "model",
  "latency_ms": 4.72
}
```

### `GET /health`
```json
{ "status": "ok", "model": "loaded" }
```

---

## 🧠 ML Model Details

### Features Used (23 total)

| # | Feature | Type | Description |
|---|---------|------|-------------|
| 1 | `url_length` | int | Total characters in URL |
| 2 | `domain_length` | int | Hostname character count |
| 3 | `num_dots` | int | Dots in hostname |
| 4 | `has_at_symbol` | bool | Presence of @ in URL |
| 5 | `has_ip_address` | bool | IP literal as hostname |
| 6 | `has_https` | bool | HTTPS protocol |
| 7 | `num_hyphens` | int | Hyphens in hostname |
| 8 | `path_hyphens` | int | Hyphens in path |
| 9 | `num_slashes` | int | Total forward slashes |
| 10 | `has_double_slash` | bool | `//` after protocol |
| 11 | `has_suspicious_tld` | bool | .tk, .ml, .ga, .cf, etc. |
| 12 | `has_port` | bool | Non-standard port number |
| 13 | `num_subdomains` | int | Depth of subdomains |
| 14 | `query_length` | int | Query string length |
| 15 | `num_query_params` | int | Number of query params |
| 16 | `has_redirect` | bool | URL redirection patterns |
| 17 | `suspicious_keyword_count` | int | Count of phishing keywords |
| 18 | `is_url_shortener` | bool | Known shortener domains |
| 19 | `path_depth` | int | Path segment depth |
| 20 | `digits_in_domain` | int | Digit count in hostname |
| 21 | `hostname_entropy` | float | Shannon entropy (randomness) |
| 22 | `has_encoding` | bool | URL-encoded characters |
| 23 | `digit_ratio` | float | digits / domain_length |

### Model Performance (on sample dataset)

| Metric | Score |
|--------|-------|
| Accuracy | ~96% |
| ROC-AUC | ~0.98 |
| Precision (phishing) | ~95% |
| Recall (phishing) | ~97% |

> For production accuracy, train on PhishTank + Tranco top-1M dataset (~100k URLs).

---

## 🔒 Permissions Explained

| Permission | Why Needed |
|------------|-----------|
| `tabs` | Read current tab URL |
| `activeTab` | Access tab info on click |
| `scripting` | Inject warning banner into page |
| `storage` | Save history, cache, settings |
| `<all_urls>` | Monitor all URLs for phishing |

---

## 🔮 Future Improvements

- [ ] **Real dataset training** — PhishTank + Tranco 1M URLs (~100k samples)
- [ ] **WHOIS features** — domain age, registrar, creation date
- [ ] **Screenshot analysis** — Vision model for visual cloning detection
- [ ] **Block page** — Redirect to warning page instead of banner
- [ ] **Allowlist/blocklist** — User-managed trusted/blocked domains
- [ ] **Browser sync** — Sync settings across devices via `chrome.storage.sync`
- [ ] **Dashboard page** — Full-page analytics with charts
- [ ] **Export history** — Download scan history as CSV/JSON
- [ ] **PWA companion** — Mobile companion app

---

## 📸 Screenshots

| Main UI — Safe | Main UI — Phishing | History Panel |
|---|---|---|
| ![Safe](screenshots/safe.png) | ![Phishing](screenshots/phishing.png) | ![History](screenshots/history.png) |

---

## 🛠️ Tech Stack

**Extension:** HTML5, CSS3 (custom properties), Vanilla JS, Chrome MV3 APIs

**Backend:** Python 3.10, FastAPI, scikit-learn, NumPy, Pandas, Uvicorn

**ML:** Random Forest Classifier + Gradient Boosting, sklearn Pipeline

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

## 👤 Author

Built as a portfolio project demonstrating:
- Chrome Extension development (Manifest V3)
- Machine learning integration in production
- REST API design with FastAPI  
- Feature engineering for security applications
- Professional UI/UX design

> ⭐ Star this repo if it helped you!
