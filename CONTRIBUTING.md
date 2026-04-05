# 🛡️ PhishGuard — Web App (Contributor & Project Guide)

---

## 1. Project Overview

### Description

PhishGuard Web App is a **real-time phishing URL detection system** built using Streamlit and machine learning. It allows users to analyze any URL and determine whether it is safe or malicious.

The system extracts **15+ URL features** and provides:
- Prediction (safe / phishing)
- Confidence score
- Feature breakdown
- Plain-English explanation

🚀 **Live Demo:**  
https://phishguard-extension-pb9ahd84x4tbbu8djkrxqj.streamlit.app/

---

### Tech Stack

| Layer            | Technology                          |
|------------------|----------------------------------|
| Web App          | Python, Streamlit                |
| Backend API      | Python, FastAPI, Uvicorn         |
| ML Model         | scikit-learn (Random Forest, GBM)|
| Feature Engineering | NumPy, Pandas, urllib         |
| Deployment       | Streamlit Cloud                  |
| Other Tools      | pickle, pytest                   |

---

### Current Features

PhishGuard Web App currently supports:

✅ Paste-and-check URL analyzer  
✅ 15+ feature extraction (URL length, @ symbol, IP, entropy, etc.)  
✅ Confidence score  
✅ Feature breakdown with risk indicators  
✅ Plain-English explanation  
✅ Scan history with timestamps  
✅ Fast API-based prediction  
✅ Clean and responsive UI  

---

### Target Users

PhishGuard is built for:

- Everyday users checking suspicious links  
- Students learning ML security applications  
- Developers exploring phishing detection  
- Security enthusiasts  

---

## 2. Architecture / Key Modules

### Module Overview

| Module                | Location                          | Purpose |
|----------------------|----------------------------------|--------|
| Streamlit Web App    | phishguard-web/streamlit_app.py  | UI + user interaction |
| FastAPI Backend      | backend/main.py                  | API for predictions |
| Feature Engineering  | backend/feature_engineering.py   | Extract URL features |
| ML Model             | backend/model.pkl                | Prediction model |
| Training Script      | backend/train_model.py           | Model training |

---

### Project Structure

```
phishguard/
├── backend/
│   ├── main.py
│   ├── feature_engineering.py
│   ├── train_model.py
│   ├── model.pkl
│   └── requirements.txt
│
├── phishguard-web/
│   ├── streamlit_app.py
│   └── requirements.txt
│
└── README.md
```

---

### Architecture Flow

User enters URL  
        │  
        ▼  
Streamlit App (UI)  
        │  
        ▼  
POST request → FastAPI `/predict`  
        │  
        ├── Feature extraction  
        ├── ML prediction  
        └── Confidence + explanation  
        │  
        ▼  
Result displayed in UI  

---

## 3. High-Impact Feature Roadmap

---

### 🚀 Feature 1: Real-Time Threat Intelligence Integration

- Integrate Google Safe Browsing / PhishTank APIs  
- Combine ML + API-based detection  
- Return hybrid risk score  

---

### 🧠 Feature 2: Explainable AI (XAI) Dashboard

- Show *why* a URL is phishing  
- Highlight top contributing features  
- Improve transparency  

---

### 📊 Feature 3: User Risk Analytics Dashboard

- Total scans  
- Safe vs phishing ratio  
- Trends over time  
- Risky domains  

---

### 🌍 Feature 4: Batch URL Scanner

- Upload CSV of URLs  
- Analyze all at once  
- Download results  

---

### 🔐 Feature 5: Domain Reputation System

- Maintain domain risk scores  
- Track frequently flagged domains  

---

### ⚡ Feature 6: Real Dataset Training

- Use PhishTank + Tranco datasets  
- Improve accuracy  

---

### 🤖 Feature 7: Public REST API

- Expose `/predict` endpoint  
- Allow external integration  

---

## 4. Feature Implementation Pipeline

### WHOIS Domain Age Feature

1. Add WHOIS library  
2. Extract domain age  
3. Add to feature vector  
4. Retrain model  
5. Display in UI  

---

### Dashboard Pipeline

1. Store scan history  
2. Compute analytics  
3. Build charts  
4. Display in Streamlit  

---

## 5. Resume-Level Issues

---

### 🟢 Beginner

---

#### Issue 1: Add Confidence Progress Bar

- Use `st.progress()`  
- Color-based risk display  

---

#### Issue 2: Add URL Validation

- Validate input URL  
- Show error messages  

---

#### Issue 3: Copy Result Button

- Copy result to clipboard  
- Improve UX  

---

### 🟡 Intermediate

---

#### Issue 4: Export History as CSV

- Convert history to CSV  
- Add download button  

---

#### Issue 5: Feature Importance Display

- Show top contributing features  
- Improve explainability  

---

#### Issue 6: Batch URL Scanner

- Upload CSV  
- Process multiple URLs  

---

### 🔴 Advanced

---

#### Issue 7: PhishTank API Integration

- Fetch real phishing data  
- Combine with ML output  

---

#### Issue 8: Deploy Backend

- Deploy FastAPI  
- Connect to Streamlit  

---

#### Issue 9: Authentication System

- User login/signup  
- Personalized history  

---

#### Issue 10: Model Improvement Pipeline

- Add real datasets  
- Retrain and evaluate  

---

## 6. Contributor Notes

---

### Getting Started

#### Prerequisites

- Python 3.10+  
- Git  

---

### Setup Steps

#### 1. Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/phishguard.git
cd phishguard
```

---

#### 2. Setup Backend

```bash
cd backend
python -m venv venv

venv\Scripts\activate

pip install -r requirements.txt
python train_model.py

uvicorn main:app --reload --port 8000
```

---

#### 3. Run Web App

```bash
cd phishguard-web
pip install streamlit

streamlit run streamlit_app.py
```

---

### Development Workflow

```bash
git checkout -b feat/your-feature

git add .
git commit -m "feat: your feature"
git push origin feat/your-feature
```

---

### Common Issues

| Issue | Solution |
|------|---------|
| model.pkl missing | Run train_model.py |
| Backend not running | Start FastAPI |
| App not loading | Check Streamlit path |
| CORS error | Ensure backend is running |

---

## 📜 License

MIT License

---

## 🙌 Final Note

PhishGuard is built for **security awareness, machine learning, and real-world application development**.
