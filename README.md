# 🛡️ PhishGuard Web App

PhishGuard Web App is a **machine learning-powered phishing detection tool** that allows users to check whether a URL is safe or potentially malicious — directly from a simple web interface.

Unlike the browser extension, this version works as a **standalone web application**, making it easy to test and use across any device.

---

## 🌐 Live Demo

🔗 Try the app here:  
https://phishguard-extension-pb9ahd84x4tbbu8djkrxqj.streamlit.app/

---


## 🚀 Features

- 🔍 Detect phishing URLs instantly  
- 🤖 Machine Learning-based prediction  
- 🌐 Simple and clean web interface (Streamlit)  
- ⚡ Fast and lightweight  
- 📊 Real-time results  

---

## 🧠 How It Works

1. User enters a URL  
2. The model extracts relevant features  
3. ML model analyzes the URL  
4. Returns:
   - ✅ Safe  
   - ⚠️ Suspicious / Phishing  

---

## 🛠️ Tech Stack

- **Frontend:** Streamlit  
- **Backend:** Python  
- **ML Model:** Scikit-learn  
- **Libraries:** Pandas, NumPy  

---

## 📂 Project Structure

```bash
phishguard-web/
│── index.html
│── streamlit_app.py
│── requirements.txt
```

---

## ⚙️ Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/your-username/phishguard.git
cd phishguard/phishguard-web
```

### 2. Create virtual environment (optional but recommended)

```bash
python -m venv venv
venv\Scripts\activate   # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the app

```bash
streamlit run streamlit_app.py
```

---

## 🌐 Usage

- Open the app in your browser  
- Enter any URL  
- Click **Check**  
- View prediction result instantly  

---

## 📌 Example

**Input:**
```
http://fake-login-page.xyz
```

**Output:**
```
⚠️ This website is likely a phishing site
```

---

## 🎯 Future Improvements

- 🔐 Add real-time API integration  
- 📱 Improve UI/UX  
- 📊 Show confidence score  
- 🌍 Deploy on cloud (Streamlit Cloud / Vercel backend)

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repo  
2. Create a new branch  
3. Make changes  
4. Submit a Pull Request  

---

## 📜 License

This project is open-source and available under the MIT License.
