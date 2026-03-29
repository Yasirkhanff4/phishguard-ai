# 🛡️ PhishGuard AI — Advanced Phishing Detection System

A professional full-stack cybersecurity web application that detects whether a URL is phishing or legitimate using rule-based analysis and machine learning.

---

## 📁 Project Structure

```
phishing-detector/
│
├── backend/
│   ├── app.py                  ← Flask REST API server
│   ├── feature_extractor.py    ← 20+ feature extraction engine
│   ├── train_model.py          ← ML training (RF, LR, DT)
│   └── database.db             ← SQLite scan log (auto-created)
│
├── frontend/
│   ├── index.html              ← Main app (Scanner + Dashboard + Logs)
│   ├── style.css               ← Cybersecurity dark theme
│   └── script.js               ← Frontend logic + API calls
│
├── dataset/
│   └── phishing_urls.csv       ← Sample dataset (add real Kaggle data here)
│
├── requirements.txt
└── README.md
```

---

## 🚀 Setup & Run

### 1. Install Python dependencies

```bash
cd phishing-detector
pip install -r requirements.txt
```

### 2. (Optional) Train the ML model

Download a real phishing dataset from Kaggle:
- Search: **"Phishing Site URLs"** or **"Web page Phishing Detection"**
- Place the CSV at: `dataset/phishing_urls.csv`
- Columns needed: `url`, `label` (phishing / legitimate)

```bash
cd backend
python train_model.py
```

This trains Random Forest, Decision Tree, and Logistic Regression — saves the best as `model.pkl`.

> ⚠️ If you skip this step, the app uses the built-in rule-based engine (still accurate).

### 3. Start the backend server

```bash
cd backend
python app.py
```

Server runs at: **http://localhost:5000**

### 4. Open the frontend

Open `frontend/index.html` in your browser — or serve with any static server:

```bash
cd frontend
python -m http.server 8080
# Then visit http://localhost:8080
```

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Health check |
| POST | `/api/scan` | Analyze a URL |
| GET | `/api/scans` | Fetch scan history |
| GET | `/api/stats` | Dashboard statistics |
| DELETE | `/api/scans/clear` | Clear all records |

### POST `/api/scan` — Example

**Request:**
```json
{ "url": "http://secure-login-paypal.verification.com/signin" }
```

**Response:**
```json
{
  "url": "http://secure-login-paypal.verification.com/signin",
  "verdict": "phishing",
  "confidence": 94,
  "risk_score": 87,
  "model_used": "rule_based",
  "features": {
    "url_length": 54,
    "has_https": false,
    "has_ip": false,
    "has_at_sign": false,
    "hyphen_count": 3,
    "subdomain_count": 2,
    "found_keywords": ["login", "secure", "verify"],
    "risk_score": 87
  }
}
```

---

## 🤖 Features Extracted (20+)

| Feature | Description |
|---------|-------------|
| `url_length` | Total URL character count |
| `dot_count` | Number of dots |
| `has_https` | Secure protocol check |
| `has_ip` | IP address instead of domain |
| `has_at_sign` | @ in URL (phishing trick) |
| `has_double_slash` | Redirect indicator |
| `hyphen_count` | Hyphens in domain |
| `subdomain_count` | Depth of subdomains |
| `suspicious_keyword_count` | Count of phishing keywords |
| `found_keywords` | Detected keywords list |
| `domain_length` | Length of domain name |
| `digits_in_domain` | Numeric chars in domain |
| `entropy_ratio` | Ratio of special/non-alpha chars |
| `is_shortened` | URL shortener service detected |
| `special_in_path` | Special chars in URL path |
| `risk_score` | Weighted total (0–100) |

---

## 🧪 Test URLs

**Phishing (should be flagged 🚨):**
```
http://secure-login-paypal.verification-update.com/signin
http://192.168.1.1/bank-login/update-account?verify=true
http://amazon-security-alert.com//verify//account@phish
```

**Legitimate (should be safe ✅):**
```
https://www.google.com
https://github.com/openai/gpt-4
https://www.microsoft.com
```

---

## 📊 ML Models

Three classifiers are trained and compared:

| Model | Typical Accuracy |
|-------|-----------------|
| Random Forest | ~96–98% |
| Decision Tree | ~93–95% |
| Logistic Regression | ~90–93% |

Best model by cross-validation is auto-selected and saved as `model.pkl`.

---

## 🎓 Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, Flask, Flask-CORS |
| ML | scikit-learn, pandas, numpy |
| Database | SQLite (via Python `sqlite3`) |
| Frontend | HTML5, CSS3, JavaScript (ES6+) |
| Charts | Chart.js |
| Fonts | Google Fonts (Orbitron, Share Tech Mono) |

---

## 🔐 Advanced Upgrades (Optional)

- **WHOIS API** — Domain age check (newly registered = suspicious)
- **Google Safe Browsing API** — Real blacklist lookup
- **IP Geolocation** — Track origin country of domain
- **Deep Learning** — LSTM or BERT on URL character sequences
- **Email Alerts** — SMTP alert on phishing detection
- **Browser Extension** — Real-time protection while browsing

---

## 💡 Portfolio Highlights

This project demonstrates:
- ✅ Full-stack development (Python + JS)
- ✅ Machine learning integration (scikit-learn pipeline)
- ✅ REST API design (Flask)
- ✅ Database management (SQLite)
- ✅ Cybersecurity fundamentals (phishing indicators)
- ✅ SOC-style dashboard (threat intelligence UI)
- ✅ Production-grade code structure

---

*Built for portfolio, internship interviews, and SOC Analyst job applications.*
