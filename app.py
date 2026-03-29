"""
PhishGuard AI - Flask Backend
==============================
Run: python app.py
API Base: http://localhost:5000
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import os
import pickle
import json
from datetime import datetime
from feature_extractor import extract_features

app = Flask(__name__)
CORS(app)

DB_PATH = os.path.join(os.path.dirname(__file__), "database.db")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")

# ─────────────────────────────────────────
# DATABASE SETUP
# ─────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            verdict TEXT NOT NULL,
            confidence REAL NOT NULL,
            features TEXT NOT NULL,
            ai_analysis TEXT,
            timestamp TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def save_scan(url, verdict, confidence, features, ai_analysis=""):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scans (url, verdict, confidence, features, ai_analysis, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        url,
        verdict,
        confidence,
        json.dumps(features),
        ai_analysis,
        datetime.now().isoformat()
    ))
    conn.commit()
    conn.close()

def get_all_scans(limit=100):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_stats():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM scans")
    total = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM scans WHERE verdict='phishing'")
    phishing = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM scans WHERE verdict='safe'")
    safe = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM scans WHERE verdict='suspicious'")
    suspicious = cursor.fetchone()[0]
    conn.close()
    return {"total": total, "phishing": phishing, "safe": safe, "suspicious": suspicious}

# ─────────────────────────────────────────
# LOAD ML MODEL
# ─────────────────────────────────────────
model = None
if os.path.exists(MODEL_PATH):
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)

# ─────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────

@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "PhishGuard AI backend running", "model_loaded": model is not None})


@app.route("/api/scan", methods=["POST"])
def scan_url():
    """
    POST /api/scan
    Body: { "url": "http://example.com" }
    Returns: verdict, confidence, features, risk_score
    """
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' field"}), 400

    url = data["url"].strip()
    if not url:
        return jsonify({"error": "URL cannot be empty"}), 400

    # Extract features
    features = extract_features(url)

    # ML Prediction (if model loaded)
    if model:
        feature_vector = [
            features["url_length"],
            features["dot_count"],
            1 if features["has_https"] else 0,
            features["subdomain_count"],
            1 if features["has_ip"] else 0,
            1 if features["has_at_sign"] else 0,
            1 if features["has_double_slash"] else 0,
            features["hyphen_count"],
            features["suspicious_keyword_count"],
        ]
        prob = model.predict_proba([feature_vector])[0]
        phishing_prob = prob[1]
        confidence = round(phishing_prob * 100, 1)
        if phishing_prob >= 0.65:
            verdict = "phishing"
        elif phishing_prob >= 0.4:
            verdict = "suspicious"
        else:
            verdict = "safe"
            confidence = round((1 - phishing_prob) * 100, 1)
    else:
        # Rule-based fallback
        score = features["risk_score"]
        if score >= 60:
            verdict = "phishing"
            confidence = min(score, 99)
        elif score >= 35:
            verdict = "suspicious"
            confidence = 50 + (score // 4)
        else:
            verdict = "safe"
            confidence = max(95 - score, 60)

    # Save to DB
    save_scan(url, verdict, confidence, features)

    return jsonify({
        "url": url,
        "verdict": verdict,
        "confidence": confidence,
        "features": features,
        "risk_score": features["risk_score"],
        "model_used": "ml_model" if model else "rule_based"
    })


@app.route("/api/scans", methods=["GET"])
def get_scans():
    """GET /api/scans — return recent scan history"""
    limit = request.args.get("limit", 100, type=int)
    scans = get_all_scans(limit)
    for s in scans:
        s["features"] = json.loads(s["features"])
    return jsonify(scans)


@app.route("/api/stats", methods=["GET"])
def stats():
    """GET /api/stats — dashboard statistics"""
    return jsonify(get_stats())


@app.route("/api/scans/clear", methods=["DELETE"])
def clear_scans():
    """DELETE /api/scans/clear — wipe all scan history"""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM scans")
    conn.commit()
    conn.close()
    return jsonify({"message": "All scan records deleted"})


# ─────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("=" * 50)
    print("  PhishGuard AI — Backend Server")
    print("  http://localhost:5000")
    print("=" * 50)
    app.run(debug=True, port=5000)
