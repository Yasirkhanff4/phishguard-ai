"""
PhishGuard AI — Model Training Script
========================================
Trains Random Forest, Logistic Regression, and Decision Tree
on phishing_urls.csv, then saves the best model as model.pkl.

Run:  python train_model.py
"""

import os
import sys
import pickle
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler

# Add backend dir to path for feature_extractor import
sys.path.insert(0, os.path.dirname(__file__))
from feature_extractor import extract_features

# ─────────────────────────────────────────
DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "dataset", "phishing_urls.csv")
MODEL_PATH   = os.path.join(os.path.dirname(__file__), "model.pkl")
# ─────────────────────────────────────────


def load_and_prepare(csv_path: str) -> tuple:
    """
    Load dataset CSV.
    Expected columns: url, label   (label = 'phishing' | 'legitimate')
    Returns X (feature matrix) and y (0=safe, 1=phishing)
    """
    print(f"[+] Loading dataset: {csv_path}")
    df = pd.read_csv(csv_path)
    print(f"    Shape: {df.shape}")
    print(f"    Columns: {list(df.columns)}")

    # Normalise column names
    df.columns = [c.strip().lower() for c in df.columns]

    url_col   = next((c for c in df.columns if "url" in c), None)
    label_col = next((c for c in df.columns if "label" in c or "type" in c or "status" in c), None)

    if not url_col or not label_col:
        raise ValueError(f"Cannot find url/label columns. Found: {list(df.columns)}")

    df = df[[url_col, label_col]].dropna()
    df.columns = ["url", "label"]

    # Map labels → 0/1
    df["label"] = df["label"].astype(str).str.lower()
    phishing_values = {"phishing", "1", "bad", "malicious", "spam"}
    df["y"] = df["label"].apply(lambda x: 1 if x in phishing_values else 0)

    print(f"    Phishing: {df['y'].sum()}  |  Legitimate: {(df['y']==0).sum()}")

    # Extract features for each URL
    print("[+] Extracting features (this may take a minute)…")
    records = []
    for i, row in df.iterrows():
        try:
            f = extract_features(str(row["url"]))
            records.append({
                "url_length":               f["url_length"],
                "dot_count":                f["dot_count"],
                "has_https":                int(f["has_https"]),
                "subdomain_count":          f["subdomain_count"],
                "has_ip":                   int(f["has_ip"]),
                "has_at_sign":              int(f["has_at_sign"]),
                "has_double_slash":         int(f["has_double_slash"]),
                "hyphen_count":             f["hyphen_count"],
                "suspicious_keyword_count": f["suspicious_keyword_count"],
                "y":                        row["y"],
            })
        except Exception:
            pass

    feat_df = pd.DataFrame(records)
    feature_cols = [c for c in feat_df.columns if c != "y"]
    X = feat_df[feature_cols].values
    y = feat_df["y"].values
    return X, y, feature_cols


def train_all(X, y):
    """Train multiple models, print comparison, return best."""
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    models = {
        "Random Forest":       RandomForestClassifier(n_estimators=200, max_depth=20, random_state=42, n_jobs=-1),
        "Decision Tree":       DecisionTreeClassifier(max_depth=15, random_state=42),
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
    }

    results = {}
    for name, clf in models.items():
        print(f"\n[+] Training {name}…")
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        cv  = cross_val_score(clf, X, y, cv=5, scoring="accuracy").mean()
        results[name] = {"clf": clf, "acc": acc, "cv": cv}
        print(f"    Accuracy:  {acc:.4f}")
        print(f"    CV (5-fold): {cv:.4f}")
        print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    # Pick best by CV score
    best_name = max(results, key=lambda k: results[k]["cv"])
    best_clf  = results[best_name]["clf"]
    print(f"\n✅ Best model: {best_name} (CV={results[best_name]['cv']:.4f})")
    return best_clf


def save_model(clf):
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(clf, f)
    print(f"[+] Model saved → {MODEL_PATH}")


# ─────────────────────────────────────────
if __name__ == "__main__":
    if not os.path.exists(DATASET_PATH):
        print(f"[!] Dataset not found at {DATASET_PATH}")
        print("    Download from Kaggle: 'Phishing Site URLs' dataset")
        print("    Place as: dataset/phishing_urls.csv")
        sys.exit(1)

    X, y, cols = load_and_prepare(DATASET_PATH)
    best_model = train_all(X, y)
    save_model(best_model)
    print("\n🎉 Training complete! Run app.py to start the server.")
