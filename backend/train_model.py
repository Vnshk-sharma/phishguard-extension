"""
PhishGuard — train_model.py
Trains a Random Forest classifier on phishing URL data.

Usage:
    python train_model.py

Datasets (download first):
    - PhishTank: https://www.phishtank.com/developer_info.php
    - ISCX-URL-2016: Available on Kaggle
    - Simulated data is generated here for demo purposes.

Output: model.pkl
"""

import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, accuracy_score
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from feature_engineering import extract_features
import warnings
warnings.filterwarnings("ignore")


# ──────────────────────────────────────────────────────────────────────────
# SAMPLE DATASET (replace with real PhishTank data in production)
# Format: (url, label)  — label 1 = phishing, 0 = safe
# ──────────────────────────────────────────────────────────────────────────
SAMPLE_DATA = [
    # SAFE URLs
    ("https://www.google.com", 0),
    ("https://github.com/login", 0),
    ("https://stackoverflow.com/questions", 0),
    ("https://www.amazon.com/dp/B08X6HNLP7", 0),
    ("https://en.wikipedia.org/wiki/Phishing", 0),
    ("https://www.microsoft.com/en-us/security", 0),
    ("https://news.ycombinator.com", 0),
    ("https://www.reddit.com/r/netsec", 0),
    ("https://www.bbc.co.uk/news", 0),
    ("https://stripe.com/docs/payments", 0),
    ("https://docs.python.org/3/library/urllib.html", 0),
    ("https://www.coursera.org/learn/machine-learning", 0),

    # PHISHING URLs (patterns — not real sites)
    ("http://paypal-verify-account.tk/login/secure", 1),
    ("http://192.168.1.1/bankofamerica/verify.php", 1),
    ("http://secure-appleid.apple.com.xyz/signin", 1),
    ("http://amazon-account-update.ml/confirm/password", 1),
    ("http://login-facebook.com.verify-account.tk", 1),
    ("http://192.0.2.1/signin/microsoft-account-suspended", 1),
    ("http://google-account-confirm.cf/verify/identity", 1),
    ("http://paypal.com.secure-update.ga/login?redirect=http://evil.com", 1),
    ("http://bit.ly/2xyzPhishingLink", 1),
    ("http://urgent-account-suspended@banklogin.xyz/verify", 1),
    ("http://free-win-prize-claim.top/account/confirm/credentials", 1),
    ("http://support-helpdesk-microsoft.gq/recover/wallet/bitcoin", 1),
]


def load_dataset():
    """
    Load URLs from sample data.
    In production, replace with:
        df = pd.read_csv("phishing_urls.csv")
    """
    urls   = [row[0] for row in SAMPLE_DATA]
    labels = [row[1] for row in SAMPLE_DATA]

    print(f"[Dataset] Loaded {len(urls)} URLs "
          f"({labels.count(1)} phishing, {labels.count(0)} safe)")
    return urls, labels


def build_feature_matrix(urls: list[str]) -> np.ndarray:
    """Extract features from all URLs into a numpy matrix."""
    X = []
    failed = 0
    for url in urls:
        try:
            vec, _ = extract_features(url)
            X.append(vec)
        except Exception as e:
            print(f"  [!] Feature extraction failed for {url[:60]}: {e}")
            X.append([0] * 23)  # zero vector as fallback
            failed += 1
    print(f"[Features] Extracted {len(X)} vectors ({failed} failures)")
    return np.array(X)


def train_and_evaluate(X: np.ndarray, y: list[int]):
    """Train model, evaluate, and return best model."""
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\n[Split] Train: {len(X_train)}, Test: {len(X_test)}")

    # ── Model candidates ──────────────────────────────────────────────────
    models = {
        "RandomForest": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", RandomForestClassifier(
                n_estimators=200,
                max_depth=12,
                min_samples_split=2,
                class_weight="balanced",
                random_state=42,
                n_jobs=-1,
            )),
        ]),
        "GradientBoosting": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", GradientBoostingClassifier(
                n_estimators=150,
                learning_rate=0.1,
                max_depth=5,
                random_state=42,
            )),
        ]),
    }

    best_model = None
    best_auc   = 0.0

    for name, pipeline in models.items():
        print(f"\n── Training {name} ──")
        pipeline.fit(X_train, y_train)

        y_pred  = pipeline.predict(X_test)
        y_proba = pipeline.predict_proba(X_test)[:, 1]

        acc = accuracy_score(y_test, y_pred)
        auc = roc_auc_score(y_test, y_proba)

        print(f"  Accuracy : {acc:.4f}")
        print(f"  ROC-AUC  : {auc:.4f}")
        print(f"\n{classification_report(y_test, y_pred, target_names=['Safe','Phishing'])}")

        # Cross-validation
        cv_scores = cross_val_score(pipeline, X, y, cv=3, scoring="roc_auc")
        print(f"  CV ROC-AUC: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

        if auc > best_auc:
            best_auc   = auc
            best_model = pipeline
            print(f"  ✓ New best model: {name} (AUC={auc:.4f})")

    return best_model


def save_model(model, path: str = "model.pkl"):
    """Serialize model to disk."""
    with open(path, "wb") as f:
        pickle.dump(model, f, protocol=pickle.HIGHEST_PROTOCOL)
    print(f"\n[Saved] Model written to {path}")


def demo_prediction(model):
    """Run a few demo predictions."""
    test_cases = [
        ("https://www.google.com",                        "SAFE"),
        ("http://paypal-verify-update.tk/login",          "PHISHING"),
        ("http://192.168.1.1/bank/signin.php",            "PHISHING"),
        ("https://github.com/features/copilot",           "SAFE"),
        ("http://free-amazon-gift-card.xyz/claim/urgent", "PHISHING"),
    ]
    print("\n── Demo Predictions ──")
    for url, expected in test_cases:
        vec, _ = extract_features(url)
        X = np.array(vec).reshape(1, -1)
        pred  = model.predict(X)[0]
        proba = model.predict_proba(X)[0][1]
        label = "PHISHING" if pred == 1 else "SAFE"
        match = "✓" if label == expected else "✗"
        print(f"  {match} [{label} {proba:.0%}] {url[:70]}")


# ──────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("═" * 60)
    print("  PhishGuard — ML Model Training")
    print("═" * 60)

    urls, labels = load_dataset()
    X = build_feature_matrix(urls)
    model = train_and_evaluate(X, labels)
    demo_prediction(model)
    save_model(model)

    print("\n[Done] Run 'uvicorn main:app --reload' to start the API")
