"""
PhishGuard — FastAPI Backend
Serves ML-powered phishing detection predictions.

Run with:
    uvicorn main:app --reload --port 8000
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from feature_engineering import extract_features, get_feature_explanations
import uvicorn
import logging
import time

# ── Optional: load trained model if available ──────────────────────────────
try:
    import pickle, os
    MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, "rb") as f:
            model = pickle.load(f)
        USE_MODEL = True
        logging.info("[PhishGuard] Loaded model.pkl successfully")
    else:
        model = None
        USE_MODEL = False
        logging.warning("[PhishGuard] model.pkl not found — using heuristic scoring")
except Exception as e:
    model = None
    USE_MODEL = False
    logging.warning(f"[PhishGuard] Model load failed: {e}")

# ──────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="PhishGuard API",
    description="Real-time phishing URL detection powered by machine learning",
    version="1.0.0",
)

# CORS — allow Chrome extension to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # in production, restrict to your extension ID
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──────────────────────────────────────────────────────────────────────────
# REQUEST / RESPONSE SCHEMAS
# ──────────────────────────────────────────────────────────────────────────
class URLRequest(BaseModel):
    url: str

class FeatureDetail(BaseModel):
    name: str
    value: str | int | float | bool
    risk: str           # "high" | "medium" | "low"

class PredictionResponse(BaseModel):
    url: str
    label: str          # "phishing" | "safe"
    confidence: float   # 0.0 → 1.0
    score: int          # raw heuristic score 0-100
    features: list[FeatureDetail]
    explanation: str
    source: str         # "model" | "heuristic"
    latency_ms: float

# ──────────────────────────────────────────────────────────────────────────
# ENDPOINTS
# ──────────────────────────────────────────────────────────────────────────
@app.get("/", tags=["Health"])
def root():
    return {
        "service": "PhishGuard API",
        "status": "online",
        "model_loaded": USE_MODEL,
    }

@app.get("/health", tags=["Health"])
def health():
    return {"status": "ok", "model": "loaded" if USE_MODEL else "heuristic"}


@app.post("/predict", response_model=PredictionResponse, tags=["Prediction"])
def predict(req: URLRequest):
    t0 = time.perf_counter()
    url = req.url.strip()

    if not url:
        raise HTTPException(status_code=422, detail="URL cannot be empty")

    # ── Extract numeric feature vector ────────────────────────────────────
    try:
        feature_vector, raw_features = extract_features(url)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Feature extraction failed: {e}")

    # ── Predict ───────────────────────────────────────────────────────────
    if USE_MODEL and model is not None:
        try:
            import numpy as np
            X = np.array(feature_vector).reshape(1, -1)
            proba = model.predict_proba(X)[0]          # [p_safe, p_phishing]
            phish_prob = float(proba[1])
            label = "phishing" if phish_prob >= 0.5 else "safe"
            confidence = phish_prob if label == "phishing" else 1.0 - phish_prob
            score = int(phish_prob * 100)
            source = "model"
        except Exception as e:
            logging.error(f"Model prediction failed: {e}, falling back to heuristic")
            label, confidence, score, source = heuristic_predict(raw_features)
    else:
        label, confidence, score, source = heuristic_predict(raw_features)

    # ── Build feature details ─────────────────────────────────────────────
    feature_details = get_feature_explanations(raw_features)

    # ── Explanation ───────────────────────────────────────────────────────
    explanation = build_explanation(label, raw_features)

    latency = round((time.perf_counter() - t0) * 1000, 2)

    return PredictionResponse(
        url=url,
        label=label,
        confidence=round(confidence, 3),
        score=score,
        features=feature_details,
        explanation=explanation,
        source=source,
        latency_ms=latency,
    )


@app.post("/batch", tags=["Prediction"])
def batch_predict(urls: list[str]):
    """Predict multiple URLs at once (max 50)."""
    if len(urls) > 50:
        raise HTTPException(status_code=400, detail="Max 50 URLs per batch request")
    return [predict(URLRequest(url=u)) for u in urls]


# ──────────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────────
def heuristic_predict(raw: dict):
    """
    Rule-based scoring when ML model is unavailable.
    Returns (label, confidence, score, source).
    """
    score = 0
    if raw.get("has_at_symbol"):       score += 25
    if raw.get("has_ip_address"):      score += 30
    if raw.get("url_length", 0) > 100: score += 15
    elif raw.get("url_length", 0) > 75: score += 8
    if raw.get("num_dots", 0) > 4:     score += 15
    if raw.get("num_hyphens", 0) > 3:  score += 10
    if not raw.get("has_https"):       score += 10
    if raw.get("has_suspicious_tld"):  score += 20
    if raw.get("has_port"):            score += 15
    if raw.get("has_double_slash"):    score += 10
    if raw.get("has_redirect"):        score += 15
    kw = raw.get("suspicious_keyword_count", 0)
    score += min(kw * 8, 30)
    if raw.get("domain_length", 0) > 30: score += 10

    score = min(score, 100)
    label = "phishing" if score >= 40 else "safe"
    confidence = score / 100 if label == "phishing" else 1.0 - score / 100
    return label, round(confidence, 3), score, "heuristic"


def build_explanation(label: str, raw: dict) -> str:
    reasons = []
    if raw.get("has_at_symbol"):
        reasons.append('contains "@" symbol which hides the true destination domain')
    if raw.get("has_ip_address"):
        reasons.append("uses a raw IP address instead of a registered domain name")
    if raw.get("has_suspicious_tld"):
        reasons.append("uses a free/suspicious TLD frequently exploited for phishing")
    kw = raw.get("top_keyword")
    if kw:
        reasons.append(f'contains deceptive keyword "{kw}"')
    if not raw.get("has_https"):
        reasons.append("does not use HTTPS encryption")
    if raw.get("num_dots", 0) > 4:
        reasons.append(f"has {raw['num_dots']} dots suggesting excessive subdomain nesting")
    if raw.get("url_length", 0) > 100:
        reasons.append("URL length exceeds 100 characters — a common obfuscation tactic")

    if label == "phishing":
        if reasons:
            return "Flagged because this URL " + "; and ".join(reasons) + "."
        return "Multiple phishing patterns detected in this URL."
    else:
        return "No significant phishing indicators found. URL follows standard conventions."


# ──────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
