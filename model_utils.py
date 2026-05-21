# model_utils.py — Shared utilities used by both train_model.py and app.py
import os
import json
import numpy as np
import joblib

from config import (
    MODEL_PATH, SCALER_PATH, METADATA_PATH, MODELS_DIR,
    RISK_SAFE_MAX, RISK_SUSPICIOUS_MAX, RISK_LABELS,
    FEATURE_COLUMNS
)

# Save and Load
def save_model(model, scaler, metadata: dict) -> None:
    """Save the trained model, scaler, and metadata JSON to the models/ folder."""
    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(model,  MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    with open(METADATA_PATH, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"  [✓] Model saved   → {MODEL_PATH}")
    print(f"  [✓] Scaler saved  → {SCALER_PATH}")
    print(f"  [✓] Metadata saved→ {METADATA_PATH}")


def load_model():
    missing = [p for p in [MODEL_PATH, SCALER_PATH, METADATA_PATH]
               if not os.path.exists(p)]
    if missing:
        raise FileNotFoundError(
            f"Model files not found: {missing}\n"
            "Please run:  python train_model.py   first."
        )
    model    = joblib.load(MODEL_PATH)
    scaler   = joblib.load(SCALER_PATH)
    with open(METADATA_PATH, "r") as f:
        metadata = json.load(f)
    return model, scaler, metadata


def model_is_trained() -> bool:
    """Returns True if all three model files exist on disk."""
    return all(
        os.path.exists(p)
        for p in [MODEL_PATH, SCALER_PATH, METADATA_PATH]
    )

# Risk Classification
def classify_risk(phishing_prob: float) -> str:
    """
    Map phishing probability (0.0 to 1.0) to a risk label.

    Thresholds (defined in config.py):
        0.00 – 0.40  →  Safe
        0.40 – 0.70  →  Suspicious
        0.70 – 1.00  →  Dangerous
    """
    if phishing_prob < RISK_SAFE_MAX:
        return "Safe"
    elif phishing_prob < RISK_SUSPICIOUS_MAX:
        return "Suspicious"
    else:
        return "Dangerous"


# ─────────────────────────────────────────────────────────────────────────────
# Prediction
# ─────────────────────────────────────────────────────────────────────────────

def predict(model, scaler, feature_values: list) -> dict:
    """
    Run a prediction on a single website's features.

    Parameters
    ----------
    model         : trained sklearn classifier (LogisticRegression or RandomForest)
    scaler        : fitted StandardScaler
    feature_values: list of 30 numeric values (in FEATURE_COLUMNS order)

    Returns
    -------
    dict with keys:
        label            – "Phishing" or "Legitimate"
        phishing_prob    – float 0–1
        legit_prob       – float 0–1
        confidence_pct   – float 0–100 (confidence in the predicted class)
        risk_level       – "Safe", "Suspicious", or "Dangerous"
        risk_meta        – dict with emoji, color, bg, border from RISK_LABELS
    """
    # Reshape for sklearn: (1 sample, 30 features)
    X = np.array(feature_values, dtype=float).reshape(1, -1)

    # Scale using the same scaler used during training
    X_scaled = scaler.transform(X)

    # Get class probabilities
    proba         = model.predict_proba(X_scaled)[0]   
    classes       = list(model.classes_)               

    phishing_prob = float(proba[classes.index(-1)])    
    legit_prob    = float(proba[classes.index( 1)])    

    # Get predicted class and human label
    predicted     = int(model.predict(X_scaled)[0])
    label         = "Phishing" if predicted == -1 else "Legitimate"

    # Confidence = probability of the predicted class
    confidence_pct = round(max(phishing_prob, legit_prob) * 100, 1)

    risk_level = classify_risk(phishing_prob)

    return {
        "label":          label,
        "phishing_prob":  phishing_prob,
        "legit_prob":     legit_prob,
        "confidence_pct": confidence_pct,
        "risk_level":     risk_level,
        "risk_meta":      RISK_LABELS[risk_level],
    }

# Feature Vector Builder
def build_feature_vector(user_inputs: dict) -> list:
    """
    Convert a dict {column_name: value} to an ordered list matching FEATURE_COLUMNS.

    Raises a clear KeyError if any feature is missing from the dict.
    """
    missing = [col for col in FEATURE_COLUMNS if col not in user_inputs]
    if missing:
        raise KeyError(
            f"These features are missing from your input: {missing}\n"
            "Make sure all 30 features are filled in the form."
        )
    return [user_inputs[col] for col in FEATURE_COLUMNS]
