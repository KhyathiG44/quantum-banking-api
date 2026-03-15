import os
import joblib
import numpy as np
from fastapi import APIRouter, Depends, HTTPException
from schemas.transaction import TransactionRequest, PredictionResponse
from security.auth import verify_api_key
import logging

router = APIRouter(prefix="/api/v1", tags=["predictions"])
logger = logging.getLogger(__name__)

_model  = None
_scaler = None

def load_model():
    global _model, _scaler
    BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    model_path  = os.path.join(BASE_DIR, "model", "fraud_model.pkl")
    scaler_path = os.path.join(BASE_DIR, "model", "scaler.pkl")
    print(f"Loading model from:  {model_path}")
    print(f"Loading scaler from: {scaler_path}")
    _model  = joblib.load(model_path)
    _scaler = joblib.load(scaler_path)
    logger.info("Model loaded successfully")

def score_to_risk(score: float):
    if score < 0.3:
        return "low", "approve"
    elif score < 0.7:
        return "medium", "review"
    else:
        return "high", "block"

def extract_features(txn: TransactionRequest) -> np.ndarray:
    return np.array([[
        txn.Time,
        txn.V1,  txn.V2,  txn.V3,  txn.V4,  txn.V5,
        txn.V6,  txn.V7,  txn.V8,  txn.V9,  txn.V10,
        txn.V11, txn.V12, txn.V13, txn.V14, txn.V15,
        txn.V16, txn.V17, txn.V18, txn.V19, txn.V20,
        txn.V21, txn.V22, txn.V23, txn.V24, txn.V25,
        txn.V26, txn.V27, txn.V28,
        txn.Amount
    ]])

@router.post("/predict", response_model=PredictionResponse)
async def predict_fraud(
    transaction: TransactionRequest,
    client: str = Depends(verify_api_key)
):
    if _model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    try:
        features        = extract_features(transaction)
        features_scaled = _scaler.transform(features)
        proba           = _model.predict_proba(features_scaled)
        fraud_score     = float(proba[0][1])
    except Exception as e:
        import traceback
        print("FULL ERROR:", traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")

    is_fraud                   = fraud_score >= 0.5
    risk_level, recommendation = score_to_risk(fraud_score)

    logger.info(f"txn={transaction.transaction_id} score={fraud_score:.4f} risk={risk_level}")

    return PredictionResponse(
        transaction_id = transaction.transaction_id,
        fraud_score    = round(fraud_score, 4),
        is_fraud       = is_fraud,
        risk_level     = risk_level,
        recommendation = recommendation
    )

@router.get("/health")
async def health():
    return {
        "status":       "ok" if _model is not None else "degraded",
        "model_loaded": _model is not None
    }
