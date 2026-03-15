from fastapi import FastAPI
from pydantic import BaseModel

from model import PhishModel

app = FastAPI(title="PhishGuard ML")
model = PhishModel()


class PredictReq(BaseModel):
    url: str
    subject: str = ""
    snippet: str = ""


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/v1/model")
def model_info():
    return {
        "model_version": model.model_version,
        "base_model": model.base_model,
    }


@app.post("/v1/predict/url")
def predict_url(req: PredictReq):
    score, risk, features = model.predict(req.url, req.subject, req.snippet)
    return {
        "score": score,
        "risk": risk,
        "model_version": model.model_version,
        "features": features,
    }