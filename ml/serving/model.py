class PhishModel:
    def __init__(self):
        self.model_version = "0.1.0"
        self.base_model = "stub-model"

    def predict(self, url: str, subject: str, snippet: str):
        score = 0.1
        risk = 1

        if "login" in url or "verify" in url or "secure" in url:
            score = 0.82
            risk = 3

        features = {
            "len_url": len(url),
            "has_at": "@" in url,
            "subject_len": len(subject),
        }

        return score, risk, features