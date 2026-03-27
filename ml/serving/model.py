import json
import math
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

try:
    import joblib
except ImportError:  # pragma: no cover - optional runtime dependency
    joblib = None

try:
    from scipy.sparse import csr_matrix, hstack
except ImportError:  # pragma: no cover - optional runtime dependency
    csr_matrix = None
    hstack = None

try:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline
except ImportError:  # pragma: no cover - optional runtime dependency
    torch = None
    AutoModelForSequenceClassification = None
    AutoTokenizer = None
    pipeline = None


URL_SUSPICIOUS_KEYWORDS = (
    "login",
    "verify",
    "secure",
    "update",
    "account",
    "bonus",
    "gift",
    "bank",
    "password",
    "wallet",
)

TEXT_SUSPICIOUS_KEYWORDS = (
    "срочно",
    "подтвердите",
    "аккаунт",
    "вход",
    "безопасность",
    "пароль",
    "ограничен",
    "блокировка",
    "выплата",
    "verify",
    "urgent",
    "account",
    "login",
    "security",
    "password",
)

KNOWN_BRANDS = (
    "paypal",
    "google",
    "microsoft",
    "apple",
    "amazon",
    "sberbank",
    "tinkoff",
    "gosuslugi",
    "alfabank",
    "yandex",
    "ozon",
    "wildberries",
)

TRUSTED_DOMAINS = {
    "google.com",
    "googleapis.com",
    "microsoft.com",
    "github.com",
    "apple.com",
    "amazon.com",
    "yandex.ru",
    "mail.ru",
    "gosuslugi.ru",
    "sberbank.ru",
    "tbank.ru",
    "tinkoff.ru",
    "vk.com",
    "wildberries.ru",
    "ozon.ru",
}

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "clck.ru",
}

URL_FEATURE_ORDER = [
    "url_length",
    "domain_length",
    "dot_count",
    "dash_count",
    "digit_count",
    "has_at_symbol",
    "has_ip_host",
    "has_punycode",
    "suspicious_keyword_count",
    "is_https",
    "query_param_count",
    "subdomain_count",
    "brand_similarity",
    "has_shortener",
    "path_length",
]

FUSION_FEATURE_ORDER = [
    "url_score",
    "text_score",
    "is_ip",
    "has_punycode",
    "brand_similarity",
    "suspicious_words_count",
    "has_shortener",
    "text_keyword_count",
]


def _env_path(name: str, default: str) -> Path:
    return Path(os.getenv(name, default))


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _bool_to_int(value: bool) -> int:
    return 1 if value else 0


def _safe_ratio(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 0.0
    return numerator / denominator


def _count_digits(value: str) -> int:
    return sum(ch.isdigit() for ch in value)


def _combined_text(subject: str, body: str) -> str:
    return " ".join(part.strip() for part in (subject, body) if part and part.strip())


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ch_a in enumerate(a, start=1):
        curr = [i]
        for j, ch_b in enumerate(b, start=1):
            insert_cost = curr[j - 1] + 1
            delete_cost = prev[j] + 1
            replace_cost = prev[j - 1] + (0 if ch_a == ch_b else 1)
            curr.append(min(insert_cost, delete_cost, replace_cost))
        prev = curr
    return prev[-1]


def _brand_similarity(host: str) -> float:
    host = host.lower()
    if not host:
        return 0.0
    labels = [label for label in host.split(".") if label]
    if not labels:
        return 0.0

    best = 0.0
    for label in labels:
        for brand in KNOWN_BRANDS:
            distance = _levenshtein(label, brand)
            score = 1.0 - _safe_ratio(distance, max(len(label), len(brand)))
            if brand in label and label != brand:
                score = max(score, 0.92)
            if score > best:
                best = score
    return round(max(0.0, min(1.0, best)), 4)


def _is_trusted_host(host: str) -> bool:
    host = (host or "").lower()
    if not host:
        return False
    return any(host == domain or host.endswith("." + domain) for domain in TRUSTED_DOMAINS)


def extract_url_features(url: str) -> dict[str, Any]:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    full_lower = url.lower()

    suspicious_keyword_count = sum(keyword in full_lower for keyword in URL_SUSPICIOUS_KEYWORDS)

    return {
        "host": host,
        "url_length": len(url),
        "domain_length": len(host),
        "dot_count": host.count("."),
        "dash_count": host.count("-"),
        "digit_count": _count_digits(url),
        "has_at_symbol": _bool_to_int("@" in url),
        "has_ip_host": _bool_to_int(bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))),
        "has_punycode": _bool_to_int("xn--" in host),
        "suspicious_keyword_count": suspicious_keyword_count,
        "is_https": _bool_to_int(parsed.scheme.lower() == "https"),
        "query_param_count": len(parse_qsl(parsed.query or "", keep_blank_values=True)),
        "subdomain_count": max(host.count(".") - 1, 0),
        "brand_similarity": _brand_similarity(host),
        "has_shortener": _bool_to_int(host in SHORTENERS),
        "path_length": len(path),
    }


def extract_text_features(subject: str, body: str) -> dict[str, Any]:
    combined = _combined_text(subject, body)
    lower = combined.lower()
    keyword_count = sum(keyword in lower for keyword in TEXT_SUSPICIOUS_KEYWORDS)
    exclamation_count = combined.count("!")
    uppercase_ratio = _safe_ratio(sum(ch.isupper() for ch in combined), len(combined))

    return {
        "text_length": len(combined),
        "subject_length": len(subject),
        "body_length": len(body),
        "keyword_count": keyword_count,
        "exclamation_count": exclamation_count,
        "uppercase_ratio": round(uppercase_ratio, 4),
        "contains_urgent_phrase": _bool_to_int(keyword_count > 0),
        "combined_text": combined,
    }


class URLClassifier:
    def __init__(self):
        self.model_path = _env_path("MODEL_URL_PATH", "/app/ml_models/url_model.joblib")
        self.metadata_path = _env_path("MODEL_URL_METADATA_PATH", "/app/ml_models/url_model.json")
        self.model_version = "url-heuristic-v1"
        self.base_model = "heuristic"
        self.loaded = False
        self.load_error = ""
        self.feature_order = list(URL_FEATURE_ORDER)
        self._bundle = None
        self._load()

    def _load(self) -> None:
        if not self.model_path.exists():
            self.load_error = f"url model not found: {self.model_path}"
            return

        metadata = _read_json(self.metadata_path)
        self.model_version = str(metadata.get("model_version", self.model_version))
        self.base_model = str(metadata.get("base_model", self.base_model))
        self.feature_order = list(metadata.get("feature_order", self.feature_order))

        if joblib is None:
            self.load_error = "joblib is not installed"
            return

        try:
            self._bundle = joblib.load(self.model_path)
        except Exception as exc:  # pragma: no cover - runtime safety
            self.load_error = f"failed to load url model: {exc}"
            return

        self.loaded = True

    def _heuristic_score(self, features: dict[str, Any]) -> float:
        score = 0.05
        if features["suspicious_keyword_count"] > 0:
            score += 0.28
        if features["has_ip_host"]:
            score += 0.25
        if features["has_punycode"]:
            score += 0.15
        if features["brand_similarity"] >= 0.85:
            score += 0.2
        if features["has_shortener"]:
            score += 0.15
        if features["subdomain_count"] >= 2:
            score += 0.08
        if not features["is_https"]:
            score += 0.04
        return max(0.0, min(1.0, score))

    def _apply_trusted_domain_adjustment(self, score: float, features: dict[str, Any]) -> float:
        if not _is_trusted_host(features["host"]):
            return score

        if features["has_ip_host"] or features["has_punycode"] or features["has_at_symbol"]:
            return score

        adjusted = min(score, 0.12)
        if features["is_https"]:
            adjusted = min(adjusted, 0.08)
        return adjusted

    def predict(self, url: str) -> tuple[float, dict[str, Any]]:
        features = extract_url_features(url)
        if self.loaded and self._bundle is not None:
            try:
                classifier = self._bundle["model"] if isinstance(self._bundle, dict) else self._bundle
                row = [[float(features[name]) for name in self.feature_order]]
                score = float(classifier.predict_proba(row)[0][1])
                mode = "artifact"
            except Exception as exc:  # pragma: no cover - runtime safety
                self.loaded = False
                self.load_error = f"url inference failed: {exc}"
                score = self._heuristic_score(features)
                mode = "fallback"
        else:
            score = self._heuristic_score(features)
            mode = "fallback"

        score = self._apply_trusted_domain_adjustment(score, features)

        features["inference_mode"] = mode
        features["trusted_domain"] = _bool_to_int(_is_trusted_host(features["host"]))
        if self.load_error:
            features["load_error"] = self.load_error
        return score, features


class TextClassifier:
    def __init__(self):
        self.model_path = _env_path("MODEL_TEXT_PATH", "/app/ml_models/text_model.joblib")
        self.metadata_path = _env_path("MODEL_TEXT_METADATA_PATH", "/app/ml_models/text_model.json")
        self.model_version = "text-heuristic-v1"
        self.base_model = "heuristic"
        self.loaded = False
        self.load_error = ""
        self.mode = "heuristic"
        self._transformers_pipeline = None
        self._bundle = None
        self._load()

    def _load(self) -> None:
        metadata = _read_json(self.metadata_path)
        self.model_version = str(metadata.get("model_version", self.model_version))
        self.base_model = str(metadata.get("base_model", self.base_model))

        if self.model_path.is_dir():
            if pipeline is None or AutoTokenizer is None or AutoModelForSequenceClassification is None:
                self.load_error = "transformers is not installed"
                return
            try:
                tokenizer = AutoTokenizer.from_pretrained(str(self.model_path))
                model = AutoModelForSequenceClassification.from_pretrained(str(self.model_path))
                device = 0 if torch is not None and torch.cuda.is_available() else -1
                self._transformers_pipeline = pipeline(
                    "text-classification",
                    model=model,
                    tokenizer=tokenizer,
                    device=device,
                    truncation=True,
                )
            except Exception as exc:  # pragma: no cover - runtime safety
                self.load_error = f"failed to load text transformers model: {exc}"
                return
            self.loaded = True
            self.mode = "transformers"
            return

        if self.model_path.exists():
            if joblib is None:
                self.load_error = "joblib is not installed"
                return
            try:
                self._bundle = joblib.load(self.model_path)
            except Exception as exc:  # pragma: no cover - runtime safety
                self.load_error = f"failed to load text bundle: {exc}"
                return
            self.loaded = True
            self.mode = "sklearn"
            return

        self.load_error = f"text model not found: {self.model_path}"

    def _heuristic_score(self, features: dict[str, Any]) -> float:
        score = 0.03
        score += min(0.45, features["keyword_count"] * 0.08)
        score += min(0.12, features["exclamation_count"] * 0.03)
        if features["uppercase_ratio"] > 0.2:
            score += 0.08
        if features["contains_urgent_phrase"]:
            score += 0.12
        return max(0.0, min(1.0, score))

    def _predict_transformers(self, text: str) -> float:
        result = self._transformers_pipeline(text, truncation=True, max_length=512)[0]
        label = str(result.get("label", "")).lower()
        score = float(result.get("score", 0.0))
        if "safe" in label or label.endswith("0") or "legit" in label:
            return 1.0 - score
        return score

    def _predict_sklearn(self, text: str) -> float:
        if self._bundle is None or csr_matrix is None or hstack is None:
            raise RuntimeError("text sklearn bundle is unavailable")

        vectorizer = self._bundle["vectorizer"]
        classifier = self._bundle["model"]
        matrix = vectorizer.transform([text])
        if hasattr(classifier, "predict_proba"):
            return float(classifier.predict_proba(matrix)[0][1])
        raw_score = float(classifier.decision_function(matrix)[0])
        return 1.0 / (1.0 + math.exp(-raw_score))

    def predict(self, subject: str, body: str) -> tuple[float, dict[str, Any]]:
        features = extract_text_features(subject, body)
        text = features["combined_text"]

        if self.loaded:
            try:
                if self.mode == "transformers":
                    score = self._predict_transformers(text)
                elif self.mode == "sklearn":
                    score = self._predict_sklearn(text)
                else:
                    score = self._heuristic_score(features)
                mode = "artifact"
            except Exception as exc:  # pragma: no cover - runtime safety
                self.loaded = False
                self.load_error = f"text inference failed: {exc}"
                score = self._heuristic_score(features)
                mode = "fallback"
        else:
            score = self._heuristic_score(features)
            mode = "fallback"

        response = {k: v for k, v in features.items() if k != "combined_text"}
        response["inference_mode"] = mode
        if self.load_error:
            response["load_error"] = self.load_error
        return score, response


class FusionClassifier:
    def __init__(self):
        self.model_path = _env_path("MODEL_FUSION_PATH", "/app/ml_models/fusion_model.joblib")
        self.metadata_path = _env_path("MODEL_FUSION_METADATA_PATH", "/app/ml_models/fusion_model.json")
        self.model_version = "fusion-rules-v1"
        self.base_model = "rule-engine"
        self.loaded = False
        self.load_error = ""
        self.feature_order = list(FUSION_FEATURE_ORDER)
        self._bundle = None
        self._load()

    def _load(self) -> None:
        if not self.model_path.exists():
            self.load_error = f"fusion model not found: {self.model_path}"
            return
        if joblib is None:
            self.load_error = "joblib is not installed"
            return

        metadata = _read_json(self.metadata_path)
        self.model_version = str(metadata.get("model_version", self.model_version))
        self.base_model = str(metadata.get("base_model", "logistic-regression"))
        self.feature_order = list(metadata.get("feature_order", self.feature_order))

        try:
            self._bundle = joblib.load(self.model_path)
        except Exception as exc:  # pragma: no cover - runtime safety
            self.load_error = f"failed to load fusion model: {exc}"
            return
        self.loaded = True

    def _rule_score(self, features: dict[str, Any]) -> float:
        url_score = float(features["url_score"])
        text_score = float(features["text_score"])

        if url_score >= 0.85:
            return max(url_score, 0.92)
        if text_score >= 0.85 and url_score >= 0.50:
            return max(text_score, 0.9)
        if features["is_ip"] or features["has_punycode"]:
            return max(url_score, text_score, 0.72)
        if features["brand_similarity"] >= 0.9 and features["suspicious_words_count"] > 0:
            return max(url_score, 0.82)
        if url_score >= 0.60 or text_score >= 0.70:
            return max(url_score, text_score, 0.68)
        return max(url_score * 0.65 + text_score * 0.35, 0.02)

    def predict(self, features: dict[str, Any]) -> tuple[float, int, dict[str, Any]]:
        if self.loaded and self._bundle is not None:
            try:
                classifier = self._bundle["model"] if isinstance(self._bundle, dict) else self._bundle
                row = [[float(features[name]) for name in self.feature_order]]
                if hasattr(classifier, "predict_proba"):
                    score = float(classifier.predict_proba(row)[0][1])
                else:
                    raw_score = float(classifier.decision_function(row)[0])
                    score = 1.0 / (1.0 + math.exp(-raw_score))
                mode = "artifact"
            except Exception as exc:  # pragma: no cover - runtime safety
                self.loaded = False
                self.load_error = f"fusion inference failed: {exc}"
                score = self._rule_score(features)
                mode = "fallback"
        else:
            score = self._rule_score(features)
            mode = "fallback"

        score = max(0.0, min(1.0, score))
        if score >= 0.8:
            risk = 3
        elif score >= 0.45:
            risk = 2
        else:
            risk = 1

        info = {
            "inference_mode": mode,
            "feature_order": self.feature_order,
        }
        if self.load_error:
            info["load_error"] = self.load_error
        return score, risk, info


class PhishModel:
    def __init__(self):
        self.url_model = URLClassifier()
        self.text_model = TextClassifier()
        self.fusion_model = FusionClassifier()
        self.model_version = self._compose_version()
        self.base_model = "hybrid-pipeline"

    def _compose_version(self) -> str:
        return "|".join(
            [
                f"url:{self.url_model.model_version}",
                f"text:{self.text_model.model_version}",
                f"fusion:{self.fusion_model.model_version}",
            ]
        )

    def model_info(self) -> dict[str, Any]:
        return {
            "model_version": self.model_version,
            "base_model": self.base_model,
            "components": {
                "url": {
                    "model_version": self.url_model.model_version,
                    "base_model": self.url_model.base_model,
                    "loaded_from_artifact": self.url_model.loaded,
                    "model_path": str(self.url_model.model_path),
                    "load_error": self.url_model.load_error,
                },
                "text": {
                    "model_version": self.text_model.model_version,
                    "base_model": self.text_model.base_model,
                    "loaded_from_artifact": self.text_model.loaded,
                    "model_path": str(self.text_model.model_path),
                    "load_error": self.text_model.load_error,
                },
                "fusion": {
                    "model_version": self.fusion_model.model_version,
                    "base_model": self.fusion_model.base_model,
                    "loaded_from_artifact": self.fusion_model.loaded,
                    "model_path": str(self.fusion_model.model_path),
                    "load_error": self.fusion_model.load_error,
                },
            },
        }

    def predict(self, url: str, subject: str, snippet: str):
        url_score, url_features = self.url_model.predict(url)
        text_score, text_features = self.text_model.predict(subject, snippet)

        fusion_features = {
            "url_score": url_score,
            "text_score": text_score,
            "is_ip": url_features["has_ip_host"],
            "has_punycode": url_features["has_punycode"],
            "brand_similarity": url_features["brand_similarity"],
            "suspicious_words_count": url_features["suspicious_keyword_count"],
            "has_shortener": url_features["has_shortener"],
            "text_keyword_count": text_features["keyword_count"],
        }

        final_score, risk, fusion_info = self.fusion_model.predict(fusion_features)
        self.model_version = self._compose_version()

        features = {
            "url_features": url_features,
            "text_features": text_features,
            "fusion_features": fusion_features,
            "components": {
                "url_score": round(url_score, 6),
                "text_score": round(text_score, 6),
                "fusion_mode": fusion_info["inference_mode"],
            },
        }
        if "load_error" in fusion_info:
            features["fusion_load_error"] = fusion_info["load_error"]

        return final_score, risk, features
