import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression

from serving.model import FUSION_FEATURE_ORDER, URL_FEATURE_ORDER, extract_text_features, extract_url_features


URL_SAMPLES = [
    {"url": "https://www.google.com/search?q=golang", "label": 0},
    {"url": "https://github.com/golang/go", "label": 0},
    {"url": "https://www.sberbank.ru/ru/person", "label": 0},
    {"url": "https://www.gosuslugi.ru/help", "label": 0},
    {"url": "https://mail.yandex.ru/", "label": 0},
    {"url": "http://secure-login-account.com/verify", "label": 1},
    {"url": "http://192.168.0.5/bank/login", "label": 1},
    {"url": "https://bit.ly/secure-wallet-check", "label": 1},
    {"url": "http://paypa1-support.example.com/update", "label": 1},
    {"url": "http://xn--secure-paypal-9db.example/login", "label": 1},
]

TEXT_SAMPLES = [
    {"subject": "Meeting tomorrow", "body": "Please review the attached project notes before the call.", "label": 0},
    {"subject": "Invoice copy", "body": "The invoice was already paid last week, no action required.", "label": 0},
    {"subject": "Repository update", "body": "A new comment was added to the pull request in GitHub.", "label": 0},
    {"subject": "Срочно подтвердите аккаунт", "body": "Ваш доступ будет ограничен, подтвердите вход немедленно.", "label": 1},
    {"subject": "Security alert", "body": "Urgent verification required to avoid account suspension.", "label": 1},
    {"subject": "Получите выплату", "body": "Для получения выплаты срочно подтвердите банковские реквизиты.", "label": 1},
]

FUSION_SAMPLES = [
    {"url_score": 0.10, "text_score": 0.08, "is_ip": 0, "has_punycode": 0, "brand_similarity": 0.05, "suspicious_words_count": 0, "has_shortener": 0, "text_keyword_count": 0, "label": 0},
    {"url_score": 0.22, "text_score": 0.18, "is_ip": 0, "has_punycode": 0, "brand_similarity": 0.15, "suspicious_words_count": 1, "has_shortener": 0, "text_keyword_count": 1, "label": 0},
    {"url_score": 0.61, "text_score": 0.45, "is_ip": 0, "has_punycode": 0, "brand_similarity": 0.88, "suspicious_words_count": 2, "has_shortener": 0, "text_keyword_count": 1, "label": 1},
    {"url_score": 0.84, "text_score": 0.73, "is_ip": 1, "has_punycode": 0, "brand_similarity": 0.94, "suspicious_words_count": 3, "has_shortener": 0, "text_keyword_count": 2, "label": 1},
    {"url_score": 0.79, "text_score": 0.82, "is_ip": 0, "has_punycode": 1, "brand_similarity": 0.91, "suspicious_words_count": 2, "has_shortener": 1, "text_keyword_count": 3, "label": 1},
]


def output_dir() -> Path:
    path = Path(__file__).resolve().parents[1] / "ml_models"
    path.mkdir(parents=True, exist_ok=True)
    return path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def train_url_model(path: Path) -> None:
    rows = [extract_url_features(item["url"]) for item in URL_SAMPLES]
    labels = [item["label"] for item in URL_SAMPLES]
    train_matrix = [[float(row[name]) for name in URL_FEATURE_ORDER] for row in rows]

    model = HistGradientBoostingClassifier(
        learning_rate=0.1,
        max_depth=5,
        max_iter=80,
        random_state=42,
    )
    model.fit(train_matrix, labels)
    joblib.dump({"model": model}, path / "url_model.joblib")

    metadata = {
        "model_version": "url-hgb-baseline-v1",
        "base_model": "HistGradientBoostingClassifier",
        "feature_order": URL_FEATURE_ORDER,
        "trained_at": utc_now(),
        "samples_used": len(URL_SAMPLES),
    }
    (path / "url_model.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")


def train_text_model(path: Path) -> None:
    texts = []
    labels = []
    for sample in TEXT_SAMPLES:
        features = extract_text_features(sample["subject"], sample["body"])
        texts.append(features["combined_text"])
        labels.append(sample["label"])

    vectorizer = TfidfVectorizer(ngram_range=(1, 2), lowercase=True, min_df=1)
    matrix = vectorizer.fit_transform(texts)

    model = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42)
    model.fit(matrix, labels)

    bundle = {
        "model": model,
        "vectorizer": vectorizer,
    }
    joblib.dump(bundle, path / "text_model.joblib")

    metadata = {
        "model_version": "text-baseline-v1",
        "base_model": "TFIDF+LogisticRegression",
        "trained_at": utc_now(),
        "samples_used": len(TEXT_SAMPLES),
    }
    (path / "text_model.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")


def train_fusion_model(path: Path) -> None:
    matrix = [[float(item[name]) for name in FUSION_FEATURE_ORDER] for item in FUSION_SAMPLES]
    labels = [item["label"] for item in FUSION_SAMPLES]

    model = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42)
    model.fit(matrix, labels)
    joblib.dump({"model": model}, path / "fusion_model.joblib")

    metadata = {
        "model_version": "fusion-baseline-v1",
        "base_model": "LogisticRegression",
        "feature_order": FUSION_FEATURE_ORDER,
        "trained_at": utc_now(),
        "samples_used": len(FUSION_SAMPLES),
    }
    (path / "fusion_model.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")


def main() -> None:
    path = output_dir()
    train_url_model(path)
    train_text_model(path)
    train_fusion_model(path)
    print(f"saved baseline artifacts to {path}")


if __name__ == "__main__":
    main()
