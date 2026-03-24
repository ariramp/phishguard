import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from sklearn.linear_model import LogisticRegression

from serving.model import FUSION_FEATURE_ORDER, extract_text_features, extract_url_features
from train_utils import compute_metrics, save_json_report, stratified_fallback_split, summarize_dataset


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def processed_path() -> Path:
    return project_root() / "ml" / "data" / "processed" / "fusion_dataset.csv"


def model_dir() -> Path:
    path = project_root() / "ml_models"
    path.mkdir(parents=True, exist_ok=True)
    return path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_dataset() -> pd.DataFrame:
    path = processed_path()
    if not path.exists():
        raise FileNotFoundError(f"dataset not found: {path}. Run ml/prepare_datasets.py first.")
    frame = pd.read_csv(path)
    if frame.empty:
        raise ValueError(f"dataset is empty: {path}")
    required = {"url", "body", "label"}
    if not required.issubset(frame.columns):
        raise ValueError(f"dataset must contain {required}: {path}")
    if "subject" not in frame.columns:
        frame["subject"] = ""
    frame = frame.dropna(subset=["url", "body", "label"]).copy()
    return frame.drop_duplicates(subset=["url", "subject", "body", "label"]).reset_index(drop=True)


def heuristic_url_score(url_features: dict) -> float:
    score = 0.05
    if url_features["suspicious_keyword_count"] > 0:
        score += 0.28
    if url_features["has_ip_host"]:
        score += 0.25
    if url_features["has_punycode"]:
        score += 0.15
    if url_features["brand_similarity"] >= 0.85:
        score += 0.2
    if url_features["has_shortener"]:
        score += 0.15
    if url_features["subdomain_count"] >= 2:
        score += 0.08
    if not url_features["is_https"]:
        score += 0.04
    return max(0.0, min(1.0, score))


def heuristic_text_score(text_features: dict) -> float:
    score = 0.03
    score += min(0.45, text_features["keyword_count"] * 0.08)
    score += min(0.12, text_features["exclamation_count"] * 0.03)
    if text_features["uppercase_ratio"] > 0.2:
        score += 0.08
    if text_features["contains_urgent_phrase"]:
        score += 0.12
    return max(0.0, min(1.0, score))


def build_feature_frame(frame: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, sample in frame.iterrows():
        url_features = extract_url_features(str(sample["url"]))
        text_features = extract_text_features(str(sample["subject"]), str(sample["body"]))
        rows.append(
            {
                "url_score": heuristic_url_score(url_features),
                "text_score": heuristic_text_score(text_features),
                "is_ip": url_features["has_ip_host"],
                "has_punycode": url_features["has_punycode"],
                "brand_similarity": url_features["brand_similarity"],
                "suspicious_words_count": url_features["suspicious_keyword_count"],
                "has_shortener": url_features["has_shortener"],
                "text_keyword_count": text_features["keyword_count"],
            }
        )
    feature_frame = pd.DataFrame(rows)
    return feature_frame[FUSION_FEATURE_ORDER]


def main() -> None:
    frame = load_dataset()
    train_frame, test_frame = stratified_fallback_split(frame, test_size=0.2, random_state=42)

    x_train = build_feature_frame(train_frame)
    x_test = build_feature_frame(test_frame)
    y_train = train_frame["label"].astype(int)
    y_test = test_frame["label"].astype(int)

    model = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42)
    model.fit(x_train, y_train)

    y_score = model.predict_proba(x_test)[:, 1]
    y_pred = (y_score >= 0.5).astype(int)
    metrics = compute_metrics(y_test, y_pred, y_score)

    path = model_dir()
    artifact_path = path / "fusion_model.joblib"
    metadata_path = path / "fusion_model.json"
    report_path = path / "fusion_model_report.json"

    joblib.dump({"model": model}, artifact_path)
    metadata = {
        "model_version": "fusion-logreg-v1",
        "base_model": "LogisticRegression",
        "feature_order": FUSION_FEATURE_ORDER,
        "split_strategy": "stratified-random",
        "trained_at": utc_now(),
        "samples_used": int(len(frame)),
        "train_rows": int(len(train_frame)),
        "test_rows": int(len(test_frame)),
        "metrics": metrics,
        "artifact_uri": str(artifact_path),
    }
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
    save_json_report(
        report_path,
        {
            "model_version": metadata["model_version"],
            "dataset_summary": summarize_dataset(frame),
            "train_summary": summarize_dataset(train_frame),
            "test_summary": summarize_dataset(test_frame),
            "metrics": metrics,
        },
    )

    print(json.dumps(metadata, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
