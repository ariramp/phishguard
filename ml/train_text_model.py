import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from train_utils import compute_metrics, grouped_split, save_json_report, stratified_fallback_split, summarize_dataset, text_group


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def processed_path() -> Path:
    return project_root() / "ml" / "data" / "processed" / "text_dataset.csv"


def model_dir() -> Path:
    path = project_root() / "ml_models"
    path.mkdir(parents=True, exist_ok=True)
    return path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def combine_text(subject: str, body: str) -> str:
    return f"[SUBJECT] {subject.strip()} [BODY] {body.strip()}".strip()


def load_dataset() -> pd.DataFrame:
    path = processed_path()
    if not path.exists():
        raise FileNotFoundError(f"dataset not found: {path}. Run ml/prepare_datasets.py first.")
    frame = pd.read_csv(path)
    if frame.empty:
        raise ValueError(f"dataset is empty: {path}")
    if "body" not in frame.columns or "label" not in frame.columns:
        raise ValueError(f"dataset must contain body and label columns: {path}")
    if "subject" not in frame.columns:
        frame["subject"] = ""
    frame = frame.dropna(subset=["body", "label"]).copy()
    return frame.drop_duplicates(subset=["subject", "body", "label"]).reset_index(drop=True)


def train_tfidf_baseline(frame: pd.DataFrame) -> dict:
    groups = frame.apply(lambda row: text_group(row["subject"], row["body"]), axis=1)
    try:
        train_frame, test_frame = grouped_split(frame, groups=groups, test_size=0.2, random_state=42)
    except ValueError:
        train_frame, test_frame = stratified_fallback_split(frame, test_size=0.2, random_state=42)

    train_text = train_frame.apply(lambda row: combine_text(str(row["subject"]), str(row["body"])), axis=1)
    test_text = test_frame.apply(lambda row: combine_text(str(row["subject"]), str(row["body"])), axis=1)

    vectorizer = TfidfVectorizer(ngram_range=(1, 2), lowercase=True, min_df=2, max_features=50000)
    x_train = vectorizer.fit_transform(train_text)
    x_test = vectorizer.transform(test_text)

    y_train = train_frame["label"].astype(int)
    y_test = test_frame["label"].astype(int)

    classifier = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42)
    classifier.fit(x_train, y_train)

    y_score = classifier.predict_proba(x_test)[:, 1]
    y_pred = (y_score >= 0.5).astype(int)
    metrics = compute_metrics(y_test, y_pred, y_score)

    return {
        "bundle": {"model": classifier, "vectorizer": vectorizer},
        "metrics": metrics,
        "train_rows": int(len(train_frame)),
        "test_rows": int(len(test_frame)),
        "base_model": "TFIDF+LogisticRegression",
        "artifact_name": "text_model.joblib",
        "train_frame": train_frame,
        "test_frame": test_frame,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the phishing email text model.")
    parser.add_argument("--model-type", default="tfidf", choices=["tfidf"])
    args = parser.parse_args()

    frame = load_dataset()

    if args.model_type != "tfidf":
        raise ValueError(f"unsupported model type: {args.model_type}")

    result = train_tfidf_baseline(frame)
    path = model_dir()
    artifact_path = path / result["artifact_name"]
    metadata_path = path / "text_model.json"
    report_path = path / "text_model_report.json"

    joblib.dump(result["bundle"], artifact_path)
    metadata = {
        "model_version": "text-tfidf-v1",
        "base_model": result["base_model"],
        "split_strategy": "grouped-by-exact-normalized-text",
        "trained_at": utc_now(),
        "samples_used": int(len(frame)),
        "train_rows": result["train_rows"],
        "test_rows": result["test_rows"],
        "metrics": result["metrics"],
        "artifact_uri": str(artifact_path),
    }
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
    save_json_report(
        report_path,
        {
            "model_version": metadata["model_version"],
            "dataset_summary": summarize_dataset(frame),
            "train_summary": summarize_dataset(result["train_frame"]),
            "test_summary": summarize_dataset(result["test_frame"]),
            "metrics": result["metrics"],
        },
    )

    print(json.dumps(metadata, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
