import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier

from serving.model import URL_FEATURE_ORDER, extract_url_features
from train_utils import compute_metrics, domain_group, grouped_split, save_json_report, stratified_fallback_split, summarize_dataset


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def processed_path() -> Path:
    return project_root() / "ml" / "data" / "processed" / "url_dataset.csv"


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
    if "url" not in frame.columns or "label" not in frame.columns:
        raise ValueError(f"dataset must contain url and label columns: {path}")
    frame = frame.dropna(subset=["url", "label"]).copy()
    return frame.drop_duplicates(subset=["url", "label"]).reset_index(drop=True)


def build_feature_frame(urls: pd.Series) -> pd.DataFrame:
    rows = [extract_url_features(url) for url in urls]
    feature_frame = pd.DataFrame(rows)
    return feature_frame[URL_FEATURE_ORDER]


def main() -> None:
    frame = load_dataset()
    groups = frame["url"].map(domain_group)
    try:
        train_frame, test_frame = grouped_split(frame, groups=groups, test_size=0.2, random_state=42)
    except ValueError:
        train_frame, test_frame = stratified_fallback_split(frame, test_size=0.2, random_state=42)

    x_train = build_feature_frame(train_frame["url"])
    x_test = build_feature_frame(test_frame["url"])
    y_train = train_frame["label"].astype(int)
    y_test = test_frame["label"].astype(int)

    model = HistGradientBoostingClassifier(
        learning_rate=0.08,
        max_depth=6,
        max_iter=300,
        early_stopping=False,
        random_state=42,
    )
    model.fit(x_train, y_train)

    y_score = model.predict_proba(x_test)[:, 1]
    y_pred = (y_score >= 0.5).astype(int)
    metrics = compute_metrics(y_test, y_pred, y_score)

    path = model_dir()
    model_path = path / "url_model.joblib"
    metadata_path = path / "url_model.json"
    report_path = path / "url_model_report.json"

    joblib.dump({"model": model}, model_path)
    metadata = {
        "model_version": "url-hgb-v1",
        "base_model": "HistGradientBoostingClassifier",
        "feature_order": URL_FEATURE_ORDER,
        "split_strategy": "grouped-by-registrable-domain",
        "trained_at": utc_now(),
        "samples_used": int(len(frame)),
        "train_rows": int(len(train_frame)),
        "test_rows": int(len(test_frame)),
        "metrics": metrics,
        "artifact_uri": str(model_path),
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
