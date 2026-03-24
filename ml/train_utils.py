import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit, train_test_split


def compute_metrics(y_true, y_pred, y_score) -> dict:
    metrics = {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 6),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 6),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 6),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 6),
    }
    if len(set(y_true)) > 1:
        metrics["roc_auc"] = round(float(roc_auc_score(y_true, y_score)), 6)
    return metrics


def summarize_dataset(frame: pd.DataFrame, label_column: str = "label", source_column: str = "source") -> dict:
    summary = {
        "rows": int(len(frame)),
    }
    if label_column in frame.columns:
        label_counts = frame[label_column].value_counts(dropna=False).to_dict()
        summary["label_distribution"] = {str(key): int(value) for key, value in label_counts.items()}
    if source_column in frame.columns:
        source_counts = frame[source_column].value_counts().head(20).to_dict()
        summary["top_sources"] = {str(key): int(value) for key, value in source_counts.items()}
    return summary


def save_json_report(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def domain_group(url: str) -> str:
    host = (urlparse(str(url)).hostname or "").lower()
    if not host:
        return "unknown-host"
    parts = [part for part in host.split(".") if part]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def text_group(subject: str, body: str) -> str:
    normalized = f"{str(subject).strip().lower()}||{str(body).strip().lower()}"
    return hashlib.sha1(normalized.encode("utf-8", errors="ignore")).hexdigest()


def grouped_split(frame: pd.DataFrame, groups, test_size: float = 0.2, random_state: int = 42) -> tuple[pd.DataFrame, pd.DataFrame]:
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
    train_idx, test_idx = next(splitter.split(frame, groups=groups))
    train_frame = frame.iloc[train_idx].reset_index(drop=True)
    test_frame = frame.iloc[test_idx].reset_index(drop=True)
    return train_frame, test_frame


def stratified_fallback_split(frame: pd.DataFrame, test_size: float = 0.2, random_state: int = 42) -> tuple[pd.DataFrame, pd.DataFrame]:
    train_frame, test_frame = train_test_split(
        frame,
        test_size=test_size,
        random_state=random_state,
        stratify=frame["label"],
    )
    return train_frame.reset_index(drop=True), test_frame.reset_index(drop=True)
