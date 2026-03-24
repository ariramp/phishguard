import argparse
import random
from io import StringIO
from pathlib import Path

import pandas as pd


URL_COLUMN_HINTS = {"url", "link", "domain", "href"}
TEXT_SUBJECT_HINTS = {"subject", "title"}
TEXT_BODY_HINTS = {"body", "text", "content", "message", "email"}
LABEL_HINTS = {"label", "target", "class", "result", "is_phishing", "status"}

PHISHING_VALUES = {"1", "true", "phishing", "spam", "malicious", "bad", "yes", "phish"}
LEGIT_VALUES = {"0", "false", "legitimate", "legit", "ham", "benign", "safe", "good", "no"}


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def data_root() -> Path:
    return project_root() / "ml" / "data"


def raw_root() -> Path:
    return data_root() / "raw"


def processed_root() -> Path:
    path = data_root() / "processed"
    path.mkdir(parents=True, exist_ok=True)
    return path


def iter_data_files(folder: Path) -> list[Path]:
    if not folder.exists():
        return []
    files = []
    for pattern in ("*.csv", "*.tsv", "*.txt"):
        files.extend(folder.rglob(pattern))
    return sorted(files)


def detect_separator(path: Path) -> str:
    if path.suffix.lower() == ".tsv":
        return "\t"
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        sample = handle.read(2048)
    if sample.count("\t") > sample.count(","):
        return "\t"
    return ","


def read_table(path: Path) -> pd.DataFrame:
    preview_lines = []
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for _ in range(50):
            line = handle.readline()
            if not line:
                break
            stripped = line.strip()
            if stripped:
                preview_lines.append(stripped)

    if path.suffix.lower() == ".txt":
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            data_lines = [line.strip() for line in handle if line.strip() and not line.startswith("#")]
        if data_lines and "," in data_lines[0]:
            return pd.read_csv(StringIO("\n".join(data_lines)), low_memory=False)
        return pd.DataFrame({"url": data_lines})

    if preview_lines and "," in preview_lines[0]:
        first_fields = [field.strip() for field in preview_lines[0].split(",")]
        if len(first_fields) == 2 and first_fields[0].isdigit() and "." in first_fields[1]:
            return pd.read_csv(path, names=["rank", "url"], header=None, low_memory=False)

    sep = detect_separator(path)
    try:
        return pd.read_csv(path, sep=sep, comment="#", low_memory=False)
    except pd.errors.ParserError:
        # Some public email corpora contain malformed quoted lines; the Python engine
        # is slower but much more tolerant for one-time dataset normalization.
        return pd.read_csv(path, sep=sep, comment="#", engine="python", on_bad_lines="skip")


def clean_text(value) -> str:
    if pd.isna(value):
        return ""
    return str(value).strip()


def normalize_url_value(value) -> str:
    text = clean_text(value)
    if not text:
        return ""
    if text.startswith(("http://", "https://")):
        return text
    if "." in text and " " not in text:
        return f"https://{text}"
    return text


def normalize_label(value, default: int | None = None) -> int | None:
    if pd.isna(value):
        return default

    text = clean_text(value).lower()
    if text in PHISHING_VALUES:
        return 1
    if text in LEGIT_VALUES:
        return 0

    try:
        return 1 if int(float(text)) == 1 else 0
    except Exception:
        return default


def pick_column(columns: list[str], hints: set[str]) -> str | None:
    lowered = {column.lower(): column for column in columns}
    for hint in hints:
        for lower, original in lowered.items():
            if hint == lower or hint in lower:
                return original
    return None


def select_url_column(frame: pd.DataFrame) -> str | None:
    columns = list(frame.columns)
    candidate = pick_column(columns, URL_COLUMN_HINTS)
    if candidate:
        return candidate
    for column in columns:
        series = frame[column].astype(str)
        if series.str.contains(r"https?://", regex=True, na=False).mean() > 0.1:
            return column
    return None


def select_subject_column(frame: pd.DataFrame) -> str | None:
    return pick_column(list(frame.columns), TEXT_SUBJECT_HINTS)


def select_body_column(frame: pd.DataFrame) -> str | None:
    columns = list(frame.columns)
    candidate = pick_column(columns, TEXT_BODY_HINTS)
    if candidate:
        return candidate
    text_columns = [
        column for column in columns
        if frame[column].dtype == object and frame[column].astype(str).str.len().mean() > 30
    ]
    return text_columns[0] if text_columns else None


def select_label_column(frame: pd.DataFrame) -> str | None:
    return pick_column(list(frame.columns), LABEL_HINTS)


def normalize_url_frame(path: Path, default_label: int | None = None) -> pd.DataFrame:
    frame = read_table(path)
    url_column = select_url_column(frame)
    label_column = select_label_column(frame)

    if url_column is None:
        raise ValueError(f"could not detect URL column in {path}")

    normalized = pd.DataFrame(
        {
            "url": frame[url_column].map(normalize_url_value),
            "label": frame[label_column].map(lambda value: normalize_label(value, default_label))
            if label_column
            else default_label,
            "source": path.stem,
        }
    )
    normalized = normalized.dropna(subset=["label"])
    normalized = normalized[normalized["url"] != ""]
    normalized["label"] = normalized["label"].astype(int)
    return normalized


def normalize_text_frame(path: Path, default_label: int | None = None) -> pd.DataFrame:
    frame = read_table(path)
    subject_column = select_subject_column(frame)
    body_column = select_body_column(frame)
    label_column = select_label_column(frame)

    if body_column is None:
        raise ValueError(f"could not detect body column in {path}")

    normalized = pd.DataFrame(
        {
            "subject": frame[subject_column].map(clean_text) if subject_column else "",
            "body": frame[body_column].map(clean_text),
            "label": frame[label_column].map(lambda value: normalize_label(value, default_label))
            if label_column
            else default_label,
            "source": path.stem,
        }
    )
    normalized = normalized.dropna(subset=["label"])
    normalized = normalized[normalized["body"] != ""]
    normalized["label"] = normalized["label"].astype(int)
    return normalized


def normalize_fusion_frame(path: Path, default_label: int | None = None) -> pd.DataFrame:
    frame = read_table(path)
    url_column = select_url_column(frame)
    subject_column = select_subject_column(frame)
    body_column = select_body_column(frame)
    label_column = select_label_column(frame)

    if url_column is None or body_column is None:
        raise ValueError(f"could not detect fusion columns in {path}")

    normalized = pd.DataFrame(
        {
            "url": frame[url_column].map(normalize_url_value),
            "subject": frame[subject_column].map(clean_text) if subject_column else "",
            "body": frame[body_column].map(clean_text),
            "label": frame[label_column].map(lambda value: normalize_label(value, default_label))
            if label_column
            else default_label,
            "source": path.stem,
        }
    )
    normalized = normalized.dropna(subset=["label"])
    normalized = normalized[(normalized["url"] != "") & (normalized["body"] != "")]
    normalized["label"] = normalized["label"].astype(int)
    return normalized


def collect_url_dataset() -> pd.DataFrame:
    parts = []
    for path in iter_data_files(raw_root() / "url" / "phishing"):
        parts.append(normalize_url_frame(path, default_label=1))
    for path in iter_data_files(raw_root() / "url" / "legitimate"):
        parts.append(normalize_url_frame(path, default_label=0))
    for path in iter_data_files(raw_root() / "url" / "benchmark"):
        parts.append(normalize_url_frame(path))
    if not parts:
        return pd.DataFrame(columns=["url", "label", "source"])
    dataset = pd.concat(parts, ignore_index=True)
    dataset = dataset.drop_duplicates(subset=["url", "label"])
    return dataset.sample(frac=1.0, random_state=42).reset_index(drop=True)


def collect_text_dataset() -> pd.DataFrame:
    parts = []
    for path in iter_data_files(raw_root() / "email" / "phishing"):
        parts.append(normalize_text_frame(path, default_label=1))
    for path in iter_data_files(raw_root() / "email" / "legitimate"):
        parts.append(normalize_text_frame(path, default_label=0))
    for path in iter_data_files(raw_root() / "email" / "mixed"):
        parts.append(normalize_text_frame(path))
    if not parts:
        return pd.DataFrame(columns=["subject", "body", "label", "source"])
    dataset = pd.concat(parts, ignore_index=True)
    dataset = dataset.drop_duplicates(subset=["subject", "body", "label"])
    return dataset.sample(frac=1.0, random_state=42).reset_index(drop=True)


def collect_fusion_dataset() -> pd.DataFrame:
    parts = []
    for path in iter_data_files(raw_root() / "fusion"):
        parts.append(normalize_fusion_frame(path))
    if not parts:
        return pd.DataFrame(columns=["url", "subject", "body", "label", "source"])
    dataset = pd.concat(parts, ignore_index=True)
    dataset = dataset.drop_duplicates(subset=["url", "subject", "body", "label"])
    return dataset.sample(frac=1.0, random_state=42).reset_index(drop=True)


def synthesize_fusion_dataset(url_dataset: pd.DataFrame, text_dataset: pd.DataFrame, samples_per_class: int = 2000) -> pd.DataFrame:
    if url_dataset.empty or text_dataset.empty:
        return pd.DataFrame(columns=["url", "subject", "body", "label", "source"])

    random.seed(42)
    rows = []
    for label in (0, 1):
        url_rows = url_dataset[url_dataset["label"] == label].reset_index(drop=True)
        text_rows = text_dataset[text_dataset["label"] == label].reset_index(drop=True)
        if url_rows.empty or text_rows.empty:
            continue

        target_size = min(samples_per_class, len(url_rows), len(text_rows))
        url_indices = random.sample(range(len(url_rows)), target_size) if len(url_rows) >= target_size else list(range(len(url_rows)))
        text_indices = random.sample(range(len(text_rows)), target_size) if len(text_rows) >= target_size else list(range(len(text_rows)))

        for url_idx, text_idx in zip(url_indices, text_indices):
            url_item = url_rows.iloc[url_idx]
            text_item = text_rows.iloc[text_idx]
            rows.append(
                {
                    "url": url_item["url"],
                    "subject": text_item["subject"],
                    "body": text_item["body"],
                    "label": label,
                    "source": f"synthetic::{url_item['source']}+{text_item['source']}",
                }
            )

    if not rows:
        return pd.DataFrame(columns=["url", "subject", "body", "label", "source"])

    dataset = pd.DataFrame(rows)
    dataset = dataset.drop_duplicates(subset=["url", "subject", "body", "label"])
    return dataset.sample(frac=1.0, random_state=42).reset_index(drop=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize raw phishing datasets into training-ready CSV files.")
    parser.add_argument(
        "--synthesize-fusion",
        action="store_true",
        help="Create a synthetic fusion dataset from URL and email datasets when raw fusion data is absent.",
    )
    parser.add_argument(
        "--fusion-samples-per-class",
        type=int,
        default=2000,
        help="Maximum synthetic fusion samples to create per class.",
    )
    args = parser.parse_args()

    processed = processed_root()
    url_dataset = collect_url_dataset()
    text_dataset = collect_text_dataset()
    fusion_dataset = collect_fusion_dataset()

    if fusion_dataset.empty and args.synthesize_fusion:
        fusion_dataset = synthesize_fusion_dataset(
            url_dataset,
            text_dataset,
            samples_per_class=args.fusion_samples_per_class,
        )

    url_path = processed / "url_dataset.csv"
    text_path = processed / "text_dataset.csv"
    fusion_path = processed / "fusion_dataset.csv"

    url_dataset.to_csv(url_path, index=False)
    text_dataset.to_csv(text_path, index=False)
    fusion_dataset.to_csv(fusion_path, index=False)

    print(f"url rows: {len(url_dataset)} -> {url_path}")
    print(f"text rows: {len(text_dataset)} -> {text_path}")
    print(f"fusion rows: {len(fusion_dataset)} -> {fusion_path}")


if __name__ == "__main__":
    main()
