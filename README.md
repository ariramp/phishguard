# PhishGuard

PhishGuard is a local service for detecting phishing links in email.

## Stack

- Go backend for mailbox polling, parsing, storage, and API
- Python ML service for URL scoring, email text scoring, and final fusion
- PostgreSQL for persistence
- Docker Compose for local development
- Built-in web console served by the Go backend

## ML Pipeline

The current ML architecture uses three layers:

- `Model A`: URL classifier with engineered URL features
- Current implementation uses `HistGradientBoostingClassifier` for local compatibility on Windows/Python 3.13.
- `Model B`: email text classifier using `subject + body/snippet`
- `Model C`: fusion classifier that combines URL and text scores

## Training Workflow

1. Put raw datasets into [ml/data/README.md](/C:/Users/thank/projects/phishguard/ml/data/README.md) layout.
2. Run `python ml/prepare_datasets.py`.
3. If you do not have a joined `fusion` dataset yet, run `python ml/prepare_datasets.py --synthesize-fusion`.
4. Run `python ml/train_url_model.py`.
5. Run `python ml/train_text_model.py`.
6. Run `python ml/train_fusion_model.py`.
7. Start services with `docker compose up --build`.

## Suggested Mapping For Your Sources

- `PhishTank`, `URLhaus`, phishing URL Kaggle sets -> `ml/data/raw/url/phishing/`
- benign URL benchmarks -> `ml/data/raw/url/legitimate/`
- mixed URL benchmark CSV files -> `ml/data/raw/url/benchmark/`
- `Nazario`, phishing-email Kaggle sets -> `ml/data/raw/email/phishing/`
- `Enron`, `TREC07 ham` -> `ml/data/raw/email/legitimate/`
- mixed email CSV files with their own labels -> `ml/data/raw/email/mixed/`

## Notes

- The synthetic fusion dataset is acceptable as a temporary training fallback while we do not yet have a real linked corpus of `email + URL + final label`.
- When you later obtain a real joined corpus, place it into `ml/data/raw/fusion/` and rerun preprocessing.
- Training now saves extra evaluation reports in `ml_models/*_report.json` to make the metrics easier to justify in the diploma.
- URL evaluation uses a domain-grouped split, and text evaluation uses grouped exact-text splits to reduce leakage between train and test.

Generated model artifacts are stored in `ml_models/` and mounted into the Python serving container.

## Web Console

Open `http://localhost:8080/` after `docker compose up --build`.

The interface currently supports:

- viewing service statistics
- viewing timeseries data
- adding IMAP accounts
- triggering manual polling from the interface
- viewing the latest phishing detection history
