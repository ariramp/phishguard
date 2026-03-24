# ML Data Layout

This folder stores local datasets before training.

## Folder Structure

```text
ml/data/
  raw/
    url/
      benchmark/
      phishing/
      legitimate/
    email/
      mixed/
      phishing/
      legitimate/
    fusion/
  processed/
```

## Where To Put Your Sources

### URL phishing

Put these into `raw/url/phishing/`:

- PhishTank CSV exports
- URLhaus CSV/TXT exports
- Kaggle phishing URL datasets

### URL legitimate

Put these into `raw/url/legitimate/`:

- benchmark CSV files that already contain benign URLs
- trusted URL lists you prepare separately

### URL benchmark

Put these into `raw/url/benchmark/`:

- mixed URL benchmark datasets that already contain both phishing and legitimate labels
- feature-rich CSV datasets with explicit `url` and `status/label`

### Email phishing

Put these into `raw/email/phishing/`:

- Nazario phishing email dataset
- Kaggle phishing email CSV files
- other phishing mail corpora with `subject/body/label` or similar fields

### Email legitimate

Put these into `raw/email/legitimate/`:

- Enron email dataset exports
- TREC07 ham subset exports
- other legitimate mail corpora

### Email mixed

Put these into `raw/email/mixed/` if one file already contains both phishing and legitimate labels.

### Fusion

Put these into `raw/fusion/` only if you already have a joined dataset with:

- `url`
- `subject`
- `body`
- `label`

If you do not have a joined dataset yet, `prepare_datasets.py` can synthesize a temporary fusion dataset from URL and email sets.

## Supported Input Formats

The normalizer can read:

- `.csv`
- `.tsv`
- `.txt` for simple one-URL-per-line lists

It tries to auto-detect common columns such as:

- URL: `url`, `link`, `domain`
- Subject: `subject`, `title`
- Body: `body`, `text`, `content`, `message`
- Label: `label`, `target`, `class`, `result`, `status`

## Outputs

After running preprocessing, these files are generated in `processed/`:

- `url_dataset.csv` with `url,label,source`
- `text_dataset.csv` with `subject,body,label,source`
- `fusion_dataset.csv` with `url,subject,body,label,source`
