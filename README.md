# Spam tracing and detection

Code, saved results and figures for COS30015 IT Security, Assignment 2 (Swinburne): trace 60 recent spam and phishing emails to their source, characterise 1,742 of them, and build and evaluate a Python spam detector.

This repository holds code and aggregate results only. It does not contain any email, raw or cleaned, any model file or any API key.

## What it does

| Part | Question | Where |
|---|---|---|
| Tracing | Where did 60 spam messages come from (handoff server, hosting, authentication, link host, campaigns)? | `notebooks/tracing.ipynb` |
| Characterisation | What language, topic, purpose and techniques do 1,742 spam messages show? | `notebooks/characterisation.ipynb` |
| Detection | How well do Naive Bayes, logistic regression and a linear SVM, trained on Enron + SpamAssassin, catch 2024-26 spam and keep 2025-26 mailing-list mail? How easily can an attacker evade them, and what does input normalising win back? | `notebooks/detection.ipynb` |

Evaluation A is the held-out 20% of each training corpus. Evaluation B is 1,742 external spam plus 1,720 public Apache mailing-list messages as ham, scored once. The linear SVM was named the primary model before any external scoring.

Headline external result (linear SVM): recall 0.781, specificity 0.983, precision 0.978, F1 0.869, AUC 0.967. Held-out F1 is 0.97 to 0.99, so the models do not transfer cleanly to newer mail.

## Layout

- `scripts/` steps that read raw mail or download data (run these first).
- `notebooks/` the three analyses above. They read only cleaned tables and are offline by default.
- `results/` metrics, predictions (scores only, no text) and run logs.
- `figures/` plots used in the report.

## Setup

Python 3.12, then `pip install -r requirements.txt`. Copy `.env.example` to `.env` and fill in the keys only if you want to re-run lookups online (`ONLINE=1` in `tracing.ipynb`); AbuseIPDB, VirusTotal and urlscan.io keys are read from there and never printed.

## Data (not included)

Download each set yourself into its own empty folder under `data/raw/` (and the training CSVs under `data/train/`), then run the scripts. The notebooks check their outputs against the saved files in `results/`, so they need the same data.

| Set | Role | Source |
|---|---|---|
| Nazario phishing corpus (2024, 2025) | spam, traced | https://monkey.org/~jose/phishing/ |
| Guenter spam archive (2026-10) | spam, traced | https://untroubled.org/spam/ |
| Phishing Pot (newest 60) | spam, traced | https://github.com/rf-peixoto/phishing_pot |
| Apache `users@` lists, 2025-11 to 2026-10 | ham | `scripts/download_ham_apache.py` (ASF public archive policy: https://www.apache.org/foundation/public-archives.html) |
| Enron and SpamAssassin CSVs (Champa et al., CC BY 4.0) | training | Zenodo record 8339691 |

Check each source's licence before reuse.

## Run order

From `scripts/`, with `python -I` for anything that reads raw mail: `download_ham_apache.py`, `ingest.py`, `build_traced_set.py`, `build_ham_apache.py`, `trace_parse.py`, `extract_traced_features.py`. Then, from `notebooks/`: `tracing.ipynb`, `characterisation.ipynb`, `detection.ipynb` (about 8 minutes). `RETRAIN=1` retrains the models into a separate folder and writes nothing else.

## Safety

The spam corpora contain live malicious content. Read them only in memory through Python, never open or render a message, attachment or HTML, never fetch a link from a sample and never contact a sender. Lookups are passive and send indicator strings only. Indicators in the results are defanged (`hxxp://`, `[.]`).

## Limits

Tracing covers 60 messages, so the infrastructure findings are indicative. Most Guenter headers are forged. The ham is plain-text developer mail on four lists, so specificity is not a general false-positive rate. Attribution rests on headers and public lookups and names no person.
