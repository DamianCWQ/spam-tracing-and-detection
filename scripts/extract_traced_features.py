r"""Raw-mail stage for section 3.1 (characterisation): recompute the HTML and attachment features of the 1,742 traced messages.

This is the ONLY step of the characterisation that reads raw mail (HTML, attachments), so it stays a script run in isolated mode.
Everything else (language, topic, techniques, figures) is in notebooks/characterisation.ipynb and reads only cleaned text and this
file. Messages are matched to traced_all.csv by the SHA-256 of the raw bytes, and the re-extracted text is asserted equal to the
text in traced_all.csv. Writes data/processed/traced_features.csv: id plus counts and flags (no text, subject or address).

Run (from scripts/):  ..\.venv\Scripts\python.exe -I extract_traced_features.py ..\data\raw ..\data\processed
"""
import hashlib
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))
from ingest import SPAM_SOURCES, extract, iter_raw   # noqa: E402


def main():
    raw_dir, proc = (Path(a) for a in sys.argv[1:3])
    traced = pd.read_csv(proc / "traced_all.csv", dtype=str, keep_default_na=False)
    by_hash = {}
    for corpus, (kind, rel, _) in SPAM_SOURCES.items():
        for _, raw in iter_raw(kind, raw_dir / rel):
            by_hash[hashlib.sha256(raw).hexdigest()] = raw
    assert traced.sha256.isin(by_hash).all(), "some traced messages were not found in the raw corpora"

    rows = []
    for r in traced.itertuples():
        text, feats, _, _ = extract(by_hash[r.sha256])
        assert text == r.text, f"{r.id}: re-extracted text differs from traced_all.csv"
        rows.append(dict(id=r.id, **feats))
    df = pd.DataFrame(rows)
    assert len(df) == 1742 and df.id.is_unique and not df.apply(lambda c: c.astype(str).str.contains("@")).any().any()
    df.to_csv(proc / "traced_features.csv", index=False)
    print(f"wrote traced_features.csv: {len(df)} messages, columns {list(df.columns)}")


if __name__ == "__main__":
    main()
