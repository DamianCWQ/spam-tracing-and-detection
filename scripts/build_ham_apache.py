r"""Build the public-ham half of Test 3b from the 48 Apache users@ mbox files (data/raw/ham-apache).

Same extraction, redaction and defanging as the spam (ingest.extract), so nothing differs between the classes except the mail.
Drops only: bot-like senders (JIRA/GitHub/noreply...), unparseable (extract needs a valid Date), too short, exact duplicate text.
Each message gets a `thread` id (first Reference, else its own Message-ID) for thread-aware intervals, and two texts:
  text           = as extracted (PRIMARY, identical pipeline to the spam)
  text_stripped  = same minus quoted reply lines ('>') and list-footer lines (SENSITIVITY: removes ham-only boilerplate)
Writes data/processed/ham_apache.csv  id, list, year, origin_key, sha256, thread, text, text_stripped. Prints counts only.

Run (from scripts/):  ..\.venv\Scripts\python.exe -I build_ham_apache.py ..\data\raw ..\data\processed
"""
import csv, hashlib, re, sys
from collections import Counter
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))
from ingest import MIN_TEXT_CHARS, clean_text, extract, iter_raw, parse, part_text   # noqa: E402

BOT_RE = re.compile(r"jira|github|gitbox|noreply|no-reply|bugzilla|notifications", re.I)
FOOTER_RE = re.compile(r"unsubscribe|-help@|list-help|mailing list|mailto:", re.I)
digest = lambda t: hashlib.sha256(t.lower().encode()).hexdigest()   # same duplicate rule as ingest.py


def stripped_text(raw):
    """Body of a message without quoted lines and list-footer lines, cleaned like the primary text."""
    msg = parse(raw)
    part = msg.get_body(("plain",))
    body = part_text(part) if part else ""
    if not body.strip():
        return ""   # HTML-only: no stripped variant, caller falls back to the primary text
    keep = [ln for ln in body.splitlines() if not ln.lstrip().startswith(">") and not FOOTER_RE.search(ln)]
    return clean_text(str(msg.get("Subject", "") or ""), "\n".join(keep))


def main():
    raw_dir, proc = Path(sys.argv[1]) / "ham-apache", Path(sys.argv[2])
    rows, why = [], Counter()
    for f in sorted(raw_dir.rglob("*.mbox")):
        for key, raw in iter_raw("mbox", f):
            msg = parse(raw)
            if BOT_RE.search(str(msg.get("From") or "") + str(msg.get("X-Mailer") or "")):
                why["bot-like sender"] += 1
                continue
            try:
                text, _, _, year = extract(raw)
            except Exception:
                why["unparseable (extract needs a valid Date)"] += 1
                continue
            if len(text) < MIN_TEXT_CHARS:
                why["too short"] += 1
                continue
            refs = str(msg.get("References") or "").split()
            thread = refs[0] if refs else str(msg.get("Message-ID") or "").strip()
            alt = stripped_text(raw) or text
            rows.append(dict(list=f.parent.name, year=year, origin_key=f"{f.name}:{key}",
                             sha256=hashlib.sha256(raw).hexdigest(), thread=thread, text=text, text_stripped=alt))
    df = pd.DataFrame(rows)
    before = len(df)
    df = df[~df.text.map(digest).duplicated()].reset_index(drop=True)
    why["duplicate text"] = before - len(df)
    # thread id -> short stable label (no Message-ID text kept)
    order = {t: f"th{i:04d}" for i, t in enumerate(dict.fromkeys(df.thread))}
    df["thread"] = df.thread.map(order)
    df.insert(0, "id", [f"ha{i:04d}" for i in range(1, len(df) + 1)])
    df.to_csv(proc / "ham_apache.csv", index=False, quoting=csv.QUOTE_NONNUMERIC)

    assert df.sha256.is_unique and df.text.map(digest).is_unique
    for c in ("text", "text_stripped"):
        assert df[c].str.contains(r"https?://", case=False, regex=True).sum() == 0, f"live URL left in {c}"
        assert df[c].str.contains(r"[\w.+-]+@[\w-]+\.[\w.-]+", regex=True).sum() == 0, f"email address left in {c}"
    short = (df.text_stripped.str.len() < MIN_TEXT_CHARS).sum()
    print(f"ham set: {len(df)} messages -> ham_apache.csv; by list {df.list.value_counts().to_dict()}; "
          f"by year {df.year.value_counts().sort_index().to_dict()}")
    print(f"threads: {df.thread.nunique()} (largest {df.thread.value_counts().max()}); stripped text differs for "
          f"{int((df.text != df.text_stripped).sum())}; stripped text under {MIN_TEXT_CHARS} chars: {int(short)}")
    print(f"median chars: text {int(df.text.str.len().median())}, stripped {int(df.text_stripped.str.len().median())}")
    for reason, n in why.items():
        print(f"  skipped {n:4d}  {reason}")


if __name__ == "__main__":
    main()
