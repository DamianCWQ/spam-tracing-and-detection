"""Make the two plain-text files for the manual trace check (10 messages, seed 42). Reads raw headers in memory only.

  data/validation/headers_to_check.txt  the Received / Authentication-Results / Received-SPF lines of each message,
                                        email addresses removed and IPv4 dots defanged. NO script answers, no body text.
  data/validation/answers.txt           a blank form (never overwritten if it exists)

Run (from the project folder):  python -I scripts\\make_validation_files.py      (data/ is git-ignored)
"""
import csv, hashlib, re, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))   # -I drops the script folder from sys.path
from ingest import parse                          # noqa: E402
from trace_parse import raw_for                   # noqa: E402

RAW, PROC, OUT = Path("data/raw"), Path("data/processed"), Path("data/validation")
ids = [r["id"] for r in csv.DictReader(open("results/trace_validation_sheet.csv", encoding="utf-8"))]
index = {r["id"]: r for r in csv.DictReader(open(PROC / "emails.csv", encoding="utf-8"))}

ADDR = re.compile(r"[\w.+'-]+@[\w.-]+")
IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
tidy = lambda value: IPV4.sub(r"\1[.]\2[.]\3[.]\4", ADDR.sub("[addr]", " ".join(str(value).split())))

RULES = """HOW TO READ THESE (the report's rules; apply them yourself, do not open or render any message)
  Hops are listed TOP (newest, nearest the recipient) to BOTTOM (oldest). Each Received line says "from <sender host> ([IP]) by <receiving host>".
  handoff IP : the sending IP in the FIRST hop from the top whose IP is public (not 10.x / 172.16-31.x / 192.168.x / 127.x / fe80 / ::1),
               skipping hops where both the "from" and "by" servers belong to the receiving provider itself (its own internal relays).
  claimed IP : the LOWEST public sending IP in the whole chain (the oldest hop). If nothing public sits below the handoff, it is the handoff IP.
  spf        : the spf= result in the TOPMOST Authentication-Results line (pass, fail, softfail, neutral, temperror, permerror).
               If there is no Authentication-Results line, or it has no spf= part, write: none
  Type IPs defanged exactly as shown here, e.g. 96[.]125[.]168[.]36 (the check compares text exactly). Leave blank if there is none.
"""

OUT.mkdir(parents=True, exist_ok=True)
lines = [RULES]
for sid in ids:
    row = index[sid]
    raw = raw_for(RAW, row)
    assert hashlib.sha256(raw).hexdigest() == row["sha256"], f"hash mismatch for {sid}"
    msg = parse(raw)
    lines += ["", "=" * 100, f"{sid}   ({row['corpus']})", "=" * 100]
    received = msg.get_all("Received") or []
    lines.append(f"Received hops: {len(received)} (top = newest)")
    lines += [f"  [{n}] {tidy(h)}" for n, h in enumerate(received, 1)]
    for name in ("Authentication-Results", "Received-SPF"):
        values = msg.get_all(name) or []
        lines.append(f"{name}: {len(values)} header(s)" + ("  <- none present" if not values else ""))
        lines += [f"  ({n}) {tidy(v)}" for n, v in enumerate(values, 1)]
(OUT / "headers_to_check.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

answers = OUT / "answers.txt"
if not answers.exists():
    form = ["Fill in after each colon, then tell Claude 'done'. Defanged IPs as in headers_to_check.txt. spf: pass/fail/softfail/neutral/temperror/permerror/none", ""]
    for sid in ids:
        form += [sid, "  handoff_ip: ", "  claimed_ip: ", "  spf: ", ""]
    answers.write_text("\n".join(form), encoding="utf-8")
    print("created", answers)
else:
    print("kept your existing", answers)
text = (OUT / "headers_to_check.txt").read_text(encoding="utf-8")
print("wrote", OUT / "headers_to_check.txt", f"({len(ids)} messages, {len(text.splitlines())} lines, '@' count {text.count('@')})")
