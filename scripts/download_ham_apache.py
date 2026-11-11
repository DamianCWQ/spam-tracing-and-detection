"""Download monthly mbox files for 4 Apache users@ lists (ham). Bytes are saved, never parsed or opened.
Run:  .venv\\Scripts\\python.exe -I scripts\\download_ham_apache.py
Polite: one request at a time, 3 s apart. Skips files that already exist. Appends to data/raw/downloads.csv.
"""
import csv, hashlib, time, urllib.request, urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "data" / "raw"
OUT = ROOT / "ham-apache"
LISTS = {"httpd": "httpd.apache.org", "tomcat": "tomcat.apache.org",
         "spamassassin": "spamassassin.apache.org", "kafka": "kafka.apache.org"}
MONTHS = ["2025-11", "2025-12"] + [f"2026-{m:02d}" for m in range(1, 11)]  # approved range
URL = "https://lists.apache.org/api/mbox.lua?list=users&domain={dom}&d={d}"
DELAY = 3  # seconds between requests (mail-archives.apache.org robots asks for crawl-delay)

rows = []
for name, dom in LISTS.items():
    (OUT / name).mkdir(parents=True, exist_ok=True)
    for d in MONTHS:
        dest = OUT / name / f"{name}-users-{d}.mbox"
        if dest.exists():
            continue
        url = URL.format(dom=dom, d=d)
        req = urllib.request.Request(url, headers={"User-Agent": "swinburne-cos30015-student-research"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                data = r.read()
        except urllib.error.URLError as e:
            print("FAIL", name, d, e)
            time.sleep(DELAY)
            continue
        dest.write_bytes(data)
        rows.append([url, str(dest.relative_to(ROOT)), len(data), hashlib.sha256(data).hexdigest()])
        print("ok", name, d, len(data))
        time.sleep(DELAY)

if rows:
    with open(ROOT / "downloads.csv", "a", newline="") as f:
        csv.writer(f, quoting=csv.QUOTE_ALL).writerows(rows)
print("saved", len(rows))
