r"""Counts-only profile of data/raw/ham-apache (no subjects, addresses or bodies printed).
Run from repo root: .venv\Scripts\python.exe -I scripts\profile_ham_apache.py data\raw\ham-apache
"""
import sys, mailbox, collections, email.utils, re
from pathlib import Path

root = Path(sys.argv[1])
tot = collections.Counter()
for lst in sorted(p for p in root.iterdir() if p.is_dir()):
    c = collections.Counter(); ids = set(); years = collections.Counter(); sizes = []
    for f in sorted(lst.glob("*.mbox")):
        for m in mailbox.mbox(str(f)):
            c["msgs"] += 1
            mid = (m.get("Message-ID") or "").strip()
            if mid in ids: c["dup_msgid"] += 1
            ids.add(mid)
            if m.get("Received"): c["has_received"] += 1
            if m.get("Authentication-Results") or m.get("ARC-Authentication-Results"): c["has_auth"] += 1
            if m.get("List-Id"): c["has_listid"] += 1
            try: d = email.utils.parsedate_to_datetime(str(m["Date"])) if m.get("Date") else None
            except Exception: d = None
            if d: years[d.year] += 1
            else: c["no_date"] += 1
            txt = [p for p in m.walk() if p.get_content_type() == "text/plain"]
            htm = [p for p in m.walk() if p.get_content_type() == "text/html"]
            if htm and not txt: c["html_only"] += 1
            if any(p.get_filename() for p in m.walk()): c["attachment"] += 1
            if m.is_multipart() is False and not m.get_payload(): c["empty"] += 1
            # machine-generated senders (header pattern only; never printed)
            if re.search(r"(jira|github|gitbox|noreply|no-reply|bugzilla|notifications)", str(m.get("From") or "") + str(m.get("X-Mailer") or ""), re.I):
                c["botlike_from"] += 1
            if m.get("In-Reply-To") or m.get("References"): c["reply"] += 1
            sizes.append(len(m.as_bytes()))
    sizes.sort()
    print(lst.name, dict(c), "years", dict(years), "median_bytes", sizes[len(sizes)//2] if sizes else 0)
    tot.update(c)
print("TOTAL", dict(tot))
