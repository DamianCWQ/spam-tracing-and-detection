"""Stage 1 + 3: Ingest raw samples, select the study set, and write cleaned text and features.

Only this script (and the later tracing script) reads raw samples. Everything is parsed in memory;
nothing is opened, rendered or fetched. Only counts are printed, never subjects, addresses or bodies.

Run (from scripts/):
  ..\\.venv\\Scripts\\python.exe -I ingest.py <data/raw dir> <out dir> <frozen model .joblib> \\
      --ham hp,own-promotions,<promotions .mbox>,50 --ham hu,own-updates,<updates .mbox>,50 [--drop-ham ids.txt]

Outputs (in <out dir>):
  emails.csv           id, source, corpus, label, year, origin_file, origin_key, sha256   (pointer back to each raw message)
  clean.csv            id, label, text      text = subject + " " + body, redacted and defanged, NOT masked
  features.csv         id + technique features read from the raw message (HTML flags, URLs, attachments, ...)
  selection_report.csv per corpus: parsed, eligible, selected, failed
"""
import argparse, csv, hashlib, ipaddress, mailbox, random, re, sys
import email, email.policy, email.utils
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

import joblib

SEED = 42
MIN_TEXT_CHARS = 30
PLACEHOLDER = "[redacted]"   # must be out-of-vocabulary for the frozen models (checked at the end)

# Spam study set: corpus -> (how to read it, quota). 20+10+15+15 = 60 spam.
SPAM_SOURCES = {
    "nazario-2025":    ("mbox",  "nazario-2025/phishing-2025", 20),
    "nazario-2024":    ("mbox",  "nazario-2024/phishing-2024", 10),
    "guenter-2026-10": ("files", "guenter-2026-10-extracted",  15),
    "phishing-pot":    ("files", "phishing-pot",               15),
}

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
              "cutt.ly", "shorturl.at", "t.ly", "tiny.cc", "rb.gy", "lnkd.in"}

# ----------------------------------------------------------------------------- reading raw messages


def iter_raw(kind, path):
    """Yield (key, raw message bytes) without ever writing anything to disk."""
    if kind == "mbox":
        box = mailbox.mbox(path)
        for i, k in enumerate(box.iterkeys()):
            yield str(i), box.get_bytes(k)
    else:
        for f in sorted(Path(path).rglob("*.txt")):
            yield f.relative_to(path).as_posix(), f.read_bytes()


def parse(raw):
    return email.message_from_bytes(raw, policy=email.policy.default)


def part_text(part):
    """Decoded text of a text part; falls back to a lenient decode if the charset is bad."""
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        return payload.decode(part.get_content_charset() or "utf-8", errors="replace")


# ----------------------------------------------------------------------------- HTML (parsed as text only)


class Page(HTMLParser):
    """Collects visible text, links and images from HTML. Never fetches anything."""
    BLOCK = {"br", "p", "div", "tr", "td", "li", "table", "h1", "h2", "h3", "h4"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.chunks, self.links, self.imgs = [], [], []
        self._skip, self._href, self._anchor = 0, None, []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "a":
            self._href, self._anchor = a.get("href") or "", []
        elif tag == "img":
            self.imgs.append((a.get("width"), a.get("height"), a.get("style") or ""))
        if tag in self.BLOCK:
            self.chunks.append(" ")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._anchor).strip()))
            self._href = None
        if tag in self.BLOCK:
            self.chunks.append(" ")

    def handle_data(self, data):
        if not self._skip:
            self.chunks.append(data)
            if self._href is not None:
                self._anchor.append(data)

    def text(self):
        return " ".join("".join(self.chunks).split())


# ----------------------------------------------------------------------------- redaction and defanging
# Applied identically to spam and ham so a placeholder can never leak the label.
# URLs are defanged with brackets: http[:]//www[.]example[.]com has exactly the same tokens as the
# original URL, so the trained models see the same features (checked at the end).
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
PHONE_RE = re.compile(r"(?<![\w.])\+?\d(?:[\s().-]?\d){8,}(?![\w])")   # 9+ digits: phone and account numbers
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)


def defang_url(match):
    return match.group(0).replace("://", "[:]//").replace(".", "[.]")


def clean_text(subject, body):
    text = f"{subject} {body}"
    text = EMAIL_RE.sub(f" {PLACEHOLDER} ", text)
    text = PHONE_RE.sub(f" {PLACEHOLDER} ", text)
    text = URL_RE.sub(defang_url, text)
    text = re.sub(r"(https?)://", r"\1[:]//", text, flags=re.I)   # bare scheme left after an address inside a URL was redacted
    return " ".join(text.split())


# ----------------------------------------------------------------------------- per-message extraction
HIDDEN_RE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0"
                       r"|color\s*:\s*(?:#fff(?:fff)?\b|white)", re.I)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)


def host_of(url):
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def registrable(host):
    return ".".join(host.split(".")[-2:])   # crude (no public-suffix list); fine for a mismatch flag


def global_ips(header):
    found = re.findall(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])|\[([0-9a-f:]{3,})\]", str(header), re.I)
    out = []
    for v4, v6 in found:
        try:
            if ipaddress.ip_address(v4 or v6).is_global:
                out.append(v4 or v6)
        except ValueError:
            pass
    return out


def extract(raw):
    """Return (clean text, features dict, has_global_hop, year) for one raw message."""
    msg = parse(raw)
    subject = str(msg.get("Subject", "") or "")
    plain_part, html_part = msg.get_body(("plain",)), msg.get_body(("html",))
    plain = part_text(plain_part) if plain_part else ""
    html = part_text(html_part) if html_part else ""
    page = Page()
    if html:
        page.feed(html)
        page.close()
    body = plain if plain.strip() else page.text()   # hidden HTML text is kept when the message is HTML-only

    urls = {u for u in URL_RE.findall(f"{plain} {html}")} | {h for h, _ in page.links if h.lower().startswith("http")}
    hosts = {host_of(u) for u in urls} - {""}
    mismatch = any(
        (m := DOMAIN_RE.search(text)) and host_of(href) and registrable(m.group(0).lower()) != registrable(host_of(href))
        for href, text in page.links
    )
    attachments = [p.get_content_type() for p in msg.walk()
                   if not p.is_multipart() and (p.get_filename() or p.get_content_disposition() == "attachment")]

    received = msg.get_all("Received") or []
    date = email.utils.parsedate_to_datetime(str(msg["Date"]))   # raises if missing or bad -> counted as a failure
    text = clean_text(subject, body)
    features = {
        "has_plain": bool(plain.strip()), "has_html": bool(html.strip()),
        "html_only": bool(html.strip()) and not plain.strip(),
        "n_urls": len(urls), "n_hosts": len(hosts),
        "shortener": any(h in SHORTENERS for h in hosts),
        "punycode": any("xn--" in h for h in hosts),
        "link_mismatch": bool(mismatch),
        "n_images": len(page.imgs),
        "tracking_pixel": any((w in ("0", "1", "1px") or h in ("0", "1", "1px") or re.search(r"(?:width|height)\s*:\s*1px", s or "", re.I))
                              for w, h, s in page.imgs),
        "hidden_text": bool(HIDDEN_RE.search(html)),
        "n_attachments": len(attachments), "attachment_types": ";".join(sorted(set(attachments))),
        "n_received": len(received),
        "text_chars": len(text),
    }
    has_global_hop = any(global_ips(h) for h in received[1:])   # ignore the top hop: it is our own receiving server
    return text, features, has_global_hop, date.year


# ----------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("raw_dir"); ap.add_argument("out_dir"); ap.add_argument("model")
    ap.add_argument("--ham", action="append", required=True, metavar="PREFIX,CORPUS,MBOX,LIMIT",
                    help="a ham mbox, e.g. hp,own-promotions,path.mbox,50 (repeat for each set)")
    ap.add_argument("--drop-ham", help="text file with ham ids (hp007, hu012, ...) to exclude")
    args = ap.parse_args()
    raw_dir, out_dir = Path(args.raw_dir), Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    drop = set(Path(args.drop_ham).read_text().split()) if args.drop_ham else set()
    rng, report = random.Random(SEED), []

    index, clean, feats = [], [], []

    def add(id_, source, corpus, label, year, origin, key, raw, text, features):
        index.append(dict(id=id_, source=source, corpus=corpus, label=label, year=year, origin_file=origin,
                          origin_key=key, sha256=hashlib.sha256(raw).hexdigest()))
        clean.append(dict(id=id_, label=label, text=text))
        feats.append(dict(id=id_, **features))

    # ---- spam: read every message, keep the eligible ones, then pick a seeded quota per corpus
    seen_text, spam_rows = set(), []
    for corpus, (kind, rel, quota) in SPAM_SOURCES.items():
        parsed = failed = eligible = dup = 0
        pool = []
        for key, raw in iter_raw(kind, raw_dir / rel):
            try:
                text, features, hop, year = extract(raw)
            except Exception:
                failed += 1
                continue
            parsed += 1
            if not (hop and len(text) >= MIN_TEXT_CHARS):
                continue
            digest = hashlib.sha256(text.lower().encode()).hexdigest()
            if digest in seen_text:
                dup += 1
                continue
            seen_text.add(digest)
            eligible += 1
            pool.append((key, raw, text, features, year))
        picked = sorted(rng.sample(pool, min(quota, len(pool))), key=lambda r: (len(r[0]), r[0]))
        spam_rows += [(corpus, rel, *p) for p in picked]
        report.append(dict(corpus=corpus, parsed=parsed, failed=failed, duplicate_text=dup, eligible=eligible, selected=len(picked)))
        print(f"{corpus}: parsed={parsed} failed={failed} duplicate_text={dup} eligible={eligible} selected={len(picked)}")
    for n, (corpus, rel, key, raw, text, features, year) in enumerate(spam_rows, 1):
        add(f"s{n:03d}", "external", corpus, "spam", year, rel, key, raw, text, features)

    # ---- ham: each --ham set is read in full, then a seeded pick of at most `limit` messages is kept.
    # Ids follow the position in the mbox (e.g. hp007), so dropping or capping never renumbers anything.
    for spec in args.ham:
        prefix, corpus, path, limit = spec.split(",")
        failed = dropped = 0
        pool = []
        box = mailbox.mbox(path)
        for i, k in enumerate(box.iterkeys(), 1):
            id_ = f"{prefix}{i:03d}"
            if id_ in drop:
                dropped += 1
                continue
            raw = box.get_bytes(k)
            try:
                text, features, _, year = extract(raw)
            except Exception:
                failed += 1
                continue
            if len(text) < MIN_TEXT_CHARS:
                failed += 1
                continue
            pool.append((id_, i - 1, raw, text, features, year))
        picked = sorted(rng.sample(pool, min(int(limit), len(pool))))   # tuples sort by id first
        for id_, pos, raw, text, features, year in picked:
            add(id_, "own", corpus, "ham", year, Path(path).name, str(pos), raw, text, features)
        report.append(dict(corpus=corpus, parsed=len(pool), failed=failed, duplicate_text=0, eligible=len(pool), selected=len(picked)))
        print(f"{corpus}: eligible={len(pool)} failed_or_empty={failed} dropped_by_user={dropped} selected={len(picked)}")

    for name, rows in (("emails.csv", index), ("clean.csv", clean), ("features.csv", feats), ("selection_report.csv", report)):
        with open(out_dir / name, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)

    # ---- self-checks
    ids = [r["id"] for r in index]
    assert len(ids) == len(set(ids)), "duplicate ids"
    n_spam = sum(r["label"] == "spam" for r in index)
    print(f"written: {n_spam} spam + {len(index) - n_spam} ham -> {out_dir}")
    for r in clean:   # no live links or addresses may remain in the stored text
        assert not re.search(r"https?://", r["text"], re.I), f"live URL left in {r['id']}"
        assert not EMAIL_RE.search(r["text"]), f"email address left in {r['id']}"
    # Frozen models must see identical tokens for a URL and its defanged form, and must not know the placeholder.
    for name in ("combined_LinearSVM_mask_only", "combined_LinearSVM_mask_source_filter"):
        tfidf = joblib.load(Path(args.model).parent / f"{name}.joblib").named_steps["tfidf"]
        analyze = tfidf.build_analyzer()
        assert analyze("see http://www.example.com/a.php?x=1 now") == analyze("see http[:]//www[.]example[.]com/a[.]php?x=1 now"), name
        assert "redacted" not in tfidf.vocabulary_, f"placeholder is in the vocabulary of {name}"
    print("self-checks passed: unique ids, no live URLs/addresses, defanging keeps tokens, placeholder out-of-vocabulary")


if __name__ == "__main__":
    main()
