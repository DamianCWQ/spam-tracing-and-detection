"""Stage 2a: parse the Received chain and sender headers of the 60 spam. Offline: no network.

Reads the raw messages in memory (located through emails.csv, hash-checked) and writes:
  trace_headers.csv  one row per spam: handoff IP, claimed origin IP, auth results, sender/link domains, forgery flags
  trace_hops.csv     one row per Received hop (id, hop 0 = top, from/by host, IP, time, role)

Trust model (see the project plan, not in this repo): each server prepends a Received line, so the chain reads bottom to top.
  hops above the handoff : the recipient's own internal relays (private IPs, same-organisation hops)  -> role "internal"
  the handoff hop        : written by the receiving side; its from-IP is the last trustworthy address   -> role "handoff"
  hops below the handoff : written by whoever sent the message; any of it can be forged                -> role "claimed"
claimed_origin_ip is the bottom-most global IP, kept separate from handoff_ip and never merged with it.

Only domains are stored (no address local parts, no To/Cc, no "for <addr>" clauses): Nazario 2024/2025 is not anonymised.

Run (from scripts/):  ..\\.venv\\Scripts\\python.exe -I trace_parse.py ..\\data\\raw ..\\data\\processed
"""
import csv, hashlib, ipaddress, mailbox, re, sys
import email.utils
from collections import Counter
from datetime import timezone
from pathlib import Path
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).parent))   # -I drops the script folder from sys.path
from ingest import SPAM_SOURCES, URL_RE, Page, host_of, parse, part_text   # noqa: E402

BACKWARDS_SLACK_S = 300   # a lower hop may be at most 5 minutes later than the hop above it (clock skew)
IP_RE = re.compile(r"(?<![\w:.])((?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4})(?![\w:])", re.I)
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "edu", "ac"}
# Link hosts that say nothing about the campaign (page boilerplate) are skipped when choosing the pivot host.
IGNORE_LINK_HOSTS = {"www.w3.org", "fonts.googleapis.com", "fonts.gstatic.com", "schemas.microsoft.com", "www.google.com", "twitter.com"}
# Legitimate services that spam abuses for hosting/redirecting: a domain-age or reputation lookup on them is meaningless.
ABUSED_SERVICES = ("storage.googleapis.com", "docs.google.com", "ipfs.io", "cf-ipfs.com", "4everland.link", "netlify.app",
                   "vercel.app", "replit.app", "glitch.me", "dropbox.com", "cloudfront.net", "hs-sites-eu1.com",
                   "tinyurl.com", "rb.gy", "bit.ly", "zoom.us")
ORG_ALIAS = {"office365.com": "outlook.com", "office.com": "outlook.com", "microsoft.com": "outlook.com",
             "googlemail.com": "google.com", "gmail.com": "google.com"}   # one provider, several domains


def org_of(host):
    """Registrable domain, crude (no public-suffix list) but aware of co.uk-style names."""
    p = [x for x in host.lower().strip(".").split(".") if x]
    if len(p) < 2 or all(x.isdigit() for x in p):
        return ""
    org = ".".join(p[-3:] if len(p) >= 3 and p[-2] in SECOND_LEVEL and len(p[-1]) == 2 else p[-2:])
    return ORG_ALIAS.get(org, org)


def domain_of_addr(value):
    addr = email.utils.parseaddr(str(value or ""))[1]
    return addr.rsplit("@", 1)[1].lower() if "@" in addr else ""


def last_ip(text):
    ips = []
    for cand in IP_RE.findall(text):
        try:
            ips.append(ipaddress.ip_address(cand))
        except ValueError:
            pass
    return ips[-1] if ips else None


def parse_hop(header):
    """One Received header -> dict(from_host, from_ip, by_host, with_, ts). Missing parts are empty."""
    s = " ".join(str(header).split())
    body, _, date = s.rpartition(";")
    if not body:
        body, date = s, ""
    m = re.match(r"(?i)from\s+(.*?)(?:\s+by\s+|$)", body)
    from_clause = m.group(1) if m else ""
    by = re.search(r"(?i)\bby\s+(\S+)", body)
    wth = re.search(r"(?i)\bwith\s+(.*?)(?:\s+id\s|\s+for\s|$)", body)
    try:
        ts = email.utils.parsedate_to_datetime(date.strip())
    except (TypeError, ValueError):
        ts = None
    if ts and ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)   # a date without a zone is assumed UTC
    ip = last_ip(from_clause)
    helo = from_clause.split(" ", 1)[0].strip("[]()") if from_clause else ""
    return dict(from_host=helo, from_ip=ip, by_host=(by.group(1).strip("();") if by else ""),
                with_=(re.sub(r"\S*@\S*", "<addr>", wth.group(1)) if wth else ""), ts=ts)   # envelope addresses can sit in this clause


def mark_roles(hops):
    """Set hop['role'] and return the index of the handoff hop (or None)."""
    receiver = next((org_of(h["by_host"]) for h in hops if org_of(h["by_host"])), "")
    handoff = None
    for i, h in enumerate(hops):
        transport = re.search(r"(?i)frontend transport|mailbox transport|mapi", h["with_"])
        same_org = receiver and org_of(h["from_host"]) == receiver and org_of(h["by_host"]) == receiver
        if handoff is None and h["from_ip"] and h["from_ip"].is_global and not transport and not same_org:
            handoff = i
        h["role"] = "internal" if handoff is None else ("handoff" if i == handoff else "claimed")
    return handoff


def auth(msg):
    """spf/dkim/dmarc from the TOPMOST Authentication-Results header only (spammers insert fake ones lower down)."""
    top = str((msg.get_all("Authentication-Results") or [""])[0])
    out = {k: (re.search(rf"\b{k}=(\w+)", top, re.I) or [None, ""])[1].lower() for k in ("spf", "dkim", "dmarc")}
    rspf = str((msg.get_all("Received-SPF") or [""])[0]).split(" ", 1)[0].lower()
    return out, rspf


def link_hosts(msg):
    plain_part, html_part = msg.get_body(("plain",)), msg.get_body(("html",))
    plain = part_text(plain_part) if plain_part else ""
    html = part_text(html_part) if html_part else ""
    page = Page()
    if html:
        page.feed(html)
        page.close()
    urls = set(URL_RE.findall(f"{plain} {html}")) | {h for h, _ in page.links if h.lower().startswith("http")}
    return Counter(h for h in (real_host(u) for u in urls) if h)   # hosts only, never full URLs


def real_host(url):
    """Host of a link; Microsoft Safe Links (added by the recipient's mail system) is unwrapped to its real destination."""
    host = host_of(url)
    if host.endswith("safelinks.protection.outlook.com"):
        target = re.search(r"[?&;]url=([^&;\s]+)", url)
        return host_of(unquote(target.group(1))) if target else ""
    return host


def service_of(host):
    """Name of the abused legitimate service hosting this link, or ''."""
    if ".ipfs." in host:
        return "ipfs"
    return next((s for s in ABUSED_SERVICES if host == s or host.endswith("." + s)), "")


def trace(sid, raw):
    msg = parse(raw)
    hops = [parse_hop(h) for h in (msg.get_all("Received") or [])]
    handoff = mark_roles(hops)
    below = [h for h in hops if h["role"] == "claimed" and h["from_ip"] and h["from_ip"].is_global]
    claimed = (below[-1]["from_ip"] if below else (hops[handoff]["from_ip"] if handoff is not None else None))
    stamps = [h["ts"] for h in hops if h["ts"]]
    backwards = any((lo - up).total_seconds() > BACKWARDS_SLACK_S for up, lo in zip(stamps, stamps[1:]))
    a, rspf = auth(msg)
    f_dom, rp_dom, rt_dom = domain_of_addr(msg["From"]), domain_of_addr(msg["Return-Path"]), domain_of_addr(msg["Reply-To"])
    mid = re.search(r"@([^>\s]+)", str(msg["Message-ID"] or ""))
    display = email.utils.parseaddr(str(msg["From"] or ""))[0].lower()
    hosts = link_hosts(msg)
    ranked = [h for h, _ in sorted(hosts.items(), key=lambda kv: (-kv[1], kv[0])) if h not in IGNORE_LINK_HOSTS]
    pivot = next((h for h in ranked if not service_of(h)), ranked[0] if ranked else "")   # own domain first, abused service second
    xo = last_ip(str(msg["X-Originating-IP"] or ""))
    row = dict(
        id=sid, n_hops=len(hops), n_internal=sum(h["role"] == "internal" for h in hops),
        handoff_ip=str(hops[handoff]["from_ip"]) if handoff is not None else "",
        handoff_helo=hops[handoff]["from_host"] if handoff is not None else "",
        claimed_origin_ip=str(claimed or ""), same_as_handoff=bool(claimed) and handoff is not None and claimed == hops[handoff]["from_ip"],
        timestamps_backwards=backwards,
        chain_span_s=int((stamps[0] - stamps[-1]).total_seconds()) if len(stamps) > 1 else "",
        spf=a["spf"], dkim=a["dkim"], dmarc=a["dmarc"], received_spf=rspf,
        from_domain=f_dom, return_path_domain=rp_dom, reply_to_domain=rt_dom, message_id_domain=(mid.group(1).lower() if mid else ""),
        from_ne_return_path=bool(f_dom and rp_dom and org_of(f_dom) != org_of(rp_dom)),
        from_ne_reply_to=bool(f_dom and rt_dom and org_of(f_dom) != org_of(rt_dom)),
        from_ne_message_id=bool(f_dom and mid and org_of(f_dom) != org_of(mid.group(1))),
        display_name_has_domain=bool(re.search(r"[\w-]+\.(?:com|net|org|[a-z]{2})\b|@", display)),
        x_originating_ip=str(xo) if xo and xo.is_global else "",
        x_mailer=re.sub(r"[^\w .,/;:()+-]", "", str(msg["X-Mailer"] or msg["User-Agent"] or ""))[:60],
        n_link_hosts=len(hosts), link_hosts=";".join(sorted(hosts)[:10]),
        pivot_link_host=pivot, pivot_service=service_of(pivot), safelinks_unwrapped=bool(re.search(r"safelinks\.protection\.outlook\.com", raw.decode("latin-1", "replace"), re.I)),
    )
    hop_rows = [dict(id=sid, hop=i, role=h["role"], from_host=h["from_host"], from_ip=h["from_ip"] or "", by_host=h["by_host"],
                     with_=h["with_"], time_utc=h["ts"].astimezone(timezone.utc).isoformat() if h["ts"] else "")
                for i, h in enumerate(hops)]
    return row, hop_rows


def raw_for(raw_dir, row):
    """Find one message exactly as ingest.iter_raw did: mbox by position, files by relative path."""
    kind, rel, _ = SPAM_SOURCES[row["corpus"]]
    if kind == "mbox":
        box = mailbox.mbox(raw_dir / rel)
        return box.get_bytes(list(box.iterkeys())[int(row["origin_key"])])
    return (raw_dir / rel / row["origin_key"]).read_bytes()


def main():
    raw_dir, proc = Path(sys.argv[1]), Path(sys.argv[2])
    index = [r for r in csv.DictReader(open(proc / "emails.csv", encoding="utf-8")) if r["label"] == "spam"]
    n_received = {r["id"]: int(r["n_received"]) for r in csv.DictReader(open(proc / "features.csv", encoding="utf-8"))}
    rows, hops = [], []
    for r in index:
        raw = raw_for(raw_dir, r)
        assert hashlib.sha256(raw).hexdigest() == r["sha256"], f"hash mismatch for {r['id']}: wrong message located"
        row, hop_rows = trace(r["id"], raw)
        assert row["n_hops"] == n_received[r["id"]], f"hop count differs from features.csv for {r['id']}"
        rows.append(dict(corpus=r["corpus"], year=r["year"], **row))
        hops += hop_rows
    for name, data in (("trace_headers.csv", rows), ("trace_hops.csv", hops)):
        with open(proc / name, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(data[0]))
            w.writeheader()
            w.writerows(data)

    # ---- self-checks
    assert len(rows) == 60, f"expected 60 spam, got {len(rows)}"
    assert not any("@" in str(v) for d in rows + hops for v in d.values()), "an address leaked into the output"
    print(f"self-checks passed: 60 rows, hashes match emails.csv, hop counts match features.csv, no '@' in outputs")
    print(f"{'corpus':16}{'n':>3}{'handoff':>9}{'claimed':>9}{'=same':>7}{'spf':>5}{'dkim':>6}{'dmarc':>7}{'backw':>7}{'From!=RP':>9}{'From!=RT':>9}")
    for corpus in SPAM_SOURCES:
        g = [r for r in rows if r["corpus"] == corpus]
        c = lambda f: sum(bool(f(r)) for r in g)
        print(f"{corpus:16}{len(g):>3}{c(lambda r: r['handoff_ip']):>9}{c(lambda r: r['claimed_origin_ip']):>9}{c(lambda r: r['same_as_handoff']):>7}"
              f"{c(lambda r: r['spf']):>5}{c(lambda r: r['dkim']):>6}{c(lambda r: r['dmarc']):>7}{c(lambda r: r['timestamps_backwards']):>7}"
              f"{c(lambda r: r['from_ne_return_path']):>9}{c(lambda r: r['from_ne_reply_to']):>9}")
    ips = {r["handoff_ip"] for r in rows if r["handoff_ip"]} | {r["claimed_origin_ip"] for r in rows if r["claimed_origin_ip"]}
    doms = {r[k] for r in rows for k in ("from_domain", "return_path_domain", "reply_to_domain") if r[k]} | {h for r in rows for h in r["link_hosts"].split(";") if h}
    print(f"unique indicators to look up: {len(ips)} IPs, {len(doms)} domains/hosts")


if __name__ == "__main__":
    main()
