"""Build the spam-only Test 3 set: EVERY message of the four tracing corpora (the 60 study spam are included).

Only exact duplicates (same cleaned-text digest) and too-short or unparseable messages are removed. Campaign-mates are
KEPT (a training pool would drop them to avoid leakage; a test set should not hide them): a test set should not hide the
near-duplicates, so instead each message gets a `cluster` id and the notebook reports cluster-aware intervals.
Cluster = connected group by same own-domain link host, same From domain (big providers never link), or TF-IDF cosine >= 0.80.
A link domain seen with MAX_FROM_ORGS or more different From domains is shared infrastructure (a CDN, mailer or e-signature
service) and does not link: without this rule one chain of such domains merged 753 unrelated messages into one cluster.

Reads raw samples in memory only (run with -I), same extraction/redaction/defanging as ingest.py. Writes
  data/processed/traced_all.csv   id, corpus, year, origin_key, sha256, in_test60, cluster, text   (text = cleaned, NOT masked)
Prints counts only.

Run (from scripts/):  ..\\.venv\\Scripts\\python.exe -I build_traced_set.py ..\\data\\raw ..\\data\\processed
"""
import csv, hashlib, sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer

sys.path.insert(0, str(Path(__file__).parent))
from ingest import MIN_TEXT_CHARS, SPAM_SOURCES, extract, iter_raw, parse   # noqa: E402
from trace_campaigns import SHARED_PROVIDERS, TEXT_SIM   # noqa: E402
from trace_parse import IGNORE_LINK_HOSTS, domain_of_addr, link_hosts, org_of, service_of   # noqa: E402

MAX_FROM_ORGS = 5

digest = lambda text: hashlib.sha256(text.lower().encode()).hexdigest()   # same rule as ingest.py's duplicate check


def own_link_orgs(msg):
    """Registrable domains of the message's own-domain link hosts (no abused services, no boilerplate, no big providers)."""
    hosts = [h for h in link_hosts(msg) if h not in IGNORE_LINK_HOSTS and not service_of(h)]
    return {org_of(h) for h in hosts if org_of(h)} - SHARED_PROVIDERS


def main():
    raw_dir, proc = Path(sys.argv[1]), Path(sys.argv[2])
    emails = pd.read_csv(proc / "emails.csv", dtype=str, keep_default_na=False)
    clean = pd.read_csv(proc / "clean.csv", dtype=str, keep_default_na=False)
    test = emails[emails.label == "spam"].merge(clean[["id", "text"]], on="id")
    assert len(test) == 60
    selected = {(c, k): t for c, k, t in zip(test.corpus, test.origin_key, test.text)}

    rows, why, from_org, link_orgs = [], Counter(), [], []
    for corpus, (kind, rel, _) in SPAM_SOURCES.items():
        for key, raw in iter_raw(kind, raw_dir / rel):
            try:
                text, _, _, year = extract(raw)
                msg = parse(raw)
                fo, lo = org_of(domain_of_addr(msg["From"])), own_link_orgs(msg)
            except Exception:
                why[corpus, "unparseable (extract needs a valid Date)"] += 1
                continue
            if len(text) < MIN_TEXT_CHARS:
                why[corpus, "too short"] += 1
                continue
            is_test = (corpus, key) in selected
            if is_test:
                assert text == selected[corpus, key], f"{corpus}/{key}: re-extracted text differs from clean.csv"
            rows.append(dict(corpus=corpus, year=year, origin_key=key, sha256=hashlib.sha256(raw).hexdigest(),
                             in_test60=is_test, text=text))
            from_org.append(fo)
            link_orgs.append(lo)
    df = pd.DataFrame(rows).assign(from_org=from_org, link_orgs=link_orgs)
    assert df.in_test60.sum() == 60, f"only {df.in_test60.sum()} of the 60 study spam were re-read"

    # exact duplicates: keep the study spam first so none of the 60 is dropped
    before = len(df)
    df = df.assign(d=df.text.map(digest)).sort_values("in_test60", ascending=False, kind="stable").drop_duplicates("d")
    df = df.drop(columns="d").reset_index(drop=True)
    why["all", "duplicate text"] = before - len(df)
    assert df.in_test60.sum() == 60

    # ---- clusters (union-find over strong links)
    parent = list(range(len(df)))
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    def union(a, b):
        parent[find(a)] = find(b)

    froms = defaultdict(set)   # link domain -> distinct From domains it appears with
    for r in df.itertuples():
        for o in r.link_orgs:
            froms[o].add(r.from_org)
    shared_infra = {o for o, f in froms.items() if len(f) >= MAX_FROM_ORGS}
    keys = defaultdict(list)
    for i, r in enumerate(df.itertuples()):
        for o in sorted(r.link_orgs - shared_infra):
            keys["link", o].append(i)
        if r.from_org and r.from_org not in SHARED_PROVIDERS:
            keys["from", r.from_org].append(i)
    for idx in keys.values():
        for j in idx[1:]:
            union(idx[0], j)
    x = TfidfVectorizer(sublinear_tf=True).fit_transform(df.text)
    sim = (x @ x.T).toarray()
    np.fill_diagonal(sim, 0)
    for i, j in np.argwhere(np.triu(sim) >= TEXT_SIM):
        union(i, j)
    root = [find(i) for i in range(len(df))]
    first = {}
    for i, r in enumerate(root):
        first.setdefault(r, i)   # label = lowest row number in the cluster, so labels do not depend on set iteration order
    df["cluster"] = [f"k{first[r]:04d}" for r in root]
    size = df.cluster.map(df.cluster.value_counts())

    df.insert(0, "id", [f"t{i:04d}" for i in range(1, len(df) + 1)])
    df = df.drop(columns=["from_org", "link_orgs"])
    df.to_csv(proc / "traced_all.csv", index=False, quoting=csv.QUOTE_NONNUMERIC)

    # ---- self-checks and counts
    assert df.sha256.is_unique and df.text.map(digest).is_unique
    assert df.text.str.contains(r"https?://", case=False, regex=True).sum() == 0, "live URL left in the text"
    assert set(df[df.in_test60].sha256) == set(emails[emails.label == "spam"].sha256), "study spam differ from emails.csv"
    print(f"traced set: {len(df)} messages -> traced_all.csv; by corpus {df.corpus.value_counts().to_dict()}; "
          f"by year {df.year.value_counts().sort_index().to_dict()}")
    print(f"{len(shared_infra)} link domains treated as shared infrastructure (>= {MAX_FROM_ORGS} different From domains)")
    print(f"clusters: {df.cluster.nunique()} (largest {size.max()}; {int((size == 1).sum())} singletons); the 60 study spam sit in {df[df.in_test60].cluster.nunique()} clusters")
    for (corpus, reason), n in sorted(why.items()):
        print(f"  skipped {n:4d}  {corpus:16} {reason}")


if __name__ == "__main__":
    main()
