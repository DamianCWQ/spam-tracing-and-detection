"""Stage 2c: group the 60 spam into campaigns. Offline: reads only processed CSVs, never raw samples.

Two emails are linked only by a STRONG shared indicator:
  same pivot link host (own domain, not an abused service) | same sender (From) domain | same Reply-To domain
  | same handoff or claimed-origin IP | near-identical text (TF-IDF cosine >= 0.80 on clean.csv)
Big shared providers (Google, Microsoft, mail relays) are never a link: sharing Gmail says nothing about who sent it.
Weak shared features (ASN, registrar, hosting flag) are reported per campaign as supporting evidence but do not merge anything.
A campaign is a connected group of linked emails; an email with no link is a singleton ("no campaign").

Writes data/processed/trace_campaigns.csv (id, campaign, links) and prints a defanged summary.
Run (from scripts/):  ..\\.venv\\Scripts\\python.exe -I trace_campaigns.py ..\\data\\processed
"""
import sys
from collections import defaultdict
from itertools import combinations
from pathlib import Path

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

sys.path.insert(0, str(Path(__file__).parent))
from trace_parse import org_of   # noqa: E402

TEXT_SIM = 0.80
SHARED_PROVIDERS = {"google.com", "outlook.com", "gmail.com", "yahoo.com", "hotmail.com", "microsoft.com", "secureserver.net"}
d = lambda s: str(s).replace(".", "[.]")


def main():
    proc = Path(sys.argv[1])
    e = pd.read_csv(proc / "trace_enriched.csv", dtype=str).fillna("")
    h = pd.read_csv(proc / "trace_headers.csv", dtype=str).fillna("")
    clean = pd.read_csv(proc / "clean.csv", dtype=str).fillna("")
    df = e.merge(h[["id", "reply_to_domain", "pivot_link_host", "pivot_service", "year"]], on="id").merge(clean[["id", "text"]], on="id")
    assert len(df) == 60

    # ---- strong keys: (kind, value) -> ids that share it
    keys = defaultdict(set)
    for r in df.itertuples():
        own_pivot = r.pivot_link_host if not r.pivot_service else ""
        for kind, val in (("link host", org_of(own_pivot)), ("sender domain", org_of(r.from_domain)),
                          ("reply-to domain", org_of(r.reply_to_domain)),
                          ("handoff IP", r.handoff_ip), ("claimed IP", r.claimed_ip)):
            if val and val not in SHARED_PROVIDERS:
                keys[(kind, val)].add(r.id)
    vec = TfidfVectorizer(sublinear_tf=True, min_df=1).fit_transform(df.text)
    sim = cosine_similarity(vec)
    for i, j in combinations(range(len(df)), 2):
        if sim[i, j] >= TEXT_SIM:
            keys[("near-identical text", f"{df.id[i]}~{df.id[j]}")] |= {df.id[i], df.id[j]}

    # ---- union-find over the strong links
    parent = {i: i for i in df.id}
    def _find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for ids in keys.values():
        ids = sorted(ids)
        for other in ids[1:]:
            parent[_find(other)] = _find(ids[0])
    groups = defaultdict(list)
    for i in df.id:
        groups[_find(i)].append(i)
    multi = sorted((sorted(g) for g in groups.values() if len(g) > 1), key=lambda g: (-len(g), g[0]))
    cid = {i: f"C{n:02d}" for n, g in enumerate(multi, 1) for i in g}
    links = defaultdict(list)
    for (kind, val), ids in keys.items():
        if len(ids) > 1:
            for i in ids:
                links[i].append(f"{kind}={d(val)}")
    out = pd.DataFrame({"id": df.id, "campaign": df.id.map(cid).fillna(""), "links": df.id.map(lambda i: " | ".join(sorted(set(links[i]))))})
    out.to_csv(proc / "trace_campaigns.csv", index=False)

    # ---- summary (defanged, counts and indicators only)
    in_c = sum(len(g) for g in multi)
    print(f"{len(multi)} campaigns covering {in_c} of 60 emails; {60 - in_c} singletons")
    by = df.set_index("id")
    for n, g in enumerate(multi, 1):
        sub = by.loc[g]
        kinds = sorted({k.split("=")[0] for i in g for k in links[i]})
        asn = sub.handoff_asn.value_counts().head(1)
        print(f"C{n:02d} n={len(g)} {','.join(g)} | corpus {dict(sub.corpus.value_counts())} | linked by {kinds} "
              f"| top handoff ASN {d(asn.index[0]) if len(asn) else '-'} ({asn.iloc[0] if len(asn) else 0}) | years {sorted(set(sub.year))}")
        for k in sorted({k for i in g for k in links[i]})[:4]:
            print(f"     {k}")
    # self-check: every email is in exactly one group, campaign ids are consistent
    assert sum(len(g) for g in groups.values()) == 60 and set(cid) <= set(df.id)


if __name__ == "__main__":
    main()
