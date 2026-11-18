import pandas as pd, sys
pd.set_option('display.width',250); pd.set_option('display.max_columns',30)
i = sys.argv[1]
d = lambda s: str(s).replace('.', '[.]')
h = pd.read_csv('data/processed/trace_hops.csv'); h = h[h.id==i]
h = h.assign(from_host=h.from_host.map(d), from_ip=h.from_ip.map(d), by_host=h.by_host.map(lambda s: str(s)[:40]))
print(h[['hop','role','from_host','from_ip','by_host','time_utc']].to_string(index=False))
e = pd.read_csv('data/processed/trace_enriched.csv'); e = e[e.id==i].iloc[0]
print()
print('handoff_ip       ', d(e.handoff_ip))
print('handoff_asn/org  ', e.handoff_asn, e.handoff_org)
print('handoff_country  ', e.handoff_country, '| hosting:', e.handoff_hosting)
print('abuseipdb score  ', e.handoff_abuse_score, '(%s reports)' % e.handoff_abuse_reports, '| VT malicious:', e.handoff_vt_malicious)
print('link_age_days    ', e.link_age_days_at_receipt, '| link VT malicious:', e.link_vt_malicious)
t = pd.read_csv('data/processed/trace_headers.csv'); t = t[t.id==i].iloc[0]
print('SPF/DKIM/DMARC   ', t.spf, '/', t.dkim, '/', t.dmarc, '| n_hops:', t.n_hops, '| chain_span_s:', t.chain_span_s)
print('link host        ', d(t.pivot_link_host))
