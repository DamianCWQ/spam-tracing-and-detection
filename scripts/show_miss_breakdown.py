"""Print the SVM miss rate by topic and the effect of the largest spam cluster. Read-only: saved CSVs, no message text.
Run (from the project folder):  python -I scripts\\show_miss_breakdown.py
"""
import pandas as pd

p = pd.read_csv("results/test3_predictions.csv")
topic = pd.read_csv("data/processed/characterised.csv")[["id", "topic"]]
m = p.merge(topic, on="id").assign(missed=lambda d: d.svm_filter_pred == 0)

print("Linear SVM (primary) on the 1,742 external spam: missed spam by topic\n")
by_topic = m.groupby("topic").missed.agg(["sum", "count"]).assign(rate=lambda d: d["sum"] / d["count"]).sort_values("rate", ascending=False)
print(f"{'topic':30}{'missed':>7}{'total':>7}{'miss rate':>11}")
for name, r in by_topic.iterrows():
    print(f"{name:30}{int(r['sum']):>7}{int(r['count']):>7}{r.rate:>11.1%}")

big = m.cluster.value_counts().index[0]
in_big, rest = m[m.cluster == big], m[m.cluster != big]
print(f"\nlargest cluster: {len(in_big)} messages, {int(in_big.missed.sum())} missed")
print(f"recall, all {len(m)} spam:               {1 - m.missed.mean():.3f}")
print(f"recall, without that cluster ({len(rest)}): {1 - rest.missed.mean():.3f}")
