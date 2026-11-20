"""Print the six anonymised error cases used in the report's error-analysis table. Read-only: saved CSVs, no message text.
Run (from the project folder):  python -I scripts\\show_errors.py
"""
import pandas as pd

SPAM_IDS = ["t0284", "t0668", "t0788", "t0855"]    # SVM false negatives
HAM_IDS = ["ha0722", "ha0152"]                      # SVM false positives
label = lambda pred: "spam" if pred else "ham"

p = pd.read_csv("results/test3_predictions.csv")
e = pd.read_csv("results/extra_spam_predictions.csv")[["id", "nb_pred", "lr_pred"]]
c = pd.read_csv("data/processed/characterised.csv")[["id", "topic", "text_chars", "html_only", "attachment"]]
spam = p.merge(e, on="id").merge(c, on="id").set_index("id").loc[SPAM_IDS]

h = pd.read_csv("results/test3b_ham_predictions.csv")
he = pd.read_csv("results/extra_ham_predictions.csv")[["id", "nb_pred", "lr_pred"]]
chars = pd.read_csv("data/processed/ham_apache.csv", usecols=["id", "text"]).assign(chars=lambda d: d.text.str.len())[["id", "chars"]]
ham = h.merge(he, on="id").merge(chars, on="id").set_index("id").loc[HAM_IDS]

print("Primary linear SVM errors (threshold 0). Scores and predictions from results/*.csv; no message text.\n")
print(f"{'case':8}{'source':18}{'actual':8}{'SVM score':>10}  {'SVM':5}{'NB':5}{'LR':5}{'topic / list':24}{'chars':>6}")
for i, r in spam.iterrows():
    print(f"{i:8}{r.corpus:18}{'spam':8}{r.svm_filter_score:>10.2f}  {label(r.svm_filter_pred):5}{label(r.nb_pred):5}{label(r.lr_pred):5}{r.topic:24}{r.text_chars:>6}")
for i, r in ham.iterrows():
    print(f"{i:8}{'apache':18}{'ham':8}{r.svm_filter_score:>10.2f}  {label(r.svm_filter_pred):5}{label(r.nb_pred):5}{label(r.lr_pred):5}{r['list']:24}{r.chars:>6}")
print("\nAll 381 SVM misses: median score", round(p[p.svm_filter_pred == 0].svm_filter_score.median(), 2),
      "| lowest", round(p.svm_filter_score.min(), 2))
