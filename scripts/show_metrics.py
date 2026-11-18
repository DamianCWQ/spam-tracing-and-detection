import pandas as pd
m = pd.read_csv('results/metrics_external.csv'); m = m[m.variant=='primary']
print('Evaluation B - external: 1,742 traced spam + 1,720 Apache ham (scored once)')
print(m[['model','TP','FN','FP','TN','recall','specificity','precision','f1','auc']].round(3).to_string(index=False))
h = pd.read_csv('results/eval_heldout.csv')
print('\nEvaluation A - held-out 20% of Enron and SpamAssassin')
print(h[['model','test','tn','fp','fn','tp','prec','rec','f1','auc']].round(3).to_string(index=False))
