"""Evaluation against Ground_Truth_Evaluation. Labels are used here and nowhere else."""
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from .schema import BASE_CATEGORICAL


def _rates(y, scores, boundary):
    y = np.asarray(y)
    flagged = np.asarray(scores) >= boundary
    recall = float(flagged[y == 1].mean()) if (y == 1).any() else None
    fpr = float(flagged[y == 0].mean()) if (y == 0).any() else None
    precision = float(y[flagged].mean()) if flagged.any() else None
    return recall, fpr, precision


def headline(y, scores, boundaries):
    y = np.asarray(y)
    result = dict(events=int(len(y)), attacks=int(y.sum()), normals=int((y == 0).sum()),
                  auroc=float(roc_auc_score(y, scores)), auprc=float(average_precision_score(y, scores)),
                  attack_prevalence=float(y.mean()))
    for level in ('high', 'medium'):
        recall, fpr, precision = _rates(y, scores, boundaries[level])
        result[f'{level}_level'] = dict(score_boundary=boundaries[level], recall=recall,
                                        realized_false_positive_rate=fpr, precision=precision)
    return result


def per_category(frame, boundaries):
    normals = frame[frame.label_binary == 0]
    rows = {}
    for category, group in frame[frame.label_binary == 1].groupby('attack_category'):
        both = pd.concat([normals, group])
        rows[category] = dict(
            events=int(len(group)), sessions=int(group.session_id.nunique()),
            auroc_vs_normal=float(roc_auc_score(both.label_binary, both.score)),
            auprc_vs_normal=float(average_precision_score(both.label_binary, both.score)),
            recall_at_high_level=float((group.score >= boundaries['high']).mean()),
            recall_at_medium_level=float((group.score >= boundaries['medium']).mean()),
            sessions_with_any_high_event=int(group.assign(h=group.score >= boundaries['high']).groupby('session_id').h.any().sum()),
        )
    return rows


def bootstrap(frame, boundary, repeats=300, seed=7):
    """95% intervals. Normal events resampled individually; attacks resampled by whole
    session, because events of one generated scenario are not independent."""
    rng = np.random.default_rng(seed)
    normals = frame[frame.label_binary == 0].score.to_numpy()
    sessions = [g.score.to_numpy() for _, g in frame[frame.label_binary == 1].groupby('session_id')]
    stats = {'auroc': [], 'auprc': [], 'recall_at_high_level': []}
    for _ in range(repeats):
        n = normals[rng.integers(0, len(normals), len(normals))]
        a = np.concatenate([sessions[i] for i in rng.integers(0, len(sessions), len(sessions))])
        y = np.r_[np.zeros(len(n)), np.ones(len(a))]
        s = np.r_[n, a]
        stats['auroc'].append(roc_auc_score(y, s))
        stats['auprc'].append(average_precision_score(y, s))
        stats['recall_at_high_level'].append((a >= boundary).mean())
    return {k: [float(np.quantile(v, 0.025)), float(np.quantile(v, 0.975))] for k, v in stats.items()}


def feature_audit(brain, frame, train):
    """Univariate separability of each model input. A single column separating attacks
    almost perfectly is a shortcut/leak candidate and must be reported (principle 6)."""
    X = brain.matrix(frame)
    Xtrain = brain.matrix(train)
    y = frame.label_binary.to_numpy()
    audit = {}
    for column in X.columns:
        if column in BASE_CATEGORICAL:
            freq = Xtrain[column].value_counts(normalize=True)
            values = -np.log(X[column].map(freq).fillna(0).to_numpy() + 1 / (len(Xtrain) + 1))
            unseen = ~X[column].isin(freq.index)
            extra = dict(attack_share_unseen_in_normal_training=float(unseen[y == 1].mean()),
                         normal_share_unseen_in_normal_training=float(unseen[y == 0].mean()))
        else:
            values = X[column].to_numpy(dtype=float)
            values = np.where(np.isnan(values), np.nanmedian(Xtrain[column].to_numpy(dtype=float)), values)
            extra = {}
        auc = roc_auc_score(y, values)
        audit[column] = dict(univariate_auroc=float(max(auc, 1 - auc)), **extra)
    flagged = sorted([c for c, v in audit.items() if v['univariate_auroc'] >= 0.95], key=lambda c: -audit[c]['univariate_auroc'])
    return audit, flagged


def employee_days(brain, window, labels):
    daily = brain.employee_daily_risk(window)
    truth = window.merge(labels, on='feature_row_id')
    truth['day'] = truth.ts.dt.tz_convert('Asia/Riyadh').dt.date
    positive = truth[truth.label_binary == 1].groupby(['employee_id', 'day']).size().rename('attack_events')
    daily = daily.merge(positive.reset_index(), on=['employee_id', 'day'], how='left')
    daily['attack_events'] = daily.attack_events.fillna(0).astype(int)
    y = (daily.attack_events > 0).astype(int)
    result = headline(y, daily.risk, brain.employee_boundaries_)
    result['unit'] = 'employee-day'
    return result, daily
