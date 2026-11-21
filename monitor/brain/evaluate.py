"""Evaluation against Ground_Truth_Evaluation. Labels are used here and nowhere else."""
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from .risk import rolling_risk
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
    """Employee-day evaluation: rolling risk at the employee's last event of each local day.
    A day is positive if it contains any attack event. Event count per day is kept only
    to compare against (it is not part of the risk)."""
    scored = window.assign(score=brain.score_events(window))
    scored['risk'] = rolling_risk(scored, brain.half_life_seconds)
    scored = scored.dropna(subset=['employee_id']).merge(labels, on='feature_row_id')
    scored['day'] = scored.ts.dt.tz_convert('Asia/Riyadh').dt.date
    scored = scored.sort_values('ts', kind='stable')
    grouped = scored.groupby(['employee_id', 'day'])
    daily = grouped.agg(risk=('risk', 'last'), events=('score', 'size'),
                        attack_events=('label_binary', 'sum')).reset_index()
    y = (daily.attack_events > 0).astype(int)
    result = headline(y, daily.risk, brain.employee_boundaries_)
    result['unit'] = 'employee-day (rolling risk at the last event of the day)'
    result['event_count_only_auroc_for_reference'] = float(roc_auc_score(y, daily.events))
    result['risk_vs_event_count_spearman'] = float(daily[['risk', 'events']].corr(method='spearman').iloc[0, 1])
    return result, daily


def count_invariance(brain, window):
    """Duplicate every event: a count-free aggregation must give the same ranking."""
    sample = window.dropna(subset=['employee_id'])
    base = brain.employee_risk(sample)
    doubled = brain.employee_risk(pd.concat([sample, sample], ignore_index=True))
    merged = base.merge(doubled, on='employee_id', suffixes=('', '_doubled'))
    return dict(max_abs_risk_change=float((merged.risk - merged.risk_doubled).abs().max()),
                ranking_identical=bool((base.employee_id.to_numpy() == doubled.employee_id.to_numpy()).all()))
