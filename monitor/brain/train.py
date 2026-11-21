"""Train, calibrate and evaluate the insider-threat brain.

    python -m monitor.brain.train [--dataset PATH] [--out models/ai_engine]

Protocol (Model_Training_Recommendations):
  * fit on Normal_Behavior_Learning only, chronologically: first 70% of normal time
  * calibrate level boundaries on the next 15% of normal events (independent)
  * evaluate on the last 15% of normal events + attack events, against
    Ground_Truth_Evaluation, which is loaded only after the model is frozen
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
import sklearn
from sklearn.metrics import roc_auc_score

from . import evaluate as ev
from .dataset import DEFAULT_DATASET, chronological_split, load_evaluation_labels, load_events
from .model import InsiderThreatBrain

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / 'models' / 'ai_engine'

ABLATIONS = {
    'base_13_features': dict(use_personal=False),
    'base_13_without_destination_port': dict(use_personal=False, exclude=('destination_port',)),
    'personal_without_destination_port': dict(exclude=('destination_port',)),
    'personal_without_port_and_burst_volume': dict(exclude=('destination_port', 'source_events_previous_hour', 'emp_activity_z')),
}


def evaluate_brain(brain, events, labels, train, cuts, full=True):
    data = events.merge(labels, on='feature_row_id', how='left', validate='one_to_one')
    data['score'] = brain.score_events(data)
    test_normals = data[(data.label_binary == 0) & (data.ts >= cuts[1])]
    attacks = data[data.label_binary == 1]
    in_window = data[data.ts >= cuts[1]]
    all_attacks = pd.concat([test_normals, attacks])
    report = {
        'all_attacks_vs_heldout_normals': ev.headline(all_attacks.label_binary, all_attacks.score, brain.boundaries_),
        'chronological_test_window': ev.headline(in_window.label_binary, in_window.score, brain.boundaries_),
        'per_attack_category': ev.per_category(all_attacks, brain.boundaries_),
    }
    if full:
        report['all_attacks_vs_heldout_normals']['confidence_95'] = ev.bootstrap(all_attacks, brain.boundaries_['high'])
        audit, flagged = ev.feature_audit(brain, all_attacks, train)
        report['feature_audit'] = dict(univariate=audit, near_separating_features=flagged)
        window = events[events.ts >= cuts[1]]
        emp_report, daily = ev.employee_days(brain, window, labels)
        report['employee_day'] = emp_report
        report['_daily'] = daily
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--dataset', default=str(DEFAULT_DATASET))
    parser.add_argument('--out', default=str(OUTPUT))
    parser.add_argument('--skip-ablations', action='store_true')
    args = parser.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    print('Loading workbook (features + attribution context only)...', flush=True)
    data = load_events(args.dataset)
    train, calibration, test_normal, cuts = chronological_split(data.normal_training)
    print(f'normal train={len(train)} calibration={len(calibration)} test={len(test_normal)}; cuts={cuts[0]} / {cuts[1]}', flush=True)

    brain = InsiderThreatBrain().fit(train).calibrate(calibration)
    print('Model frozen. Loading evaluation labels...', flush=True)
    labels = load_evaluation_labels(args.dataset)

    report = evaluate_brain(brain, data.all_events, labels, train, cuts)
    daily = report.pop('_daily')

    ablations = {}
    if not args.skip_ablations:
        for name, kwargs in ABLATIONS.items():
            print('Ablation:', name, flush=True)
            variant = InsiderThreatBrain(**kwargs).fit(train).calibrate(calibration)
            r = evaluate_brain(variant, data.all_events, labels, train, cuts, full=False)
            ablations[name] = dict(
                features=variant.feature_names,
                auroc=r['all_attacks_vs_heldout_normals']['auroc'],
                auprc=r['all_attacks_vs_heldout_normals']['auprc'],
                recall_at_1pct_fpr=r['all_attacks_vs_heldout_normals']['high_level']['recall'],
                per_category_recall_at_1pct_fpr={k: v['recall_at_high_level'] for k, v in r['per_attack_category'].items()},
                per_category_auroc={k: v['auroc_vs_normal'] for k, v in r['per_attack_category'].items()},
            )

    # Employee ranking for the held-out window: risk per EMP id, worst day first.
    window = data.all_events[data.all_events.ts >= cuts[1]]
    ranking = brain.employee_risk(window)
    attacked = set(daily.loc[daily.attack_events > 0, 'employee_id'])
    ranking_eval = dict(
        employees_ranked=int(len(ranking)),
        employees_with_attacks_in_window=len(attacked),
        their_ranks=sorted(int(i) + 1 for i in ranking.index[ranking.employee_id.isin(attacked)]),
        employees_at_high_level=int((ranking.level == 'high').sum()),
    )
    ranking.to_csv(out / 'employee_risk_heldout_window.csv', index=False)
    explained = window.assign(score=brain.score_events(window)).nlargest(5, 'score')
    examples = [dict(employee_id=e, score=float(s), level=str(lv), reasons=r) for e, s, lv, r in zip(
        explained.employee_id, explained.score, brain.event_levels(explained.score), brain.explain(explained))]

    # Principle 6: a perfect score is a failure signal. Event-level perfection blocks the
    # model; any perfect score is reported with a diagnosis.
    y_day = (daily.attack_events > 0).astype(int)
    count_only = float(roc_auc_score(y_day, daily.events))
    perfect_scores = []
    if report['employee_day']['auroc'] >= 0.99999:
        perfect_scores.append(dict(
            metric='employee_day.auroc', value=report['employee_day']['auroc'],
            identifier_or_label_in_matrix=False,
            event_count_only_auroc=count_only,
            normal_day_max_events=int(daily.loc[y_day == 0, 'events'].max()),
            attack_day_min_events=int(daily.loc[y_day == 1, 'events'].min()),
            diagnosis=('Not a leak: no identifier/label reaches the model, but the number of events per '
                       'employee-day alone separates the classes perfectly. Attack scenarios are generated '
                       'as dense bursts while each employee has only 60 normal events in ~90 days. '
                       'Employee-day separation therefore reflects the dataset generator, not detection skill.')))
    leakage = [k for k, v in {'main': report['all_attacks_vs_heldout_normals']['auroc'], **{k: v['auroc'] for k, v in ablations.items()}}.items() if v >= 0.99999]
    metrics = {
        'generated_at_utc': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'dataset': Path(args.dataset).name,
        'dataset_type': 'synthetic_only',
        'model': 'IsolationForest (unsupervised, trained on normal behaviour only)',
        'model_config': dict(n_estimators=brain.n_estimators, random_state=brain.random_state, max_samples='auto',
                             scoring='-score_samples (higher = more anomalous)', sklearn=sklearn.__version__),
        'features': brain.feature_names,
        'protocol': dict(
            training=f'Normal_Behavior_Learning, earliest 70% by time ({len(train)} events, before {cuts[0].isoformat()})',
            calibration=f'Normal_Behavior_Learning, next 15% ({len(calibration)} events); level boundaries are quantiles of these scores',
            evaluation=f'Remaining normal events from {cuts[1].isoformat()} ({len(test_normal)}) and all 2,168 attack events; labels from Ground_Truth_Evaluation used only here',
            entity_attribution='source_ip -> Device_Profiles -> employee_id (as a live collector would); identifiers never enter the model matrix',
            personal_baselines='recomputed from the training window only; the workbook Employee_Behavior_Baselines cover all 60,000 normal events and would leak held-out normal statistics',
        ),
        'level_policy': dict(medium_false_positive_budget=brain.policy.medium_fpr, high_false_positive_budget=brain.policy.high_fpr,
                             event_score_boundaries=brain.boundaries_, employee_day_risk_boundaries=brain.employee_boundaries_),
        **report,
        'employee_ranking_heldout_window': ranking_eval,
        'top_event_explanations': examples,
        'ablations': ablations,
        'leakage_alert': leakage or None,
        'perfect_score_alerts': perfect_scores or None,
        'limitations': [
            'Training and evaluation data are synthetic; no real-world detection claim is made.',
            'Anomaly means deviation from learned normal behaviour; it is not proof of malicious intent.',
            'Feature design was fixed before evaluation; the ablations show sensitivity to dataset generation artifacts.',
        ],
    }
    (out / 'metrics.json').write_text(json.dumps(metrics, indent=2, default=lambda v: v.item() if hasattr(v, 'item') else str(v)))
    if leakage:
        print('LEAKAGE ALERT: perfect separation in', leakage, '- model not saved; investigate before use.', file=sys.stderr)
        return 2
    joblib.dump(brain, out / 'insider_brain.joblib', compress=3)

    h = report['all_attacks_vs_heldout_normals']
    print(f"AUROC={h['auroc']:.4f} AUPRC={h['auprc']:.4f} recall@1%FPR={h['high_level']['recall']:.3f} "
          f"realizedFPR={h['high_level']['realized_false_positive_rate']:.4f}")
    for k, v in report['per_attack_category'].items():
        print(f"  {k:28s} AUROC={v['auroc_vs_normal']:.4f} recall@high={v['recall_at_high_level']:.3f}")
    print('employee-day AUROC', round(report['employee_day']['auroc'], 4), 'ranks of attacked employees', ranking_eval['their_ranks'])
    for alert in perfect_scores:
        print('PERFECT SCORE ALERT:', alert['metric'], '-', alert['diagnosis'], file=sys.stderr)
    print('near-separating single features:', report['feature_audit']['near_separating_features'])
    for name, a in ablations.items():
        print(f"  ablation {name:42s} AUROC={a['auroc']:.4f} recall@1%={a['recall_at_1pct_fpr']:.3f}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
