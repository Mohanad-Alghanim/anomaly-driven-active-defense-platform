"""Train, calibrate, evaluate and export the insider-threat brain.

    python -m monitor.brain.train [--dataset PATH] [--out models/ai_engine]

Protocol (Model_Training_Recommendations):
  * fit on Normal_Behavior_Learning only, chronologically: first 70% of normal time
  * calibrate level boundaries on the next 15% of normal events (independent)
  * evaluate on the last 15% of normal events + attack events, against
    Ground_Truth_Evaluation, which is loaded only after the model is frozen

Outputs (models/ai_engine/): insider_brain.joblib, metrics.json, directory.json,
employee_risk_heldout_window.csv; samples/behavioral_demo.jsonl (unlabelled demo replay).
"""
import argparse
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.metrics import roc_auc_score

from . import evaluate as ev
from .dataset import DEFAULT_DATASET, chronological_split, load_evaluation_labels, load_events
from .model import InsiderThreatBrain
from .replay import live_features, parity, raw_events, to_jsonl
from .risk import epoch_seconds
from .runtime import pandas_references
from .schema import EXCLUDED_DATASET_FEATURES
from .telemetry import Directory, export_directory

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / 'models' / 'ai_engine'
DEMO = ROOT / 'samples' / 'behavioral_demo.jsonl'

BURST = ('source_events_previous_hour', 'emp_activity_z')
VARIANTS = {
    # The honest floor: the main model without the burst-volume signal.
    'artifact_free_floor': dict(exclude=BURST),
    'base_12_features': dict(use_personal=False),
}
ARTIFACTS = [
    dict(name='destination_port',
         finding='In normal data the port is random relative to the service (53/443/445/1194/5432 for every service); '
                 'attacks use canonical service ports, and 22/389/8088/8443 never occur in normal traffic.',
         decision='Removed from the model matrix before the final training run: a generation artifact with no behavioural '
                  'meaning; random ports per service are not realistic.'),
    dict(name='burst volume on a sparse normal baseline (source_events_previous_hour, emp_activity_z)',
         finding='Each employee has only 60 normal events in ~90 days, so normal activity in the preceding hour is almost '
                 'always 0, while attack scenarios are dense bursts (~20 events, seconds apart).',
         decision='Kept in the model. Limitation: on this sparse baseline these features separate far more easily than they '
                  'would on production telemetry. The artifact-free floor excludes them.'),
]


def evaluate_brain(brain, events, labels, train, cuts, full=True):
    data = events.merge(labels, on='feature_row_id', how='left', validate='one_to_one')
    data['score'] = brain.score_events(data)
    test_normals = data[(data.label_binary == 0) & (data.ts >= cuts[1])]
    attacks = data[data.label_binary == 1]
    in_window = data[data.ts >= cuts[1]]
    everything = pd.concat([test_normals, attacks])
    report = {
        'all_attacks_vs_heldout_normals': ev.headline(everything.label_binary, everything.score, brain.boundaries_),
        'chronological_test_window': ev.headline(in_window.label_binary, in_window.score, brain.boundaries_),
        'per_attack_category': ev.per_category(everything, brain.boundaries_),
    }
    if full:
        report['all_attacks_vs_heldout_normals']['confidence_95'] = ev.bootstrap(everything, brain.boundaries_['high'])
        audit, flagged = ev.feature_audit(brain, everything, train)
        report['feature_audit'] = dict(univariate=audit, near_separating_features=flagged)
    return report


def summary(report):
    h = report['all_attacks_vs_heldout_normals']
    return dict(auroc=h['auroc'], auprc=h['auprc'], recall_at_1pct_fpr=h['high_level']['recall'],
                realized_false_positive_rate=h['high_level']['realized_false_positive_rate'],
                per_category_recall_at_1pct_fpr={k: v['recall_at_high_level'] for k, v in report['per_attack_category'].items()},
                per_category_auroc={k: v['auroc_vs_normal'] for k, v in report['per_attack_category'].items()})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--dataset', default=str(DEFAULT_DATASET))
    parser.add_argument('--out', default=str(OUTPUT))
    parser.add_argument('--demo', default=str(DEMO))
    args = parser.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    print('Loading workbook (features + attribution context only)...', flush=True)
    data = load_events(args.dataset)
    train, calibration, test_normal, cuts = chronological_split(data.normal_training)
    print(f'normal train={len(train)} calibration={len(calibration)} test={len(test_normal)}', flush=True)

    brain = InsiderThreatBrain().fit(train).calibrate(calibration)
    variants = {name: InsiderThreatBrain(**kw).fit(train).calibrate(calibration) for name, kw in VARIANTS.items()}
    print('Models frozen. Loading evaluation labels...', flush=True)
    labels = load_evaluation_labels(args.dataset)

    report = evaluate_brain(brain, data.all_events, labels, train, cuts)
    variant_reports = {}
    for name, variant in variants.items():
        variant_reports[name] = summary(evaluate_brain(variant, data.all_events, labels, train, cuts, full=False))
        variant_reports[name]['features'] = variant.feature_names

    # ---------------------------------------------------------------- employees
    window = data.all_events[data.all_events.ts >= cuts[1]]
    employee_day, daily = ev.employee_days(brain, window, labels)
    floor_day, _ = ev.employee_days(variants['artifact_free_floor'], window, labels)
    invariance = ev.count_invariance(brain, window)
    ranking = brain.employee_risk(window)
    attacked = set(daily.loc[daily.attack_events > 0, 'employee_id'])
    by_peak = ranking.sort_values('peak_risk', ascending=False).reset_index(drop=True)
    ranking_eval = dict(
        employees_ranked=int(len(ranking)), employees_with_attacks_in_window=len(attacked),
        ranks_by_current_risk_at_window_end=sorted(int(i) + 1 for i in ranking.index[ranking.employee_id.isin(attacked)]),
        ranks_by_peak_risk_in_window=sorted(int(i) + 1 for i in by_peak.index[by_peak.employee_id.isin(attacked)]),
        employees_at_high_level_at_window_end=int((ranking.level == 'high').sum()),
        note='Current risk is a decayed mean, so an employee whose recent activity is normal again falls back down; '
             'peak risk keeps the incident visible.',
    )
    ranking.to_csv(out / 'employee_risk_heldout_window.csv', index=False)

    perfect = [dict(metric=name, value=value) for name, value in
               [('event.full_model', report['all_attacks_vs_heldout_normals']['auroc']), ('employee_day.full_model', employee_day['auroc'])]
               + [(f'event.{k}', v['auroc']) for k, v in variant_reports.items()] if value >= 0.99999]

    # ---------------------------------------------------------------- live path exports
    local_train = pd.to_datetime(train.ts).dt.tz_convert('Asia/Riyadh')
    weekend_days = sorted(set(local_train.dt.day_of_week[train.is_weekend_observed.to_numpy() == 1]))
    directory_data = export_directory(args.dataset, weekend_days=weekend_days)
    (out / 'directory.json').write_text(json.dumps(directory_data))
    directory = Directory(directory_data)
    raw, workbook_features = raw_events(args.dataset)
    normal_ids = set(data.normal_training.feature_row_id)
    feature_parity = parity(raw, workbook_features, directory, normal_ids)
    derived, employees = live_features(raw, directory)
    derived['employee_id'] = employees.to_numpy()
    derived['feature_row_id'] = raw.feature_row_id.to_numpy()
    check = derived.merge(workbook_features[['feature_row_id', 'source_events_previous_hour']], on='feature_row_id', suffixes=('', '_wb'))
    check = check[check.feature_row_id.isin(normal_ids)]
    replay = derived[['feature_row_id']].assign(score=brain.score_events(derived)).merge(labels, on='feature_row_id')
    replay = replay[(replay.label_binary == 1) | replay.feature_row_id.isin(set(test_normal.feature_row_id))]
    live_parity = dict(
        description='Features derived from raw telemetry by the live collector code vs. workbook Model_Features (normal rows).',
        max_abs_difference=feature_parity,
        source_events_previous_hour_mismatched_normal_rows=int((check.source_events_previous_hour != check.source_events_previous_hour_wb).sum()),
        mismatch_explanation='Normal events that follow an attack burst from the same device: live counting includes all traffic from the IP.',
        attack_rows_time_inconsistency=('Attack rows in Model_Features carry hour/day features that do not match their own timestamps '
                                        '(e.g. 19:00 Friday encoded as 09:30 Thursday). The live path derives time from the timestamp.'),
        replayed_attacks_recall_at_high_level=float((replay.score[replay.label_binary == 1] >= brain.boundaries_['high']).mean()),
        replayed_attacks_auroc_vs_heldout_normals=float(roc_auc_score(replay.label_binary, replay.score)),
    )

    # Demo replay: 48 h of all employees around the model's highest-scoring event in
    # the held-out window (chosen by model output, never by labels).
    scored_window = window.assign(score=brain.score_events(window))
    peak_ts = scored_window.loc[scored_window.score.idxmax(), 'ts']
    lo, hi = epoch_seconds(pd.Series([peak_ts - pd.Timedelta(hours=36), peak_ts + pd.Timedelta(hours=12)]))
    to_jsonl(raw[(raw.ts >= lo) & (raw.ts < hi)], args.demo)

    h = report['all_attacks_vs_heldout_normals']
    floor = variant_reports['artifact_free_floor']
    metrics = {
        'generated_at_utc': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'dataset': Path(args.dataset).name,
        'dataset_type': 'synthetic_only',
        'headline': dict(
            full_model=dict(auroc=h['auroc'], auprc=h['auprc'], recall_at_1pct_fpr=h['high_level']['recall'],
                            realized_false_positive_rate=h['high_level']['realized_false_positive_rate']),
            artifact_free_floor=dict(auroc=floor['auroc'], auprc=floor['auprc'], recall_at_1pct_fpr=floor['recall_at_1pct_fpr'],
                                     realized_false_positive_rate=floor['realized_false_positive_rate'],
                                     excludes=list(EXCLUDED_DATASET_FEATURES) + list(BURST)),
            read_this='Report both numbers together. The full model benefits from dataset artifacts; the floor is the honest '
                      'estimate without them. Neither establishes real-world detection performance.',
            artifacts=ARTIFACTS,
        ),
        'model': 'IsolationForest (unsupervised, trained on normal behaviour only)',
        'model_config': dict(n_estimators=brain.n_estimators, random_state=brain.random_state, max_samples='auto',
                             scoring='-score_samples (higher = more anomalous)', sklearn=sklearn.__version__,
                             trained_with=dict(python=platform.python_version(), numpy=np.__version__, pandas=pd.__version__,
                                               scikit_learn=sklearn.__version__, joblib=joblib.__version__),
                             artifact_contains_pandas_objects=False),
        'features': brain.feature_names,
        'excluded_dataset_features': list(EXCLUDED_DATASET_FEATURES),
        'protocol': dict(
            training=f'Normal_Behavior_Learning, earliest 70% by time ({len(train)} events, before {cuts[0].isoformat()})',
            calibration=f'Normal_Behavior_Learning, next 15% ({len(calibration)} events); level boundaries are quantiles of these scores',
            evaluation=f'Remaining normal events from {cuts[1].isoformat()} ({len(test_normal)}) and all 2,168 attack events; '
                       'labels from Ground_Truth_Evaluation used only here',
            entity_attribution='source_ip -> Device_Profiles -> employee_id (as the live collector does); identifiers never enter the model matrix',
            personal_baselines='recomputed from the training window only; the workbook Employee_Behavior_Baselines cover all '
                               '60,000 normal events and would leak held-out normal statistics',
        ),
        'level_policy': dict(
            medium_false_positive_budget=brain.policy.medium_fpr, high_false_positive_budget=brain.policy.high_fpr,
            event_score_boundaries=brain.boundaries_, employee_risk_boundaries=brain.employee_boundaries_,
            employee_risk=f'time-decayed mean of event anomaly scores (half-life {brain.risk_half_life_hours:g} h); event count is '
                          'not an input; boundaries are quantiles of the same aggregate replayed over calibration normals'),
        **report,
        'employee_day': dict(full_model=employee_day, artifact_free_floor=floor_day),
        'employee_risk_count_invariance': invariance,
        'employee_ranking_heldout_window': ranking_eval,
        'variants': variant_reports,
        'live_feature_parity': live_parity,
        'perfect_score_alerts': perfect or None,
        'limitations': [
            'Training and evaluation data are synthetic; no real-world detection claim is made.',
            'Anomaly means deviation from learned normal behaviour; it is not proof of malicious intent.',
            'The normal baseline is sparse (60 events per employee in ~90 days), so volume and burst features separate '
            'attacks here more easily than they would on production telemetry.',
            'All six attack categories share one generated volume/bytes profile; per-category results mostly reflect that profile.',
        ],
    }
    (out / 'metrics.json').write_text(json.dumps(metrics, indent=2, default=lambda v: v.item() if hasattr(v, 'item') else str(v)))
    if any(p['metric'].startswith('event.') for p in perfect):
        print('LEAKAGE ALERT: perfect event-level separation', perfect, '- model not saved.', file=sys.stderr)
        return 2
    leaked = pandas_references(brain)
    if leaked:
        print('PORTABILITY ALERT: pandas objects in the fitted model', leaked, '- model not saved.', file=sys.stderr)
        return 3
    joblib.dump(brain, out / 'insider_brain.joblib', compress=3)

    print(f"FULL MODEL  AUROC={h['auroc']:.4f} AUPRC={h['auprc']:.4f} recall@1%FPR={h['high_level']['recall']:.3f} "
          f"FPR={h['high_level']['realized_false_positive_rate']:.4f}")
    print(f"FLOOR       AUROC={floor['auroc']:.4f} AUPRC={floor['auprc']:.4f} recall@1%FPR={floor['recall_at_1pct_fpr']:.3f}")
    for k, v in report['per_attack_category'].items():
        print(f"  {k:28s} AUROC={v['auroc_vs_normal']:.4f} recall@high={v['recall_at_high_level']:.3f} "
              f"floor={floor['per_category_recall_at_1pct_fpr'][k]:.3f}")
    print('employee-day AUROC', round(employee_day['auroc'], 4), 'floor', round(floor_day['auroc'], 4),
          'count-only', round(employee_day['event_count_only_auroc_for_reference'], 4), 'invariance', invariance)
    print('ranks current', ranking_eval['ranks_by_current_risk_at_window_end'], 'peak', ranking_eval['ranks_by_peak_risk_in_window'])
    print('parity', {k: f'{v:.1e}' for k, v in feature_parity.items()},
          'replayed attack recall', round(live_parity['replayed_attacks_recall_at_high_level'], 3))
    print('perfect-score alerts:', perfect)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
