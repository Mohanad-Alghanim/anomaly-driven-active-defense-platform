"""Unit tests for the unsupervised insider-threat brain (no workbook required)."""
import ast
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from monitor.brain import InsiderThreatBrain, LevelPolicy, assert_no_leakage
from monitor.brain.dataset import chronological_split
from monitor.brain.schema import BASE_FEATURES

BRAIN_DIR = Path(__file__).resolve().parents[1] / 'monitor' / 'brain'
SERVICES = ['File Server', 'ERP', 'Internal Web', 'DNS']


def synthetic_events(n_employees=40, per_employee=60, seed=0, start='2026-08-20'):
    rng = np.random.default_rng(seed)
    rows = []
    t0 = pd.Timestamp(start, tz='UTC')
    for e in range(n_employees):
        services = rng.choice(SERVICES, size=2, replace=False)
        bytes_mean = rng.normal(6.5, 0.3)
        for i in range(per_employee):
            hour = rng.normal(11, 2) % 24
            dow = int(rng.integers(0, 5))
            rows.append(dict(
                ts=t0 + pd.Timedelta(days=float(rng.uniform(0, 90))),
                employee_id=f'EMP{e:04d}', device_id=f'DEV{e:04d}-1', source_ip=f'10.200.0.{e}',
                hour_sin=np.sin(2 * np.pi * hour / 24), hour_cos=np.cos(2 * np.pi * hour / 24),
                day_of_week_sin=np.sin(2 * np.pi * dow / 7), day_of_week_cos=np.cos(2 * np.pi * dow / 7),
                is_weekend_observed=0, within_assumed_work_hours=int(8 <= hour <= 17),
                bytes_in_log1p=rng.normal(bytes_mean + 0.5, 0.4), bytes_out_log1p=rng.normal(bytes_mean, 0.4),
                response_time_ms_log1p=rng.normal(4, 0.5) if rng.random() < 0.5 else np.nan,
                destination_port=int(rng.choice([443, 445, 53])), protocol='TCP',
                destination_service=str(rng.choice(services)), source_events_previous_hour=int(rng.random() < 0.05),
            ))
    frame = pd.DataFrame(rows)
    frame.insert(0, 'feature_row_id', range(1, len(frame) + 1))
    return frame


def anomalous_like(frame, n=20):
    """Night-time, large outbound transfers to a service the employee never used."""
    bad = frame.sample(n, random_state=1).copy()
    bad['hour_sin'], bad['hour_cos'] = np.sin(2 * np.pi * 3 / 24), np.cos(2 * np.pi * 3 / 24)
    bad['within_assumed_work_hours'] = 0
    bad['bytes_out_log1p'] = bad['bytes_out_log1p'] + 3
    bad['destination_service'] = 'Database'
    bad['source_events_previous_hour'] = 30
    return bad


class BrainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = synthetic_events()
        cls.train, cls.calibration, cls.test, cls.cuts = chronological_split(cls.events)
        cls.brain = InsiderThreatBrain(n_estimators=100).fit(cls.train).calibrate(cls.calibration)

    def test_chronological_split_has_no_time_overlap(self):
        self.assertLess(self.train.ts.max(), self.calibration.ts.min())
        self.assertLess(self.calibration.ts.max(), self.test.ts.min())

    def test_leakage_guard_rejects_identifiers_labels_and_ips(self):
        for column in ('employee_id', 'source_ip', 'label_binary', 'attack_category', 'severity', 'session_id', 'feature_row_id'):
            with self.assertRaises(ValueError):
                assert_no_leakage([*BASE_FEATURES, column])
        assert_no_leakage(self.brain.feature_names)

    def test_model_matrix_contains_only_approved_features(self):
        X = self.brain.matrix(self.test)
        self.assertEqual(list(X.columns), self.brain.feature_names)
        for column in ('employee_id', 'device_id', 'source_ip', 'ts', 'feature_row_id'):
            self.assertNotIn(column, X.columns)

    def test_refuses_to_fit_on_labelled_frame(self):
        with self.assertRaises(ValueError):
            InsiderThreatBrain(n_estimators=10).fit(self.train.assign(label_binary=0))

    def test_scores_are_continuous_and_anomalies_score_higher(self):
        normal = self.brain.score_events(self.test)
        bad = self.brain.score_events(anomalous_like(self.test))
        self.assertTrue(np.isfinite(normal).all())
        self.assertGreater(len(np.unique(normal)), len(normal) // 2)
        self.assertGreater(np.median(bad), np.quantile(normal, 0.99))

    def test_levels_are_quantiles_of_calibration_scores(self):
        scores = self.brain.calibration_scores_
        self.assertAlmostEqual(self.brain.boundaries_['high'], float(np.quantile(scores, 0.99)))
        self.assertAlmostEqual(self.brain.boundaries_['medium'], float(np.quantile(scores, 0.95)))
        flagged = (self.brain.score_events(self.test) >= self.brain.boundaries_['high']).mean()
        self.assertLess(flagged, 0.05)
        # Boundaries move with the data instead of being fixed numbers.
        other = InsiderThreatBrain(n_estimators=100).fit(self.train).calibrate(self.calibration.iloc[: len(self.calibration) // 2])
        self.assertNotEqual(other.boundaries_['high'], self.brain.boundaries_['high'])

    def test_level_policy_validation(self):
        with self.assertRaises(ValueError):
            LevelPolicy(medium_fpr=0.01, high_fpr=0.05)

    def test_personal_features_capture_employee_specific_novelty(self):
        sample = self.test.iloc[:50]
        baseline = self.brain.baseline_
        personal = baseline.transform(sample)
        swapped = sample.copy()
        used = baseline.service_prob_.idxmax(axis=1)
        swapped['destination_service'] = [next(s for s in SERVICES if baseline.service_prob_.at[e, s] == baseline.service_prob_.loc[e].min()) for e in swapped.employee_id]
        self.assertTrue((baseline.transform(swapped).emp_service_rarity.to_numpy() >= personal.emp_service_rarity.to_numpy() - 1e-9).all())
        self.assertTrue(len(used))
        unknown = sample.assign(employee_id='EMP-UNKNOWN')
        self.assertTrue(baseline.transform(unknown).isna().all().all())
        self.assertTrue(np.isfinite(self.brain.score_events(unknown)).all())

    def test_employee_risk_one_row_per_employee_and_ranks_anomalous_employee_first(self):
        window = self.test.copy()
        bad = anomalous_like(window, n=5).assign(employee_id='EMP0003', ts=window.ts.max())
        window = pd.concat([window, bad], ignore_index=True)
        table = self.brain.employee_risk(window)
        self.assertEqual(table.employee_id.nunique(), len(table))
        self.assertEqual(table.iloc[0].employee_id, 'EMP0003')
        self.assertEqual(table.iloc[0].level, 'high')
        self.assertTrue(table.peak_daily_risk.is_monotonic_decreasing)

    def test_explanations_name_the_deviating_features(self):
        reasons = self.brain.explain(anomalous_like(self.test, n=3))
        self.assertEqual(len(reasons), 3)
        self.assertTrue(any('bytes_out' in r or 'activity' in r or 'source_events' in r for r in reasons[0]))

    def test_brain_has_no_supervised_models_or_rule_engine(self):
        forbidden = {'DecisionTreeClassifier', 'RandomForestClassifier', 'LogisticRegression', 'SVC',
                     'GradientBoostingClassifier', 'KNeighborsClassifier', 'MLPClassifier'}
        for path in BRAIN_DIR.glob('*.py'):
            names = {n.id for n in ast.walk(ast.parse(path.read_text())) if isinstance(n, ast.Name)}
            names |= {a.name for n in ast.walk(ast.parse(path.read_text())) if isinstance(n, ast.ImportFrom) for a in n.names}
            self.assertFalse(names & forbidden, f'{path.name} uses {names & forbidden}')
        self.assertFalse((BRAIN_DIR.parent / 'ai_engine.py').exists())
        self.assertFalse((BRAIN_DIR.parent / 'ai_training.py').exists())

    def test_training_code_reads_labels_only_after_freezing(self):
        source = (BRAIN_DIR / 'train.py').read_text()
        self.assertLess(source.index('.calibrate(calibration)'), source.index('load_evaluation_labels(args.dataset)'))
        for module in ('model.py', 'features.py'):
            text = (BRAIN_DIR / module).read_text()
            self.assertNotIn('Ground_Truth_Evaluation', text)
            self.assertNotIn('load_evaluation_labels', text)


if __name__ == '__main__':
    unittest.main()
