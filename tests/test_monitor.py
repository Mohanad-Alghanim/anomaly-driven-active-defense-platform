"""Engine, collection and dashboard tests for the brain-scored pipeline (no rules)."""
import ast
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

import numpy as np

from monitor.core import Engine, RETIRED_RULE_KEYS, collect, config, parse
from monitor.demo import events as demo_events
from monitor.views import active_ranking, device_ips, employee_ip, employee_table, snapshot

ROOT = Path(__file__).resolve().parents[1]
DEVICE = '10.200.0.10'      # DEV0001-1 -> EMP0001
OTHER = '10.200.0.11'       # DEV0002-1 -> EMP0002
FILE_SERVER = '10.10.1.20'


def activity(ts, ip=DEVICE, **extra):
    record = dict(ts=ts, source_ip=ip, destination_ip=FILE_SERVER, destination_port=445, bytes_in=1500,
                  bytes_out=600, response_time_ms=45, kind='file_read', message=f'activity {ts}')
    record.update(extra)
    return record


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)/'events.db'
        self.e = Engine(self.path)

    def tearDown(self):
        self.e.close()
        self.tmp.cleanup()

    def test_every_event_scored_with_data_derived_level(self):
        base = 1794042000
        results = [self.e.process(activity(base + i * 600)) for i in range(5)]
        brain = self.e.brain
        for result in results:
            expected = 'high' if result['score'] >= brain.boundaries_['high'] else 'medium' if result['score'] >= brain.boundaries_['medium'] else 'low'
            self.assertEqual(result['level'], expected)
            self.assertEqual(result['employee_id'], 'EMP0001')
        rows = self.e.rows('events')
        self.assertTrue(all(r['status'] == r['level'].upper() for r in rows))
        features = json.loads(rows[0]['features'])
        self.assertEqual(set(features), set(brain.feature_names))
        self.assertNotIn('destination_port', features)

    def test_active_ranking_keeps_a_calmed_spike_above_a_steady_employee(self):
        """An employee who spiked then went quiet must outrank one with low, steady risk."""
        base = 1794042000
        # EMP0002 spikes early (an anomalous burst), then only normal activity after.
        for i in range(8):
            self.e.process(activity(base + 60 + i, ip=OTHER, destination_ip='10.20.1.20', destination_port=5432,
                                    bytes_in=60000, bytes_out=9000, response_time_ms=1500))
        for i in range(30):
            self.e.process(activity(base + 7200 + i * 1800, ip=OTHER))   # back to normal, spread out
        # EMP0001 is steadily normal throughout.
        for i in range(30):
            self.e.process(activity(base + i * 1800))
        brain = self.e.brain
        ranked = active_ranking(self.e, brain, base - 1)
        self.assertEqual(ranked[0]['employee_id'], 'EMP0002')
        self.assertGreater(ranked[0]['peak_risk'], ranked[0]['risk'])        # calmed: peak above current
        self.assertEqual(ranked[0]['peak_level'], 'high')
        current_order = active_ranking(self.e, brain, base - 1)
        self.assertTrue(all(current_order[i]['peak_risk'] >= current_order[i + 1]['peak_risk']
                            for i in range(len(current_order) - 1)))
        # A window that starts after the spike no longer sees it as the peak.
        later = active_ranking(self.e, brain, base + 3600)
        emp2 = next(e for e in later if e['employee_id'] == 'EMP0002')
        self.assertLess(emp2['peak_risk'], ranked[0]['peak_risk'])

    def test_ranking_reports_ip_of_latest_event_for_display_only(self):
        base = 1794042000
        self.e.process(activity(base, ip='10.200.0.11'))            # DEV0002-1 -> EMP0002
        self.e.process(activity(base + 600, ip='10.200.0.12'))      # DEV0002-2 -> EMP0002 (latest)
        self.e.process(activity(base + 300))                        # EMP0001
        ranked = {e['employee_id']: e for e in active_ranking(self.e, self.e.brain, base - 1)}
        self.assertEqual(ranked['EMP0002']['last_ip'], '10.200.0.12')
        self.assertEqual(ranked['EMP0001']['last_ip'], DEVICE)
        directory = self.e.directory
        self.assertEqual(device_ips(directory, 'EMP0002'), ['10.200.0.11', '10.200.0.12'])
        self.assertEqual(employee_ip(directory, 'EMP0002', '10.200.0.12'), '10.200.0.12')
        self.assertEqual(employee_ip(directory, 'EMP0002'), '10.200.0.11, 10.200.0.12')
        self.assertEqual(employee_ip(directory, 'NOBODY'), '')
        # The IP is display context only: it never reaches the model's inputs.
        self.assertFalse({'ip', 'source_ip', 'last_ip'} & set(self.e.brain.feature_names))
        features = json.loads(self.e.rows('events')[0]['features'])
        self.assertFalse(any('ip' == k or k.endswith('_ip') for k in features))

    def test_unusual_behaviour_scores_higher_than_routine(self):
        base = 1794042000 + 3 * 3600   # 06:00 local (Riyadh) on a working day
        routine = self.e.process(activity(base))
        burst = [self.e.process(activity(base + 7200 + i, ip=OTHER, destination_ip='10.20.1.20', destination_port=5432,
                                         bytes_in=60000, bytes_out=9000, response_time_ms=1500)) for i in range(25)]
        self.assertGreater(burst[-1]['score'], routine['score'])
        self.assertEqual(burst[-1]['level'], 'high')
        table = employee_table(self.e)
        self.assertEqual(table[0]['employee_id'], 'EMP0002')
        self.assertEqual(table[0]['level'], 'high')

    def test_employee_risk_is_count_free(self):
        """Repeating the same events must not change an employee's risk."""
        once = Engine(Path(self.tmp.name)/'once.db')
        twice = Engine(Path(self.tmp.name)/'twice.db')
        try:
            for i in range(4):
                record = activity(1794042000 + i * 900)
                once.process(record)
                twice.process(record)
                twice.process(record | dict(message=f'copy {i}'))
            a, b = employee_table(once)[0], employee_table(twice)[0]
            self.assertEqual(b['events'], 2 * a['events'])
            self.assertAlmostEqual(a['risk'], b['risk'], delta=0.05)
        finally:
            once.close()
            twice.close()

    def test_previous_hour_activity_counts_same_source_only(self):
        base = 1794042000
        for i in range(3):
            self.e.process(activity(base + i))
        self.e.process(activity(base + 3, ip=OTHER))
        self.e.process(activity(base + 4000))
        prev = {r['ts']: r['prev_hour'] for r in self.e.rows('events')}
        self.assertEqual([prev[base], prev[base + 1], prev[base + 2]], [0, 1, 2])
        self.assertEqual(prev[base + 3], 0)
        self.assertEqual(prev[base + 4000], 0)

    def test_unattributed_events_scored_but_not_ranked(self):
        result = self.e.process(dict(ts=1794042000, ip='192.0.2.1', kind='activity', message='unknown host'))
        self.assertIsNone(result['employee_id'])
        self.assertIsNotNone(result['score'])
        self.assertEqual(employee_table(self.e), [])

    def test_duplicate_and_persistence(self):
        for _ in range(2):
            for record in demo_events()[:50]:
                self.e.process(record)
        self.assertEqual(len(self.e.rows('events')), 50)
        risk = employee_table(self.e)
        self.e.close()
        self.e = Engine(self.path)
        self.assertEqual(employee_table(self.e), risk)

    def test_ingestion_partial_and_duplicate(self):
        path = Path(self.tmp.name)/'test.jsonl'
        record = json.dumps(activity(1))
        path.write_text(record+'\n'+record)
        self.e.c['sources'] = [dict(path=str(path))]
        collect(self.e)
        collect(self.e)
        self.assertEqual(len(self.e.rows('events')), 1)
        with path.open('a') as handle:
            handle.write('\n')
        collect(self.e)
        self.assertEqual(len(self.e.rows('events')), 2)

    def test_malformed_and_missing_source(self):
        path = Path(self.tmp.name)/'test.jsonl'
        path.write_text('bad json\n[]\n' + json.dumps(dict(ts=1, source_ip='not-an-ip')) + '\n')
        self.e.c['sources'] = [dict(path=str(path)), dict(path=str(path)+'missing')]
        status = collect(self.e)
        self.assertIn('rejected lines this poll: 3', status[0]['status'])
        self.assertIn('No such file', status[1]['status'])

    def test_file_monitor_records_changes_for_scoring(self):
        path = Path(self.tmp.name)/'file'
        path.write_text('a')
        self.e.c['files'] = [dict(path=str(path), authorized_sha256=hashlib.sha256(b'b').hexdigest())]
        collect(self.e)
        path.write_text('b')
        collect(self.e)
        path.write_text('c')
        collect(self.e)
        collect(self.e)
        changes = [r for r in self.e.rows('events') if r['kind'] == 'file_change']
        self.assertEqual(len(changes), 2)
        self.assertEqual(sorted(bool(r['authorized']) for r in changes), [False, True])
        self.assertTrue(all(r['score'] is not None for r in changes))

    def test_auth_parser(self):
        event = parse('Nov  7 12:00:00 host sshd: Failed password for root from 192.0.2.1 port 22', 'auth', 'auth', '1')
        self.assertEqual(event['kind'], 'auth_failure')
        self.assertEqual(event['ip'], '192.0.2.1')

    def test_invalid_event(self):
        for event in [dict(ts=float('nan'), message='bad'), dict(ts=1, port=0, message='bad'), dict(ts=1, authorized='false', message='bad'),
                      dict(ts=1, bytes_out=-5), dict(ts='2026-11-01T10:00:00')]:
            with self.assertRaises(ValueError):
                self.e.process(event)
        self.assertEqual(self.e.rows('events'), [])

    def test_invalid_config_and_retired_rule_keys(self):
        path = Path(self.tmp.name)/'config.json'
        path.write_text('{"poll_seconds":0}')
        with self.assertRaises(ValueError):
            config(path)
        path.write_text(json.dumps({key: 5 for key in RETIRED_RULE_KEYS}))
        loaded = config(path)
        self.assertFalse(set(RETIRED_RULE_KEYS) & set(loaded))

    def test_rotation(self):
        path = Path(self.tmp.name)/'log.jsonl'
        path.write_text(json.dumps(activity(1))+'\n')
        self.e.c['sources'] = [dict(path=str(path))]
        collect(self.e)
        path.rename(path.with_suffix('.old'))
        path.write_text(json.dumps(activity(2))+'\n')
        collect(self.e)
        self.assertEqual(len(self.e.rows('events')), 2)

    def test_demo_replay_keeps_weekday_and_local_time(self):
        raw = [json.loads(line) for line in (ROOT/'samples/behavioral_demo.jsonl').read_text().splitlines()]
        shifted = demo_events()
        self.assertEqual(len(raw), len(shifted))
        deltas = {round(s['ts'] - r['ts']) for r, s in zip(raw, shifted)}
        self.assertEqual(len(deltas), 1)
        self.assertEqual(deltas.pop() % (7 * 86400), 0)

    def test_snapshot_counts_by_level(self):
        for record in demo_events()[:200]:
            self.e.process(record)
        view = snapshot(self.e, 0)
        counts = view['counts']
        self.assertEqual(counts['total'], 200)
        self.assertEqual(counts['high'] + counts['medium'] + counts['low'], counts['scored'])

    def test_no_rule_engine_remains(self):
        """No regex attack signatures, attack categories or windowed count thresholds in the pipeline."""
        for name in ('core.py', 'adapters.py', 'collectors.py', 'journal.py', 'views.py', 'worker.py', 'lab_readiness.py'):
            text = (ROOT/'monitor'/name).read_text()
            tree = ast.parse(text)
            assigned = {t.id for n in ast.walk(tree) if isinstance(n, ast.Assign) for t in n.targets if isinstance(t, ast.Name)}
            self.assertFalse(assigned & {'CATEGORIES', 'ACTIONS', 'SQL', 'PRIV'}, name)
            for phrase in ('Brute Force', 'Port Scanning', 'Denial of Service', 'Rule-based', 'hits.append'):
                self.assertNotIn(phrase, text, f'{phrase} in {name}')
        for name in ('ssh_lab.py', 'lab_test.py', 'privilege_probe.py', 'dataset_analysis.py', 'ai_engine.py', 'ai_training.py'):
            self.assertFalse((ROOT/'monitor'/name).exists(), name)
        self.assertNotIn('Rule-based', (ROOT/'app.py').read_text())

    def test_dashboard_demo_ranks_employees_and_explains(self):
        from unittest.mock import patch
        from streamlit.testing.v1 import AppTest
        with patch.dict(os.environ, {'SIX_DATA': self.tmp.name, 'SIX_CONFIG': str(ROOT/'config.example.json')}):
            app = AppTest.from_file(str(ROOT / 'app.py')).run(timeout=60)
            self.assertFalse(app.exception)
            app.sidebar.radio[0].set_value('Demonstration').run(timeout=60)
            app.button[0].click().run(timeout=120)
            self.assertFalse(app.exception)
            metrics = {m.label: m.value for m in app.metric}
            self.assertGreater(int(metrics['Employees monitored']), 100)
            self.assertGreater(int(metrics['High risk']), 0)
            ranking = next(frame.value for frame in app.dataframe if 'Percentile vs normal' in frame.value.columns)
            # Primary sort is the peak risk reached in the window (not current risk).
            self.assertTrue(np.all(np.diff(ranking['Peak risk'].to_numpy()) <= 0))
            self.assertIn('Current risk', ranking.columns)
            self.assertIn('Peak time', ranking.columns)
            columns = list(ranking.columns)
            self.assertEqual(columns[columns.index('Employee') + 1], 'IP Address')
            self.assertTrue(ranking['IP Address'].str.match(r'^\d+\.\d+\.\d+\.\d+').all())
            self.assertTrue(any(m.value.startswith('**Device IP of the most influential event:**') for m in app.markdown))
            self.assertTrue(ranking['Level'].iloc[0].endswith('HIGH'))
            self.assertTrue(any(h.value.startswith('AI analysis — ' + ranking['Employee'].iloc[0]) for h in app.subheader))
            self.assertTrue(any('standard deviations' in m.value for m in app.markdown))
            app.selectbox(key='analyse_employee').select(ranking['Employee'].iloc[-1]).run(timeout=60)
            self.assertFalse(app.exception)
            self.assertTrue(any(h.value.startswith('AI analysis — ' + ranking['Employee'].iloc[-1]) for h in app.subheader))
            app.sidebar.radio[0].set_value('Live monitoring').run(timeout=60)
            self.assertFalse(app.exception)
            self.assertEqual(app.metric[0].value, '0')
