"""Active-defense (Phase 4) tests: score trigger, enforcement, reversal, attribution."""
import json
import tempfile
import unittest
from pathlib import Path

from monitor.core import Engine, now
from monitor.collectors import attribution, actor_sidecar
from monitor.response import Responder, MODES

DEVICE = '10.200.0.11'   # DEV0002-1 -> EMP0002


def activity(ts, ip=DEVICE, **extra):
    record = dict(ts=ts, source_ip=ip, destination_ip='10.10.1.20', destination_port=445, bytes_in=1500,
                  bytes_out=600, response_time_ms=45, kind='file_read', message=f'activity {ts}')
    record.update(extra)
    return record


class ResponseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.settings = {'lab': {'runtime': str(root / 'lab')}}
        self.e = Engine(root / 'live.db', self.settings)
        self.brain = self.e.brain
        self.high = self.brain.employee_boundaries_['high']
        # EMP0002 has crossed the high boundary; EMP0001 sits below it.
        self.e.db.execute("INSERT INTO employee_risk(employee_id, peak_risk, risk, level) VALUES (?,?,?,?)",
                          ('EMP0002', self.high + 0.05, self.high + 0.05, 'high'))
        self.e.db.execute("INSERT INTO employee_risk(employee_id, peak_risk, risk, level) VALUES (?,?,?,?)",
                          ('EMP0001', self.high - 0.05, self.high - 0.05, 'medium'))
        self.e.db.commit()
        self.r = Responder(self.e)

    def tearDown(self):
        self.e.close()
        self.tmp.cleanup()

    def test_default_mode_is_manual_and_validated(self):
        self.assertEqual(self.r.mode(), 'manual')
        with self.assertRaises(ValueError):
            self.r.set_mode('nonsense')
        for m in MODES:
            self.assertEqual(self.r.set_mode(m), m)

    def test_only_high_peak_is_a_candidate(self):
        ids = {c['employee_id'] for c in self.r.candidates(self.brain)}
        self.assertIn('EMP0002', ids)
        self.assertNotIn('EMP0001', ids)   # medium never triggers

    def test_auto_mode_responds_and_writes_enforcement(self):
        self.r.set_mode('auto')
        created = self.r.evaluate(self.brain)
        self.assertEqual(len(created), 1)
        active = self.r.active_responses()
        self.assertEqual(active[0]['employee_id'], 'EMP0002')
        self.assertEqual(active[0]['created_by'], 'auto')
        enforcement = json.loads(self.e.enforcement_path.read_text())
        self.assertIn(DEVICE, enforcement['blocked_ips'])
        self.assertIn('EMP0002', enforcement['ended_sessions'])
        # Idempotent: a second evaluation creates nothing new.
        self.assertEqual(self.r.evaluate(self.brain), [])

    def test_blocks_the_ip_that_raised_the_risk_not_the_first_device(self):
        from monitor.brain.explain import explain_employee
        from monitor.views import employee_events, risk_source_ip
        second = '10.200.0.12'                                     # DEV0002-2 -> EMP0002
        base = now() - 7200
        self.e.process(activity(base))
        self.e.process(activity(base + 600, ip=second, destination_ip='10.20.1.20', destination_port=5432,
                                bytes_in=60000, bytes_out=9000000, response_time_ms=1500))
        self.e.process(activity(base + 1200))                       # latest event back on the first device
        self.r.respond('EMP0002', brain=self.brain, peak_risk=self.high + 0.05)
        blocked = self.r.active_responses()[0]['source_ip']
        self.assertEqual(blocked, second)
        self.assertIn(second, json.loads(self.e.enforcement_path.read_text())['blocked_ips'])
        self.assertNotIn(DEVICE, json.loads(self.e.enforcement_path.read_text())['blocked_ips'])
        # Same address as the ranking column and the AI analysis line.
        self.assertEqual(risk_source_ip(self.e, self.brain, 'EMP0002'), blocked)
        row = dict(employee_id='EMP0002', risk=self.high, level='high', risk_percentile=99.0)
        report = explain_employee(self.brain, self.e.directory, row, employee_events(self.e, 'EMP0002'))
        self.assertEqual(report['key_events'][0]['ip'], blocked)

    def test_without_events_falls_back_to_the_directory_device(self):
        self.r.respond('EMP0002', brain=self.brain, peak_risk=self.high + 0.05)
        self.assertEqual(self.r.active_responses()[0]['source_ip'], DEVICE)

    def test_dashboard_shows_blocked_ip_beside_employee(self):
        import os
        from unittest.mock import patch
        from streamlit.testing.v1 import AppTest
        root = Path(__file__).resolve().parents[1]
        self.e.process(activity(now()))
        self.r.respond('EMP0002', brain=self.brain, peak_risk=self.high + 0.05, created_by='analyst')
        with patch.dict(os.environ, {'SIX_DATA': self.tmp.name, 'SIX_CONFIG': str(root / 'config.example.json')}):
            app = AppTest.from_file(str(root / 'app.py')).run(timeout=60)
        self.assertFalse(app.exception)
        lines = [m.value for m in app.markdown]
        self.assertTrue(any(v.startswith('🛡️ EMP0002') and f'⛔ Blocked IP: `{DEVICE}`' in v for v in lines), lines)
        ranking = next(f.value for f in app.dataframe if 'IP Address' in f.value.columns)
        self.assertEqual(ranking.set_index('Employee').loc['EMP0002', 'IP Address'], DEVICE)

    def test_revert_sticks_in_auto_mode_until_peak_rises(self):
        self.r.set_mode('auto')
        [rid] = self.r.evaluate(self.brain)
        self.r.revert(rid)
        # Same peak: the analyst's decision is not immediately undone by the auto loop.
        self.assertEqual(self.r.evaluate(self.brain), [])
        # A genuinely escalating threat (higher peak) re-triggers.
        self.e.db.execute("UPDATE employee_risk SET peak_risk=? WHERE employee_id='EMP0002'", (self.high + 0.2,))
        self.e.db.commit()
        self.assertEqual(len(self.r.evaluate(self.brain)), 1)

    def test_manual_and_disabled_do_not_auto_respond(self):
        self.r.set_mode('manual')
        self.assertEqual(self.r.evaluate(self.brain), [])
        self.r.set_mode('disabled')
        self.assertEqual(self.r.evaluate(self.brain), [])
        self.assertEqual(self.r.active_responses(), [])

    def test_collector_honours_block(self):
        self.r.set_mode('auto')
        self.r.evaluate(self.brain)
        result = self.e.process(activity(now()))
        self.assertTrue(result['enforced'])
        row = next(r for r in self.e.rows('events'))
        self.assertEqual(row['status'], 'BLOCKED')
        self.assertEqual(row['enforced'], 1)
        # A blocked attempt does not change the employee's risk state.
        peak = self.e.db.execute("SELECT peak_risk FROM employee_risk WHERE employee_id='EMP0002'").fetchone()[0]
        self.assertAlmostEqual(peak, self.high + 0.05)

    def test_revert_lifts_enforcement_and_audits(self):
        self.r.set_mode('auto')
        [response_id] = self.r.evaluate(self.brain)
        self.assertTrue(self.r.revert(response_id, actor='tester'))
        enforcement = json.loads(self.e.enforcement_path.read_text())
        self.assertNotIn(DEVICE, enforcement['blocked_ips'])
        self.assertNotIn('EMP0002', enforcement['ended_sessions'])
        self.assertEqual(self.r.active_responses(), [])
        row = self.e.db.execute('SELECT status, reverted_by FROM responses WHERE id=?', (response_id,)).fetchone()
        self.assertEqual((row['status'], row['reverted_by']), ('reverted', 'tester'))
        actions = {a['action'] for a in self.r.audit_log()}
        self.assertTrue({'respond', 'revert', 'mode_change'} <= actions)
        # After reverting, the same source is no longer blocked by the collector.
        self.assertFalse(self.e.process(activity(now() + 1))['enforced'])

    def test_block_lifts_only_when_no_other_response_needs_it(self):
        self.r.set_mode('manual')
        a = self.r.respond('EMP0002', created_by='analyst', peak_risk=self.high + 0.05)
        b = self.r.respond('EMP0002', actions=('block_ip',), created_by='analyst', peak_risk=self.high + 0.05)
        self.r.revert(a)
        # b still blocks the IP.
        self.assertIn(DEVICE, json.loads(self.e.enforcement_path.read_text())['blocked_ips'])
        self.r.revert(b)
        self.assertNotIn(DEVICE, json.loads(self.e.enforcement_path.read_text())['blocked_ips'])


class AttributionTests(unittest.TestCase):
    def test_sidecar_attributes_recent_change_and_is_consumed(self):
        with tempfile.TemporaryDirectory() as tmp:
            watched = Path(tmp) / 'settings.txt'
            watched.write_text('x')
            actor_sidecar(watched).write_text(json.dumps(dict(source_ip=DEVICE, employee_id='EMP0002', ts=now())))
            result = attribution(watched)
            self.assertEqual(result, {'source_ip': DEVICE})
            self.assertFalse(actor_sidecar(watched).exists())   # consumed

    def test_stale_sidecar_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            watched = Path(tmp) / 'settings.txt'
            watched.write_text('x')
            actor_sidecar(watched).write_text(json.dumps(dict(source_ip=DEVICE, ts=now() - 10000)))
            self.assertEqual(attribution(watched), {})

    def test_no_sidecar_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(attribution(Path(tmp) / 'settings.txt'), {})


class LabEnforcementTests(unittest.TestCase):
    def test_blocked_sources_reads_enforcement_file(self):
        from monitor.lab import blocked_sources
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp)
            (runtime / 'enforcement.json').write_text(json.dumps({'blocked_ips': {DEVICE: {}}}))
            self.assertEqual(blocked_sources({'runtime': runtime}), {DEVICE})
            (runtime / 'enforcement.json').unlink()
            self.assertEqual(blocked_sources({'runtime': runtime}), set())


if __name__ == '__main__':
    unittest.main()
