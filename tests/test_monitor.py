import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from monitor.core import Engine, CATEGORIES, collect, parse, config
from monitor.demo import events


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)/'events.db'
        self.e = Engine(self.path)

    def tearDown(self):
        self.e.close()
        self.tmp.cleanup()

    def test_all_six_rules_and_alert_fields(self):
        for event in events():
            self.e.process(event)
        self.assertEqual(set(a['attack'] for a in self.e.rows('alerts')), set(CATEGORIES))
        self.assertEqual(len(self.e.rows('alerts')), 6)
        for alert in self.e.rows('alerts'):
            for field in ('attack', 'ts', 'severity', 'rule', 'description', 'action', 'event_id'):
                self.assertTrue(alert[field])
            linked = next(e for e in self.e.rows('events') if e['id'] == alert['event_id'])
            self.assertEqual(linked['status'], 'ABNORMAL')

    def test_normal(self):
        for e in [dict(ts=1, kind='normal', message='ok'), dict(ts=2, kind='http', message='GET /'), dict(ts=3, kind='file', message='approved', authorized=True), dict(ts=4, kind='privilege', message='sudo: COMMAND=/usr/bin/ls')]:
            self.assertEqual(self.e.process(e), [])
        self.assertTrue(all(e['status'] == 'NORMAL' for e in self.e.rows('events')))

    def test_threshold_windows_and_sources(self):
        for i in range(4):
            self.e.process(dict(ts=i, kind='ssh_failed', ip='192.0.2.1', message=str(i)))
        self.e.process(dict(ts=61, kind='ssh_failed', ip='192.0.2.1', message='late'))
        self.e.process(dict(ts=3, kind='ssh_failed', ip='192.0.2.2', message='other'))
        self.assertEqual(self.e.rows('alerts'), [])

    def test_ssh_inclusive_boundary(self):
        for i in [0, 10, 20, 30, 60]:
            self.e.process(dict(ts=i, kind='ssh_failed', ip='192.0.2.1', message=str(i)))
        self.assertEqual(len(self.e.rows('alerts')), 1)

    def test_duplicate_and_persistence(self):
        for _ in range(2):
            for event in events(100):
                self.e.process(event)
        self.assertEqual(len(self.e.rows('alerts')), 6)
        self.assertEqual(len(self.e.rows('events')), 74)
        self.e.close()
        self.e = Engine(self.path)
        self.assertEqual(len(self.e.rows('alerts')), 6)

    def test_cooldown(self):
        for i in range(10):
            self.e.process(dict(ts=i, kind='ssh_failed', ip='192.0.2.1', message=str(i)))
        self.assertEqual(len(self.e.rows('alerts')), 1)
        self.assertEqual(sum(e['status'] == 'ABNORMAL' for e in self.e.rows('events')), 6)

    def test_distinct_ports(self):
        for i in range(20):
            self.e.process(dict(ts=i, kind='connection', ip='192.0.2.1', port=80, message=str(i)))
        self.assertEqual(self.e.rows('alerts'), [])

    def test_configurable_dos_boundary(self):
        self.e.c.update(dos_count=3, dos_window=2)
        for i in range(3):
            result = self.e.process(dict(ts=i, kind='http', ip='192.0.2.1', message='GET /'))
            self.assertEqual(bool(result), i == 2)

    def test_ingestion_partial_and_duplicate(self):
        path = Path(self.tmp.name)/'test.jsonl'
        record = json.dumps(dict(ts=1, kind='normal', message='ok'))
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
        path.write_text('bad json\n[]\n')
        self.e.c['sources'] = [dict(path=str(path)), dict(path=str(path)+'missing')]
        status = collect(self.e)
        self.assertIn('rejected lines this poll: 2', status[0]['status'])
        self.assertIn('No such file', status[1]['status'])

    def test_file_monitor_authorization(self):
        path = Path(self.tmp.name)/'file'
        path.write_text('a')
        self.e.c['files'] = [dict(path=str(path), authorized_sha256=hashlib.sha256(b'b').hexdigest())]
        collect(self.e)
        path.write_text('b')
        collect(self.e)
        self.assertEqual(len(self.e.rows('alerts')), 0)
        path.write_text('c')
        collect(self.e)
        collect(self.e)
        self.assertEqual(len(self.e.rows('alerts')), 1)

    def test_auth_parser(self):
        event = parse('Nov  7 12:00:00 host sshd: Failed password for root from 192.0.2.1 port 22', 'auth', 'auth', '1')
        self.assertEqual(event['kind'], 'ssh_failed')
        self.assertEqual(event['ip'], '192.0.2.1')

    def test_invalid_event(self):
        for event in [dict(ts=float('nan'), kind='normal', message='bad'), dict(ts=1, kind='connection', port=0, message='bad'), dict(ts=1, kind='file', authorized='false', message='bad')]:
            with self.assertRaises(ValueError):
                self.e.process(event)
        self.assertEqual(self.e.rows('events'), [])

    def test_invalid_config(self):
        path = Path(self.tmp.name)/'config.json'
        path.write_text('{"ssh_count":0}')
        with self.assertRaises(ValueError):
            config(path)

    def test_dashboard_startup_demo_and_filters(self):
        from unittest.mock import patch
        from streamlit.testing.v1 import AppTest
        with patch.dict(os.environ, {'SIX_DATA': self.tmp.name}):
            app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / 'app.py')).run(timeout=20)
            self.assertFalse(app.exception)
            app.button[0].click().run()
            self.assertFalse(app.exception)
            self.assertEqual([m.value for m in app.metric], ['74', '68', '6', '6'])
            app.button[0].click().run()
            self.assertEqual([m.value for m in app.metric], ['74', '68', '6', '6'])
            app.sidebar.selectbox[0].select('SQL Injection').run()
            self.assertFalse(app.exception)
            self.assertEqual([m.value for m in app.metric], ['1', '0', '1', '1'])
            app.sidebar.radio[0].set_value('Live monitoring').run()
            self.assertFalse(app.exception)
            self.assertEqual(app.metric[0].value, '0')

    def test_jsonl_pipeline_six_categories(self):
        path = Path(self.tmp.name)/'all.jsonl'
        path.write_text('\n'.join(json.dumps(e) for e in events())+'\n')
        self.e.c['sources'] = [dict(path=str(path))]
        collect(self.e)
        collect(self.e)
        self.assertEqual(len(self.e.rows('events')), 74)
        self.assertEqual({a['attack'] for a in self.e.rows('alerts')}, set(CATEGORIES))

    def test_rotation(self):
        path = Path(self.tmp.name)/'log.jsonl'
        path.write_text(json.dumps(dict(ts=1, kind='normal', message='first'))+'\n')
        self.e.c['sources'] = [dict(path=str(path))]
        collect(self.e)
        path.rename(path.with_suffix('.old'))
        path.write_text(json.dumps(dict(ts=2, kind='normal', message='second'))+'\n')
        collect(self.e)
        self.assertEqual(len(self.e.rows('events')), 2)
