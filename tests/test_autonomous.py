import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from monitor.adapters import parse_journal, parse_line
from monitor.core import Engine, config, now
from monitor.fixtures import write_fixtures
from monitor.install import prepare
from monitor.journal import collect_journal, read_journal
from monitor.views import collector_health, employee_table, snapshot
from monitor.worker import cycle

ROOT = Path(__file__).resolve().parents[1]


def journal_reader(records, fail_cursor=False):
    def read(command, limit):
        cursors = [arg.split('=',1)[1] for arg in command if arg.startswith('--after-cursor=')]
        if cursors and fail_cursor:
            return [], 1, 'Failed to seek to cursor: Invalid argument'
        start = 0
        if cursors:
            start = next((i+1 for i,r in enumerate(records) if r['__CURSOR'] == cursors[0]), 0)
        return [json.dumps(r) for r in records[start:start+limit]], 0, ''
    return read


class AutonomousTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root/'live.db'

    def tearDown(self):
        self.temp.cleanup()

    def settings(self):
        return config(ROOT/'config.example.json')

    def test_telemetry_scored_attributed_and_restart(self):
        records = write_fixtures(self.root/'fixtures', now()-70)
        settings = self.settings()
        settings['sources'] = [dict(path=str(self.root/'fixtures/access.log.example'), format='http_access', destination='lab', destination_port=8080), dict(path=str(self.root/'fixtures/firewall.log.example'), format='netfilter')]
        settings['files'] = [dict(path=str(self.root/'fixtures/lab-file.txt'))]
        engine = Engine(self.db, settings)
        try:
            cycle(engine, journal_reader([]))  # establish file baseline
            (self.root/'fixtures/lab-file.txt').write_text('Synthetic unauthorized change\n')
            health = cycle(engine, journal_reader(records))
            self.assertEqual(health['status'], 'RUNNING')
            self.assertTrue(health['model_version'].startswith('insider_brain:'))
            rows = engine.rows('events')
            self.assertTrue(all(e['score'] is not None and e['level'] in ('low', 'medium', 'high') for e in rows))
            sudo = [e for e in rows if 'COMMAND=/usr/bin/id' in e['message']]
            self.assertEqual(sudo[0]['kind'], 'privilege_command')
            self.assertEqual({e['employee_id'] for e in rows if e['ip'] == '10.200.0.10'}, {'EMP0001'})
            self.assertEqual({r['employee_id'] for r in employee_table(engine)}, {'EMP0001', 'EMP0002'})
            self.assertTrue(any(e['kind'] == 'file_change' and e['employee_id'] is None for e in rows))
            connection = min((e for e in rows if e['kind']=='connection'), key=lambda e: e['ts'])
            self.assertEqual(connection['dst_service'], 'File Server')
            self.assertEqual(connection['dst_ip'], '10.10.1.20')
            self.assertTrue(connection['source_port'])
            self.assertTrue(json.loads(engine.state('journal_cursor'))['cursor'].endswith(':6'))
            count = len(rows)
        finally:
            engine.close()
        engine = Engine(self.db, settings)
        try:
            cycle(engine, journal_reader(records))
            self.assertEqual(len(engine.rows('events')), count)
            self.assertEqual(sum(r['events'] for r in employee_table(engine)), sum(e['employee_id'] is not None for e in engine.rows('events')))
            with EngineContext(self.db) as reader:
                view = snapshot(reader, now()-3600)
                self.assertEqual(view['counts']['total'], count)
                self.assertEqual(view['counts']['scored'], count)
        finally:
            engine.close()

    def test_expired_journal_cursor_recovery(self):
        records = write_fixtures(self.root/'fixtures')
        engine = Engine(self.db, self.settings())
        try:
            first = collect_journal(engine, journal_reader(records))
            self.assertTrue(first['available'])
            count = len(engine.rows('events'))
            result = collect_journal(engine, journal_reader(records, fail_cursor=True))
            self.assertTrue(result['recovered'])
            self.assertEqual(len(engine.rows('events')), count)
            self.assertTrue(all(e['score'] is not None for e in engine.rows('events')))
        finally:
            engine.close()

    def test_journal_small_batches_preserve_oldest_records(self):
        records = write_fixtures(self.root/'fixtures')
        settings = self.settings(); settings['batch_lines'] = 2
        engine = Engine(self.db, settings)
        try:
            for _ in range(4):
                collect_journal(engine, journal_reader(records))
            self.assertEqual(len(engine.rows('events')), 7)
            self.assertEqual(json.loads(engine.state('journal_cursor'))['cursor'], 'synthetic:auth:6')
        finally:
            engine.close()

    def test_journal_parsing_normal_sudo_su_and_ssh(self):
        records = write_fixtures(self.root/'fixtures')
        self.assertEqual(parse_journal(records[0])['kind'], 'auth_failure')
        self.assertEqual(parse_journal(records[0])['destination_service'], 'SSH Gateway')
        self.assertEqual(parse_journal(records[5])['kind'], 'privilege_command')
        self.assertEqual(parse_journal(records[5])['dst_host'], 'isolated-lab')
        su = records[5] | dict(SYSLOG_IDENTIFIER='su', MESSAGE='pam_unix(su:session): session opened for user root')
        engine = Engine(self.db)
        try:
            self.assertIn(engine.process(parse_journal(su))['level'], ('low', 'medium', 'high'))
            self.assertIsNone(engine.process(parse_journal(records[5])))  # same Journal cursor: deduplicated
            self.assertIn(engine.process(parse_journal(records[6]))['level'], ('low', 'medium', 'high'))
        finally:
            engine.close()
        with self.assertRaises(ValueError):
            parse_journal(dict(MESSAGE='missing cursor'))

    def test_journal_failures_visible_and_cursor_not_lost(self):
        engine = Engine(self.db, self.settings())
        try:
            engine.set_state('journal_cursor', json.dumps(dict(cursor='existing', ts=1)))
            result = collect_journal(engine, lambda *args: ([], 1, 'Permission denied'))
            self.assertFalse(result['available'])
            self.assertEqual(json.loads(engine.state('journal_cursor'))['cursor'], 'existing')
        finally:
            engine.close()

    def test_real_reader_is_bounded_without_journal(self):
        # Exercises the same process/stream logic using harmless JSON output.
        command = [sys.executable, '-c', "import json; [print(json.dumps({'n':i}),flush=True) for i in range(100)]"]
        records, code, issue = read_journal(command, 3)
        self.assertEqual([json.loads(r)['n'] for r in records], [0,1,2])
        self.assertEqual(code, 0)

    def test_access_and_netfilter_parsers(self):
        web = '192.0.2.2 - - [07/Nov/2026:12:00:00 +0000] "GET /report%20q3 HTTP/1.1" 200 512\n'
        result = parse_line(web, 'http_access', 'web', 'id', dict(destination='lab', destination_port=8080, destination_service='Internal Web'))
        self.assertIn('/report q3', result['message'])
        self.assertEqual(result['destination_port'], 8080)
        self.assertEqual(result['destination_service'], 'Internal Web')
        self.assertEqual(result['bytes_in'], 512)
        event = parse_line('2026-11-07T12:00:00Z kernel: SRC=192.0.2.1 DST=192.0.2.2 SPT=40000 DPT=22 PROTO=TCP', 'netfilter','fw','x')
        self.assertEqual(event['dst_ip'],'192.0.2.2')
        self.assertEqual(event['source_port'],40000)

    def test_health_stale_and_missing_sources(self):
        settings = self.settings()
        settings['sources'] = [dict(path=str(self.root/'missing'), format='http_access')]
        engine = Engine(self.db, settings)
        try:
            health = cycle(engine, journal_reader([]))
            self.assertEqual(health['status'],'DEGRADED')
            missing = next(s for s in health['sources'] if s['source'] == str(self.root/'missing'))
            self.assertFalse(missing['available'])
            engine.set_state('collector_health', json.dumps(dict(status='RUNNING', heartbeat=1, sources=[])))
            self.assertEqual(collector_health(engine)['status'], 'STALE / STOPPED')
        finally:
            engine.close()

    def test_database_old_schema_migrates_without_loss(self):
        old = sqlite3.connect(self.db)
        old.execute('CREATE TABLE events(id TEXT PRIMARY KEY, ts REAL, source TEXT, kind TEXT, ip TEXT, port INTEGER, message TEXT, authorized INTEGER, status TEXT)')
        old.execute("INSERT INTO events VALUES('old',1,'source','normal',NULL,NULL,'retained',0,'NORMAL')")
        old.execute('CREATE TABLE alerts(id INTEGER PRIMARY KEY, attack TEXT)')
        old.execute("INSERT INTO alerts(attack) VALUES('historical rule alert')")
        old.commit(); old.close()
        engine = Engine(self.db)
        try:
            self.assertEqual(engine.rows('events')[0]['message'], 'retained')
            engine.process(dict(ts=2,kind='normal',message='new',dst_host='lab'))
            self.assertEqual(len(engine.rows('events')),2)
            self.assertEqual(engine.db.execute('SELECT attack FROM alerts').fetchone()[0], 'historical rule alert')
            self.assertEqual(engine.db.execute('PRAGMA user_version').fetchone()[0], 3)
        finally:
            engine.close()

    def test_capacity_pauses_without_deleting(self):
        settings = self.settings(); settings['journal']={'enabled':False}; settings['max_events']=1
        path = self.root/'input.jsonl'
        path.write_text(''.join(json.dumps(dict(ts=i,kind='normal',message=str(i)))+'\n' for i in range(2)))
        settings['sources']=[dict(path=str(path))]
        engine = Engine(self.db,settings)
        try:
            health=cycle(engine)
            self.assertEqual(health['status'],'CAPACITY REACHED')
            self.assertEqual(len(engine.rows('events')),1)
        finally:
            engine.close()

    def test_concurrent_readonly_dashboard_and_writer(self):
        engine = Engine(self.db)
        engine.close()
        errors=[]
        def write():
            e=Engine(self.db)
            try:
                for i in range(50): e.process(dict(ts=i,kind='normal',message=str(i)))
            except Exception as exc: errors.append(exc)
            finally: e.close()
        thread=threading.Thread(target=write); thread.start()
        reader=Engine(self.db, readonly=True)
        try:
            for _ in range(20): snapshot(reader,0)
        finally: reader.close()
        thread.join()
        self.assertEqual(errors,[])

    def test_deployment_preparation_no_service_activation(self):
        home=self.root/'home'; (home/'Desktop').mkdir(parents=True)
        import shutil
        project = self.root/'project'
        (project/'.venv/bin').mkdir(parents=True)
        (project/'.venv/bin/python').symlink_to(sys.executable)
        shutil.copytree(ROOT/'deploy',project/'deploy')
        shutil.copy2(ROOT/'config.example.json',project/'config.example.json')
        with patch('monitor.install.subprocess.run', side_effect=AssertionError('must not start services')):
            units=prepare(project,home)
        dashboard=(units/'active-defense-dashboard.service').read_text()
        collector=(units/'active-defense-collector.service').read_text()
        self.assertIn('--server.address 127.0.0.1 --server.port 8501',dashboard)
        self.assertIn('WantedBy=default.target',collector)
        self.assertIn('Restart=on-failure',collector)
        self.assertTrue((home/'Desktop/active-defense.desktop').exists())

    def test_worker_process_restart_without_browser(self):
        data=self.root/'worker-data'; path=self.root/'source.jsonl'; cfg=self.root/'config.json'
        path.write_text(json.dumps(dict(ts=now(),kind='normal',message='before restart'))+'\n')
        cfg.write_text(json.dumps(dict(journal={'enabled':False},poll_seconds=1,sources=[dict(path=str(path))])))
        command=[sys.executable,'-m','monitor.worker','--data',str(data),'--config',str(cfg)]
        def wait_count(expected):
            deadline=time.monotonic()+8
            while time.monotonic()<deadline:
                try:
                    with EngineContext(data/'live.db') as e:
                        if len(e.rows('events'))==expected: return
                except sqlite3.Error: pass
                time.sleep(0.05)
            self.fail('Worker did not ingest expected events')
        for expected in (1,2):
            process=subprocess.Popen(command,cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            try:
                wait_count(expected)
            finally:
                process.terminate(); _,errors=process.communicate(timeout=10)
            self.assertEqual(process.returncode,0,errors.decode())
            if expected==1:
                with path.open('a') as handle: handle.write(json.dumps(dict(ts=now(),kind='normal',message='after restart'))+'\n')
        with EngineContext(data/'live.db') as e:
            self.assertEqual(collector_health(e)['status'],'STOPPED')
        self.assertEqual((data/'live.db').stat().st_mode & 0o777,0o600)

    def test_live_dashboard_reads_worker_state_without_collection(self):
        from streamlit.testing.v1 import AppTest
        engine=Engine(self.db,self.settings())
        try:
            cycle(engine,journal_reader([]))
            engine.process(dict(ts=now(),kind='http_request',ip='10.200.0.10',dst_ip='10.20.1.10',port=443,bytes_in=900,bytes_out=400,message='GET /report'))
        finally: engine.close()
        with patch.dict(os.environ,{'SIX_DATA':str(self.root),'SIX_CONFIG':str(ROOT/'config.example.json')}), patch('monitor.collectors.collect_files',side_effect=AssertionError('Dashboard must not collect')):
            app=AppTest.from_file(str(ROOT/'app.py')).run(timeout=20)
            self.assertFalse(app.exception)
            self.assertEqual(app.metric[0].value,'1')
            self.assertEqual(app.metric[3].value,'1')
            self.assertTrue(any('RUNNING' in message.value for message in app.success))
            self.assertTrue(any('AI analysis — EMP0001' in header.value for header in app.subheader))
            self.assertTrue(any('Internal Web' in str(frame.value.to_dict()) for frame in app.dataframe))

    def test_single_collector_lock(self):
        import fcntl
        from monitor.worker import run
        data = self.root/'locked'
        data.mkdir()
        with (data/'collector.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(RuntimeError, 'Another collector'):
                run(ROOT/'config.example.json',data,once=True)

    def test_oversized_log_record_is_skipped_without_losing_next(self):
        from monitor.collectors import collect_files
        settings = self.settings(); settings['max_line_bytes']=128; settings['batch_lines']=2
        path=self.root/'log.jsonl'
        path.write_text('x'*500+'\n'+json.dumps(dict(ts=1,kind='normal',message='valid'))+'\n')
        settings['sources']=[dict(path=str(path))]
        engine=Engine(self.db,settings)
        try:
            for _ in range(4): collect_files(engine)
            self.assertEqual(len(engine.rows('events')),1)
            self.assertEqual(engine.rows('events')[0]['message'],'valid')
        finally: engine.close()

    def test_byte_capacity_reports_health(self):
        from monitor.worker import run
        cfg=self.root/'small.json'
        cfg.write_text(json.dumps(dict(journal={'enabled':False},max_database_bytes=1)))
        run(cfg,self.root/'small-data',once=True)
        with EngineContext(self.root/'small-data/live.db') as engine:
            self.assertEqual(collector_health(engine)['status'],'CAPACITY REACHED')

    def test_graphical_activation_requires_positive_confirmation(self):
        from monitor.install import main
        with patch('sys.argv',['install','--activate-gui']), patch('monitor.install.dialog',return_value=False), patch('monitor.install.activate',side_effect=AssertionError('must not activate')):
            self.assertEqual(main(),0)

    def test_fifo_sources_report_unavailable_without_blocking(self):
        from monitor.collectors import collect_files
        fifo=self.root/'pipe'
        os.mkfifo(fifo)
        settings=self.settings()
        settings['sources']=[dict(path=str(fifo))]
        settings['files']=[dict(path=str(fifo))]
        engine=Engine(self.db,settings)
        try:
            statuses=collect_files(engine)
            self.assertEqual(len(statuses),2)
            self.assertTrue(all(not s['available'] and 'regular file' in s['status'] for s in statuses))
        finally: engine.close()


class EngineContext:
    def __init__(self,path): self.path=path
    def __enter__(self): self.engine=Engine(self.path,readonly=True); return self.engine
    def __exit__(self,*_): self.engine.close()
