"""SSH regression fixtures are synthetic; live evidence is tested separately."""
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from monitor.core import CATEGORIES, Engine, config, now
from monitor.lab_setup import install_ssh_configuration, paths, ssh_configuration
from monitor.lab_test import run_case
from monitor.ssh_lab import NativeFailures, collected_failures, failed_logins, reload_isolated_daemon
from monitor.collectors import collect_files

ROOT=Path(__file__).resolve().parents[1]


class SSHRegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.p=paths(self.root)
        self.p['runtime'].mkdir(parents=True)
        self.p['auth'].write_text('')
        self.settings=config(ROOT/'config.example.json')

    def tearDown(self):
        self.temp.cleanup()

    def log(self,port=40000,text=None):
        if text is None:
            text=f'Failed password for invalid user six-soc-invalid from 127.0.0.1 port {port} ssh2'
        stamp=datetime.now(timezone.utc).isoformat()
        message=stamp+' lab sshd: '+text
        with self.p['auth'].open('a') as handle:
            handle.write(message+'\n')
        return message

    def test_only_managed_loopback_configuration_migrates(self):
        target=self.p['ssh_config']
        legacy=ssh_configuration(self.p).replace('PerSourcePenalties no\n','')
        target.write_text(legacy)
        unrelated=self.root/'host-sshd-config'
        unrelated.write_text('PerSourcePenalties yes\n')
        self.assertTrue(install_ssh_configuration(self.p))
        text=target.read_text()
        self.assertEqual(text,legacy.replace('LoginGraceTime 5','PerSourcePenalties no\nLoginGraceTime 5'))
        self.assertIn('ListenAddress 127.0.0.1\n',text)
        self.assertIn('Port 2222\n',text)
        self.assertEqual(unrelated.read_text(),'PerSourcePenalties yes\n')
        self.assertFalse(install_ssh_configuration(self.p))
        self.assertEqual(len(list(self.p['runtime'].glob('sshd_config.backup-*'))),1)

    def test_unknown_config_is_preserved(self):
        text=ssh_configuration(self.p).replace('Port 2222','Port 22')
        self.p['ssh_config'].write_text(text)
        with self.assertRaises(RuntimeError):
            install_ssh_configuration(self.p)
        self.assertEqual(self.p['ssh_config'].read_text(),text)

    def test_parser_rejection_never_replaces_existing_config(self):
        legacy=ssh_configuration(self.p).replace('PerSourcePenalties no\n','')
        self.p['ssh_config'].write_text(legacy)
        self.p['hostkey'].write_text('test placeholder key; parser is mocked')
        with patch('monitor.lab_setup.subprocess.run',return_value=subprocess.CompletedProcess([],1,'','Unsupported option')):
            with self.assertRaisesRegex(RuntimeError,'OpenSSH rejected'):
                install_ssh_configuration(self.p)
        self.assertEqual(self.p['ssh_config'].read_text(),legacy)

    def test_preexisting_failures_and_connection_drops_never_count(self):
        for i in range(4): self.log(port=40000+i)
        evidence=NativeFailures(self.p['auth'])
        self.log(text='srclimit_penalise: activating ipv4 penalty')
        self.log(text='drop connection from 127.0.0.1 port 40005 penalty: failed authentication')
        self.assertEqual(evidence.read(),[])
        self.log(port=40006)
        self.assertEqual(len(evidence.read()),1)
        self.assertEqual(len(evidence.read()),1)

    def test_partial_lines_rotation_and_wrong_identity(self):
        evidence=NativeFailures(self.p['auth'])
        self.log(text='Failed password for invalid user another-user from 127.0.0.1 port 40000 ssh2')
        self.log(text='Failed password for invalid user six-soc-invalid from 192.0.2.1 port 40001 ssh2')
        self.log(port=40002)
        self.p['auth'].rename(Path(str(self.p['auth'])+'.1'))
        self.p['auth'].write_text('')
        stamp=datetime.now(timezone.utc).isoformat()
        with self.p['auth'].open('a') as handle:
            handle.write(stamp+' lab sshd: Failed password for invalid user six-soc-invalid from 127.0.0.1 port 40003 ssh2')
        self.assertEqual(len(evidence.read()),1)
        with self.p['auth'].open('a') as handle:handle.write('\n')
        self.assertEqual(len(evidence.read()),2)
        self.assertEqual(len(evidence.read()),2)

    def runner(self,callback):
        with patch('monitor.ssh_lab.shutil.which',return_value='/installed/client'), patch('monitor.ssh_lab.subprocess.run',side_effect=callback), patch('monitor.ssh_lab.time.sleep'), patch('monitor.ssh_lab.time.monotonic',side_effect=range(1000)):
            return failed_logins(self.root,self.settings)

    def test_four_failures_then_penalty_drop_requires_sixth_client(self):
        calls=[]
        def client(*args,**kwargs):
            calls.append(1)
            if len(calls)==5:
                self.log(text='drop connection from 127.0.0.1 penalty: failed authentication')
            else:
                self.log(port=40000+len(calls))
            return subprocess.CompletedProcess(args,255)
        result=self.runner(client)
        self.assertEqual(len(calls),6)
        self.assertEqual(result['attempts'],6)
        self.assertEqual(result['native_failed_password_records'],5)

    def test_stops_at_five_actual_failures(self):
        calls=[]
        def client(*args,**kwargs):
            calls.append(1); self.log(port=40000+len(calls))
            return subprocess.CompletedProcess(args,255)
        result=self.runner(client)
        self.assertEqual(result['attempts'],5)
        self.assertEqual(len(calls),5)

    def test_ten_drops_or_client_timeouts_are_unverified(self):
        calls=[]
        def client(*args,**kwargs):
            calls.append(1)
            self.log(text='drop connection from 127.0.0.1 penalty: failed authentication')
            raise subprocess.TimeoutExpired(args[0],1)
        with self.assertRaisesRegex(RuntimeError,'0 actual new Failed password records from 10 client attempts'):
            self.runner(client)
        self.assertEqual(len(calls),10)

    def test_four_actual_failures_never_satisfy_threshold(self):
        calls=[]
        def client(*args,**kwargs):
            calls.append(1)
            if len(calls)<=4:self.log(port=40000+len(calls))
            return subprocess.CompletedProcess(args,255)
        with self.assertRaisesRegex(RuntimeError,'4 actual new Failed password records from 10 client attempts'):
            self.runner(client)

    def test_collector_and_dashboard_evidence_correlates_native_messages(self):
        settings=self.settings|dict(sources=[dict(path=str(self.p['auth']),format='auth',destination='127.0.0.1',destination_port=2222)])
        engine=Engine(self.root/'data/live.db',settings)
        engine.close()
        def clients_and_collection(*_):
            native=NativeFailures(self.p['auth'])
            for i in range(5):self.log(port=40000+i)
            records=native.read()
            engine=Engine(self.root/'data/live.db',settings)
            try:
                collect_files(engine)
                collect_files(engine)
                self.assertEqual(len(engine.rows('events')),5)
                self.assertEqual(len(engine.rows('alerts')),1)
                self.assertEqual(engine.rows('alerts')[0]['severity'],'HIGH')
            finally:engine.close()
            return dict(attempts=6,native_failed_password_records=5,_native_failures=records)
        with patch('monitor.lab_test.check_services'),patch('monitor.lab_test.wait_clean_window'),patch('monitor.lab_test.activity',side_effect=clients_and_collection):
            result=run_case('ssh',self.root,self.settings,self.root/'data')
        self.assertEqual(result['status'],'PIPELINE VERIFIED')
        self.assertEqual(result['classification'],'ABNORMAL')
        self.assertEqual(result['severity'],'HIGH')
        self.assertEqual(result['collected_ssh_failed_events'],5)
        self.assertIn(result['event_id'],result['confirmed_event_ids'])

    def test_wrong_sqlite_kind_or_ip_cannot_validate(self):
        native=NativeFailures(self.p['auth'])
        messages=[self.log(port=40000+i) for i in range(5)]
        records=native.read()
        engine=Engine(self.root/'data/live.db')
        try:
            for i,message in enumerate(messages):
                engine.process(dict(ts=now(),kind='normal',ip='127.0.0.1',source=str(self.p['auth']),message=message))
        finally:engine.close()
        with self.assertRaisesRegex(RuntimeError,'only 0 native failures'):
            collected_failures(self.root,self.root/'data',dict(_native_failures=records),timeout=0)

    def test_threshold_cannot_be_lowered_to_claim_validation(self):
        with patch('monitor.ssh_lab.subprocess.run') as client:
            with self.assertRaisesRegex(RuntimeError,'unchanged threshold'):
                failed_logins(self.root,self.settings|dict(ssh_count=4))
            client.assert_not_called()
        self.assertEqual((self.settings['ssh_count'],self.settings['ssh_window']),(5,60))

    def test_single_ssh_success_preserves_other_five_verification_results(self):
        from monitor.lab_test import main
        report=dict(normal_activity='PASS',tests={name:dict(status='PIPELINE VERIFIED',alert_id=i) for i,name in enumerate(CATEGORIES)})
        report['tests'][CATEGORIES[0]]={'status':'UNVERIFIED'}
        self.p['validation'].write_text(json.dumps(report))
        result=dict(status='PIPELINE VERIFIED',native_failed_password_records=5,collected_ssh_failed_events=5,severity='HIGH')
        with patch('sys.argv',['lab_test','ssh','--root',str(self.root)]),patch('monitor.lab_test.run_case',return_value=result),patch('builtins.print'):
            self.assertEqual(main(),0)
        updated=json.loads(self.p['validation'].read_text())
        self.assertEqual(updated['tests'][CATEGORIES[0]],result)
        for name in CATEGORIES[1:]:self.assertEqual(updated['tests'][name],report['tests'][name])
        self.assertEqual(updated['normal_activity'],'PASS')

    def test_single_ssh_failure_preserves_other_five_verification_results(self):
        from monitor.lab_test import main
        report=dict(normal_activity='PASS',tests={name:dict(status='PIPELINE VERIFIED',alert_id=i) for i,name in enumerate(CATEGORIES)})
        self.p['validation'].write_text(json.dumps(report))
        with patch('sys.argv',['lab_test','ssh','--root',str(self.root)]),patch('monitor.lab_test.run_case',side_effect=RuntimeError('0 native failures')),patch('builtins.print'):
            self.assertEqual(main(),1)
        updated=json.loads(self.p['validation'].read_text())
        self.assertEqual(updated['tests'][CATEGORIES[0]]['status'],'UNVERIFIED')
        for name in CATEGORIES[1:]:self.assertEqual(updated['tests'][name],report['tests'][name])

    def test_unobservable_pid_is_not_signalled(self):
        (self.p['runtime']/'sshd.pid').write_text('123456')
        with patch('monitor.ssh_lab.os.pidfd_open',side_effect=ProcessLookupError),patch('monitor.ssh_lab.signal.pidfd_send_signal') as send:
            with self.assertRaises(ProcessLookupError):reload_isolated_daemon(self.root)
            send.assert_not_called()
