import configparser
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from monitor.core import CATEGORIES, Engine, config, now
from monitor.install import render_unit, validate_unit
from monitor.lab import Catalog, record_connection
from monitor.lab_setup import BASELINE, paths, provision
from monitor.lab_readiness import readiness
from monitor.privilege_probe import probe
from monitor.worker import cycle

ROOT=Path(__file__).resolve().parents[1]


class LabDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)/'lab project % space'
        self.root.mkdir()
        shutil.copytree(ROOT/'deploy',self.root/'deploy')

    def tearDown(self):
        self.temp.cleanup()

    def provision(self):
        return provision(self.root,generate_key=False)

    def test_working_directory_unquoted_regression_all_units(self):
        for name in ('collector','dashboard','lab'):
            text=render_unit(self.root,f'six-soc-{name}.service')
            parser=configparser.ConfigParser(interpolation=None,strict=False)
            parser.read_string(text)
            actual=parser['Service']['WorkingDirectory']
            self.assertEqual(actual,str(self.root).replace('%','%%'))
            self.assertFalse(actual.startswith('"'))
            self.assertTrue(validate_unit(text))
            with self.assertRaises(ValueError):
                validate_unit(text.replace('WorkingDirectory='+actual,'WorkingDirectory="'+actual+'"'))

    def test_provision_preserves_existing_config_and_is_idempotent(self):
        cfg=self.root/'config.local.json'
        original=dict(ssh_count=5,ssh_window=60,sources=[dict(path='/existing/auth',format='auth')],custom='keep')
        cfg.write_text(json.dumps(original))
        p=self.provision()
        first=cfg.read_text()
        self.provision()
        self.assertEqual(first,cfg.read_text())
        result=json.loads(first)
        self.assertEqual(result['sources'][0],original['sources'][0])
        self.assertEqual(result['custom'],'keep')
        self.assertEqual(len(result['sources']),5)
        self.assertEqual(p['watched'].read_bytes(),BASELINE)
        self.assertTrue(list(self.root.glob('config.local.json.backup-*')))
        text=p['ssh_config'].read_text()
        self.assertIn('ListenAddress 127.0.0.1',text)
        self.assertIn('UsePAM no',text)
        self.assertIn('AllowTcpForwarding no',text)

    def test_disposable_sql_target_real_sqlite_behavior(self):
        catalog=Catalog()
        try:
            self.assertEqual(catalog.search('pencil'),['pencil'])
            self.assertEqual(set(catalog.search("' OR 1=1 --")),{'pencil','notebook'})
            with self.assertRaises(sqlite3.Error):
                catalog.search("'; DROP TABLE catalog; --")
            self.assertEqual(catalog.search('notebook'),['notebook'])
        finally: catalog.close()

    def test_real_os_denial_and_file_change_full_collector_pipeline(self):
        p=self.provision()
        settings=config(self.root/'config.local.json')
        settings['journal']={'enabled':False}
        data=self.root/'data'
        engine=Engine(data/'live.db',settings)
        try:
            cycle(engine)
            probe(self.root,normal=True)
            cycle(engine)
            self.assertEqual(engine.rows('alerts'),[])
            before=p['watched'].read_bytes()
            p['watched'].write_text('Actual temporary lab file modification\n')
            result=probe(self.root)
            self.assertTrue(result['denied'])
            cycle(engine)
            self.assertEqual({a['attack'] for a in engine.rows('alerts')},{CATEGORIES[4],CATEGORIES[5]})
            p['watched'].write_bytes(before)
            cycle(engine)
            self.assertEqual(len(engine.rows('alerts')),2)
            self.assertTrue(all(e['status']=='ABNORMAL' for e in engine.rows('events') if 'LAB_PRIVILEGE_DENIED' in e['message']))
        finally: engine.close()
        from streamlit.testing.v1 import AppTest
        with patch.dict(os.environ,{'SIX_DATA':str(data),'SIX_CONFIG':str(self.root/'config.local.json')}):
            app=AppTest.from_file(str(ROOT/'app.py')).run(timeout=20)
            self.assertFalse(app.exception)
            self.assertEqual(app.metric[3].value,'2')
            alerts=next(frame.value for frame in app.dataframe if 'detected_at_utc' in frame.value.columns)
            self.assertEqual(set(alerts['attack']),{CATEGORIES[4],CATEGORIES[5]})

    def test_readiness_never_uses_demo_or_unit_results_as_live_proof(self):
        self.provision()
        settings=config(self.root/'config.local.json')
        rows=readiness(settings,dict(status='RUNNING',sources=[]))
        self.assertEqual(len(rows),6)
        self.assertTrue(all(r['validation']=='UNVERIFIED' for r in rows))
        self.assertTrue(all('NOT READY' in r['readiness'] for r in rows))

    def test_generated_units_with_systemd_parser_when_available(self):
        # A real parser check, explicitly skipped when the execution sandbox blocks the manager.
        unit=self.root/'six-soc-lab.service'
        unit.write_text(render_unit(ROOT,'six-soc-lab.service'))
        result=subprocess.run(['systemd-analyze','--user','verify',str(unit)],capture_output=True,text=True,timeout=15)
        if 'Operation not permitted' in result.stderr or 'Failed to connect' in result.stderr:
            self.skipTest('Sandbox blocks systemd user-manager validation')
        self.assertEqual(result.returncode,0,result.stderr)

    def test_lab_preparation_does_not_overwrite_repaired_running_units(self):
        from monitor.install import prepare_lab
        home=self.root/'home'
        units=home/'.config/systemd/user'
        units.mkdir(parents=True)
        before={}
        for name in ('collector','dashboard'):
            path=units/f'six-soc-{name}.service'
            path.write_text('WorkingDirectory=/manually/repaired\n')
            before[path]=path.read_bytes()
        with patch('monitor.lab_setup.provision'):
            prepare_lab(self.root,home)
        for path,content in before.items(): self.assertEqual(path.read_bytes(),content)
        self.assertTrue((units/'six-soc-lab.service').exists())

    def test_lab_control_cancel_never_enables_services(self):
        from argparse import Namespace
        from monitor.install import lab_control
        flags=dict(lab_status_gui=False,lab_stop_gui=False,lab_start_gui=True,lab_restart_gui=False)
        with patch('monitor.install.dialog',return_value=False), patch('monitor.install.systemctl',side_effect=AssertionError('No approval')):
            lab_control(Namespace(**flags))


class LiveNetworkDeliveryTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('SIX_LAB_NETWORK_TESTS')=='1','Explicit opt-in and approved running lab required; network paths UNVERIFIED otherwise')
    def test_live_target_telemetry_pipeline(self):
        from monitor.lab_test import verify
        # Targets must already be activated through the approved graphical control.
        root=ROOT
        report=verify(root,config(root/'config.local.json'),root/'data')
        self.assertTrue(all(row['status']=='PIPELINE VERIFIED' for row in report['tests'].values()),report)
