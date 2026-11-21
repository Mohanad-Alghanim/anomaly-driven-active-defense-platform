import configparser
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from monitor.core import Engine, config, now
from monitor.install import render_unit, validate_unit
from monitor.lab import Catalog
from monitor.lab_setup import BASELINE, provision
from monitor.lab_readiness import readiness
from monitor.views import employee_table
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
        return provision(self.root)

    def test_working_directory_unquoted_regression_all_units(self):
        for name in ('collector','dashboard','lab'):
            text=render_unit(self.root,f'active-defense-{name}.service')
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
        retired=str(self.root.resolve()/'runtime/lab/ssh-auth.log')
        original=dict(ssh_count=5,ssh_window=60,sources=[dict(path='/existing/auth',format='auth'),dict(path=retired,format='auth')],custom='keep')
        cfg.write_text(json.dumps(original))
        p=self.provision()
        first=cfg.read_text()
        self.provision()
        self.assertEqual(first,cfg.read_text())
        result=json.loads(first)
        self.assertEqual(result['sources'][0],original['sources'][0])
        self.assertEqual(result['custom'],'keep')
        # Retired external-attack lab sources are removed; the new inbox and web log are added.
        self.assertEqual([s['path'] for s in result['sources']],['/existing/auth',str(p['access']),str(p['telemetry'])])
        self.assertEqual(p['watched'].read_bytes(),BASELINE)
        self.assertTrue(list(self.root.glob('config.local.json.backup-*')))
        # Threshold keys of the removed rule engine never reach the running configuration.
        loaded=config(cfg)
        self.assertNotIn('ssh_count',loaded)
        self.assertNotIn('ssh_window',loaded)

    def test_disposable_sql_target_real_sqlite_behavior(self):
        catalog=Catalog()
        try:
            self.assertEqual(catalog.search('pencil'),['pencil'])
            self.assertEqual(set(catalog.search("' OR 1=1 --")),{'pencil','notebook'})
            with self.assertRaises(sqlite3.Error):
                catalog.search("'; DROP TABLE catalog; --")
            self.assertEqual(catalog.search('notebook'),['notebook'])
        finally: catalog.close()

    def test_telemetry_inbox_and_file_change_full_collector_pipeline(self):
        p=self.provision()
        settings=config(self.root/'config.local.json')
        settings['journal']={'enabled':False}
        data=self.root/'data'
        engine=Engine(data/'live.db',settings)
        try:
            cycle(engine)
            self.assertEqual(engine.rows('events'),[])
            record=dict(ts=now(),source_ip='10.200.0.10',destination_ip='10.10.1.20',destination_port=445,
                        bytes_in=1500,bytes_out=600,response_time_ms=40,kind='file_read',message='Lab scenario record')
            with p['telemetry'].open('a') as handle:
                handle.write(json.dumps(record)+'\n')
            before=p['watched'].read_bytes()
            p['watched'].write_text('Actual temporary lab file modification\n')
            cycle(engine)
            rows=engine.rows('events')
            self.assertEqual({e['kind'] for e in rows},{'file_read','file_change'})
            self.assertTrue(all(e['score'] is not None and e['level'] for e in rows))
            inbox=next(e for e in rows if e['kind']=='file_read')
            self.assertEqual((inbox['employee_id'],inbox['dst_service'],inbox['protocol']),('EMP0001','File Server','TCP'))
            self.assertEqual([r['employee_id'] for r in employee_table(engine)],['EMP0001'])
            p['watched'].write_bytes(before)
            cycle(engine)
            self.assertEqual(sum(e['kind']=='file_change' for e in engine.rows('events')),2)
        finally: engine.close()
        from streamlit.testing.v1 import AppTest
        with patch.dict(os.environ,{'SIX_DATA':str(data),'SIX_CONFIG':str(self.root/'config.local.json')}):
            app=AppTest.from_file(str(ROOT/'app.py')).run(timeout=30)
            self.assertFalse(app.exception)
            self.assertEqual(app.metric[0].value,'1')
            self.assertTrue(any('AI analysis — EMP0001' in header.value for header in app.subheader))

    def test_readiness_reports_components_not_attack_categories(self):
        self.provision()
        settings=config(self.root/'config.local.json')
        rows=readiness(settings,dict(status='RUNNING',sources=[]))
        self.assertEqual([r['component'] for r in rows],['web','telemetry','file'])
        self.assertTrue(all(r['state']=='STOPPED' and r['telemetry']=='NOT READ' for r in rows))

    def test_generated_units_with_systemd_parser_when_available(self):
        # A real parser check, explicitly skipped when the execution sandbox blocks the manager.
        unit=self.root/'active-defense-lab.service'
        unit.write_text(render_unit(ROOT,'active-defense-lab.service'))
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
            path=units/f'active-defense-{name}.service'
            path.write_text('WorkingDirectory=/manually/repaired\n')
            before[path]=path.read_bytes()
        with patch('monitor.lab_setup.provision'):
            prepare_lab(self.root,home)
        for path,content in before.items(): self.assertEqual(path.read_bytes(),content)
        self.assertTrue((units/'active-defense-lab.service').exists())

    def test_lab_control_cancel_never_enables_services(self):
        from argparse import Namespace
        from monitor.install import lab_control
        flags=dict(lab_status_gui=False,lab_stop_gui=False,lab_start_gui=True,lab_restart_gui=False)
        with patch('monitor.install.dialog',return_value=False), patch('monitor.install.systemctl',side_effect=AssertionError('No approval')):
            lab_control(Namespace(**flags))
