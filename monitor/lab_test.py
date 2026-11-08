"""Explicit bounded activity against this lab only. Never runs at login/startup."""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.parse import quote
from urllib.request import urlopen
from .core import CATEGORIES, Engine, config, now
from .lab_setup import BASELINE, SCAN_PORTS, SSH_PORT, WEB_PORT, paths, atomic_json
from .privilege_probe import probe
from .views import collector_health, snapshot
from .ssh_lab import failed_logins, collected_failures

NAMES = dict(ssh=CATEGORIES[0],scan=CATEGORIES[1],sql=CATEGORIES[2],dos=CATEGORIES[3],file=CATEGORIES[4],privilege=CATEGORIES[5])


def web(path):
    with urlopen(f'http://127.0.0.1:{WEB_PORT}'+path,timeout=3) as response:
        return json.loads(response.read(16384))


def activity(name, root, settings):
    p=paths(root)
    if name=='ssh':
        return failed_logins(root,settings)
    elif name=='scan':
        if settings['port_count']>len(SCAN_PORTS):
            raise RuntimeError('Configured port threshold exceeds the 20 lab listeners')
        for port in SCAN_PORTS:
            with socket.create_connection(('127.0.0.1',port),timeout=2):
                pass
            time.sleep(0.05)
    elif name=='sql':
        result=web('/search?q='+quote("' OR 1=1 --",safe=''))
        if len(result.get('results',[]))!=2:
            raise RuntimeError('Disposable SQL target did not exhibit the expected lab behavior')
    elif name=='dos':
        count=settings['dos_count']+2
        if count>64:
            raise RuntimeError('Configured HTTP threshold exceeds the 64-request safety limit')
        started=time.monotonic()
        for _ in range(count):
            web('/health')
        if time.monotonic()-started>settings['dos_window']:
            raise RuntimeError('Requests were too slow to reach the configured rate threshold')
    elif name=='file':
        p['watched'].write_text('Active Defense Platform lab test\nmode=changed-'+str(time.time_ns())+'\n')
    elif name=='privilege':
        probe(root)


def check_services(root,data,settings,require_network=True,require_capability_rule=False):
    p=paths(root)
    target=json.loads(p['health'].read_text()) if p['health'].exists() else {}
    if require_network and (target.get('status')!='RUNNING' or now()-target.get('heartbeat',0)>10):
        raise RuntimeError('Lab targets are stopped/stale; use Active Defense Platform — Start Monitoring')
    engine=Engine(data/'live.db',readonly=True)
    try:
        health=collector_health(engine,settings['poll_seconds'])
        if health['status'] not in ('RUNNING','DEGRADED'):
            raise RuntimeError('Background collector is not running: '+health['status'])
        if require_capability_rule and health.get('rules_version',2)<3:
            raise RuntimeError('Active Defense Platform — Restart Monitoring once to load the new capability-denial rule')
        if not engine.state('hash:'+str(p['watched'].resolve())):
            raise RuntimeError('Collector has not established the lab file baseline yet; retry in a few seconds')
    finally:
        engine.close()


def wait_clean_window(name,data,settings):
    kind='ssh_failed' if name=='ssh' else 'connection' if name=='scan' else 'http' if name in ('sql','dos') else None
    if not kind:
        return
    seconds=settings['ssh_window'] if name=='ssh' else settings['port_window'] if name=='scan' else settings['dos_window']
    if seconds>120:
        raise RuntimeError('Lab test runner requires a window <=120 seconds for bounded waits')
    engine=Engine(data/'live.db',readonly=True)
    try:
        row=engine.db.execute('SELECT MAX(ts) FROM events WHERE kind=? AND ip=?',(kind,'127.0.0.1')).fetchone()
        delay=(row[0] or 0)+seconds+0.2-now()
    finally:
        engine.close()
    if delay>0:
        print(f'Waiting {delay:.1f}s for the previous {kind} window to expire...',flush=True)
        time.sleep(min(delay,121))


def wait_alert(name, data, after_id, root, timeout=20):
    p=paths(root)
    source=str(p[{'ssh':'auth','scan':'connections','sql':'access','dos':'access','file':'watched','privilege':'privilege'}[name]])
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        engine=Engine(data/'live.db',readonly=True)
        try:
            row=engine.db.execute('SELECT a.* FROM alerts a JOIN events e ON e.id=a.event_id WHERE a.id>? AND a.attack=? AND e.source=? ORDER BY a.id DESC LIMIT 1',(after_id,NAMES[name],source)).fetchone()
            if row:
                alert=dict(row)
                event=engine.db.execute('SELECT * FROM events WHERE id=?',(alert['event_id'],)).fetchone()
                if event and event['status']=='ABNORMAL':
                    view=snapshot(engine,now()-3600,NAMES[name])
                    if any(a['id']==alert['id'] for a in view['alerts']):
                        return dict(alert_id=alert['id'],event_id=alert['event_id'],classification='ABNORMAL',severity=alert['severity'],category=NAMES[name],checked_at=now(),status='PIPELINE VERIFIED')
        finally:
            engine.close()
        time.sleep(0.25)
    raise RuntimeError('No new matching alert reached SQLite/dashboard read model within 20 seconds')


def run_case(name,root,settings,data):
    check_services(root,data,settings,require_network=name in ('ssh','scan','sql','dos'),require_capability_rule=name=='privilege')
    wait_clean_window(name,data,settings)
    engine=Engine(data/'live.db',readonly=True)
    try:
        previous=engine.db.execute('SELECT COALESCE(MAX(id),0) FROM alerts').fetchone()[0]
    finally:
        engine.close()
    try:
        evidence=activity(name,root,settings)
        if name=='ssh':
            event_ids=collected_failures(root,data,evidence)
            result=wait_alert(name,data,previous,root)
            if result['severity']!='HIGH' or result['event_id'] not in event_ids:
                raise RuntimeError('SSH UNVERIFIED: new HIGH alert is not linked to the confirmed native failures')
            result.update(attempts=evidence['attempts'],native_failed_password_records=evidence['native_failed_password_records'],collected_ssh_failed_events=len(event_ids),source_ip='127.0.0.1',confirmed_event_ids=event_ids)
            return result
        return wait_alert(name,data,previous,root)
    finally:
        if name=='file':
            paths(root)['watched'].write_bytes(BASELINE)


def normal_activity(root):
    # Real benign operations, not generated fixture records.
    web('/search?q=pencil')
    with socket.create_connection(('127.0.0.1',SCAN_PORTS[0]),timeout=2): pass
    with socket.create_connection(('127.0.0.1',SSH_PORT),timeout=2) as connection:
        connection.recv(256)  # Read the banner, never attempt authentication.
    paths(root)['watched'].write_bytes(BASELINE)
    probe(root,normal=True)


def verify(root,settings,data):
    check_services(root,data,settings)
    for name in ('ssh','scan','sql'):
        wait_clean_window(name,data,settings)
    p=paths(root)
    source_paths={str(p[k]) for k in ('auth','access','connections','privilege','watched')}
    engine=Engine(data/'live.db',readonly=True)
    try:
        before=engine.db.execute('SELECT COALESCE(MAX(id),0) FROM alerts').fetchone()[0]
    finally:
        engine.close()
    normal_activity(root)
    time.sleep(settings['poll_seconds']*2+1)
    engine=Engine(data/'live.db',readonly=True)
    try:
        unexpected=[a for a in snapshot(engine,now()-60)['alerts'] if a['id']>before and a['source'] in source_paths]
        if unexpected:
            raise RuntimeError('Benign baseline produced a lab alert; verification failed')
    finally: engine.close()
    report=dict(checked_at=now(),normal_activity='PASS',tests={})
    for name in NAMES:
        try:
            report['tests'][NAMES[name]]=run_case(name,root,settings,data)
        except (OSError,RuntimeError,subprocess.SubprocessError) as exc:
            report['tests'][NAMES[name]]=dict(status='UNVERIFIED',error=str(exc),checked_at=now())
        atomic_json(p['validation'],report)
    return report


def save_ssh_validation(root,result):
    """Update only SSH evidence; retain the five already verified categories."""
    report_path=paths(root)['validation']
    report=json.loads(report_path.read_text()) if report_path.exists() else {}
    if not isinstance(report,dict) or not isinstance(report.get('tests',{}),dict):
        raise ValueError('Existing validation report is malformed; preserving it')
    report.setdefault('tests',{})[NAMES['ssh']]=result
    atomic_json(report_path,report)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('test',choices=[*NAMES,'normal','verify'])
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
    args=parser.parse_args()
    root=args.root.resolve()
    settings=config(root/'config.local.json')
    data=root/'data'
    try:
        if args.test=='verify':
            result=verify(root,settings,data)
        elif args.test=='normal':
            check_services(root,data,settings)
            for name in ('ssh','scan','sql'):
                wait_clean_window(name,data,settings)
            normal_activity(root)
            result=dict(status='Normal activity performed; inspect dashboard')
        else:
            result=run_case(args.test,root,settings,data)
            if args.test=='ssh':
                save_ssh_validation(root,result)
        print(json.dumps(result,indent=2))
        if args.test=='verify' and any(t['status']=='UNVERIFIED' for t in result['tests'].values()):
            return 1
        return 0
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as exc:
        if args.test=='ssh':
            try:
                save_ssh_validation(root,dict(status='UNVERIFIED',error=str(exc),checked_at=now()))
            except (OSError,ValueError) as report_error:
                print('Could not update SSH validation evidence: '+str(report_error),file=sys.stderr)
        print('UNVERIFIED: '+str(exc),file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
