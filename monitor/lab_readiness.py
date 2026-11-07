"""Separate running-target/source health from evidence of live end-to-end validation."""
import json
from pathlib import Path
from .core import CATEGORIES, now


def read_target_health(runtime):
    try:
        health=json.loads((Path(runtime)/'health.json').read_text())
    except (OSError,ValueError):
        return dict(status='STOPPED',components={},error='Lab has not reported health')
    if now()-health.get('heartbeat',0)>10:
        health['status']='STOPPED'
        health['error']='Lab heartbeat is stale'
        health['components']={key:'STOPPED' for key in health.get('components',{})}
    return health


def readiness(settings, collector):
    lab=settings.get('lab',{})
    runtime=Path(lab.get('runtime','runtime/lab'))
    health=read_target_health(runtime)
    try:
        evidence=json.loads((runtime/'validation.json').read_text()).get('tests',{})
    except (OSError,ValueError):
        evidence={}
    source_status={s['source']:s for s in collector.get('sources',[])}
    definitions=[
        ('ssh','ssh-auth.log','127.0.0.1:2222'),
        ('connections','connections.jsonl','127.0.0.1:9100–9119 (TCP connect)'),
        ('web','access.log','http://127.0.0.1:8088/search'),
        ('web','access.log','http://127.0.0.1:8088/health'),
        ('file','watched/settings.txt',str(runtime/'watched/settings.txt')),
        ('privilege','privilege.jsonl','Local CAP_SETUID permission boundary'),
    ]
    rows=[]
    for category,(component,source,target) in zip(CATEGORIES,definitions):
        running=health.get('status')=='RUNNING' and health.get('components',{}).get(component) in ('RUNNING','AVAILABLE')
        if component=='file':
            running=bool(lab) and (runtime/source).is_file() and collector.get('status') in ('RUNNING','DEGRADED')
        if component=='privilege' and collector.get('rules_version',2)<3:
            running=False
        available=source_status.get(str(runtime/source),{}).get('available',False) and collector.get('status') in ('RUNNING','DEGRADED')
        validation=evidence.get(category,{})
        verified=validation.get('status')=='PIPELINE VERIFIED'
        rows.append(dict(category=category,target=target,component='RUNNING' if running else 'STOPPED',
                         telemetry='AVAILABLE' if available else 'UNAVAILABLE',
                         validation=validation.get('status','UNVERIFIED'),
                         readiness='READY (pipeline verified)' if running and available and verified else 'UNVERIFIED / NOT READY',
                         detail=('Restart collector to load capability-denial rule' if component=='privilege' and collector.get('rules_version',2)<3 else validation.get('error',health.get('error','') if component not in ('file','privilege') else ''))))
    return rows
