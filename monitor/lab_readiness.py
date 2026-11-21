"""Lab component and source health (running targets vs. readable telemetry)."""
import json
from pathlib import Path
from .core import now


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
    """One row per lab component: is the target running and is its telemetry being read?"""
    lab=settings.get('lab')
    if not lab:
        return []
    runtime=Path(lab.get('runtime','runtime/lab'))
    health=read_target_health(runtime)
    sources={s['source']:s for s in collector.get('sources',[])}
    collecting=collector.get('status') in ('RUNNING','DEGRADED')
    rows=[]
    for component,source,target in (('web','access.log',f"http://127.0.0.1:{lab.get('web_port',8088)}"),
                                     ('telemetry','telemetry.jsonl','Behavioural telemetry inbox (JSONL)'),
                                     ('file','watched/settings.txt','Watched file content')):
        running=health.get('status')=='RUNNING' and health.get('components',{}).get(component) in ('RUNNING','AVAILABLE')
        available=collecting and sources.get(str(runtime/source),{}).get('available',False)
        rows.append(dict(component=component,target=target,state='RUNNING' if running else 'STOPPED',
                         telemetry='READ BY COLLECTOR' if available else 'NOT READ',
                         detail=health.get('error','') if not running else ''))
    return rows
