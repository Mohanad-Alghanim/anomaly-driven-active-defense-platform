"""Bounded read models for dashboard and source coverage; no ingestion."""
import json
from .core import CATEGORIES, now


def collector_health(engine, poll_seconds=2):
    health = json.loads(engine.state('collector_health') or '{}')
    if not health:
        return dict(status='NOT STARTED', sources=[], error='Background collector has not reported health')
    if now() - health.get('heartbeat', 0) > max(30, poll_seconds*4):
        health['status'] = 'STALE / STOPPED'
        for source in health.get('sources', []):
            source['available'] = False
            source['status'] = 'Collector stale; last known: ' + source.get('status', 'unknown')
    return health


def coverage(settings, statuses):
    by_source = {s['source']: s for s in statuses}
    needed = ('ssh_failed', 'connection', 'http', 'http', 'file', 'privilege')
    rows = []
    for attack, kind in zip(CATEGORIES, needed):
        candidates = []
        for source in settings['sources']:
            fmt = source.get('format', 'jsonl')
            kinds = source.get('kinds', ['ssh_failed', 'privilege'] if fmt == 'auth' else ['connection'] if fmt == 'netfilter' else ['http'] if fmt == 'http_access' else [])
            if kind in kinds:
                candidates.append(source['path'])
        if kind == 'file':
            candidates += [entry['path'] for entry in settings['files']]
        if settings['journal'].get('enabled', True) and (kind in ('ssh_failed', 'privilege') or (kind == 'connection' and settings['journal'].get('kernel_netfilter', False))):
            candidates.append('systemd Journal')
        ready = [name for name in candidates if by_source.get(name, {}).get('available')]
        status = 'Source readable; event coverage unverified' if ready else 'Source unavailable / not polled' if candidates else 'Not configured'
        rows.append(dict(category=attack, telemetry_status=status, sources=', '.join(candidates) or 'None'))
    return rows


def snapshot(engine, cutoff, category='All', limit=1000):
    params = [cutoff]
    where = 'e.ts >= ?'
    if category != 'All':
        where += ' AND EXISTS (SELECT 1 FROM matches m WHERE m.event_id=e.id AND m.attack=?)'
        params.append(category)
    counts = engine.db.execute(f"SELECT COUNT(*),COALESCE(SUM(status='NORMAL'),0),COALESCE(SUM(status='ABNORMAL'),0) FROM events e WHERE {where}", params).fetchone()
    ev = [dict(row) for row in engine.db.execute(f'''SELECT e.*,
          (SELECT group_concat(attack, ' | ') FROM matches m WHERE m.event_id=e.id) AS attack,
          (SELECT MAX(ts) FROM matches m WHERE m.event_id=e.id) AS detection_ts,
          (SELECT group_concat(severity, ' | ') FROM matches m WHERE m.event_id=e.id) AS severity,
          (SELECT group_concat(rule, ' | ') FROM matches m WHERE m.event_id=e.id) AS rule,
          (SELECT group_concat(description, ' | ') FROM matches m WHERE m.event_id=e.id) AS explanation,
          (SELECT group_concat(action, ' | ') FROM matches m WHERE m.event_id=e.id) AS recommendation
          FROM events e WHERE {where} ORDER BY e.ts DESC LIMIT ?''', [*params, limit])]
    awhere = 'a.event_ts >= ?'
    apar = [cutoff]
    if category != 'All':
        awhere += ' AND a.attack=?'
        apar.append(category)
    alerts = [dict(row) for row in engine.db.execute(f'''SELECT a.*,e.dst_ip,e.dst_host,e.port AS dst_port,e.source_port,e.status,e.source
         FROM alerts a LEFT JOIN events e ON e.id=a.event_id WHERE {awhere} ORDER BY a.ts DESC LIMIT ?''', [*apar, limit])]
    distribution = [dict(row) for row in engine.db.execute(f'SELECT attack,COUNT(*) AS alerts FROM alerts a WHERE {awhere} GROUP BY attack', apar)]
    span = now()-cutoff
    bucket = 86400 if span > 31*86400 else 3600 if span > 2*86400 else 300 if span > 7200 else 60
    timeline = [dict(row) for row in engine.db.execute(f'SELECT CAST(e.ts/{bucket} AS INTEGER)*{bucket} AS ts,e.status,COUNT(*) AS events FROM events e WHERE {where} GROUP BY 1,2 ORDER BY 1', params)]
    return dict(counts=tuple(counts), alerts=alerts, events=ev, distribution=distribution, timeline=timeline,
                total_alerts=sum(r['alerts'] for r in distribution))
