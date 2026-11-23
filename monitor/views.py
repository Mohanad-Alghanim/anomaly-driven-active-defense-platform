"""Bounded read models for the dashboard; no ingestion."""
import json
from .core import now

LEVEL_ORDER = ('high', 'medium', 'low')


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


def _has_table(engine, name):
    return engine.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def employee_table(engine):
    """Every employee with a rolling risk, highest risk first."""
    if not _has_table(engine, 'employee_risk'):
        return []
    return [dict(row) for row in engine.db.execute('SELECT * FROM employee_risk ORDER BY risk DESC, employee_id')]


def active_ranking(engine, brain, cutoff):
    """Employees active since `cutoff`, ranked by the PEAK rolling risk they reached
    inside the window (then by current risk).

    An employee who spiked and then went quiet keeps a high peak and stays near the
    top, even though their current (decayed) risk has fallen back. Current risk and the
    peak's time are reported alongside. Rolling risk is replayed from the stored event
    scores over each active employee's full history, so current risk matches the live
    employee_risk table; only events inside the window contribute to the window peak.
    """
    if not _has_table(engine, 'employee_risk'):
        return []
    recent = [r[0] for r in engine.db.execute(
        'SELECT DISTINCT employee_id FROM events WHERE ts>=? AND employee_id IS NOT NULL AND score IS NOT NULL', (cutoff,))]
    if not recent:
        return []
    from .brain.risk import RiskState
    half_life = brain.half_life_seconds
    high_boundary = brain.boundaries_['high']
    marks = ','.join('?' * len(recent))
    rows = engine.db.execute(
        f'SELECT employee_id, ts, score, ip FROM events WHERE employee_id IN ({marks}) AND score IS NOT NULL '
        'ORDER BY ts, rowid', recent).fetchall()
    states, agg = {}, {}
    for emp, ts, score, ip in rows:
        risk = states.setdefault(emp, RiskState()).update(ts, score, half_life)
        a = agg.get(emp)
        if a is None:
            a = agg[emp] = dict(peak_risk=None, peak_ts=None, risk=risk, last_ts=ts, events=0, high_events=0, max_score=score)
        a['risk'], a['last_ts'] = risk, ts
        if ip:
            a['last_ip'] = ip   # display only: the device the latest event came from
        if ts >= cutoff:
            a['events'] += 1
            a['high_events'] += int(score >= high_boundary)
            a['max_score'] = max(a['max_score'], score)
            if a['peak_risk'] is None or risk > a['peak_risk']:
                a['peak_risk'], a['peak_ts'] = risk, ts
    out = []
    for emp, a in agg.items():
        peak = a['peak_risk'] if a['peak_risk'] is not None else a['risk']
        out.append(dict(
            employee_id=emp, risk=a['risk'], level=str(brain.employee_levels([a['risk']])[0]),
            risk_percentile=float(brain.employee_percentile([a['risk']])[0]),
            peak_risk=peak, peak_level=str(brain.employee_levels([peak])[0]), peak_ts=a['peak_ts'],
            last_ts=a['last_ts'], last_ip=a.get('last_ip'), events=a['events'], high_events=a['high_events'],
            max_score=a['max_score']))
    out.sort(key=lambda e: (e['peak_risk'], e['risk']), reverse=True)
    return out


def device_ips(directory, employee_id):
    """Source IPs of every device the directory assigns to this employee (display only)."""
    return [d['source_ip'] for d in directory.data.get('devices', []) if d.get('employee_id') == employee_id]


def employee_ip(directory, employee_id, last_ip=None):
    """IP shown for an employee: the device their latest event came from, otherwise all
    of their directory device IPs, comma-separated. Never a model input."""
    if last_ip:
        return last_ip
    return ', '.join(device_ips(directory, employee_id))


def snapshot(engine, cutoff, limit=500):
    """Window summary: scored-event counts by level, timeline and recent elevated events."""
    columns = {row[1] for row in engine.db.execute('PRAGMA table_info(events)')}
    if 'level' not in columns:
        return dict(counts=dict(total=0, scored=0, high=0, medium=0, low=0, unattributed=0), timeline=[], elevated=[], employees=[])
    total, scored, high, medium, low, unattributed = engine.db.execute(
        "SELECT COUNT(*), COALESCE(SUM(score IS NOT NULL),0), COALESCE(SUM(level='high'),0), COALESCE(SUM(level='medium'),0), "
        "COALESCE(SUM(level='low'),0), COALESCE(SUM(employee_id IS NULL AND score IS NOT NULL),0) FROM events WHERE ts >= ?", (cutoff,)).fetchone()
    span = now() - cutoff
    bucket = 86400 if span > 31*86400 else 3600 if span > 2*86400 else 300 if span > 7200 else 60
    timeline = [dict(row) for row in engine.db.execute(
        f'SELECT CAST(ts/{bucket} AS INTEGER)*{bucket} AS ts, level, COUNT(*) AS events FROM events '
        'WHERE ts >= ? AND level IS NOT NULL GROUP BY 1,2 ORDER BY 1', (cutoff,))]
    elevated = [dict(row) for row in engine.db.execute(
        "SELECT id, ts, employee_id, ip, dst_ip, dst_service, protocol, port, kind, score, level, message FROM events "
        "WHERE ts >= ? AND level IN ('high','medium') ORDER BY score DESC LIMIT ?", (cutoff, limit))]
    return dict(counts=dict(total=total, scored=scored, high=high, medium=medium, low=low, unattributed=unattributed),
                timeline=timeline, elevated=elevated, employees=employee_table(engine))


def employee_events(engine, employee_id, limit=200):
    return [dict(row) for row in engine.db.execute(
        'SELECT id, ts, ip, dst_ip, dst_service, protocol, port, kind, bytes_in, bytes_out, response_ms, prev_hour, '
        'features, score, level, message FROM events WHERE employee_id=? ORDER BY ts DESC LIMIT ?', (employee_id, limit))]


def unattributed_events(engine, cutoff, limit=200):
    return [dict(row) for row in engine.db.execute(
        'SELECT id, ts, source, kind, ip, dst_ip, dst_service, score, level, message FROM events '
        'WHERE ts >= ? AND employee_id IS NULL AND score IS NOT NULL ORDER BY ts DESC LIMIT ?', (cutoff, limit))]
