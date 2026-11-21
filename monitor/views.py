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
