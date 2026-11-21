"""Durable collection, SQLite storage and unsupervised behavioural scoring.

Every stored event is scored by the insider-threat brain (monitor/brain): an
Isolation Forest trained on normal behaviour only. There are no detection rules
and no hand-written thresholds: event and employee levels are quantiles of the
score distribution of independent normal behaviour, fixed at training time.
"""
import hashlib
from copy import deepcopy
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

DEFAULT = dict(sources=[], files=[], poll_seconds=2, batch_lines=1000, max_line_bytes=65536, max_file_bytes=33554432,
               max_events=200000, max_database_bytes=268435456, journal={'enabled': True, 'lookback_seconds': 300},
               model=None, directory=None)
# Keys of the removed threshold rule engine. Old configurations may still carry
# them; they are discarded so no rule parameter survives anywhere.
RETIRED_RULE_KEYS = ('ssh_count', 'ssh_window', 'port_count', 'port_window', 'dos_count', 'dos_window')
SCHEMA_VERSION = 3


def now():
    return datetime.now(timezone.utc).timestamp()


def config(path='config.local.json'):
    settings = deepcopy(DEFAULT)
    if Path(path).exists():
        supplied = json.loads(Path(path).read_text())
        if not isinstance(supplied, dict):
            raise ValueError('Configuration must be a JSON object')
        settings.update(supplied)
    for key in RETIRED_RULE_KEYS:
        settings.pop(key, None)
    for key in ('poll_seconds', 'batch_lines', 'max_line_bytes', 'max_file_bytes', 'max_events', 'max_database_bytes'):
        if type(settings[key]) is not int or settings[key] < 1:
            raise ValueError(f'{key} must be a positive integer')
    for key in ('sources', 'files'):
        if not isinstance(settings[key], list):
            raise ValueError(f'{key} must be a list')
        for entry in settings[key]:
            if not isinstance(entry, dict) or not isinstance(entry.get('path'), str) or not entry['path']:
                raise ValueError(f'{key} entries require a nonempty path')
    if settings['poll_seconds'] > 300 or settings['batch_lines'] > 10000:
        raise ValueError('poll_seconds must be <=300; batch_lines must be <=10000')
    for key in ('model', 'directory'):
        if settings[key] is not None and not isinstance(settings[key], str):
            raise ValueError(f'{key} must be a file path')
    journal = settings.get('journal')
    if not isinstance(journal, dict) or type(journal.get('enabled', True)) is not bool:
        raise ValueError('journal must be an object with boolean enabled')
    if type(journal.get('lookback_seconds', 300)) is not int or not 1 <= journal.get('lookback_seconds', 300) <= 86400:
        raise ValueError('journal lookback_seconds must be between 1 and 86400')
    if type(journal.get('kernel_netfilter', False)) is not bool:
        raise ValueError('kernel_netfilter must be boolean')
    for source in settings['sources']:
        if source.get('format', 'jsonl') not in ('jsonl', 'auth', 'http_access', 'netfilter'):
            raise ValueError('Unsupported source format')
        for name in ('destination', 'destination_service', 'protocol', 'destination_ip'):
            if name in source and not isinstance(source[name], str):
                raise ValueError(f'{name} must be a string')
        if 'destination_port' in source and (type(source['destination_port']) is not int or not 1 <= source['destination_port'] <= 65535):
            raise ValueError('Invalid destination_port')
    for entry in settings['files']:
        if 'authorized_sha256' in entry and not re.fullmatch('[0-9a-fA-F]{64}', str(entry['authorized_sha256'])):
            raise ValueError('authorized_sha256 must be a 64-character hexadecimal hash')
    return settings


class StorageFull(RuntimeError):
    """Ingestion pauses instead of deleting historical events silently."""


class Engine:
    def __init__(self, path, settings=None, readonly=False, brain=None, directory=None):
        self.readonly = readonly
        self.database_path = None if str(path) == ':memory:' else Path(path)
        self.c = deepcopy(DEFAULT) | (settings or {})
        self._brain, self._directory = brain, directory
        if readonly:
            self.db = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True, timeout=10)
        else:
            if self.database_path is not None:
                Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                try:
                    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                except FileExistsError:
                    pass
                else:
                    os.close(descriptor)
            self.db = sqlite3.connect(path, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA busy_timeout=10000')
        if readonly:
            return
        self.db.executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, ts REAL, source TEXT, kind TEXT, ip TEXT, port INTEGER, message TEXT, authorized INTEGER, status TEXT);
        CREATE INDEX IF NOT EXISTS event_time ON events(ts);
        CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY,value TEXT);
        CREATE TABLE IF NOT EXISTS employee_risk(
            employee_id TEXT PRIMARY KEY, weighted_sum REAL, weight REAL, last_ts REAL, risk REAL, level TEXT,
            risk_percentile REAL, peak_risk REAL, peak_ts REAL, max_score REAL, events INTEGER, high_events INTEGER,
            updated_ts REAL, model_version TEXT);
        CREATE TABLE IF NOT EXISTS responses(
            id TEXT PRIMARY KEY, employee_id TEXT, source_ip TEXT, actions TEXT, reason TEXT, peak_risk REAL,
            level TEXT, created_ts REAL, created_by TEXT, status TEXT, reverted_ts REAL, reverted_by TEXT,
            model_version TEXT);
        CREATE TABLE IF NOT EXISTS response_audit(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, action TEXT, employee_id TEXT, actor TEXT, detail TEXT);
        ''')
        # Additive migration preserves earlier project databases and their history.
        added = [('dst_ip', 'TEXT'), ('dst_host', 'TEXT'), ('source_port', 'INTEGER'), ('processed_ts', 'REAL'),
                 ('employee_id', 'TEXT'), ('device_id', 'TEXT'), ('protocol', 'TEXT'), ('dst_service', 'TEXT'),
                 ('bytes_in', 'REAL'), ('bytes_out', 'REAL'), ('response_ms', 'REAL'), ('prev_hour', 'INTEGER'),
                 ('features', 'TEXT'), ('score', 'REAL'), ('level', 'TEXT'), ('model_version', 'TEXT'),
                 ('enforced', 'INTEGER')]
        for name, datatype in added:
            columns = {row[1] for row in self.db.execute('PRAGMA table_info(events)')}
            if name not in columns:
                try:
                    self.db.execute(f'ALTER TABLE events ADD COLUMN {name} {datatype}')
                except sqlite3.OperationalError:
                    if name not in {r[1] for r in self.db.execute('PRAGMA table_info(events)')}:
                        raise
        self.db.executescript('''
        CREATE INDEX IF NOT EXISTS event_source_time ON events(ip, ts);
        CREATE INDEX IF NOT EXISTS event_employee_time ON events(employee_id, ts);
        CREATE INDEX IF NOT EXISTS event_level_time ON events(level, ts);
        ''')
        if self.db.execute('PRAGMA user_version').fetchone()[0] < SCHEMA_VERSION:
            self.db.execute(f'PRAGMA user_version={SCHEMA_VERSION}')
        self.db.commit()
        self.event_count = self.db.execute('SELECT COUNT(*) FROM events').fetchone()[0]

    # ------------------------------------------------------------------ model
    @property
    def brain(self):
        if self._brain is None:
            from .brain.runtime import load_brain
            self._brain = load_brain(self.c.get('model'))
        return self._brain

    @property
    def directory(self):
        if self._directory is None:
            from .brain.telemetry import DEFAULT_DIRECTORY, Directory
            self._directory = Directory.load(self.c.get('directory') or DEFAULT_DIRECTORY)
        return self._directory

    @property
    def model_version(self):
        return getattr(self.brain, 'version_', 'insider_brain:unversioned')

    @property
    def enforcement_path(self):
        """Where active-defense enforcement (blocked IPs / ended sessions) is stored.

        The same file the loopback lab target honours; the collector reads it to mark
        telemetry that arrives from a source the analyst (or the auto-responder) has blocked.
        """
        lab = self.c.get('lab')
        if lab and lab.get('runtime'):
            base = Path(lab['runtime'])
        elif self.database_path is not None:
            base = self.database_path.parent.parent / 'runtime' / 'lab'
        else:
            return None
        return base / 'enforcement.json'

    def enforcement(self):
        path = self.enforcement_path
        if not path or not path.is_file():
            return {'blocked_ips': {}, 'ended_sessions': {}}
        try:
            data = json.loads(path.read_text())
            return {'blocked_ips': dict(data.get('blocked_ips') or {}),
                    'ended_sessions': dict(data.get('ended_sessions') or {})}
        except (OSError, ValueError):
            return {'blocked_ips': {}, 'ended_sessions': {}}

    def close(self):
        self.db.close()

    def state(self, key):
        row = self.db.execute('SELECT value FROM state WHERE key=?', (key,)).fetchone()
        return row[0] if row else None

    def set_state(self, key, value):
        self.db.execute('INSERT OR REPLACE INTO state VALUES (?,?)', (key, value))
        self.db.commit()

    # ------------------------------------------------------------------ ingestion
    def prepare(self, event):
        """Validate and normalize one raw record (raises ValueError)."""
        from .brain.telemetry import normalize_event, resolve_context
        if not isinstance(event, dict):
            raise ValueError('Event must be an object')
        message = event.get('message', '')
        if isinstance(message, str) and len(message.encode('utf-8')) > self.c['max_line_bytes']:
            raise ValueError('Message exceeds configured size limit')
        if 'authorized' in event and type(event['authorized']) is not bool:
            raise ValueError('authorized must be boolean')
        prepared = resolve_context(normalize_event(event), self.directory)
        prepared['id'] = event.get('id') or hashlib.sha256(json.dumps(event, sort_keys=True, default=str).encode()).hexdigest()
        prepared['source'] = event.get('source', 'import')
        prepared['authorized'] = event.get('authorized')
        return prepared

    def process(self, event):
        """Ingest and score one raw record. Returns its result, or None for a duplicate."""
        return self.ingest([self.prepare(event)])[0]

    def ingest(self, prepared):
        """Store a batch of prepared events, score the new ones and update employee risk.

        Returns one entry per input: dict(score, level, employee_id) or None if duplicate.
        """
        from .brain.telemetry import PREVIOUS_WINDOW_SECONDS, derive_features
        results = [None] * len(prepared)
        if not prepared:
            return results
        brain, directory = self.brain, self.directory
        version = self.model_version
        inserted = []
        full = None
        with self.db:
            for index, e in enumerate(prepared):
                if self.event_count >= self.c['max_events']:
                    full = 'Event capacity reached; archive data before resuming'
                    break
                if self.database_path and self.event_count % 32 == 0:
                    size = sum(p.stat().st_size for p in (self.database_path, Path(str(self.database_path)+'-wal')) if p.exists())
                    if size >= self.c['max_database_bytes']:
                        full = 'Database size limit reached; archive before resuming'
                        break
                cur = self.db.execute(
                    'INSERT OR IGNORE INTO events(id,ts,source,kind,ip,port,message,authorized,status,dst_ip,dst_host,source_port,processed_ts,'
                    'employee_id,device_id,protocol,dst_service,bytes_in,bytes_out,response_ms,model_version) '
                    'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                    (e['id'], e['ts'], e['source'], e['kind'], e['source_ip'], e['destination_port'], e['message'],
                     e['authorized'], 'PENDING', e['destination_ip'], e.get('dst_host'), e['source_port'], now(),
                     e['employee_id'], e['device_id'], e['protocol'], e['destination_service'], e['bytes_in'],
                     e['bytes_out'], e['response_time_ms'], version))
                if cur.rowcount:
                    self.event_count += 1
                    inserted.append((index, cur.lastrowid))
            if inserted:
                rows = [prepared[i] for i, _ in inserted]
                prev = []
                for (i, rowid), e in zip(inserted, rows):
                    if e['source_ip'] is None:
                        prev.append(0)
                        continue
                    prev.append(self.db.execute(
                        'SELECT COUNT(*) FROM events WHERE ip=? AND ts>=? AND (ts<? OR (ts=? AND rowid<?))',
                        (e['source_ip'], e['ts'] - PREVIOUS_WINDOW_SECONDS, e['ts'], e['ts'], rowid)).fetchone()[0])
                frame = pd.DataFrame(rows)
                frame['source_events_previous_hour'] = prev
                features = derive_features(frame, directory)
                features['employee_id'] = frame['employee_id'].to_numpy()
                scores = brain.score_events(features)
                levels = brain.event_levels(scores)
                inputs = brain.matrix(features)
                enf = self.enforcement()
                blocked_ips, ended = set(enf['blocked_ips']), set(enf['ended_sessions'])
                risk_rows, risk_scores = [], []
                for (i, rowid), e, score, level, p, record in zip(inserted, rows, scores, levels, prev, inputs.to_dict('records')):
                    record = {k: (None if isinstance(v, float) and np.isnan(v) else v) for k, v in record.items()}
                    # An active block prevents the action: the attempt is recorded for audit but
                    # does not raise the employee's risk further.
                    enforced = int(e['source_ip'] in blocked_ips or e['employee_id'] in ended)
                    status = 'BLOCKED' if enforced else str(level).upper()
                    self.db.execute('UPDATE events SET score=?, level=?, status=?, prev_hour=?, features=?, enforced=? WHERE rowid=?',
                                    (float(score), str(level), status, int(p), json.dumps(record), enforced, rowid))
                    results[i] = dict(score=float(score), level=str(level), employee_id=e['employee_id'], enforced=bool(enforced))
                    if not enforced:
                        risk_rows.append(e)
                        risk_scores.append(score)
                self._update_risk(risk_rows, risk_scores, brain, version)
                last = max(rows, key=lambda r: r['ts'])
                self.db.execute('INSERT OR REPLACE INTO state VALUES (?,?)',
                                ('last_event', json.dumps({'event_ts': last['ts'], 'processed_ts': now()})))
        if full:
            raise StorageFull(full)
        return results

    def _update_risk(self, rows, scores, brain, version):
        """Rolling employee risk: time-decayed mean of event scores (count-free)."""
        from .brain.risk import RiskState
        order = sorted(range(len(rows)), key=lambda i: rows[i]['ts'])
        for i in order:
            emp = rows[i]['employee_id']
            if not emp:
                continue
            row = self.db.execute('SELECT * FROM employee_risk WHERE employee_id=?', (emp,)).fetchone()
            state = RiskState(row['weighted_sum'], row['weight'], row['last_ts']) if row else RiskState()
            risk = state.update(rows[i]['ts'], scores[i], brain.half_life_seconds)
            level = str(brain.employee_levels([risk])[0])
            percentile = float(brain.employee_percentile([risk])[0])
            high = int(scores[i] >= brain.boundaries_['high'])
            peak, peak_ts = (row['peak_risk'], row['peak_ts']) if row else (None, None)
            if peak is None or risk > peak:
                peak, peak_ts = risk, rows[i]['ts']
            prior_max = row['max_score'] if row and row['max_score'] is not None else float('-inf')
            prior_events = row['events'] if row and row['events'] is not None else 0
            prior_high = row['high_events'] if row and row['high_events'] is not None else 0
            self.db.execute('INSERT OR REPLACE INTO employee_risk VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)', (
                emp, state.weighted_sum, state.weight, state.last_ts, risk, level, percentile, peak, peak_ts,
                max(float(scores[i]), prior_max), prior_events + 1, prior_high + high, now(), version))

    def rows(self, table):
        if table not in ('events', 'employee_risk'):
            raise ValueError('Invalid table')
        order = 'risk DESC' if table == 'employee_risk' else 'ts DESC'
        return [dict(row) for row in self.db.execute(f'SELECT * FROM {table} ORDER BY {order}')]


def parse(line, fmt, source, identity, defaults=None):
    from .adapters import parse_line
    return parse_line(line, fmt, source, identity, defaults)


def collect(engine):
    from .collectors import collect_files
    return collect_files(engine)
