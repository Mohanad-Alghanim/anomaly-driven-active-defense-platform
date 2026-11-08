"""Transparent detection rules, durable collection and SQLite storage."""
import hashlib
from copy import deepcopy
import math
import os
import ipaddress
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

CATEGORIES = ('SSH Brute Force', 'Port Scanning', 'SQL Injection', 'Denial of Service (DoS)', 'Unauthorized File Modification', 'Suspicious Privilege Escalation')
DEFAULT = dict(ssh_count=5, ssh_window=60, port_count=15, port_window=60, dos_count=50, dos_window=10, sources=[], files=[], poll_seconds=2, batch_lines=1000, max_line_bytes=65536, max_file_bytes=33554432, max_events=200000, max_database_bytes=268435456, journal={'enabled': True, 'lookback_seconds': 300})
ACTIONS = ('Review SSH activity; restrict access and use keys.', 'Review firewall telemetry and restrict unnecessary ports.', 'Review application logs and use parameterized queries.', 'Review traffic and apply suitable rate limits.', 'Verify the change with the owner and restore a trusted copy if needed.', 'Review privileged commands and account permissions.')
SQL = re.compile(r"union\s+(?:all\s+)?select|(?:'|\")\s*or\s+['\"]?1['\"]?\s*=\s*['\"]?1|;\s*drop\s+table|--", re.I)
PRIV = re.compile(r'LAB_PRIVILEGE_DENIED operation=(?:setuid target_uid=0|capset capability=CAP_SETUID) errno=1\b|authentication failure|not in the sudoers|COMMAND=.*(?:/bin/(?:ba)?sh|chmod\s+[+]s|usermod\s+.*-aG\s+sudo)', re.I)


def now():
    return datetime.now(timezone.utc).timestamp()


def config(path='config.local.json'):
    settings = deepcopy(DEFAULT)
    if Path(path).exists():
        supplied = json.loads(Path(path).read_text())
        if not isinstance(supplied, dict):
            raise ValueError('Configuration must be a JSON object')
        settings.update(supplied)
    for key in ('ssh_count', 'ssh_window', 'port_count', 'port_window', 'dos_count', 'dos_window', 'poll_seconds', 'batch_lines', 'max_line_bytes', 'max_file_bytes', 'max_events', 'max_database_bytes'):
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
        if 'destination' in source and not isinstance(source['destination'], str):
            raise ValueError('destination must be a host label string')
        if 'destination_port' in source and (type(source['destination_port']) is not int or not 1 <= source['destination_port'] <= 65535):
            raise ValueError('Invalid destination_port')
        if 'kinds' in source and (not isinstance(source['kinds'], list) or any(k not in ('normal', 'http', 'connection', 'ssh_failed', 'privilege', 'file') for k in source['kinds'])):
            raise ValueError('Invalid source kinds')
    for entry in settings['files']:
        if 'authorized_sha256' in entry and not re.fullmatch('[0-9a-fA-F]{64}', str(entry['authorized_sha256'])):
            raise ValueError('authorized_sha256 must be a 64-character hexadecimal hash')
    return settings


class StorageFull(RuntimeError):
    """Ingestion pauses instead of deleting historical events silently."""


class Engine:
    def __init__(self, path, settings=None, readonly=False):
        self.readonly = readonly
        self.database_path = None if str(path) == ':memory:' else Path(path)
        self.c = deepcopy(DEFAULT) | (settings or {})
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
        CREATE INDEX IF NOT EXISTS event_window ON events(kind,ip,ts);
        CREATE INDEX IF NOT EXISTS event_time ON events(ts);
        CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, event_id TEXT, attack TEXT, ts REAL, event_ts REAL, ip TEXT, severity TEXT, rule TEXT, description TEXT, action TEXT, UNIQUE(event_id,attack));
        CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY,value TEXT);
        CREATE TABLE IF NOT EXISTS matches(event_id TEXT, attack TEXT, ts REAL, severity TEXT, rule TEXT, description TEXT, action TEXT, PRIMARY KEY(event_id,attack));
        CREATE INDEX IF NOT EXISTS alert_window ON alerts(attack,ip,event_ts);
        ''')
        # Additive migration preserves the original project databases.
        for name, datatype in [('dst_ip','TEXT'), ('dst_host','TEXT'), ('source_port','INTEGER'), ('processed_ts','REAL')]:
            columns = {row[1] for row in self.db.execute('PRAGMA table_info(events)')}
            if name not in columns:
                try:
                    self.db.execute(f'ALTER TABLE events ADD COLUMN {name} {datatype}')
                except sqlite3.OperationalError:
                    if name not in {r[1] for r in self.db.execute('PRAGMA table_info(events)')}:
                        raise
        if self.db.execute('PRAGMA user_version').fetchone()[0] < 2:
            self.db.execute('INSERT OR IGNORE INTO matches SELECT event_id,attack,ts,severity,rule,description,action FROM alerts')
            self.db.execute('PRAGMA user_version=2')
        self.db.commit()
        self.event_count = self.db.execute('SELECT COUNT(*) FROM events').fetchone()[0]

    def close(self):
        self.db.close()

    def state(self, key):
        row = self.db.execute('SELECT value FROM state WHERE key=?', (key,)).fetchone()
        return row[0] if row else None

    def set_state(self, key, value):
        self.db.execute('INSERT OR REPLACE INTO state VALUES (?,?)', (key, value))
        self.db.commit()

    def process(self, event):
        e = dict(event)
        for key in ('ts', 'kind', 'message'):
            if key not in e:
                raise ValueError(f'Missing {key}')
        if not isinstance(e['message'], str):
            raise ValueError('message must be a string')
        if len(e['message'].encode('utf-8')) > self.c['max_line_bytes']:
            raise ValueError('Message exceeds configured size limit')
        ts = float(e['ts'])
        if not math.isfinite(ts):
            raise ValueError('Timestamp must be finite')
        kind, ip, source = e['kind'], e.get('ip'), e.get('source', 'import')
        if kind not in ('ssh_failed', 'connection', 'http', 'file', 'privilege', 'normal'):
            raise ValueError('Unsupported event kind')
        if ip is not None:
            ip = str(ipaddress.ip_address(ip))
        dst_ip = str(ipaddress.ip_address(e['dst_ip'])) if e.get('dst_ip') else None
        dst_host = e.get('dst_host')
        if dst_host is not None and not isinstance(dst_host, str):
            raise ValueError('dst_host must be a string')
        port = e.get('dst_port', e.get('port'))
        source_port = e.get('source_port')
        if any(v is not None and (type(v) is not int or not 1 <= v <= 65535) for v in (port, source_port)):
            raise ValueError('Ports must be integers from 1 to 65535')
        if kind == 'connection' and (type(port) is not int or not 1 <= port <= 65535):
            raise ValueError('Connection requires a destination port from 1 to 65535')
        if 'authorized' in e and type(e['authorized']) is not bool:
            raise ValueError('authorized must be boolean')
        eid = e.get('id') or hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest()
        if self.event_count >= self.c['max_events']:
            raise StorageFull('Event capacity reached; archive data before resuming')
        if self.database_path and self.event_count % 32 == 0:
            size = sum(p.stat().st_size for p in (self.database_path, Path(str(self.database_path)+'-wal')) if p.exists())
            if size >= self.c['max_database_bytes']:
                raise StorageFull('Database size limit reached; archive before resuming')
        detected = now()
        with self.db:
            cur = self.db.execute('INSERT OR IGNORE INTO events(id,ts,source,kind,ip,port,message,authorized,status,dst_ip,dst_host,source_port,processed_ts) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)', (eid, ts, source, kind, ip, port, str(e['message']), bool(e.get('authorized', False)), 'NORMAL', dst_ip, dst_host, source_port, detected))
            if not cur.rowcount:
                return []
            hits = []

            def window(seconds, distinct=False):
                expression = 'COUNT(DISTINCT port)' if distinct else 'COUNT(*)'
                return self.db.execute(f'SELECT {expression} FROM events WHERE kind=? AND ip=? AND ts BETWEEN ? AND ?', (kind, ip, ts-seconds, ts)).fetchone()[0]

            if kind == 'ssh_failed' and ip and window(self.c['ssh_window']) >= self.c['ssh_count']:
                hits.append((0, f"At least {self.c['ssh_count']} failures in {self.c['ssh_window']} seconds"))
            if kind == 'connection' and ip and window(self.c['port_window'], True) >= self.c['port_count']:
                hits.append((1, f"At least {self.c['port_count']} distinct ports in {self.c['port_window']} seconds"))
            if kind == 'http' and SQL.search(e['message']):
                hits.append((2, 'HTTP request matched a predefined SQL pattern'))
            if kind == 'http' and ip and window(self.c['dos_window']) >= self.c['dos_count']:
                hits.append((3, f"At least {self.c['dos_count']} HTTP requests in {self.c['dos_window']} seconds"))
            if kind == 'file' and not e.get('authorized', False):
                hits.append((4, 'File content changed without a matching authorization hash'))
            if kind == 'privilege' and PRIV.search(e['message']):
                hits.append((5, 'Privilege log matched a suspicious command or authentication failure'))
            for index, rule in hits:
                severity = 'HIGH' if index in (0, 2, 4, 5) else 'MEDIUM'
                description = f'Possible {CATEGORIES[index]} indicator: {e["message"]}'
                self.db.execute('INSERT OR IGNORE INTO matches VALUES (?,?,?,?,?,?,?)', (eid, CATEGORIES[index], detected, severity, rule, description, ACTIONS[index]))
                seconds = self.c['ssh_window'] if index == 0 else self.c['port_window'] if index == 1 else self.c['dos_window'] if index == 3 else 0
                previous = self.db.execute('SELECT 1 FROM alerts WHERE attack=? AND ip IS ? AND event_ts BETWEEN ? AND ?', (CATEGORIES[index], ip, ts-seconds, ts)).fetchone() if seconds else None
                if not previous:
                    self.db.execute('INSERT INTO alerts(event_id,attack,ts,event_ts,ip,severity,rule,description,action) VALUES (?,?,?,?,?,?,?,?,?)', (eid, CATEGORIES[index], detected, ts, ip, severity, rule, description, ACTIONS[index]))
            if hits:
                self.db.execute("UPDATE events SET status='ABNORMAL' WHERE id=?", (eid,))
            self.db.execute('INSERT OR REPLACE INTO state VALUES (?,?)', ('last_event', json.dumps({'event_ts': ts, 'processed_ts': detected})))
        self.event_count += 1
        return [CATEGORIES[index] for index, _ in hits]

    def rows(self, table):
        if table not in ('events', 'alerts'):
            raise ValueError('Invalid table')
        return [dict(row) for row in self.db.execute(f'SELECT * FROM {table} ORDER BY ts DESC')]



def parse(line, fmt, source, identity):
    from .adapters import parse_line
    return parse_line(line, fmt, source, identity)


def collect(engine):
    from .collectors import collect_files
    return collect_files(engine)
