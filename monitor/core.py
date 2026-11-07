"""Six transparent rules, durable collection and SQLite storage."""
import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

CATEGORIES = ('SSH Brute Force', 'Port Scanning', 'SQL Injection', 'Denial of Service (DoS)', 'Unauthorized File Modification', 'Suspicious Privilege Escalation')
DEFAULT = dict(ssh_count=5, ssh_window=60, port_count=15, port_window=60, dos_count=50, dos_window=10, sources=[], files=[])
ACTIONS = ('Review SSH activity; restrict access and use keys.', 'Review firewall telemetry and restrict unnecessary ports.', 'Review application logs and use parameterized queries.', 'Review traffic and apply suitable rate limits.', 'Verify the change with the owner and restore a trusted copy if needed.', 'Review privileged commands and account permissions.')
SQL = re.compile(r"union\s+(?:all\s+)?select|(?:'|\")\s*or\s+['\"]?1['\"]?\s*=\s*['\"]?1|;\s*drop\s+table|--", re.I)
PRIV = re.compile(r'authentication failure|not in the sudoers|COMMAND=.*(?:/bin/(?:ba)?sh|chmod\s+[+]s|usermod\s+.*-aG\s+sudo)', re.I)


def now():
    return datetime.now(timezone.utc).timestamp()


def config(path='config.local.json'):
    settings = DEFAULT.copy()
    if Path(path).exists():
        supplied = json.loads(Path(path).read_text())
        if not isinstance(supplied, dict):
            raise ValueError('Configuration must be a JSON object')
        settings.update(supplied)
    for key in ('ssh_count', 'ssh_window', 'port_count', 'port_window', 'dos_count', 'dos_window'):
        if type(settings[key]) is not int or settings[key] < 1:
            raise ValueError(f'{key} must be a positive integer')
    for key in ('sources', 'files'):
        if not isinstance(settings[key], list):
            raise ValueError(f'{key} must be a list')
        for entry in settings[key]:
            if not isinstance(entry, dict) or not isinstance(entry.get('path'), str) or not entry['path']:
                raise ValueError(f'{key} entries require a nonempty path')
    return settings


class Engine:
    def __init__(self, path, settings=None):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.c = DEFAULT | (settings or {})
        self.db.executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, ts REAL, source TEXT, kind TEXT, ip TEXT, port INTEGER, message TEXT, authorized INTEGER, status TEXT);
        CREATE INDEX IF NOT EXISTS event_window ON events(kind,ip,ts);
        CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, event_id TEXT, attack TEXT, ts REAL, event_ts REAL, ip TEXT, severity TEXT, rule TEXT, description TEXT, action TEXT, UNIQUE(event_id,attack));
        CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY,value TEXT);
        ''')

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
        ts = float(e['ts'])
        import math
        if not math.isfinite(ts):
            raise ValueError('Timestamp must be finite')
        kind, ip, source = e['kind'], e.get('ip'), e.get('source', 'import')
        if kind not in ('ssh_failed', 'connection', 'http', 'file', 'privilege', 'normal'):
            raise ValueError('Unsupported event kind')
        if ip is not None:
            import ipaddress
            ip = str(ipaddress.ip_address(ip))
        port = e.get('port')
        if kind == 'connection' and (type(port) is not int or not 1 <= port <= 65535):
            raise ValueError('Connection requires a destination port from 1 to 65535')
        if 'authorized' in e and type(e['authorized']) is not bool:
            raise ValueError('authorized must be boolean')
        eid = e.get('id') or hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest()
        with self.db:
            cur = self.db.execute('INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?)', (eid, ts, source, kind, ip, port, str(e['message']), bool(e.get('authorized', False)), 'NORMAL'))
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
                seconds = self.c['ssh_window'] if index == 0 else self.c['port_window'] if index == 1 else self.c['dos_window'] if index == 3 else 0
                previous = self.db.execute('SELECT 1 FROM alerts WHERE attack=? AND ip IS ? AND event_ts BETWEEN ? AND ?', (CATEGORIES[index], ip, ts-seconds, ts)).fetchone() if seconds else None
                if not previous:
                    self.db.execute('INSERT INTO alerts(event_id,attack,ts,event_ts,ip,severity,rule,description,action) VALUES (?,?,?,?,?,?,?,?,?)', (eid, CATEGORIES[index], now(), ts, ip, 'HIGH' if index in (0, 2, 4, 5) else 'MEDIUM', rule, f'Possible {CATEGORIES[index]} indicator: {e["message"]}', ACTIONS[index]))
            if hits:
                self.db.execute("UPDATE events SET status='ABNORMAL' WHERE id=?", (eid,))
        return [CATEGORIES[index] for index, _ in hits]

    def rows(self, table):
        if table not in ('events', 'alerts'):
            raise ValueError('Invalid table')
        return [dict(row) for row in self.db.execute(f'SELECT * FROM {table} ORDER BY ts DESC')]


def parse(line, fmt, source, identity):
    if fmt == 'jsonl':
        e = json.loads(line)
        e.update(source=source, id=identity)
        return e
    # Traditional syslog has no year; infer current local year.
    try:
        ts = datetime.strptime(f'{datetime.now().year} {line[:15]}', '%Y %b %d %H:%M:%S').astimezone().timestamp()
    except ValueError:
        ts = now()
    match = re.search(r'from ([0-9a-fA-F:.]+)', line)
    kind = 'ssh_failed' if 'Failed password' in line else 'privilege' if 'sudo' in line or 'su[' in line else 'normal'
    return dict(id=identity, ts=ts, kind=kind, ip=match[1] if match else None, message=line.strip(), source=source)


def collect(engine):
    statuses = []
    for source in engine.c['sources']:
        path = Path(source['path'])
        fmt = source.get('format', 'jsonl')
        try:
            if fmt not in ('jsonl', 'auth'):
                raise ValueError('format must be jsonl or auth')
            stat = path.stat()
            key = 'cursor:' + str(path.resolve())
            saved = json.loads(engine.state(key) or '{}')
            offset = saved.get('offset', 0) if saved.get('inode') == stat.st_ino and stat.st_size >= saved.get('offset', 0) else 0
            errors = 0
            with path.open('rb') as handle:
                handle.seek(offset)
                for _ in range(5000):
                    start = handle.tell()
                    raw = handle.readline()
                    if not raw:
                        break
                    if not raw.endswith(b'\n'):
                        handle.seek(start)
                        break
                    try:
                        identity = hashlib.sha256(f'{path.resolve()}:{stat.st_ino}:{start}:'.encode() + raw).hexdigest()
                        engine.process(parse(raw.decode(), fmt, str(path), identity))
                    except (ValueError, UnicodeError, TypeError, AttributeError):
                        errors += 1
                engine.set_state(key, json.dumps(dict(inode=stat.st_ino, offset=handle.tell())))
            statuses.append(dict(source=str(path), status=f'Available; rejected lines this poll: {errors}'))
        except (OSError, ValueError) as exc:
            statuses.append(dict(source=str(path), status=str(exc)))
    for entry in engine.c['files']:
        path = Path(entry['path'])
        key = 'hash:' + str(path.resolve())
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            old = engine.state(key)
            if old and old != digest:
                engine.process(dict(ts=now(), kind='file', source=str(path), message=f'Content changed: {path}', authorized=digest == entry.get('authorized_sha256')))
            engine.set_state(key, digest)
            statuses.append(dict(source=str(path), status='Monitoring content; baseline recorded'))
        except OSError as exc:
            statuses.append(dict(source=str(path), status=str(exc)))
    return statuses
