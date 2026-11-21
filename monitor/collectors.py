"""Bounded incremental file readers and hash monitoring."""
import hashlib
import json
import stat as stat_module
from pathlib import Path
from .adapters import parse_line
from .core import now


def defaults(source):
    """Per-source context for adapters that cannot see it in the log line."""
    keys = ('destination', 'destination_ip', 'destination_port', 'destination_service', 'protocol')
    return {k: source[k] for k in keys if k in source}


ACTOR_WINDOW_SECONDS = 600  # a fresh audit record attributes the change; a stale one is ignored


def actor_sidecar(path):
    """Path of the lab audit record that names who last wrote a watched file."""
    return Path(str(path) + '.actor.json')


def attribution(path):
    """Read and consume the audit sidecar for a watched file; returns a source_ip if fresh.

    The sidecar is the lab's stand-in for file-audit (auditd): the actor records their
    device IP when they modify the file, so the integrity-change event is attributed to
    the employee instead of being left unattributed. Lab-only; the IP is validated and
    attributed through the directory exactly like any other event.
    """
    sidecar = actor_sidecar(path)
    try:
        record = json.loads(sidecar.read_text())
        sidecar.unlink()
    except (OSError, ValueError):
        return {}
    source_ip = record.get('source_ip')
    if source_ip and now() - float(record.get('ts', 0)) <= ACTOR_WINDOW_SECONDS:
        return dict(source_ip=source_ip)
    return {}


def collect_files(engine):
    statuses = []
    for source in engine.c['sources']:
        path = Path(source['path'])
        fmt = source.get('format', 'jsonl')
        status = dict(source=str(path), format=fmt, available=False, rejected=0, last_poll=now())
        try:
            stat = path.stat()
            if not stat_module.S_ISREG(stat.st_mode):
                raise ValueError('Source must be a regular file')
            key = 'cursor:' + str(path.resolve())
            saved = json.loads(engine.state(key) or '{}')
            same = saved.get('inode') == stat.st_ino and stat.st_size >= saved.get('offset', 0)
            offset = saved.get('offset', 0) if same else 0
            skipping = saved.get('skipping', False) if same else False
            errors = 0
            batch = []
            with path.open('rb') as handle:
                handle.seek(offset)
                for _ in range(engine.c['batch_lines']):
                    start = handle.tell()
                    raw = handle.readline(engine.c['max_line_bytes'] + 1)
                    if not raw:
                        break
                    if skipping:
                        skipping = not raw.endswith(b'\n')
                        continue
                    if len(raw) > engine.c['max_line_bytes']:
                        errors += 1
                        skipping = not raw.endswith(b'\n')
                        continue
                    if not raw.endswith(b'\n'):
                        handle.seek(start)
                        break
                    try:
                        # Source cursor + record content makes crash/restart replay idempotent.
                        identity = hashlib.sha256(f'{path.resolve()}:{stat.st_ino}:{start}:'.encode() + raw).hexdigest()
                        event = parse_line(raw.decode(), fmt, str(path), identity, defaults(source))
                        batch.append(engine.prepare(event))
                    except (ValueError, UnicodeError, TypeError, AttributeError, KeyError):
                        errors += 1
                # Events are stored and scored before the cursor moves: a crash replays, never skips.
                engine.ingest(batch)
                engine.set_state(key, json.dumps(dict(inode=stat.st_ino, offset=handle.tell(), skipping=skipping)))
            status.update(available=True, rejected=errors, status=f'Available; rejected lines this poll: {errors}')
        except (OSError, ValueError) as exc:
            status['status'] = str(exc)
        statuses.append(status)
    for entry in engine.c['files']:
        path = Path(entry['path'])
        status = dict(source=str(path), format='file', available=False, last_poll=now())
        key = 'hash:' + str(path.resolve())
        try:
            if not stat_module.S_ISREG(path.stat().st_mode):
                raise ValueError('Integrity target must be a regular file')
            with path.open('rb') as handle:
                initial = path.stat()
                if initial.st_size > engine.c['max_file_bytes']:
                    raise ValueError('File exceeds configured hash size limit')
                digest = hashlib.sha256()
                for _ in range(engine.c['max_file_bytes'] // 65536 + 1):
                    chunk = handle.read(65536)
                    if not chunk:
                        break
                    digest.update(chunk)
                final = path.stat()
                if (initial.st_size, initial.st_mtime_ns, initial.st_ino) != (final.st_size, final.st_mtime_ns, final.st_ino):
                    raise ValueError('File changed while hashing; retry next poll')
                digest = digest.hexdigest()
            old = engine.state(key)
            if old and old != digest:
                event = dict(ts=now(), kind='file_change', source=str(path), dst_host=str(path),
                             message=f'Content changed: {path}',
                             authorized=digest == str(entry.get('authorized_sha256', '')).lower())
                event.update(attribution(path))   # attribute the change to its actor when the lab recorded one
                engine.process(event)
            engine.set_state(key, digest)
            status.update(available=True, status='Monitoring content; baseline recorded')
        except (OSError, ValueError) as exc:
            status['status'] = str(exc)
        statuses.append(status)
    return statuses
