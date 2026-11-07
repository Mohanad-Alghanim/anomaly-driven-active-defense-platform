"""Independent collector lifecycle: one local writer, durable cursors and health."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import signal
import sqlite3
import threading
from .core import Engine, StorageFull, config, now
from .collectors import collect_files
from .journal import collect_journal


def cycle(engine, journal_reader=None):
    statuses = []
    try:
        statuses.append(collect_journal(engine, journal_reader) if journal_reader else collect_journal(engine))
        statuses.extend(collect_files(engine))
        status = 'RUNNING' if all(s['available'] and not s.get('rejected') for s in statuses if s.get('enabled', True)) else 'DEGRADED'
        health = dict(status=status, rules_version=3, heartbeat=now(), pid=os.getpid(), sources=statuses, last_event=json.loads(engine.state('last_event') or 'null'))
    except StorageFull as exc:
        health = dict(status='CAPACITY REACHED', heartbeat=now(), pid=os.getpid(), sources=statuses, error=str(exc), last_event=json.loads(engine.state('last_event') or 'null'))
    engine.set_state('collector_health', json.dumps(health))
    return health


def run(config_path, data_dir, once=False, stop=None):
    os.umask(0o077)
    data = Path(data_dir)
    data.mkdir(parents=True, exist_ok=True, mode=0o700)
    stop = stop or threading.Event()
    with (data/'collector.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Another collector already owns this data directory') from None
        while not stop.is_set():
            engine = None
            delay = 2
            try:
                settings = config(config_path)
                delay = settings['poll_seconds']
                engine = Engine(data/'live.db', settings)
                size = sum(p.stat().st_size for p in data.glob('live.db*') if p.is_file())
                if size >= settings['max_database_bytes']:
                    health = dict(status='CAPACITY REACHED', heartbeat=now(), pid=os.getpid(), error='Database size limit reached; archive before resuming', sources=[])
                    engine.set_state('collector_health', json.dumps(health))
                else:
                    cycle(engine)
                engine.db.execute('PRAGMA wal_checkpoint(PASSIVE)')
            except (OSError, ValueError, sqlite3.Error) as exc:
                # Do not log event payloads or sensitive Journal messages.
                if engine is None:
                    engine = Engine(data/'live.db')
                engine.set_state('collector_health', json.dumps(dict(status='ERROR', heartbeat=now(), pid=os.getpid(), error=str(exc)[:300], sources=[])))
            finally:
                if engine is not None:
                    engine.close()
            if once:
                break
            stop.wait(delay)
        if not once and (data/'live.db').exists():
            engine = Engine(data/'live.db')
            old = json.loads(engine.state('collector_health') or '{}')
            old.update(status='STOPPED', heartbeat=now())
            engine.set_state('collector_health', json.dumps(old))
            engine.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default=os.environ.get('SIX_CONFIG', 'config.local.json'))
    parser.add_argument('--data', default=os.environ.get('SIX_DATA', 'data'))
    parser.add_argument('--once', action='store_true', help='One bounded collection cycle, then exit')
    args = parser.parse_args()
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    run(args.config, args.data, args.once, stop)


if __name__ == '__main__':
    main()
