"""Instrumented loopback-only lab target: an Internal Web service with a real access log.

Phase 3 insider-scenario scripts write behavioural telemetry to runtime/lab/telemetry.jsonl.
"""
import argparse
from datetime import datetime, timezone
import fcntl
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import signal
import sqlite3
import threading
from urllib.parse import parse_qs, urlsplit
from .core import now
from .lab_setup import WEB_PORT, paths, atomic_json

LOG_LIMIT = 8 * 1024 * 1024  # Three retained generations, per log.


def append(path, text):
    """Append actual target telemetry, with bounded rotation and private files."""
    path = Path(path)
    if path.exists() and path.stat().st_size >= LOG_LIMIT:
        for i in (2,1):
            source = Path(str(path)+'.'+str(i))
            if source.exists():
                os.replace(source,Path(str(path)+'.'+str(i+1)))
        os.replace(path,Path(str(path)+'.1'))
    fd=os.open(path,os.O_APPEND | os.O_CREAT | os.O_WRONLY,0o600)
    with os.fdopen(fd,'a') as handle:
        handle.write(text)


class Catalog:
    """Deliberate SQL injection in a disposable in-memory catalog, without secrets."""
    def __init__(self):
        self.db=sqlite3.connect(':memory:')
        self.db.executescript("CREATE TABLE catalog(name TEXT); INSERT INTO catalog VALUES ('pencil'),('notebook');")
        self.db.set_progress_handler(lambda: 1, 10000)

    def search(self, query):
        if len(query)>256:
            raise ValueError('Query exceeds 256 characters')
        # Deliberately unsafe ONLY in this disposable lab target. execute forbids multiple statements.
        return [row[0] for row in self.db.execute("SELECT name FROM catalog WHERE name LIKE '%"+query+"%'").fetchall()]

    def close(self):
        self.db.close()


def blocked_sources(p):
    """Source IPs the active-defense layer has blocked (read fresh each request)."""
    path = p['runtime'] / 'enforcement.json'
    try:
        return set((json.loads(path.read_text()).get('blocked_ips') or {}).keys())
    except (OSError, ValueError):
        return set()


def handler_for(p, catalog):
    class Handler(BaseHTTPRequestHandler):
        server_version='ActiveDefenseLab/1'
        timeout=2
        def setup(self):
            self.request.settimeout(2)
            super().setup()
        def log_message(self,*_):
            pass
        def do_GET(self):
            try:
                parts=urlsplit(self.path)
                # Active defense: the lab honours the enforcement blocklist. A request that
                # declares a blocked source IP (X-Lab-Source) is refused, loopback-only.
                claimed=self.headers.get('X-Lab-Source')
                if len(self.path)>2048:
                    status,payload=414,dict(error='Request too long')
                elif claimed and claimed in blocked_sources(p):
                    status,payload=403,dict(error='Source blocked by active defense')
                elif parts.path=='/health':
                    status,payload=200,dict(target='active-defense-loopback-lab',status='RUNNING')
                elif parts.path=='/search':
                    try:
                        payload=dict(results=catalog.search(parse_qs(parts.query).get('q',[''])[0]))
                        status=200
                    except (sqlite3.Error,ValueError):
                        status,payload=400,dict(error='Lab query rejected')
                else:
                    status,payload=404,dict(error='Use /health or /search?q=pencil')
                body=json.dumps(payload).encode()
                self.send_response(status)
                self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError,ConnectionResetError):
                    pass
                stamp=datetime.now(timezone.utc).strftime('%d/%b/%Y:%H:%M:%S %z')
                request=self.requestline[:2048].replace('"','%22').replace('\r','').replace('\n','')
                append(p['access'],f'{self.client_address[0]} - - [{stamp}] "{request}" {status} {len(body)}\n')
            except (TimeoutError,OSError):
                self.close_connection=True
    return Handler


def run(root, stop=None, port=WEB_PORT):
    if os.geteuid()==0:
        raise RuntimeError('Lab targets must run as the normal Kali user')
    os.umask(0o077)
    p=paths(root)
    if not p['telemetry'].exists():
        raise RuntimeError('Run one-time lab preparation first')
    stop=stop or threading.Event()
    health=dict(heartbeat=now(),status='STARTING',components={})
    with (p['runtime']/'lab.lock').open('a') as lock:
        try:
            fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Lab already owns its runtime directory') from None
        catalog=Catalog()
        web=None
        try:
            web=HTTPServer(('127.0.0.1',port),handler_for(p,catalog))
            web.timeout=0.5
            while not stop.is_set():
                health.update(status='RUNNING',heartbeat=now(),components=dict(
                    web='RUNNING', telemetry='AVAILABLE' if p['telemetry'].is_file() else 'STOPPED',
                    file='RUNNING' if p['watched'].is_file() else 'STOPPED'))
                atomic_json(p['health'],health)
                web.handle_request()
        except Exception as exc:
            health.update(status='STOPPED',error=str(exc),heartbeat=now())
            raise
        finally:
            if web: web.server_close()
            catalog.close()
            health.update(status='STOPPED',heartbeat=now())
            health['components']={name:'STOPPED' for name in ('web','telemetry','file')}
            atomic_json(p['health'],health)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--port',type=int,default=WEB_PORT,help='Loopback port for the lab web target')
    args=parser.parse_args()
    stop=threading.Event()
    for sig in (signal.SIGINT,signal.SIGTERM): signal.signal(sig,lambda *_:stop.set())
    run(args.root,stop,args.port)


if __name__=='__main__':
    main()
