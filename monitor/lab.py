"""Instrumented loopback-only targets: real HTTP, TCP accepts and isolated OpenSSH."""
import argparse
from datetime import datetime, timezone
import fcntl
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import socket
import sqlite3
import subprocess
import threading
import time
from urllib.parse import parse_qs, urlsplit
from .core import now
from .lab_setup import WEB_PORT, SSH_PORT, SCAN_PORTS, paths, atomic_json, ssh_configuration

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
                if len(self.path)>2048:
                    status,payload=414,dict(error='Request too long')
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


def record_connection(listener, log):
    connection, peer = listener.accept()
    try:
        destination=connection.getsockname()
        event=dict(ts=now(),kind='connection',ip=peer[0],source_port=peer[1],
                   dst_ip=destination[0],dst_port=destination[1],message='Lab TCP connection accepted')
        append(log,json.dumps(event)+'\n')
    finally:
        connection.close()


def run(root, stop=None):
    if os.geteuid()==0:
        raise RuntimeError('Lab targets must run as the normal Kali user')
    os.umask(0o077)
    p=paths(root)
    if not p['ssh_config'].exists():
        raise RuntimeError('Run one-time lab preparation first')
    if p['ssh_config'].read_text() != ssh_configuration(p):
        raise RuntimeError('Refusing an altered SSH configuration; loopback isolation must be preserved')
    stop=stop or threading.Event()
    health=dict(heartbeat=now(),status='STARTING',components={})
    with (p['runtime']/'lab.lock').open('a') as lock:
        try:
            fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Lab already owns its runtime directory') from None
        catalog=Catalog()
        listeners=[]
        web=None
        child=None
        pump=None
        ready=threading.Event()
        try:
            with selectors.DefaultSelector() as selector:
                web=HTTPServer(('127.0.0.1',WEB_PORT),handler_for(p,catalog))
                selector.register(web.socket,selectors.EVENT_READ,('web',web))
                for port in SCAN_PORTS:
                    listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                    listeners.append(listener)
                    listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                    listener.bind(('127.0.0.1',port))
                    listener.listen(32)
                    selector.register(listener,selectors.EVENT_READ,('connection',listener))
                sshd=shutil.which('sshd') or '/usr/sbin/sshd'
                subprocess.run([sshd,'-t','-f',str(p['ssh_config'])],check=True,capture_output=True,timeout=10)
                child=subprocess.Popen([sshd,'-D','-e','-f',str(p['ssh_config'])],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
                def pump_ssh():
                    for raw in iter(child.stderr.readline,b''):
                        line=raw.decode(errors='replace')[:8192].strip()
                        append(p['auth'],datetime.now(timezone.utc).isoformat()+' lab sshd: '+line+'\n')
                        if f'Server listening on 127.0.0.1 port {SSH_PORT}' in line:
                            ready.set()
                pump=threading.Thread(target=pump_ssh,daemon=True)
                pump.start()
                if not ready.wait(6):
                    raise RuntimeError('Isolated SSH did not become ready; inspect runtime/lab/ssh-auth.log')
                health.update(status='RUNNING',components=dict(web='RUNNING',connections='RUNNING',ssh='RUNNING',file='RUNNING' if p['watched'].is_file() else 'STOPPED',privilege='AVAILABLE'))
                while not stop.is_set():
                    if child.poll() is not None:
                        raise RuntimeError('Isolated SSH exited; stopping lab to avoid partial readiness')
                    for key,_ in selector.select(timeout=0.5):
                        kind,target=key.data
                        if kind=='web':
                            web._handle_request_noblock()
                        else:
                            record_connection(target,p['connections'])
                    health['heartbeat']=now()
                    atomic_json(p['health'],health)
        except Exception as exc:
            health.update(status='STOPPED',error=str(exc),heartbeat=now())
            raise
        finally:
            if child is not None:
                child.terminate()
                try: child.wait(timeout=3)
                except subprocess.TimeoutExpired: child.kill(); child.wait()
                if pump: pump.join(timeout=2)
                child.stderr.close()
            for listener in listeners:
                listener.close()
            if web: web.server_close()
            catalog.close()
            health.update(status='STOPPED',heartbeat=now())
            health['components']={name:'STOPPED' for name in ('web','connections','ssh','file','privilege')}
            atomic_json(p['health'],health)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
    args=parser.parse_args()
    stop=threading.Event()
    for sig in (signal.SIGINT,signal.SIGTERM): signal.signal(sig,lambda *_:stop.set())
    run(args.root,stop)


if __name__=='__main__':
    main()
