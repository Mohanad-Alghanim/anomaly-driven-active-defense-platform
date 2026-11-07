"""Evidence-driven SSH lab validation and isolated-daemon configuration reload."""
import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
from .core import Engine, now
from .lab_setup import INVALID_USER, SSH_PORT, install_ssh_configuration, paths

FAILURE = re.compile(r'\bFailed password for (?:invalid user )?'+re.escape(INVALID_USER)+r' from 127\.0\.0\.1 port \d+ ssh2(?: \[preauth\])?\s*$')


class NativeFailures:
    """Read only new complete native records, including bounded log rotation."""
    def __init__(self,path):
        self.path=Path(path)
        self.started=now()
        self.offsets={}
        self.seen=set()
        self.records=[]
        for file in self.files():
            try:
                stat=file.stat()
                self.offsets[(stat.st_dev,stat.st_ino)]=stat.st_size
            except FileNotFoundError:
                pass

    def files(self):
        return [Path(str(self.path)+'.'+str(i)) for i in (3,2,1)]+[self.path]

    def read(self,window=60):
        for file in self.files():
            try:
                with file.open('rb') as handle:
                    stat=os.fstat(handle.fileno())
                    key=(stat.st_dev,stat.st_ino)
                    offset=self.offsets.get(key,0)
                    handle.seek(offset if offset<=stat.st_size else 0)
                    for _ in range(2048):
                        start=handle.tell()
                        raw=handle.readline(65537)
                        if not raw:
                            break
                        if not raw.endswith(b'\n'):
                            handle.seek(start)
                            break
                        try:
                            text=raw.decode().strip()
                            stamp=datetime.fromisoformat(text.split()[0])
                            if stamp.tzinfo is None:
                                continue
                            ts=stamp.timestamp()
                        except (ValueError,UnicodeError,IndexError):
                            continue
                        if ts<self.started or ts>now()+2 or text in self.seen or not FAILURE.search(text):
                            continue
                        self.seen.add(text)
                        self.records.append(dict(message=text,ts=ts))
                    self.offsets[key]=handle.tell()
            except FileNotFoundError:
                pass
        cutoff=now()-window
        return [record for record in self.records if record['ts']>=cutoff]


def failed_logins(root,settings):
    """At most ten clients in 60 seconds; connection drops never count as failures."""
    if settings['ssh_count']!=5 or settings['ssh_window']!=60:
        raise RuntimeError('SSH lab validation requires the unchanged threshold: five failures in 60 seconds')
    if not shutil.which('sshpass') or not shutil.which('ssh'):
        raise RuntimeError('Installed sshpass and ssh are required for bounded SSH validation')
    evidence=NativeFailures(paths(root)['auth'])
    command=['sshpass','-p','deliberately-invalid-lab-password','ssh','-p',str(SSH_PORT),
             '-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null',
             '-o','PreferredAuthentications=password','-o','PubkeyAuthentication=no',
             '-o','NumberOfPasswordPrompts=1','-o','ConnectTimeout=3',
             '-o','ConnectionAttempts=1',f'{INVALID_USER}@127.0.0.1','true']
    deadline=time.monotonic()+60
    attempts=0
    for _ in range(10):
        records=evidence.read()
        if len(records)>=5 or time.monotonic()>=deadline:
            break
        attempts+=1
        try:
            result=subprocess.run(command,capture_output=True,timeout=min(8,max(.1,deadline-time.monotonic())))
            if result.returncode==0:
                raise RuntimeError('Unexpected successful SSH login; stop the isolated daemon')
        except subprocess.TimeoutExpired:
            pass  # A timed-out/dropped client is not authentication-failure evidence.
        # The daemon's stderr pump may append just after the client exits.
        log_deadline=min(deadline,time.monotonic()+1)
        while True:
            records=evidence.read()
            if len(records)>=5 or time.monotonic()>=log_deadline:
                break
            time.sleep(.05)
    records=evidence.read()
    if len(records)<5:
        raise RuntimeError(f'SSH UNVERIFIED: {len(records)} actual new Failed password records from {attempts} client attempts; five required')
    return dict(attempts=attempts,native_failed_password_records=len(records),_native_failures=records)


def collected_failures(root,data,evidence,timeout=20):
    """Correlate the native log messages with real normalized SQLite events."""
    records=evidence['_native_failures']
    messages=[record['message'] for record in records]
    deadline=time.monotonic()+timeout
    count=0
    while True:
        engine=Engine(Path(data)/'live.db',readonly=True)
        try:
            placeholders=','.join('?' for _ in messages)
            rows=engine.db.execute(f"SELECT id,ts,message FROM events WHERE source=? AND kind='ssh_failed' AND ip='127.0.0.1' AND message IN ({placeholders})",
                                   [str(paths(root)['auth']),*messages]).fetchall()
            # A replayed/duplicated line cannot contribute twice to evidence.
            unique={row['message']:row for row in rows}
            ordered=sorted(unique.values(),key=lambda row:row['ts'])
            count=len(ordered)
            for index in range(max(0,len(ordered)-4)):
                group=ordered[index:index+5]
                if len(group)==5 and group[-1]['ts']-group[0]['ts']<=60:
                    return [row['id'] for row in ordered]
        finally:
            engine.close()
        if time.monotonic()>=deadline:
            raise RuntimeError(f'SSH UNVERIFIED: only {count} native failures confirmed as kind=ssh_failed, ip=127.0.0.1 in SQLite; five in 60 seconds required')
        time.sleep(.25)


def reload_isolated_daemon(root):
    """SIGHUP only a verified same-user sshd master, without restarting other targets."""
    p=paths(root)
    pid=int((p['runtime']/'sshd.pid').read_text().strip())
    if pid<=1:
        raise RuntimeError('Invalid isolated-daemon PID')
    # pidfd pins the identity so PID reuse cannot signal another process.
    descriptor=os.pidfd_open(pid)
    try:
        proc=Path('/proc')/str(pid)
        daemon=Path(shutil.which('sshd') or '/usr/sbin/sshd').resolve()
        command=(proc/'cmdline').read_bytes().replace(b'\0',b' ').decode().strip()
        pattern=r'(?:^|\s)-f\s+'+re.escape(str(p['ssh_config']))+r'(?:\s|$)'
        overridden=re.search(r'(?:^|\s)-(?:p|o)(?:\s|[=0-9A-Za-z])',command)
        if proc.stat().st_uid!=os.getuid() or (proc/'exe').resolve()!=daemon or not re.search(pattern,command) or overridden:
            raise RuntimeError('PID does not identify the current user\'s isolated lab SSH daemon; no signal sent')
        signal.pidfd_send_signal(descriptor,signal.SIGHUP)
    finally:
        os.close(descriptor)
    return pid


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply',action='store_true',required=True,help='Update only lab SSH config and reload only its verified sshd master')
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
    args=parser.parse_args()
    try:
        changed=install_ssh_configuration(paths(args.root))
        pid=reload_isolated_daemon(args.root)
        print(json.dumps(dict(config_updated=changed,isolated_sshd_pid=pid,reload='SIGHUP requested; run the bounded SSH validation next')))
        return 0
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as exc:
        print('SSH configuration/reload requires attention: '+str(exc),file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
