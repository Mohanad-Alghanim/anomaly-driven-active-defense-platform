"""One-time, non-root lab provisioning. Never starts listeners or host services."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import tempfile
import time

WEB_PORT = 8088
SSH_PORT = 2222
SCAN_PORTS = tuple(range(9100, 9120))
INVALID_USER = 'six-soc-invalid'
# Historical integrity baseline: retain its exact bytes and authorized SHA-256.
BASELINE = bytes.fromhex('5369782d41747461636b20534f432069736f6c61746564206c616220636f6e66696775726174696f6e0a6d6f64653d626173656c696e650a')


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.'+path.name)
    try:
        with os.fdopen(fd, 'w') as handle:
            json.dump(value, handle, indent=2)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def create_private(path, content=b''):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        if path.is_symlink() or not path.is_file():
            raise RuntimeError('Unsafe existing lab path: '+str(path))
    else:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(content)


def paths(root):
    runtime = Path(root).resolve()/'runtime/lab'
    return dict(runtime=runtime, access=runtime/'access.log', connections=runtime/'connections.jsonl',
                auth=runtime/'ssh-auth.log', privilege=runtime/'privilege.jsonl',
                watched=runtime/'watched/settings.txt', health=runtime/'health.json',
                validation=runtime/'validation.json', ssh_config=runtime/'sshd_config', hostkey=runtime/'host_ed25519_key')


def ssh_configuration(p):
    def quoted(path):
        return '"'+str(path).replace('\\','\\\\').replace('"','\\"')+'"'
    return f'''# Managed isolated lab daemon: no valid login account, no host configuration changes.
Port {SSH_PORT}
ListenAddress 127.0.0.1
HostKey {quoted(p['hostkey'])}
PidFile {quoted(p['runtime']/'sshd.pid')}
UsePAM no
PasswordAuthentication yes
KbdInteractiveAuthentication no
PubkeyAuthentication no
PermitRootLogin no
PermitEmptyPasswords no
AllowUsers {INVALID_USER}
AuthorizedKeysFile none
ForceCommand /usr/bin/false
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
PermitTTY no
MaxAuthTries 1
MaxSessions 1
MaxStartups 3:50:5
PerSourcePenalties no
LoginGraceTime 5
LogLevel VERBOSE
'''


def install_ssh_configuration(p):
    """Migrate only the exact previous managed lab config; validate before replace."""
    expected=ssh_configuration(p)
    target=p['ssh_config']
    if target.is_symlink():
        raise RuntimeError('Refusing a symlinked lab SSH configuration')
    previous=target.read_text() if target.exists() else None
    if previous==expected:
        return False
    legacy=expected.replace('PerSourcePenalties no\n','')
    if previous is not None and previous!=legacy:
        raise RuntimeError('Lab SSH config differs from the managed configuration; preserving it for review')
    descriptor,temporary=tempfile.mkstemp(prefix='.sshd_config.',dir=p['runtime'])
    try:
        with os.fdopen(descriptor,'w') as handle:
            handle.write(expected)
            handle.flush()
            os.fsync(handle.fileno())
        if p['hostkey'].exists():
            daemon=shutil.which('sshd') or '/usr/sbin/sshd'
            result=subprocess.run([daemon,'-t','-f',temporary],capture_output=True,text=True,timeout=10)
            if result.returncode:
                raise RuntimeError('OpenSSH rejected the lab-only configuration: '+result.stderr.strip())
        if previous is not None:
            create_private(target.with_name(target.name+'.backup-'+str(time.time_ns())),previous.encode())
        os.replace(temporary,target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return True


def provision(root, config_path=None, generate_key=True):
    if os.geteuid() == 0:
        raise RuntimeError('Provision the lab as the normal Kali user, without sudo')
    root = Path(root).resolve()
    config_path = Path(config_path) if config_path else root/'config.local.json'
    p = paths(root)
    for path in p.values():
        if path.is_symlink():
            raise RuntimeError('Refusing a symlinked lab path: '+str(path))
    p['runtime'].mkdir(parents=True, exist_ok=True, mode=0o700)
    for key in ('access','connections','auth','privilege'):
        create_private(p[key])
    create_private(p['watched'], BASELINE)
    try:
        pwd.getpwnam(INVALID_USER)
    except KeyError:
        pass
    else:
        raise RuntimeError('The reserved invalid SSH test username unexpectedly exists')
    if generate_key and not p['hostkey'].exists():
        keygen = shutil.which('ssh-keygen')
        if not keygen:
            raise RuntimeError('ssh-keygen is required; the installed OpenSSH client provides it')
        subprocess.run([keygen,'-q','-t','ed25519','-N','','-f',str(p['hostkey'])],check=True,timeout=15)
    install_ssh_configuration(p)
    supplied = json.loads(config_path.read_text()) if config_path.exists() else {}
    if not isinstance(supplied, dict):
        raise ValueError('Configuration must be an object')
    previous = json.dumps(supplied, sort_keys=True)
    additions = [
        dict(path=str(p['auth']),format='auth',kinds=['ssh_failed'],destination='127.0.0.1',destination_port=SSH_PORT),
        dict(path=str(p['access']),format='http_access',destination='127.0.0.1',destination_port=WEB_PORT),
        dict(path=str(p['connections']),format='jsonl',kinds=['connection']),
        dict(path=str(p['privilege']),format='jsonl',kinds=['privilege']),
    ]
    sources = supplied.setdefault('sources', [])
    for addition in additions:
        if not any(s.get('path') == addition['path'] for s in sources):
            sources.append(addition)
    files = supplied.setdefault('files', [])
    if not any(f.get('path') == str(p['watched']) for f in files):
        files.append(dict(path=str(p['watched']),authorized_sha256=hashlib.sha256(BASELINE).hexdigest()))
    supplied['lab'] = dict(runtime=str(p['runtime']),web_port=WEB_PORT,ssh_port=SSH_PORT,scan_ports=list(SCAN_PORTS))
    if json.dumps(supplied,sort_keys=True) != previous:
        if config_path.exists():
            create_private(config_path.with_name(config_path.name+'.backup-'+str(time.time_ns())),config_path.read_bytes())
        atomic_json(config_path, supplied)
    return p
