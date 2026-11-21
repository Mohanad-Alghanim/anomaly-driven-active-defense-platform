"""One-time, non-root lab provisioning. Never starts listeners or host services.

The lab provides a loopback Internal Web target, a watched file and a telemetry
inbox (JSONL in the behavioural schema) for the insider-scenario scripts.
"""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time

WEB_PORT = 8088
# Managed sources of the retired external-attack lab; removed from config on provisioning.
RETIRED_SOURCES = ('ssh-auth.log', 'connections.jsonl', 'privilege.jsonl')
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
    return dict(runtime=runtime, access=runtime/'access.log', telemetry=runtime/'telemetry.jsonl',
                watched=runtime/'watched/settings.txt', health=runtime/'health.json')


def provision(root, config_path=None):
    if os.geteuid() == 0:
        raise RuntimeError('Provision the lab as the normal Kali user, without sudo')
    root = Path(root).resolve()
    config_path = Path(config_path) if config_path else root/'config.local.json'
    p = paths(root)
    for path in p.values():
        if path.is_symlink():
            raise RuntimeError('Refusing a symlinked lab path: '+str(path))
    p['runtime'].mkdir(parents=True, exist_ok=True, mode=0o700)
    for key in ('access', 'telemetry'):
        create_private(p[key])
    create_private(p['watched'], BASELINE)
    supplied = json.loads(config_path.read_text()) if config_path.exists() else {}
    if not isinstance(supplied, dict):
        raise ValueError('Configuration must be an object')
    previous = json.dumps(supplied, sort_keys=True)
    additions = [
        dict(path=str(p['access']), format='http_access', destination='127.0.0.1', destination_ip='127.0.0.1',
             destination_port=WEB_PORT, destination_service='Internal Web', protocol='TCP'),
        dict(path=str(p['telemetry']), format='jsonl'),
    ]
    retired = {str(p['runtime']/name) for name in RETIRED_SOURCES}
    sources = [s for s in supplied.setdefault('sources', []) if s.get('path') not in retired]
    for addition in additions:
        if not any(s.get('path') == addition['path'] for s in sources):
            sources.append(addition)
    supplied['sources'] = sources
    files = supplied.setdefault('files', [])
    if not any(f.get('path') == str(p['watched']) for f in files):
        files.append(dict(path=str(p['watched']), authorized_sha256=hashlib.sha256(BASELINE).hexdigest()))
    supplied['lab'] = dict(runtime=str(p['runtime']), web_port=WEB_PORT)
    if json.dumps(supplied, sort_keys=True) != previous:
        if config_path.exists():
            create_private(config_path.with_name(config_path.name+'.backup-'+str(time.time_ns())), config_path.read_bytes())
        atomic_json(config_path, supplied)
    return p
