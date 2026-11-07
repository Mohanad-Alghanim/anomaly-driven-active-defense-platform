"""Read-only normalization for existing auth, web and firewall telemetry."""
import json
import re
from datetime import datetime
from urllib.parse import unquote_plus
from .core import now

AUTH_IDS = ('sshd', 'sshd-session', 'sudo', 'su')


def log_time(line):
    try:
        return datetime.fromisoformat(line.split()[0].replace('Z', '+00:00')).timestamp()
    except (ValueError, IndexError):
        pass
    try:
        return datetime.strptime(f'{datetime.now().year} {line[:15]}', '%Y %b %d %H:%M:%S').astimezone().timestamp()
    except ValueError:
        return now()


def auth_event(message, ts, source, identity, host=None, identifier=None):
    failure = re.search(r'(?:Failed (?:password|publickey)|authentication failure).*?(?:from |rhost=)([0-9a-fA-F:.]+)', message, re.I)
    ssh = identifier in ('sshd', 'sshd-session') or re.search(r'\bsshd(?:-session)?(?:\[|:)', message)
    # Explicit SSH messages from traditional syslog or known Journal identifiers.
    if (ssh or identifier is None) and re.search(r'Failed (?:password|publickey)', message):
        kind = 'ssh_failed'
    elif identifier in ('sudo', 'su') or re.search(r'\b(?:sudo|su)(?:\[|:)', message):
        kind = 'privilege'
    else:
        kind = 'normal'
    port = re.search(r'\bport (\d+)\b', message)
    return dict(id=identity, ts=ts, kind=kind, ip=failure[1] if failure else None,
                source_port=int(port[1]) if port else None, dst_host=host,
                message=message.strip(), source=source)


def parse_line(line, fmt, source, identity, destination=None, destination_port=None):
    if fmt == 'jsonl':
        event = json.loads(line)
        if not isinstance(event, dict):
            raise ValueError('JSONL record must be an object')
        event.update(source=source, id=identity)
    elif fmt == 'auth':
        event = auth_event(line, log_time(line), source, identity)
    elif fmt == 'http_access':
        # Apache/Nginx common or combined access log (no custom format assumption).
        match = re.match(r'^(\S+) \S+ \S+ \[([^]]+)\] "([^"\r\n]*)" (\d{3}) (?:\d+|-)(?:\s|$)', line)
        if not match:
            raise ValueError('Expected common/combined HTTP access format')
        stamp = datetime.strptime(match[2], '%d/%b/%Y:%H:%M:%S %z').timestamp()
        event = dict(ts=stamp, kind='http', ip=match[1], message=unquote_plus(match[3]), source=source, id=identity)
    elif fmt == 'netfilter':
        fields = dict(re.findall(r'\b(SRC|DST|SPT|DPT|PROTO)=([^\s]+)', line))
        if not {'SRC', 'DST', 'DPT'} <= fields.keys():
            raise ValueError('Expected netfilter SRC, DST and DPT fields')
        event = dict(ts=log_time(line), kind='connection', ip=fields['SRC'], dst_ip=fields['DST'],
                     port=int(fields['DPT']), source_port=int(fields['SPT']) if 'SPT' in fields else None,
                     message=line.strip(), source=source, id=identity)
    else:
        raise ValueError('Unsupported source format')
    if destination is not None:
        event.setdefault('dst_host', destination)
    if destination_port is not None:
        event.setdefault('port', destination_port)
    return event


def parse_journal(record):
    if not isinstance(record, dict) or not isinstance(record.get('__CURSOR'), str):
        raise ValueError('Journal record has no cursor')
    identifier = record.get('SYSLOG_IDENTIFIER') or record.get('_COMM')
    message = record.get('MESSAGE')
    if not isinstance(message, str):
        raise ValueError('Journal message must be text')
    identity = 'journal:' + record['__CURSOR']
    ts = int(record['__REALTIME_TIMESTAMP']) / 1_000_000
    if identifier == 'kernel':
        return parse_line(message, 'netfilter', 'journal:kernel', identity)
    if identifier not in AUTH_IDS:
        return None
    return auth_event(message, ts, 'journal:' + identifier, identity, record.get('_HOSTNAME'), identifier)
