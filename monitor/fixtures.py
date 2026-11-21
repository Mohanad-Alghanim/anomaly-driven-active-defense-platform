"""Safe synthetic adapter fixtures. No connections or commands are executed.

Records come from organisation devices in the directory (10.200.x.x) so that the
collector can attribute them to employees; their content is ordinary activity.
"""
from datetime import datetime, timezone
import json
from pathlib import Path

DEVICE_A = '10.200.0.10'   # DEV0001-1 (EMP0001)
DEVICE_B = '10.200.0.11'   # DEV0002-1 (EMP0002)


def write_fixtures(directory, base=1794042000):
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    journal = []
    for i in range(5):
        journal.append(dict(__CURSOR=f'synthetic:auth:{i}', __REALTIME_TIMESTAMP=str(int((base+i)*1e6)), SYSLOG_IDENTIFIER='sshd',
                            _HOSTNAME='isolated-lab', MESSAGE=f'Failed password for invalid user student from {DEVICE_A} port 44000 ssh2'))
    for i, message in enumerate(('student : TTY=pts/1 ; USER=root ; COMMAND=/usr/bin/id', 'student : user NOT in the sudoers'), 5):
        journal.append(dict(__CURSOR=f'synthetic:auth:{i}', __REALTIME_TIMESTAMP=str(int((base+i)*1e6)), SYSLOG_IDENTIFIER='sudo',
                            _HOSTNAME='isolated-lab', MESSAGE=message))
    (root/'journal.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in journal))
    firewall = []
    for i, (dst, port) in enumerate((('10.10.1.20', 445), ('10.20.1.10', 443), ('10.40.1.10', 8443))):
        stamp = datetime.fromtimestamp(base+i, timezone.utc).isoformat()
        firewall.append(f'{stamp} lab kernel: [UFW ALLOW] SRC={DEVICE_B} DST={dst} PROTO=TCP SPT={44000+i} DPT={port}\n')
    (root/'firewall.log.example').write_text(''.join(firewall))
    requests = []
    for i in range(5):
        stamp = datetime.fromtimestamp(base+20+i, timezone.utc).strftime('%d/%b/%Y:%H:%M:%S %z')
        requests.append(f'{DEVICE_A} - - [{stamp}] "GET /search?q=report HTTP/1.1" 200 {900+i} "-" "Synthetic educational fixture"\n')
    (root/'access.log.example').write_text(''.join(requests))
    (root/'lab-file.txt').write_text('Synthetic baseline\n')
    return journal
