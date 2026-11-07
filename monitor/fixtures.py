"""Safe synthetic adapter fixtures. No connections or commands are executed."""
from datetime import datetime, timezone
import json
from pathlib import Path


def write_fixtures(directory, base=1794042000):
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    journal = []
    for i in range(5):
        journal.append(dict(__CURSOR=f'synthetic:auth:{i}', __REALTIME_TIMESTAMP=str(int((base+i)*1e6)), SYSLOG_IDENTIFIER='sshd', _HOSTNAME='isolated-lab', MESSAGE='Failed password for invalid user student from 192.0.2.10 port 44000 ssh2'))
    for i, message in enumerate(('student : TTY=pts/1 ; USER=root ; COMMAND=/usr/bin/id', 'student : user NOT in the sudoers'), 5):
        journal.append(dict(__CURSOR=f'synthetic:auth:{i}', __REALTIME_TIMESTAMP=str(int((base+i)*1e6)), SYSLOG_IDENTIFIER='sudo', _HOSTNAME='isolated-lab', MESSAGE=message))
    (root/'journal.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in journal))
    firewall = []
    for i in range(15):
        stamp = datetime.fromtimestamp(base+i, timezone.utc).isoformat()
        firewall.append(f'{stamp} lab kernel: [UFW BLOCK] SRC=192.0.2.20 DST=192.0.2.100 PROTO=TCP SPT=44000 DPT={8000+i}\n')
    (root/'firewall.log.example').write_text(''.join(firewall))
    requests = []
    for ip, request, ts in [('192.0.2.30', 'GET /?q=%27%20OR%201%3D1 HTTP/1.1', base+20), *[('192.0.2.40', 'GET /index HTTP/1.1', base+30+i/10) for i in range(50)]]:
        stamp = datetime.fromtimestamp(ts, timezone.utc).strftime('%d/%b/%Y:%H:%M:%S %z')
        requests.append(f'{ip} - - [{stamp}] "{request}" 200 123 "-" "Synthetic educational fixture"\n')
    (root/'access.log.example').write_text(''.join(requests))
    (root/'lab-file.txt').write_text('Synthetic baseline\n')
    return journal
