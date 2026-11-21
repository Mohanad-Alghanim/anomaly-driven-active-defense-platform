"""Sabotage / log tampering: touching the SIEM and altering a monitored file.

Two signals:
  * employee-attributed: a rare SIEM access (most employees never touch the SIEM),
    off-hours and heavy, as if pulling and pruning logs;
  * system-level: a real modification of the watched file (runtime/lab/watched/settings.txt),
    which the collector's integrity monitor reports as an unauthorised content change
    (not attributed to any employee, by design).

Loud by design.

    python -m monitor.attacks.sabotage_log_tampering --employee EMP0234
"""
import json
from datetime import datetime, timezone
from pathlib import Path

from . import base

SERVICE = 'SIEM'


def _watched_file():
    try:
        config = json.loads(Path(base.DEFAULT_CONFIG).read_text())
        for entry in config.get('files', []):
            if str(entry.get('path', '')).endswith('watched/settings.txt'):
                return Path(entry['path'])
    except (OSError, ValueError, TypeError):
        pass
    return base.ROOT / 'runtime' / 'lab' / 'watched' / 'settings.txt'


def action(args):
    target = _watched_file()
    if not target.is_file():
        return f'watched file {target} not found (run --prepare-lab first); SIEM telemetry still emitted'
    if target.is_symlink():
        return f'refusing to write through a symlink: {target}'
    stamp = datetime.now(timezone.utc).isoformat()
    with target.open('a') as handle:
        handle.write(f'audit_retention=0  # tampered {stamp}\n')
    # Record who tampered (lab stand-in for file-audit) so the collector attributes the
    # integrity-change event to this employee instead of leaving it unattributed.
    try:
        source_ip = base.device_ip(base.load_directory(), getattr(args, "employee", None))
        sidecar = Path(str(target) + '.actor.json')
        sidecar.write_text(json.dumps(dict(source_ip=source_ip, employee_id=getattr(args, 'employee', None), ts=base.now_ts())))
    except (SystemExit, OSError):
        source_ip = None
    return (f'appended a tamper line to {target.name} (actor {source_ip}); the collector will flag an '
            'unauthorised content change, now attributed to the employee')


def build(directory, source_ip, person, args):
    ts = base.off_hours_ts(directory, person, 2)
    stamps = base.spaced(ts, args.count, args.interval)
    return [base.record(source_ip, directory, SERVICE, ts=t, kind='log_access',
                        bytes_in=256, bytes_out=5_000_000, response_time_ms=900,
                        message='bulk log export and prune') for t in stamps]


SCENARIO = base.Scenario(
    key='sabotage_log_tampering', title='Sabotage / log tampering', service=SERVICE,
    signal='rare SIEM access plus a watched-file integrity change',
    expected='HIGH', tone='loud', build=build, default_count=1, default_interval=120,
    action=action)
base.register(SCENARIO)


def main(argv=None):
    return base.run_scenario(SCENARIO, argv)


if __name__ == '__main__':
    main()
