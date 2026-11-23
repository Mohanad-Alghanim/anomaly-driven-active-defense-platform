"""Shared machinery for the insider-attack scenarios: identity, targets, emission.

Everything here is lab-only. A scenario:
  * resolves the employee's own device IP from the directory (identity theft);
  * builds behavioural telemetry records in the collector's schema;
  * appends them to the lab inbox so the live collector scores them as that employee;
  * optionally projects the brain's level for immediate operator feedback.

No attack-signature strings, no thresholds: the records describe behaviour only.
"""
import argparse
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable
from zoneinfo import ZoneInfo

from ..brain.telemetry import Directory, DEFAULT_DIRECTORY

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INBOX = ROOT / 'runtime' / 'lab' / 'telemetry.jsonl'
DEFAULT_CONFIG = ROOT / 'config.local.json'
MAX_EVENTS = 50                      # lab limit: scenarios never flood the collector
MAX_BYTES = 10 * 1024 * 1024 * 1024  # schema sanity bound on a single transfer

SCENARIOS = {}


def now_ts():
    """Current UTC epoch seconds (same basis the collector uses)."""
    import time
    return time.time()


def register(scenario):
    SCENARIOS[scenario.key] = scenario
    return scenario


# ---------------------------------------------------------------- directory lookups
def load_directory(path=None):
    return Directory.load(path or DEFAULT_DIRECTORY)


def device_ip(directory, employee_id):
    """The employee's own device source IP (the identity the scenario assumes)."""
    for device in directory.data.get('devices', []):
        if device.get('employee_id') == employee_id:
            return device['source_ip']
    raise SystemExit(f'No device found for {employee_id} in the directory. '
                     'Use an employee_id from Device_Profiles (see models/ai_engine/directory.json).')


def server(directory, service):
    """(destination_ip, destination_port, protocol) for a named real service."""
    for entry in directory.data.get('servers', []):
        if entry['service'] == service:
            return entry['ip_address'], int(entry['service_port']), entry.get('protocol', 'TCP')
    raise SystemExit(f'Unknown service {service!r}; the lab has: '
                     + ', '.join(sorted(s['service'] for s in directory.data.get('servers', []))))


def employee(directory, employee_id):
    person = directory.employee(employee_id)
    if not person:
        raise SystemExit(f'{employee_id} is not in the directory.')
    return person


# ---------------------------------------------------------------- timing
def _work_bounds(person):
    def minutes(text):
        h, m = str(text).split(':')[:2]
        return int(h) + int(m) / 60
    return minutes(person.get('work_start', '08:00')), minutes(person.get('work_end', '16:00'))


SCENARIO_WEEKDAY = 2   # Wednesday: mid-week, a workday in the lab directory


def _scenario_weekday(directory):
    """The fixed weekday scenarios land on (a workday, never a weekend day)."""
    day = SCENARIO_WEEKDAY
    for _ in range(7):
        if day not in directory.weekend_days:
            return day
        day = (day - 1) % 7
    return SCENARIO_WEEKDAY


def _recent_workday_at(directory, hour_local, minute=0):
    """The most recent past local datetime at `hour_local` on the fixed scenario weekday.

    Day of week is a model feature, so a scenario's level would otherwise drift with the
    day the demo is run. Pinning the weekday (a mid-week workday, so no 'weekend'
    deviation either) makes every scenario score the same on any day; it is always
    within the past 7 days, inside the dashboard's default window.
    """
    zone = ZoneInfo(directory.timezone)
    weekday = _scenario_weekday(directory)
    now_local = datetime.fromtimestamp(now_ts(), timezone.utc).astimezone(zone)
    local = now_local.replace(hour=hour_local % 24, minute=minute, second=0, microsecond=0)
    for _ in range(8):
        if local < now_local and local.weekday() == weekday:
            return local.timestamp()
        local -= timedelta(days=1)
    return local.timestamp()


def within_hours_ts(directory, person):
    """A recent workday timestamp inside the employee's work hours."""
    start, end = _work_bounds(person)
    hour = (start + end) / 2 if end > start else 12
    return _recent_workday_at(directory, int(hour), int(hour % 1 * 60))


def off_hours_ts(directory, person, hour_local=3):
    """A recent workday timestamp at `hour_local` local time, outside the schedule."""
    return _recent_workday_at(directory, hour_local, 7)


def opposite_habit_hour(person):
    """Local hour farthest from the employee's usual time of day (their baseline mean
    activity hour + 12 h). Falls back to the opposite of the schedule midpoint."""
    try:
        from ..brain.runtime import load_brain
        habit = load_brain().baseline_.hour(person.get('employee_id'))
    except Exception:
        habit = None
    if habit is not None:
        import math
        usual = (habit[0] % (2 * math.pi)) * 24 / (2 * math.pi)
    else:
        start, end = _work_bounds(person)
        usual = (start + end) / 2 if end > start else 12
    return int(round(usual + 12)) % 24


# ---------------------------------------------------------------- record building
def record(source_ip, directory, service, *, ts, kind, bytes_in=None, bytes_out=None,
           response_time_ms=None, message=''):
    ip, port, protocol = server(directory, service)
    out = dict(ts=float(ts), source_ip=source_ip, destination_ip=ip, destination_port=port,
               protocol=protocol, destination_service=service, kind=kind, message=message)
    for name, value in (('bytes_in', bytes_in), ('bytes_out', bytes_out), ('response_time_ms', response_time_ms)):
        if value is not None:
            out[name] = round(float(min(value, MAX_BYTES)), 3)
    return out


def spaced(base_ts, count, interval):
    """`count` timestamps ending at base_ts, `interval` seconds apart (oldest first)."""
    count = max(1, min(int(count), MAX_EVENTS))
    return [base_ts - (count - 1 - i) * interval for i in range(count)]


# ---------------------------------------------------------------- emission
def emit(records, inbox=DEFAULT_INBOX):
    inbox = Path(inbox)
    inbox.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if inbox.is_symlink():
        raise SystemExit(f'Refusing to write through a symlink: {inbox}')
    fd = os.open(inbox, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'a') as handle:
        for rec in records:
            handle.write(json.dumps(rec) + '\n')
        handle.flush()
        os.fsync(handle.fileno())
    return inbox


# ---------------------------------------------------------------- optional projection
def project_levels(records):
    """Score the records with the frozen brain in isolation, for operator feedback.

    This is a projection of behaviour considered on its own; the live employee risk
    also reflects their recent normal activity. Returns None if the model is absent.
    """
    try:
        import numpy as np
        import pandas as pd
        from ..brain.runtime import load_brain
        from ..brain.telemetry import derive_features, count_previous_hour
        from ..brain.risk import rolling_risk
    except Exception:
        return None
    try:
        brain = load_brain()
        directory = load_directory()
    except Exception:
        return None
    frame = pd.DataFrame(records)
    frame['employee_id'] = [directory.attribute(ip)[0] for ip in frame['source_ip']]
    for col in ('bytes_in', 'bytes_out', 'response_time_ms'):
        if col not in frame:
            frame[col] = np.nan
    frame['source_events_previous_hour'] = count_previous_hour(frame.assign(source_ip=frame['source_ip']))
    features = derive_features(frame, directory)
    features['employee_id'] = frame['employee_id'].to_numpy()
    scores = brain.score_events(features)
    event_levels = brain.event_levels(scores)
    scored = frame.assign(score=scores)
    risk = rolling_risk(scored, brain.half_life_seconds)
    final_risk = float(risk.dropna().iloc[-1]) if risk.notna().any() else None
    emp_level = str(brain.employee_levels([final_risk])[0]) if final_risk is not None else None
    reasons = brain.explain(features)[int(np.argmax(scores))]
    return dict(scores=[float(s) for s in scores], event_levels=[str(x) for x in event_levels],
                projected_employee_risk=final_risk, projected_employee_level=emp_level, top_reasons=reasons)


# ---------------------------------------------------------------- scenario + CLI
@dataclass
class Scenario:
    key: str                      # CLI/module name, e.g. 'data_exfiltration'
    title: str                    # human title
    service: str                  # primary targeted service
    signal: str                   # behavioural signal the brain is expected to see
    expected: str                 # design-intent level: 'HIGH' or 'MEDIUM'
    tone: str                     # 'loud' or 'stealthy'
    build: Callable               # (directory, source_ip, person, args) -> list[record]
    default_count: int = 3
    default_interval: int = 90
    action: Callable = None       # optional real loopback action: (args) -> str note
    cli_extra: Callable = None     # optional (parser) -> None to add scenario arguments


def _args(scenario, argv):
    p = argparse.ArgumentParser(prog=f'python -m monitor.attacks.{scenario.key}',
                                description=f'{scenario.title} — {scenario.signal}')
    p.add_argument('--employee', required=True, help='Employee to impersonate, e.g. EMP0234')
    p.add_argument('--inbox', default=str(DEFAULT_INBOX), help='Telemetry inbox the collector reads')
    p.add_argument('--count', type=int, default=scenario.default_count, help=f'Events to emit (<= {MAX_EVENTS})')
    p.add_argument('--interval', type=int, default=scenario.default_interval, help='Seconds between events')
    p.add_argument('--dry-run', action='store_true', help='Build and print without writing to the inbox')
    p.add_argument('--no-action', action='store_true', help='Skip the real loopback action, emit telemetry only')
    p.add_argument('--no-score', action='store_true', help='Skip the local brain projection')
    if scenario.cli_extra:
        scenario.cli_extra(p)
    return p.parse_args(argv)


def run_scenario(scenario, argv=None):
    args = _args(scenario, argv)
    directory = load_directory()
    person = employee(directory, args.employee)
    source_ip = device_ip(directory, args.employee)
    records = scenario.build(directory, source_ip, person, args)

    print(f'== {scenario.title} ==')
    print(f'Impersonating {args.employee} ({person.get("employee_name","?")}, {person.get("job_title","?")}, '
          f'{person.get("department","?")}) from device {source_ip}')
    print(f'Target service : {scenario.service}')
    print(f'Signal         : {scenario.signal}')
    print(f'Events         : {len(records)} written to {args.inbox}')
    note = None
    if scenario.action and not args.no_action and not args.dry_run:
        try:
            note = scenario.action(args)
        except Exception as exc:                      # a missing loopback target is not fatal
            note = f'(loopback action skipped: {exc})'
    if note:
        print(f'Loopback action: {note}')

    if args.dry_run:
        print('DRY RUN — records (not written):')
        for rec in records:
            print('  ' + json.dumps(rec))
    else:
        emit(records, args.inbox)
        print(f'Expected level : {scenario.expected} ({scenario.tone}). The brain is the authority; '
              'watch the dashboard as the collector ingests these events.')

    if not args.no_score:
        projection = project_levels(records)
        if projection:
            print(f'Local projection: event levels {projection["event_levels"]}, '
                  f'projected employee risk {projection["projected_employee_risk"]:.3f} '
                  f'-> {projection["projected_employee_level"].upper()}')
            print('  top reasons for the strongest event:')
            for reason in projection['top_reasons']:
                print('   - ' + reason)
    return records
