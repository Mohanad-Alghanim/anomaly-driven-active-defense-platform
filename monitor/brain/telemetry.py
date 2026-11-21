"""Live telemetry -> model features, reproducing the dataset's derivations exactly.

Conventions verified against Normal_Behavior_Learning (see train.py parity check):
  * time features use local time (directory timezone), fractional hour, Monday = 0
  * is_weekend_observed: calendar weekend days observed in the normal data
  * within_assumed_work_hours: work_start <= local hour < work_end of the employee
  * *_log1p: natural log1p of the raw value
  * source_events_previous_hour: earlier events from the same source IP whose
    timestamp is at most 3600 s before this one

Attribution: source_ip -> device -> employee via the directory, as in evaluation.
"""
import ipaddress
import json
import math
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

import numpy as np
import pandas as pd

from .schema import DATASET_FEATURES

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DIRECTORY = ROOT / 'models' / 'ai_engine' / 'directory.json'
PREVIOUS_WINDOW_SECONDS = 3600  # definition of the dataset feature "previous hour"

RAW_FIELDS = ('source_ip', 'destination_ip', 'destination_port', 'protocol', 'destination_service',
              'bytes_in', 'bytes_out', 'response_time_ms')


class Directory:
    """Organisation context: devices, employees (schedule, display names) and servers."""

    def __init__(self, data):
        self.data = data
        self.timezone = data.get('timezone', 'UTC')
        self.weekend_days = set(data.get('weekend_days', []))
        self.devices = {d['source_ip']: d for d in data.get('devices', [])}
        self.employees = {e['employee_id']: e for e in data.get('employees', [])}
        self.servers = {s['ip_address']: s for s in data.get('servers', [])}

    @classmethod
    def load(cls, path=DEFAULT_DIRECTORY):
        return _load_directory(str(path), Path(path).stat().st_mtime)

    def attribute(self, source_ip):
        device = self.devices.get(source_ip) if source_ip else None
        return (device['employee_id'], device['device_id']) if device else (None, None)

    def employee(self, employee_id):
        return self.employees.get(employee_id, {})


@lru_cache(maxsize=4)
def _load_directory(path, _mtime):
    return Directory(json.loads(Path(path).read_text()))


def export_directory(workbook, weekend_days, timezone_name='Asia/Riyadh'):
    """Build directory.json content from the workbook profile sheets (no labels)."""
    devices = pd.read_excel(workbook, sheet_name='Device_Profiles', usecols=['device_id', 'employee_id', 'source_ip', 'device_type', 'hostname'])
    people = pd.read_excel(workbook, sheet_name='Organizational_Entities',
                           usecols=['employee_id', 'employee_name', 'department', 'job_title', 'work_start', 'work_end', 'work_days'])
    servers = pd.read_excel(workbook, sheet_name='Server_Profiles', usecols=['ip_address', 'service', 'protocol', 'service_port'])
    return dict(timezone=timezone_name, weekend_days=sorted(int(d) for d in weekend_days),
                devices=devices.astype(str).to_dict('records'),
                employees=people.astype(str).to_dict('records'),
                servers=servers.assign(service_port=servers.service_port.astype(int)).to_dict('records'))


# ---------------------------------------------------------------------- normalization
def _timestamp(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not math.isfinite(value):
            raise ValueError('Timestamp must be finite')
        return float(value)
    if isinstance(value, str):
        stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if stamp.tzinfo is None:
            raise ValueError('ISO timestamps need a UTC offset')
        return stamp.timestamp()
    raise ValueError('Timestamp must be epoch seconds or ISO 8601 text')


def _ip(value, name):
    if value in (None, ''):
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise ValueError(f'{name} is not an IP address') from None


def _amount(value, name):
    if value in (None, ''):
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError(f'{name} must be a non-negative number')
    return float(value)


def normalize_event(event):
    """Validate one raw telemetry record and map legacy keys onto the behavioural schema."""
    if not isinstance(event, dict):
        raise ValueError('Event must be an object')
    if 'ts' not in event:
        raise ValueError('Missing ts')
    out = dict(ts=_timestamp(event['ts']))
    out['source_ip'] = _ip(event.get('source_ip', event.get('ip')), 'source_ip')
    out['destination_ip'] = _ip(event.get('destination_ip', event.get('dst_ip')), 'destination_ip')
    port = event.get('destination_port', event.get('dst_port', event.get('port')))
    if port is not None and (type(port) is not int or not 1 <= port <= 65535):
        raise ValueError('destination_port must be an integer from 1 to 65535')
    out['destination_port'] = port
    source_port = event.get('source_port')
    if source_port is not None and (type(source_port) is not int or not 1 <= source_port <= 65535):
        raise ValueError('source_port must be an integer from 1 to 65535')
    out['source_port'] = source_port
    for name in ('protocol', 'destination_service', 'kind', 'message', 'dst_host'):
        value = event.get(name)
        if value is not None and not isinstance(value, str):
            raise ValueError(f'{name} must be text')
        out[name] = value
    out['kind'] = out['kind'] or 'activity'
    out['message'] = out['message'] or ''
    for name in ('bytes_in', 'bytes_out', 'response_time_ms'):
        out[name] = _amount(event.get(name), name)
    return out


def resolve_context(event, directory):
    """Fill service/protocol from the server directory and attribute the employee."""
    server = directory.servers.get(event.get('destination_ip'))
    if server:
        event['destination_service'] = event.get('destination_service') or server['service']
        event['protocol'] = event.get('protocol') or server['protocol']
    event['employee_id'], event['device_id'] = directory.attribute(event.get('source_ip'))
    return event


# ---------------------------------------------------------------------- features
def _minutes(text):
    hours, minutes = str(text).split(':')[:2]
    return int(hours) + int(minutes) / 60


def derive_features(events, directory):
    """events: DataFrame with ts (epoch seconds), RAW_FIELDS, employee_id and
    source_events_previous_hour. Returns the dataset's 13 feature columns."""
    local = pd.to_datetime(events['ts'], unit='s', utc=True).dt.tz_convert(directory.timezone)
    hour = local.dt.hour + local.dt.minute / 60 + local.dt.second / 3600 + local.dt.microsecond / 3.6e9
    dow = local.dt.day_of_week
    out = pd.DataFrame(index=events.index)
    out['hour_sin'] = np.sin(2 * np.pi * hour / 24)
    out['hour_cos'] = np.cos(2 * np.pi * hour / 24)
    out['day_of_week_sin'] = np.sin(2 * np.pi * dow / 7)
    out['day_of_week_cos'] = np.cos(2 * np.pi * dow / 7)
    out['is_weekend_observed'] = dow.isin(directory.weekend_days).astype(int)
    within = []
    for emp, h in zip(events['employee_id'], hour):
        person = directory.employee(emp)
        if not person:
            within.append(np.nan)
            continue
        start, end = _minutes(person['work_start']), _minutes(person['work_end'])
        within.append(int(start <= h < end) if start <= end else int(h >= start or h < end))
    out['within_assumed_work_hours'] = within
    for raw, name in (('bytes_in', 'bytes_in_log1p'), ('bytes_out', 'bytes_out_log1p'), ('response_time_ms', 'response_time_ms_log1p')):
        out[name] = np.log1p(pd.to_numeric(events[raw], errors='coerce'))
    out['destination_port'] = events['destination_port']
    out['protocol'] = events['protocol']
    out['destination_service'] = events['destination_service']
    out['source_events_previous_hour'] = events['source_events_previous_hour']
    return out[list(DATASET_FEATURES)]


def count_previous_hour(events):
    """Offline equivalent of the collector's SQL count (stable order breaks ties)."""
    counts = pd.Series(0, index=events.index, dtype=int)
    for _, group in events.dropna(subset=['source_ip']).groupby('source_ip'):
        group = group.sort_values('ts', kind='stable')
        ts = group['ts'].to_numpy(dtype=float)
        left = np.searchsorted(ts, ts - PREVIOUS_WINDOW_SECONDS, side='left')
        counts.loc[group.index] = np.arange(len(ts)) - left
    return counts


def utc_iso(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat()
