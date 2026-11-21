"""Plain-language explanation of an employee's risk score.

The explanation names the personal features that deviated most in the events that
contribute most to the current rolling risk, and says by how much, compared with
that employee's own normal baseline. It describes deviation, not intent.
"""
import json
import math
from datetime import datetime, timezone

import numpy as np

from .features import TWO_PI

FEATURE_LABELS = {
    'emp_bytes_out_z': 'Data sent', 'emp_bytes_in_z': 'Data received', 'emp_response_time_z': 'Response time',
    'emp_activity_z': 'Activity burst', 'emp_hour_deviation': 'Time of day', 'emp_service_rarity': 'Service used',
    'within_assumed_work_hours': 'Outside schedule', 'is_weekend_observed': 'Weekend activity',
}


def _bytes(value):
    value = float(value)
    for unit in ('bytes', 'KB', 'MB', 'GB'):
        if value < 1024 or unit == 'GB':
            return f'{value:,.0f} {unit}' if unit == 'bytes' else f'{value:,.1f} {unit}'
        value /= 1024


def _clock(hours):
    hours %= 24
    return f'{int(hours):02d}:{int(round((hours % 1) * 60)) % 60:02d}'


def _contributions(events, half_life_seconds, typical_score):
    """Rank events by how much they lift the decayed mean above typical normal activity:
    weight x (score - median normal event score). Routine recent events therefore do
    not mask an earlier unusual burst that still drives the risk."""
    latest = max(e['ts'] for e in events)
    for e in events:
        e['weight'] = 0.5 ** ((latest - e['ts']) / half_life_seconds)
        e['contribution'] = e['weight'] * ((e['score'] or 0.0) - typical_score)
    return sorted(events, key=lambda e: -e['contribution'])


def _standardized(brain, features):
    num = brain.pipeline_.named_steps['pre'].named_transformers_['num']
    scaler = num.named_steps['scale']
    out = {}
    for i, name in enumerate(brain.numeric_):
        value = features.get(name)
        if value is None or (isinstance(value, float) and math.isnan(value)):
            continue
        out[name] = (float(value) - scaler.mean_[i]) / scaler.scale_[i] if scaler.scale_[i] else 0.0
    return out


def event_reasons(brain, directory, employee_id, event, top=4):
    """Sentences for one stored event (row from views.employee_events)."""
    features = json.loads(event['features']) if isinstance(event.get('features'), str) else (event.get('features') or {})
    z = _standardized(brain, features)
    base = getattr(brain, 'baseline_', None)
    person = directory.employee(employee_id)
    reasons = []

    def stat(name):
        if base is None or employee_id not in base.continuous_[name].index:
            return None
        return base.continuous_[name].loc[employee_id]

    def add(feature, text):
        reasons.append(dict(feature=feature, label=FEATURE_LABELS.get(feature, feature), text=text,
                            magnitude=abs(z.get(feature, 0.0)), value=features.get(feature)))

    for feature, raw_key, verb in (('emp_bytes_out_z', 'bytes_out', 'sent'), ('emp_bytes_in_z', 'bytes_in', 'received')):
        s, value = stat(feature), features.get(feature)
        if s is not None and value is not None and event.get(raw_key) is not None:
            typical = math.expm1(s['mean'])
            direction = 'more' if value > 0 else 'less'
            add(feature, f"{verb.capitalize()} {_bytes(event[raw_key])} in one event, versus a typical {_bytes(typical)} "
                         f"for this employee: {abs(value):.1f} standard deviations {direction} than their own normal.")
    s, value = stat('emp_response_time_z'), features.get('emp_response_time_z')
    if s is not None and value is not None and event.get('response_ms') is not None:
        add('emp_response_time_z', f"Response time was {event['response_ms']:,.0f} ms against their usual "
                                   f"{math.expm1(s['mean']):,.0f} ms ({value:+.1f} standard deviations).")
    s, value = stat('emp_activity_z'), features.get('emp_activity_z')
    if s is not None and value is not None:
        n = int(event.get('prev_hour') or 0)
        add('emp_activity_z', f"{n} other event{'s' if n != 1 else ''} came from their device in the preceding hour; "
                              f"they normally average {s['mean']:.1f} ({value:+.1f} standard deviations).")
    value = features.get('emp_hour_deviation')
    if base is not None and value is not None and employee_id in base.hour_.index:
        usual = (base.hour_.at[employee_id, 'mean_angle'] % TWO_PI) * 24 / TWO_PI
        spread = base.hour_.at[employee_id, 'std_hours']
        local = datetime.fromtimestamp(event['ts'], timezone.utc).astimezone(_zone(directory))
        add('emp_hour_deviation', f"Active at {local:%H:%M} local time; their activity usually centres on {_clock(usual)} "
                                  f"(spread about {spread:.1f} h), so this is {value:.1f}× their normal spread away.")
    value = features.get('emp_service_rarity')
    service = features.get('destination_service') or event.get('dst_service')
    if base is not None and value is not None and service and employee_id in base.service_prob_.index:
        unseen = base.service_unseen_prob_[employee_id]
        share = float(np.exp(-value))
        count = round(share / unseen - 1)
        text = (f"Accessed {service}, a service they never used during their baseline period." if count <= 0 else
                f"Accessed {service}, which made up only about {share:.0%} of their baseline activity.")
        add('emp_service_rarity', text)
    if features.get('within_assumed_work_hours') == 0 and person:
        add('within_assumed_work_hours', f"Outside their scheduled hours ({person.get('work_start')}–{person.get('work_end')}).")
    if features.get('is_weekend_observed') == 1:
        add('is_weekend_observed', 'On a weekend day.')
    return sorted(reasons, key=lambda r: -r['magnitude'])[:top]


def _share(percentile):
    return 'all observed' if percentile >= 99.95 else f'{percentile:.1f}% of'


def _zone(directory):
    from zoneinfo import ZoneInfo
    return ZoneInfo(directory.timezone)


def explain_employee(brain, directory, risk_row, events):
    """risk_row: row from employee_risk; events: rows from views.employee_events."""
    employee_id = risk_row['employee_id']
    person = directory.employee(employee_id)
    scored = [dict(e) for e in events if e.get('score') is not None]
    if not scored:
        return dict(summary=f'{employee_id} has no scored activity yet.', reasons=[], key_events=[])
    ranked = _contributions(scored, brain.half_life_seconds, float(np.median(brain.calibration_scores_)))
    key = ranked[0]
    percentile = risk_row.get('risk_percentile') or 0.0
    who = f"{employee_id}" + (f" ({person.get('employee_name')}, {person.get('job_title')}, {person.get('department')})" if person else '')
    level = risk_row.get('level', 'low')
    event_pct = float(brain.event_percentile([key['score']])[0])
    when = datetime.fromtimestamp(key['ts'], timezone.utc).astimezone(_zone(directory))
    summary = (f"{who} is at **{level.upper()}** risk. Their recent activity scores {risk_row['risk']:.3f}, higher than "
               f"{_share(percentile)} normal employee activity seen during calibration. "
               f"The event weighing most on this score ({when:%Y-%m-%d %H:%M} local, {key.get('dst_service') or 'unknown service'}) "
               f"is more unusual than {_share(event_pct)} normal events.")
    if level == 'low':
        summary = (f"{who} is at **LOW** risk: recent activity ({risk_row['risk']:.3f}) is within the range of normal "
                   f"employee behaviour (percentile {percentile:.1f}).")
    return dict(summary=summary, reasons=event_reasons(brain, directory, employee_id, key), key_events=ranked[:5],
                caveat='An anomaly score measures deviation from this employee\'s and the organisation\'s learned normal '
                       'behaviour. It requires investigation and is not proof of malicious intent.')
