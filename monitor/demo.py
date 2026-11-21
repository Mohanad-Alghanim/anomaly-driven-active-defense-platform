"""Demonstration telemetry: an unlabelled replay of held-out dataset events.

samples/behavioral_demo.jsonl holds 48 hours of synthetic organisation activity
(exported by monitor.brain.train, without labels). Timestamps are shifted by whole
weeks so the replay ends near now while every event keeps its weekday and local time.
"""
import json
from pathlib import Path

from .core import now

SAMPLE = Path(__file__).resolve().parents[1] / 'samples' / 'behavioral_demo.jsonl'
WEEK = 7 * 86400


def events(base=None, path=SAMPLE):
    records = [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]
    if not records:
        return []
    target = base if base is not None else now()
    latest = max(r['ts'] for r in records)
    shift = ((target - latest) // WEEK) * WEEK
    for r in records:
        r['ts'] = r['ts'] + shift
        r['source'] = 'DEMO'
    return records
