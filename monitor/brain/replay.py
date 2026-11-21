"""Convert workbook events back into raw collector telemetry (JSONL), without labels.

Used for (1) the live-feature parity check: deriving features from raw telemetry
must reproduce Model_Features for normal events, and (2) replaying a window through
the live collector and dashboard.

    python -m monitor.brain.replay --out runtime/replay.jsonl [--since ISO] [--until ISO]
"""
import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .dataset import DEFAULT_DATASET
from .schema import DATASET_FEATURES
from .telemetry import count_previous_hour, derive_features
from .risk import epoch_seconds


def raw_events(path=DEFAULT_DATASET):
    """One raw telemetry record per Model_Features row. Never reads Ground_Truth_Evaluation."""
    features = pd.read_excel(path, sheet_name='Model_Features')
    features.insert(0, 'feature_row_id', pd.read_excel(path, sheet_name='Feature_Row_Index').feature_row_id.to_numpy())
    mapping = pd.read_excel(path, sheet_name='Feature_Entity_Mapping', usecols=['feature_row_id', 'timestamp_riyadh', 'source_ip', 'destination_ip'])
    sequence = pd.read_excel(path, sheet_name='Sequential_Behavior', usecols=['feature_row_id', 'bytes_in', 'bytes_out'])
    raw = features.merge(mapping, on='feature_row_id', validate='one_to_one').merge(sequence, on='feature_row_id', validate='one_to_one')
    raw['ts'] = epoch_seconds(pd.to_datetime(raw.timestamp_riyadh, format='ISO8601', utc=True))
    raw['response_time_ms'] = np.expm1(raw.response_time_ms_log1p)
    columns = ['feature_row_id', 'ts', 'source_ip', 'destination_ip', 'destination_port', 'protocol',
               'destination_service', 'bytes_in', 'bytes_out', 'response_time_ms']
    return raw[columns].sort_values('ts', kind='stable').reset_index(drop=True), features


def live_features(raw, directory):
    frame = raw.copy()
    frame['employee_id'] = [directory.attribute(ip)[0] for ip in frame.source_ip]
    frame['source_events_previous_hour'] = count_previous_hour(frame)
    return derive_features(frame, directory), frame['employee_id']


def parity(raw, features, directory, normal_ids):
    """Max absolute difference between live-derived and workbook features on normal rows."""
    derived, _ = live_features(raw, directory)
    derived.index = raw.feature_row_id
    reference = features.set_index('feature_row_id').loc[derived.index, list(DATASET_FEATURES)]
    rows = derived.index.isin(normal_ids)
    report = {}
    for column in DATASET_FEATURES:
        a, b = derived.loc[rows, column], reference.loc[rows, column]
        if not (pd.api.types.is_numeric_dtype(a) and pd.api.types.is_numeric_dtype(b)):
            report[column] = float((a.astype(str) != b.astype(str)).mean())
        else:
            diff = (a.astype(float) - b.astype(float)).abs()
            both_missing = a.isna() & b.isna()
            report[column] = float(diff[~both_missing].fillna(np.inf).max()) if (~both_missing).any() else 0.0
    return report


def to_jsonl(raw, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w') as handle:
        for record in raw.drop(columns=['feature_row_id'], errors='ignore').to_dict('records'):
            record = {k: (None if isinstance(v, float) and np.isnan(v) else v) for k, v in record.items()}
            record['destination_port'] = int(record['destination_port'])
            record['bytes_in'], record['bytes_out'] = int(record['bytes_in']), int(record['bytes_out'])
            record['kind'] = 'network_activity'
            record['message'] = f"{record['destination_service']} {record['protocol']}/{record['destination_port']}"
            handle.write(json.dumps(record) + '\n')
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--dataset', default=str(DEFAULT_DATASET))
    parser.add_argument('--out', required=True)
    parser.add_argument('--since')
    parser.add_argument('--until')
    args = parser.parse_args(argv)
    raw, _ = raw_events(args.dataset)
    if args.since:
        raw = raw[raw.ts >= pd.Timestamp(args.since).timestamp()]
    if args.until:
        raw = raw[raw.ts < pd.Timestamp(args.until).timestamp()]
    print('wrote', len(raw), 'events to', to_jsonl(raw, args.out))


if __name__ == '__main__':
    main()

