"""Load the Behavioral Intelligence workbook with strict training/evaluation separation.

`load_events` returns model features plus attribution context (time, employee,
device) only. Labels live in a separate loader, `load_evaluation_labels`, which
training code never calls.
"""
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from .schema import DATASET_FEATURES as BASE_FEATURES

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET = ROOT / 'data' / 'Behavioral_Intelligence_Dataset_INTERNAL_ATTACKS_6_CLEANED.xlsx'


@dataclass
class Events:
    all_events: pd.DataFrame        # every Model_Features row + context, no labels
    normal_training: pd.DataFrame   # Normal_Behavior_Learning rows + context, no labels


def _sheet(path, name, usecols=None):
    return pd.read_excel(path, sheet_name=name, usecols=usecols)


def load_events(path=DEFAULT_DATASET):
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f'Dataset not found: {path}')
    features = _sheet(path, 'Model_Features')
    row_index = _sheet(path, 'Feature_Row_Index')
    normal = _sheet(path, 'Normal_Behavior_Learning')
    normal_index = _sheet(path, 'Normal_Learning_Row_Index')
    # Mapping is read for time and source address only: these attribute an event to
    # a device/employee the same way a live collector would (source IP -> device).
    mapping = _sheet(path, 'Feature_Entity_Mapping', ['feature_row_id', 'timestamp_riyadh', 'source_ip'])
    devices = _sheet(path, 'Device_Profiles', ['device_id', 'employee_id', 'source_ip'])

    if list(features.columns) != list(BASE_FEATURES) and set(features.columns) != set(BASE_FEATURES):
        raise ValueError(f'Unexpected Model_Features schema: {list(features.columns)}')
    if set(normal.columns) != set(BASE_FEATURES):
        raise ValueError(f'Unexpected Normal_Behavior_Learning schema: {list(normal.columns)}')
    if len(row_index) != len(features) or not row_index.model_row_index.eq(pd.RangeIndex(1, len(features) + 1)).all():
        raise ValueError('Feature_Row_Index is not aligned with Model_Features')
    if len(normal_index) != len(normal) or not normal_index.normal_training_row_index.eq(pd.RangeIndex(1, len(normal) + 1)).all():
        raise ValueError('Normal_Learning_Row_Index is not aligned with Normal_Behavior_Learning')
    if devices.source_ip.duplicated().any():
        raise ValueError('Device source IPs are not unique; IP attribution would be ambiguous')

    features = features[list(BASE_FEATURES)].copy()
    features.insert(0, 'feature_row_id', row_index.feature_row_id.to_numpy())
    context = mapping.rename(columns={'timestamp_riyadh': 'ts'})
    context['ts'] = pd.to_datetime(context['ts'], utc=True, format='ISO8601')
    context = context.merge(devices, on='source_ip', how='left', validate='many_to_one')
    events = features.merge(context, on='feature_row_id', how='left', validate='one_to_one')
    if events.ts.isna().any():
        raise ValueError('Events without timestamps')

    normal = normal[list(BASE_FEATURES)].copy()
    normal.insert(0, 'feature_row_id', normal_index.feature_row_id.to_numpy())
    # The normal sheet must be an exact subset of Model_Features (same values).
    check = events.set_index('feature_row_id').loc[normal.feature_row_id, list(BASE_FEATURES)].reset_index(drop=True)
    if not check.fillna(-1).equals(normal[list(BASE_FEATURES)].fillna(-1)):
        raise ValueError('Normal_Behavior_Learning differs from the matching Model_Features rows')
    normal = normal.merge(context, on='feature_row_id', how='left', validate='one_to_one')
    return Events(events.sort_values('ts', kind='stable').reset_index(drop=True),
                  normal.sort_values('ts', kind='stable').reset_index(drop=True))


def load_evaluation_labels(path=DEFAULT_DATASET):
    """EVALUATION ONLY. Never pass the result to fitting code."""
    return _sheet(path, 'Ground_Truth_Evaluation', ['feature_row_id', 'label_binary', 'attack_category', 'session_id'])


def load_published_baselines(path=DEFAULT_DATASET):
    return _sheet(path, 'Employee_Behavior_Baselines')


def chronological_split(normal, fractions=(0.70, 0.15)):
    """Split normal rows by time: train / calibration / test. Returns frames and cut times."""
    ordered = normal.sort_values('ts', kind='stable').reset_index(drop=True)
    first = int(len(ordered) * fractions[0])
    second = int(len(ordered) * (fractions[0] + fractions[1]))
    cuts = (ordered.ts.iloc[first], ordered.ts.iloc[second])
    train = ordered[ordered.ts < cuts[0]]
    calibration = ordered[(ordered.ts >= cuts[0]) & (ordered.ts < cuts[1])]
    test = ordered[ordered.ts >= cuts[1]]
    return train, calibration, test, cuts
