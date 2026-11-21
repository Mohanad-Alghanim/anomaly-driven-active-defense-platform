"""Unsupervised insider-threat detection brain.

Learns normal behaviour only, emits a continuous anomaly score per event,
derives risk levels from the normal score distribution and aggregates
event evidence into a risk score per employee over time.

No detection rules, no supervised classifiers, no hand-written attack thresholds.
"""
from .model import InsiderThreatBrain, LevelPolicy  # noqa: F401
from .schema import BASE_FEATURES, PERSONAL_FEATURES, assert_no_leakage  # noqa: F401
