"""Rolling employee risk: a time-decayed mean of recent event anomaly scores.

    risk(t) = sum_i w_i * score_i / sum_i w_i,   w_i = 0.5 ** ((t - t_i) / half_life)

Being a weighted *mean*, it does not grow with the number of events: repeating the
same events leaves the risk unchanged, so event count is not a ranking feature.
Recent events dominate; older ones fade with the half-life. The same update is used
for calibration, offline evaluation and the live collector.
"""
from dataclasses import dataclass

import numpy as np
import pandas as pd


@dataclass
class RiskState:
    weighted_sum: float = 0.0
    weight: float = 0.0
    last_ts: float = None

    @property
    def risk(self):
        return self.weighted_sum / self.weight if self.weight else None

    def update(self, ts, score, half_life_seconds):
        ts, score = float(ts), float(score)
        if self.last_ts is None:
            self.weighted_sum, self.weight, self.last_ts = score, 1.0, ts
        elif ts >= self.last_ts:
            decay = 0.5 ** ((ts - self.last_ts) / half_life_seconds)
            self.weighted_sum = self.weighted_sum * decay + score
            self.weight = self.weight * decay + 1.0
            self.last_ts = ts
        else:  # late event: weight it by its age relative to the current state
            decay = 0.5 ** ((self.last_ts - ts) / half_life_seconds)
            self.weighted_sum += score * decay
            self.weight += decay
        return self.risk

    def to_dict(self):
        return dict(weighted_sum=self.weighted_sum, weight=self.weight, last_ts=self.last_ts)


def epoch_seconds(ts):
    ts = pd.to_datetime(ts, utc=True)
    return ((ts - pd.Timestamp('1970-01-01', tz='UTC')) / pd.Timedelta(seconds=1)).to_numpy(dtype=float)


def rolling_risk(frame, half_life_seconds):
    """Risk after each event (aligned with frame.index). Requires employee_id, ts, score."""
    out = pd.Series(np.nan, index=frame.index, dtype=float)
    data = frame.dropna(subset=['employee_id'])
    if data.empty:
        return out
    seconds = pd.Series(epoch_seconds(data['ts']), index=data.index)
    order = seconds.sort_values(kind='stable').index
    states = {}
    for i, emp, t, s in zip(order, data.loc[order, 'employee_id'], seconds.loc[order], data.loc[order, 'score']):
        out.at[i] = states.setdefault(emp, RiskState()).update(t, s, half_life_seconds)
    return out
