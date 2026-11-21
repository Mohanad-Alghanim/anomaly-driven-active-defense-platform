"""Personal deviation features: how far an event is from its own employee's normal behaviour.

Baselines are fitted on normal training rows only. Employees without a baseline get
missing personal features, which the fitted pipeline imputes; no missingness flag is
created (missingness can encode the answer).
"""
import numpy as np
import pandas as pd

from .schema import PERSONAL_FEATURES

TWO_PI = 2 * np.pi
_CONTINUOUS = {
    'emp_bytes_in_z': 'bytes_in_log1p',
    'emp_bytes_out_z': 'bytes_out_log1p',
    'emp_response_time_z': 'response_time_ms_log1p',
    'emp_activity_z': 'source_events_previous_hour',
}


def event_hour(frame):
    """Recover the local hour (0-24) from its cyclical encoding."""
    return (np.arctan2(frame['hour_sin'], frame['hour_cos']) % TWO_PI) * 24 / TWO_PI


class PersonalBaseline:
    """Per-employee normal-behaviour statistics.

    prior_strength: pseudo-observations of the population variance blended into each
    employee's variance (empirical-Bayes shrinkage). It keeps z-scores finite for
    employees whose few training events are identical; it is a smoothing
    hyperparameter, not a detection threshold.
    """

    def __init__(self, prior_strength=5.0):
        self.prior_strength = float(prior_strength)

    def fit(self, normal):
        if normal['employee_id'].isna().all():
            raise ValueError('No attributable normal events to build baselines from')
        data = normal.dropna(subset=['employee_id'])
        k = self.prior_strength
        stats = {}
        for name, column in _CONTINUOUS.items():
            pop_mean = data[column].mean()
            pop_var = data[column].var()
            grouped = data.groupby('employee_id')[column]
            n = grouped.count()
            mean = grouped.mean()
            var = grouped.var().fillna(0.0)
            shrunk_mean = (n * mean.fillna(pop_mean) + k * pop_mean) / (n + k)
            shrunk_var = ((n - 1).clip(lower=0) * var + k * pop_var) / ((n - 1).clip(lower=0) + k)
            stats[name] = pd.DataFrame({'mean': shrunk_mean, 'std': np.sqrt(shrunk_var)})
        self.continuous_ = stats

        angle = event_hour(data) * TWO_PI / 24
        trig = pd.DataFrame({'employee_id': data['employee_id'], 's': np.sin(angle), 'c': np.cos(angle)})
        grouped = trig.groupby('employee_id')
        n = grouped.size()
        pop_r = np.hypot(trig.s.mean(), trig.c.mean())
        pop_circ_var = -2 * np.log(max(pop_r, 1e-12))
        s, c = grouped.s.mean(), grouped.c.mean()
        r = np.hypot(s, c).clip(upper=1 - 1e-12)
        circ_var = -2 * np.log(r)
        circ_var = (n * circ_var + k * pop_circ_var) / (n + k)
        self.hour_ = pd.DataFrame({'mean_angle': np.arctan2(s, c), 'std_hours': np.sqrt(circ_var) * 24 / TWO_PI})

        self.services_ = sorted(data['destination_service'].astype(str).unique())
        counts = pd.crosstab(data['employee_id'], data['destination_service'].astype(str))
        counts = counts.reindex(columns=self.services_, fill_value=0)
        # Laplace smoothing over the known vocabulary plus one slot for unseen services.
        self.service_prob_ = (counts + 1).div(counts.sum(axis=1) + len(self.services_) + 1, axis=0)
        self.service_unseen_prob_ = 1.0 / (counts.sum(axis=1) + len(self.services_) + 1)
        return self

    def transform(self, frame):
        out = pd.DataFrame(index=frame.index, columns=list(PERSONAL_FEATURES), dtype=float)
        employee = frame['employee_id']
        for name, column in _CONTINUOUS.items():
            stats = self.continuous_[name]
            mean = employee.map(stats['mean'])
            std = employee.map(stats['std'])
            out[name] = (frame[column] - mean) / std

        mean_angle = employee.map(self.hour_['mean_angle'])
        std_hours = employee.map(self.hour_['std_hours'])
        angle = event_hour(frame) * TWO_PI / 24
        diff = np.abs(np.angle(np.exp(1j * (angle - mean_angle).to_numpy(dtype=float))))
        out['emp_hour_deviation'] = (diff * 24 / TWO_PI) / std_hours.to_numpy(dtype=float)

        probs = np.full(len(frame), np.nan)
        services = frame['destination_service'].astype(str).to_numpy()
        employees = employee.to_numpy()
        known = set(self.service_prob_.index)
        for i, (emp, service) in enumerate(zip(employees, services)):
            if emp in known:
                probs[i] = self.service_prob_.at[emp, service] if service in self.service_prob_.columns else self.service_unseen_prob_[emp]
        out['emp_service_rarity'] = -np.log(probs)
        return out
