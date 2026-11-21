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

    Fitted state is stored as plain Python containers and numpy arrays only (no pandas
    objects), so the pickled model loads across pandas versions:
      employees_            list of employee ids; row i of every array below
      continuous_[name]     {'mean': array, 'std': array}
      hour_                 {'mean_angle': array, 'std_hours': array}
      services_             list of service names; columns of service_prob_
      service_prob_         array (employees x services)
      service_unseen_prob_  array (employees)
    """

    def __init__(self, prior_strength=5.0):
        self.prior_strength = float(prior_strength)

    def fit(self, normal):
        if normal['employee_id'].isna().all():
            raise ValueError('No attributable normal events to build baselines from')
        data = normal.dropna(subset=['employee_id'])
        k = self.prior_strength
        employees = sorted(str(e) for e in data['employee_id'].unique())
        employee_key = data['employee_id'].astype(str).astype(object)

        def array(series):
            return np.asarray(series.reindex(employees).to_numpy(dtype=float), dtype=float)

        stats = {}
        for name, column in _CONTINUOUS.items():
            values = data[column].astype(float)
            pop_mean = float(values.mean())
            pop_var = float(values.var())
            grouped = values.groupby(employee_key)
            n = array(grouped.count())
            mean = array(grouped.mean())
            var = np.nan_to_num(array(grouped.var()), nan=0.0)
            mean = np.where(np.isnan(mean), pop_mean, mean)
            dof = np.clip(n - 1, 0, None)
            shrunk_mean = (n * mean + k * pop_mean) / (n + k)
            shrunk_var = (dof * var + k * pop_var) / (dof + k)
            stats[name] = {'mean': shrunk_mean, 'std': np.sqrt(shrunk_var)}
        self.continuous_ = stats

        angle = event_hour(data).to_numpy(dtype=float) * TWO_PI / 24
        trig = pd.DataFrame({'s': np.sin(angle), 'c': np.cos(angle)}, index=data.index)
        grouped = trig.groupby(employee_key)
        n = array(grouped.size())
        pop_r = np.hypot(trig.s.mean(), trig.c.mean())
        pop_circ_var = -2 * np.log(max(pop_r, 1e-12))
        s, c = array(grouped.s.mean()), array(grouped.c.mean())
        r = np.clip(np.hypot(s, c), None, 1 - 1e-12)
        circ_var = (n * (-2 * np.log(r)) + k * pop_circ_var) / (n + k)
        self.hour_ = {'mean_angle': np.arctan2(s, c), 'std_hours': np.sqrt(circ_var) * 24 / TWO_PI}

        self.services_ = sorted(str(v) for v in data['destination_service'].astype(str).unique())
        counts = pd.crosstab(employee_key, data['destination_service'].astype(str).astype(object))
        counts = counts.reindex(index=employees, columns=self.services_, fill_value=0).to_numpy(dtype=float)
        # Laplace smoothing over the known vocabulary plus one slot for unseen services.
        denominator = counts.sum(axis=1) + len(self.services_) + 1
        self.service_prob_ = (counts + 1) / denominator[:, None]
        self.service_unseen_prob_ = 1.0 / denominator
        self.employees_ = employees
        self._index()
        return self

    # ------------------------------------------------------------------ lookup
    def _index(self):
        self.index_ = {e: i for i, e in enumerate(self.employees_)}
        self.service_index_ = {s: j for j, s in enumerate(self.services_)}

    def __setstate__(self, state):
        self.__dict__.update(state)
        if 'index_' not in state and 'employees_' in state:
            self._index()

    def knows(self, employee_id):
        return employee_id is not None and str(employee_id) in self.index_

    def stat(self, name, employee_id):
        """{'mean', 'std'} of a continuous personal feature for one employee, or None."""
        if not self.knows(employee_id):
            return None
        i = self.index_[str(employee_id)]
        return {'mean': float(self.continuous_[name]['mean'][i]), 'std': float(self.continuous_[name]['std'][i])}

    def hour(self, employee_id):
        """(mean_angle, std_hours) of the employee's usual activity time, or None."""
        if not self.knows(employee_id):
            return None
        i = self.index_[str(employee_id)]
        return float(self.hour_['mean_angle'][i]), float(self.hour_['std_hours'][i])

    def service_probability(self, employee_id, service):
        if not self.knows(employee_id):
            return None
        i = self.index_[str(employee_id)]
        j = self.service_index_.get(str(service))
        return float(self.service_unseen_prob_[i] if j is None else self.service_prob_[i, j])

    def unseen_service_probability(self, employee_id):
        return float(self.service_unseen_prob_[self.index_[str(employee_id)]]) if self.knows(employee_id) else None

    def _rows(self, frame):
        """Baseline row per event (-1 for employees without a baseline)."""
        return np.fromiter((self.index_.get(str(e), -1) if isinstance(e, str) else -1 for e in frame['employee_id']),
                           dtype=np.int64, count=len(frame))

    @staticmethod
    def _gather(values, rows):
        return np.where(rows >= 0, values[np.clip(rows, 0, None)], np.nan)

    def transform(self, frame):
        out = pd.DataFrame(index=frame.index, columns=list(PERSONAL_FEATURES), dtype=float)
        rows = self._rows(frame)
        for name, column in _CONTINUOUS.items():
            stats = self.continuous_[name]
            mean, std = self._gather(stats['mean'], rows), self._gather(stats['std'], rows)
            out[name] = (frame[column].to_numpy(dtype=float) - mean) / std

        mean_angle = self._gather(self.hour_['mean_angle'], rows)
        std_hours = self._gather(self.hour_['std_hours'], rows)
        angle = event_hour(frame).to_numpy(dtype=float) * TWO_PI / 24
        diff = np.abs(np.angle(np.exp(1j * (angle - mean_angle))))
        out['emp_hour_deviation'] = (diff * 24 / TWO_PI) / std_hours

        services = np.fromiter((self.service_index_.get(str(s), -1) for s in frame['destination_service']),
                               dtype=np.int64, count=len(frame))
        safe = np.clip(rows, 0, None)
        probs = np.where(services >= 0, self.service_prob_[safe, np.clip(services, 0, None)], self.service_unseen_prob_[safe])
        probs = np.where(rows >= 0, probs, np.nan)
        out['emp_service_rarity'] = -np.log(probs)
        return out
