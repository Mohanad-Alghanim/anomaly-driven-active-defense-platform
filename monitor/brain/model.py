"""Isolation Forest brain: event anomaly scores, data-derived levels, employee risk.

Workflow (all fitting uses normal behaviour only):
  1. fit(normal_train)         -> personal baselines + preprocessing + IsolationForest
  2. calibrate(normal_holdout) -> score distribution of independent normal events;
                                  level boundaries are quantiles of that distribution
  3. score_events / employee_risk for any new events
"""
from dataclasses import dataclass, field

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from .features import PersonalBaseline
from .risk import rolling_risk
from .schema import BASE_CATEGORICAL, BASE_NUMERIC, PERSONAL_FEATURES, assert_no_leakage

LEVELS = ('low', 'medium', 'high')


@dataclass(frozen=True)
class LevelPolicy:
    """Alert budgets expressed as false-positive rates on independent normal behaviour.

    These are not attack thresholds: they state how many normal events per hundred
    the analyst accepts at each level. The actual score boundaries are the
    corresponding quantiles of the calibration score distribution, so they move
    with the data. 'high' = above the 99th percentile of normal (1% FPR budget).
    """
    medium_fpr: float = 0.05
    high_fpr: float = 0.01

    def __post_init__(self):
        if not 0 < self.high_fpr < self.medium_fpr < 1:
            raise ValueError('Require 0 < high_fpr < medium_fpr < 1')


@dataclass
class InsiderThreatBrain:
    use_personal: bool = True
    exclude: tuple = ()                     # feature names to drop (used for ablation studies)
    n_estimators: int = 300
    random_state: int = 42
    # Rolling employee risk half-life: how quickly past events fade. An aggregation
    # time constant, not a detection threshold; levels come from calibration.
    risk_half_life_hours: float = 24.0
    policy: LevelPolicy = field(default_factory=LevelPolicy)

    # ------------------------------------------------------------------ features
    @property
    def numeric_(self):
        names = list(BASE_NUMERIC) + (list(PERSONAL_FEATURES) if self.use_personal else [])
        return [n for n in names if n not in self.exclude]

    @property
    def categorical_(self):
        return [n for n in BASE_CATEGORICAL if n not in self.exclude]

    @property
    def feature_names(self):
        return self.numeric_ + self.categorical_

    def matrix(self, events):
        """Build the model matrix. Only approved feature columns survive."""
        frame = events[[c for c in (*BASE_NUMERIC, *BASE_CATEGORICAL)]].copy()
        if self.use_personal:
            frame = pd.concat([frame, self.baseline_.transform(events)], axis=1)
        frame = frame[self.feature_names]
        assert_no_leakage(frame.columns)
        for column in self.categorical_:
            frame[column] = frame[column].astype(str)
        return frame

    # ------------------------------------------------------------------ fitting
    def fit(self, normal_train):
        if 'label_binary' in normal_train.columns or 'attack_category' in normal_train.columns:
            raise ValueError('Training frame carries evaluation labels; refusing to fit')
        if self.use_personal:
            self.baseline_ = PersonalBaseline().fit(normal_train)
        X = self.matrix(normal_train)
        pre = ColumnTransformer([
            ('num', Pipeline([('impute', SimpleImputer(strategy='median')), ('scale', StandardScaler())]), self.numeric_),
            ('cat', Pipeline([('impute', SimpleImputer(strategy='most_frequent')),
                              ('onehot', OneHotEncoder(handle_unknown='ignore', sparse_output=False))]), self.categorical_),
        ])
        self.pipeline_ = Pipeline([
            ('pre', pre),
            ('forest', IsolationForest(n_estimators=self.n_estimators, random_state=self.random_state, n_jobs=-1)),
        ])
        self.pipeline_.fit(X)
        self.training_rows_ = len(X)
        return self

    def score_events(self, events):
        """Continuous anomaly score per event: higher = less like normal behaviour."""
        return -self.pipeline_.score_samples(self.matrix(events))

    # ------------------------------------------------------------------ calibration
    def calibrate(self, normal_holdout):
        """Derive event and employee level boundaries from independent normal events."""
        raw = self.score_events(normal_holdout)
        self.calibration_scores_ = np.sort(raw)
        self.boundaries_ = self._boundaries(self.calibration_scores_)
        # Employee boundaries: the same rolling aggregation, replayed over normal
        # employees, gives the distribution of normal employee risk.
        risk = rolling_risk(normal_holdout.assign(score=raw), self.half_life_seconds)
        self.employee_calibration_ = np.sort(risk.dropna().to_numpy())
        self.employee_boundaries_ = self._boundaries(self.employee_calibration_)
        return self

    def _boundaries(self, sorted_values):
        return {'medium': float(np.quantile(sorted_values, 1 - self.policy.medium_fpr)),
                'high': float(np.quantile(sorted_values, 1 - self.policy.high_fpr))}

    @property
    def half_life_seconds(self):
        return self.risk_half_life_hours * 3600.0

    def tail_probability(self, scores):
        """Share of independent normal events scoring at least this high (add-one smoothed)."""
        ref = self.calibration_scores_
        above = len(ref) - np.searchsorted(ref, np.asarray(scores, dtype=float), side='left')
        return (above + 1) / (len(ref) + 1)

    @staticmethod
    def _percentile(sorted_reference, values):
        return 100 * np.searchsorted(sorted_reference, np.asarray(values, dtype=float), side='right') / len(sorted_reference)

    def event_percentile(self, scores):
        """Percent of independent normal events scoring at or below these scores."""
        return self._percentile(self.calibration_scores_, scores)

    def employee_percentile(self, risk):
        return self._percentile(self.employee_calibration_, risk)

    @staticmethod
    def _level(values, boundaries):
        values = np.asarray(values, dtype=float)
        return np.where(values >= boundaries['high'], 'high', np.where(values >= boundaries['medium'], 'medium', 'low'))

    def event_levels(self, scores):
        return self._level(scores, self.boundaries_)

    def employee_levels(self, risk):
        return self._level(risk, self.employee_boundaries_)

    # ------------------------------------------------------------------ employees
    def employee_risk(self, events, scores=None):
        """Current rolling risk per employee at the end of `events`, ranked highest first.

        Ranking uses only the aggregated anomaly scores. Event counts are reported
        as context and never used for ordering.
        """
        scored = events.assign(score=self.score_events(events) if scores is None else scores)
        scored['risk'] = rolling_risk(scored, self.half_life_seconds)
        scored = scored.dropna(subset=['employee_id']).sort_values('ts', kind='stable')
        grouped = scored.groupby('employee_id')
        table = pd.DataFrame({
            'risk': grouped['risk'].last(),
            'peak_risk': grouped['risk'].max(),
            'last_activity': grouped['ts'].max(),
            'max_event_score': grouped['score'].max(),
            'events': grouped.size(),
            'high_events': grouped['score'].apply(lambda s: int((s >= self.boundaries_['high']).sum())),
        })
        table['level'] = self.employee_levels(table['risk'])
        table['risk_percentile'] = self.employee_percentile(table['risk'])
        return table.sort_values('risk', ascending=False).reset_index()

    # ------------------------------------------------------------------ explanation
    def explain(self, events, top=3):
        """Largest standardized deviations from normal training behaviour, per event.

        Numeric features are expressed in training standard deviations; categorical
        values never seen in normal training are reported as 'unseen'.
        """
        X = self.matrix(events)
        pre = self.pipeline_.named_steps['pre']
        num = pre.named_transformers_['num']
        z = pd.DataFrame(num.transform(X[self.numeric_]), columns=self.numeric_, index=X.index)
        onehot = pre.named_transformers_['cat'].named_steps['onehot']
        seen = {c: set(v) for c, v in zip(self.categorical_, onehot.categories_)}
        reasons = []
        for i in X.index:
            row = [(abs(z.at[i, c]), f'{c} {z.at[i, c]:+.1f} sd from normal') for c in self.numeric_]
            row += [(np.inf, f'{c}={X.at[i, c]} never seen in normal behaviour') for c in self.categorical_ if X.at[i, c] not in seen[c]]
            reasons.append([text for _, text in sorted(row, key=lambda r: -r[0])[:top]])
        return reasons
