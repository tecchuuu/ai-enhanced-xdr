"""Isolation Forest detector — default occupant of the inference slot.

Wraps the exact behaviour the consumers used before the registry existed, so
the default path is byte-for-byte unchanged (same params, same random_state,
same score_samples convention).

Two ways to use it (see the registry docstring):
  fit_score(X, contamination)  live: refit on the rolling buffer every cycle
  fit(X) then score(X)         evaluation: fit once on normal data, score later
"""
import numpy as np
from sklearn.ensemble import IsolationForest


class IsolationForestDetector:
    name = "isolation_forest"
    label = "IsolationForest"

    def __init__(self, seed=42):
        self.seed = seed
        self._model = None

    def fit_score(self, X, contamination):
        m = IsolationForest(contamination=contamination, random_state=self.seed)
        flags = m.fit_predict(X)                      # -1 anomaly / 1 normal
        scores = np.round(m.score_samples(X), 4)      # lower = more anomalous
        return flags, scores

    def fit(self, X):
        # contamination only moves predict()'s cutoff; score_samples ignores it,
        # and in this mode the threshold is chosen by the evaluation instead
        self._model = IsolationForest(random_state=self.seed).fit(X)
        return self

    def score(self, X):
        """Lower = more anomalous, same convention as fit_score."""
        return self._model.score_samples(X)
