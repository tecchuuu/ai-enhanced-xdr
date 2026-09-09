"""Isolation Forest detector — default occupant of the inference slot.

Wraps the exact behaviour the consumers used before the registry existed, so
the default path is byte-for-byte unchanged (same params, same random_state,
same score_samples convention).
"""
import numpy as np
from sklearn.ensemble import IsolationForest


class IsolationForestDetector:
    name = "isolation_forest"
    label = "IsolationForest"

    def fit_score(self, X, contamination):
        m = IsolationForest(contamination=contamination, random_state=42)
        flags = m.fit_predict(X)                      # -1 anomaly / 1 normal
        scores = np.round(m.score_samples(X), 4)      # lower = more anomalous
        return flags, scores
