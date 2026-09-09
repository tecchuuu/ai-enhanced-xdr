"""Swappable detector registry — the pipeline's inference slot.

Every detector implements the same contract:

    fit_score(X, contamination) -> (flags, scores)
        flags:  array of -1 (anomaly) / 1 (normal)
        scores: array of floats, LOWER = more anomalous
    .name  : registry key
    .label : human name written into the detection document (ai.model)

Both consumers pick their model by name at startup:

    from models import get_model
    model = get_model(os.environ.get("DETECTOR_MODEL", "isolation_forest"))

So swapping Isolation Forest <-> autoencoder is a config change
(DETECTOR_MODEL in dashboard/.env), not a code edit. Adding a new model
(e.g. Morpheus's dfencoder on the SIAM H100) is one new file here + one
registry entry — nothing in the consumers changes. This is ROADMAP rule 2.
"""
from .isolation_forest import IsolationForestDetector
from .autoencoder import AutoencoderDetector

_REGISTRY = {
    "isolation_forest": IsolationForestDetector,
    "autoencoder": AutoencoderDetector,
}

def get_model(name):
    key = (name or "isolation_forest").strip().lower()
    if key not in _REGISTRY:
        raise ValueError(
            f"unknown DETECTOR_MODEL '{name}'; choices: {sorted(_REGISTRY)}")
    return _REGISTRY[key]()

def available():
    return sorted(_REGISTRY)
