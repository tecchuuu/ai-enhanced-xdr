"""Swappable detector registry — the pipeline's inference slot.

Every detector implements the same contract:

    fit_score(X, contamination) -> (flags, scores)
        flags:  array of -1 (anomaly) / 1 (normal)
        scores: array of floats, LOWER = more anomalous
        The live consumers' mode: refit on the rolling buffer every cycle.
    fit(X) -> self, then score(X) -> scores (LOWER = more anomalous)
        The evaluation's mode (scripts/evaluate.py): fit once on normal
        windows, score later windows against it, threshold chosen outside.
    .name  : registry key
    .label : human name written into the detection document (ai.model)

Both consumers pick their model by name at startup:

    from models import get_model
    model = get_model(os.environ.get("DETECTOR_MODEL", "isolation_forest"))

So swapping Isolation Forest <-> autoencoder is a config change
(DETECTOR_MODEL in dashboard/.env), not a code edit. Adding a new model is one new
file here + one registry entry — nothing in the consumers changes. Done for
real with Morpheus's dfencoder (2026-10-10), which is why there are three
entries and no consumer diff. This is ROADMAP rule 2.

Each model's heavy dependency is imported lazily inside its own fit_score, so
the registry loads everywhere: Isolation Forest needs only scikit-learn, the
autoencoder needs torch, and morpheus_dfencoder needs the Morpheus conda env.
Selecting a model you have no environment for fails at fit time with a plain
ImportError, not at import of the registry.
"""
from .isolation_forest import IsolationForestDetector
from .autoencoder import AutoencoderDetector
from .morpheus_dfencoder import MorpheusDFEncoderDetector

_REGISTRY = {
    "isolation_forest": IsolationForestDetector,
    "autoencoder": AutoencoderDetector,
    "morpheus_dfencoder": MorpheusDFEncoderDetector,
}

def get_model(name, **kwargs):
    key = (name or "isolation_forest").strip().lower()
    if key not in _REGISTRY:
        raise ValueError(
            f"unknown DETECTOR_MODEL '{name}'; choices: {sorted(_REGISTRY)}")
    return _REGISTRY[key](**kwargs)

def available():
    return sorted(_REGISTRY)
