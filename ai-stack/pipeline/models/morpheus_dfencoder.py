"""NVIDIA Morpheus DFP autoencoder (`dfencoder`) in the inference slot.

This is the point of the registry. Morpheus's Digital Fingerprinting pipeline
is built around `morpheus.models.dfencoder.AutoEncoder` — the same
reconstruction-error idea as `autoencoder.py`, but NVIDIA's production
implementation: GaussRank-scaled inputs, swap noise during training, and
per-feature loss attribution.

What it demonstrates: NVIDIA's own detection model runs in this pipeline with
nothing upstream or downstream changed — same Kafka feed, same windowed
features, same `ai-detections-*` writeback. Morpheus supplies the model; the
ingestion, windowing, storage and dashboard remain this project's. The
alternative (adopting Morpheus's pipeline runtime wholesale) would have
replaced work that is already built and evaluated, and would have left nothing
to compare against.

Environment: `morpheus-core` is a conda package (it links RAPIDS and the MRC
C++ engine, so it cannot be pip-installed). Run the consumer from the conda
env when selecting this model:

    conda activate morpheus
    DETECTOR_MODEL=morpheus_dfencoder python detection_consumer.py

The import is lazy, inside fit_score, so the registry still loads — and the
other two models still work — in the plain venv where Morpheus is absent.

Contract: fit_score(X, contamination) -> (flags, scores), scores mapped so
LOWER = more anomalous, matching IsolationForest and keeping the consumers'
severity() and writeback code model-agnostic.
Evaluation (train-once): fit(X) on normal windows, then score(X) = -(dfencoder
anomaly score) on anything later.
"""
import time

import numpy as np
import pandas as pd


class MorpheusDFEncoderDetector:
    name = "morpheus_dfencoder"
    label = "Morpheus dfencoder (DFP)"

    def __init__(self, epochs=None, batch_size=None, seed=42):
        # dfencoder defaults to batch_size=256; our windows number in the tens,
        # so a batch larger than the dataset would mean one gradient step per
        # epoch. Sized against the data in fit_score instead.
        self.epochs = int(epochs) if epochs else 50
        self.batch_size = batch_size
        self.seed = seed
        self.last_device = None
        self.last_fit_sec = None

    def fit_score(self, X, contamination):
        err = self.fit(X).errors(X)

        # same mapping as autoencoder.py: top `contamination` by reconstruction
        # error are the anomalies, and scores are negated z-scores so that
        # "lower = worse" holds across every model in the registry
        thr = np.quantile(err, 1.0 - contamination)
        flags = np.where(err >= thr, -1, 1)
        z = (err - err.mean()) / (err.std() + 1e-9)
        return flags, np.round(-z, 4)

    def score(self, X):
        """Lower = more anomalous: the negated dfencoder anomaly score."""
        return -self.errors(X)

    def errors(self, X):
        """dfencoder's per-row anomaly score under the fitted model."""
        scores = self._model.get_anomaly_score(_frame(X))
        return np.asarray(_to_numpy(scores), dtype="float64").ravel()

    def fit(self, X):
        import torch
        from morpheus.models.dfencoder import AutoEncoder

        torch.manual_seed(self.seed)
        use_cuda = torch.cuda.is_available()
        device = "cuda" if use_cuda else "cpu"
        self.last_device = (torch.cuda.get_device_name(0) + " (cuda)") if use_cuda else "cpu"

        df = _frame(X)
        n = len(df)

        batch = self.batch_size or max(2, min(256, n))
        model = AutoEncoder(
            encoder_layers=[32, 16],
            decoder_layers=[16, 32],
            activation="relu",
            batch_size=batch,
            eval_batch_size=batch,
            learning_rate=0.01,
            swap_probability=0.15,      # DFP's noise injection, kept at its default
            scaler="standard",
            min_cats=1,                 # no categorical features here
            progress_bar=False,
            verbose=False,
            patience=-1,                # no validation split, so disable early stopping
            device=device,
        )

        t0 = time.perf_counter()
        model.fit(df, epochs=self.epochs)
        if use_cuda:
            torch.cuda.synchronize()    # async kernels: time nothing until they finish
        self.last_fit_sec = round(time.perf_counter() - t0, 3)
        self._model = model
        return self


def _frame(X):
    """dfencoder infers column types from the frame, so it needs real column
    names and float dtypes — an unnamed ndarray is rejected downstream."""
    df = pd.DataFrame(X).astype("float64")
    df.columns = [str(c) for c in df.columns]
    return df


def _to_numpy(scores):
    """dfencoder has returned a tensor, a Series and an ndarray across versions."""
    if hasattr(scores, "detach"):              # torch.Tensor
        return scores.detach().cpu().numpy()
    if hasattr(scores, "to_numpy"):            # pandas / cudf Series
        return scores.to_numpy()
    if hasattr(scores, "get"):                 # cupy
        return scores.get()
    return np.asarray(scores)
