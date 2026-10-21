"""Autoencoder detector (PyTorch) — the model NVIDIA Morpheus DFP wraps.

Learns to reconstruct "normal" feature vectors; a large reconstruction error
means the window does not look like what the model learned -> anomaly. This is
the proof-of-method for the DFP approach.

Device-aware: uses CUDA when present (the SIAM H100) and CPU otherwise (local
dev) — the SAME file runs in both, picking up the GPU automatically. On SIAM,
Morpheus's own dfencoder can occupy this same registry slot under this contract.

torch is imported lazily inside fit, so the registry still loads — and
Isolation Forest still works — on a box where torch is not installed.

Contract: fit_score(X, contamination) -> (flags, scores)
  scores mapped so LOWER = more anomalous (matches IsolationForest), keeping the
  consumers' severity()/writeback code model-agnostic.
Evaluation (train-once): fit(X) on normal windows, then score(X) = -(reconstruction
  error) on anything later; the scaler is fitted on the training windows only.
"""
import time

import numpy as np
from sklearn.preprocessing import StandardScaler


class AutoencoderDetector:
    name = "autoencoder"
    label = "Autoencoder"

    def __init__(self, epochs=300, lr=1e-2, seed=42):
        self.epochs = epochs
        self.lr = lr
        self.seed = seed
        self.last_device = None   # set by fit_score: "cuda:0" / "cpu" (evidence for the report)
        self.last_fit_sec = None

    def fit_score(self, X, contamination):
        err = self.fit(X).errors(X)
        thr = np.quantile(err, 1.0 - contamination)     # top fraction = anomalies
        flags = np.where(err >= thr, -1, 1)
        z = (err - err.mean()) / (err.std() + 1e-9)
        scores = np.round(-z, 4)                          # negate: lower = worse
        return flags, scores

    def score(self, X):
        """Lower = more anomalous: the negated reconstruction error."""
        return -self.errors(X)

    def errors(self, X):
        """Per-window reconstruction error under the fitted scaler and network."""
        import torch

        t = self._tensor(self._scaler.transform(_as_2d(X)))
        self._model.eval()
        with torch.no_grad():
            return ((self._model(t) - t) ** 2).mean(dim=1).cpu().numpy()

    def _tensor(self, Xs):
        import torch
        return torch.from_numpy(Xs.astype(np.float32)).to(self._device)

    def fit(self, X):
        import torch
        from torch import nn

        torch.manual_seed(self.seed)
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self._device = device

        self.last_device = (torch.cuda.get_device_name(0) + " (cuda)"
                            if device.type == "cuda" else "cpu")

        Xv = _as_2d(X)
        n, d = Xv.shape
        self._scaler = StandardScaler().fit(Xv)
        t = self._tensor(self._scaler.transform(Xv))

        hidden = max(2, d // 2)
        latent = max(1, hidden // 2)
        model = nn.Sequential(
            nn.Linear(d, hidden), nn.ReLU(),
            nn.Linear(hidden, latent), nn.ReLU(),
            nn.Linear(latent, hidden), nn.ReLU(),
            nn.Linear(hidden, d),
        ).to(device)

        t0 = time.perf_counter()
        opt = torch.optim.Adam(model.parameters(), lr=self.lr)
        loss_fn = nn.MSELoss()
        model.train()
        for _ in range(self.epochs):
            opt.zero_grad()
            loss = loss_fn(model(t), t)
            loss.backward()
            opt.step()

        if device.type == "cuda":
            torch.cuda.synchronize()          # async kernels: time nothing until they finish
        self.last_fit_sec = round(time.perf_counter() - t0, 3)
        self._model = model
        return self


def _as_2d(X):
    Xv = np.asarray(X, dtype=np.float32)
    return Xv.reshape(-1, 1) if Xv.ndim == 1 else Xv
