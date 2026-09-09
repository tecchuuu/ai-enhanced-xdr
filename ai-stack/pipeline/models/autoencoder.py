"""Autoencoder detector (PyTorch) — the model NVIDIA Morpheus DFP wraps.

Learns to reconstruct "normal" feature vectors; a large reconstruction error
means the window does not look like what the model learned -> anomaly. This is
the proof-of-method for the DFP approach.

Device-aware: uses CUDA when present (the SIAM H100) and CPU otherwise (local
dev) — the SAME file runs in both, picking up the GPU automatically. On SIAM,
Morpheus's own dfencoder can occupy this same registry slot under this contract.

torch is imported lazily inside fit_score, so the registry still loads — and
Isolation Forest still works — on a box where torch is not installed.

Contract: fit_score(X, contamination) -> (flags, scores)
  scores mapped so LOWER = more anomalous (matches IsolationForest), keeping the
  consumers' severity()/writeback code model-agnostic.
"""
import numpy as np
from sklearn.preprocessing import StandardScaler


class AutoencoderDetector:
    name = "autoencoder"
    label = "Autoencoder"

    def __init__(self, epochs=300, lr=1e-2, seed=42):
        self.epochs = epochs
        self.lr = lr
        self.seed = seed

    def fit_score(self, X, contamination):
        import torch
        from torch import nn

        torch.manual_seed(self.seed)
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        Xv = np.asarray(X, dtype=np.float32)
        if Xv.ndim == 1:
            Xv = Xv.reshape(-1, 1)
        n, d = Xv.shape
        Xs = StandardScaler().fit_transform(Xv).astype(np.float32)
        t = torch.from_numpy(Xs).to(device)

        hidden = max(2, d // 2)
        latent = max(1, hidden // 2)
        model = nn.Sequential(
            nn.Linear(d, hidden), nn.ReLU(),
            nn.Linear(hidden, latent), nn.ReLU(),
            nn.Linear(latent, hidden), nn.ReLU(),
            nn.Linear(hidden, d),
        ).to(device)

        opt = torch.optim.Adam(model.parameters(), lr=self.lr)
        loss_fn = nn.MSELoss()
        model.train()
        for _ in range(self.epochs):
            opt.zero_grad()
            loss = loss_fn(model(t), t)
            loss.backward()
            opt.step()

        model.eval()
        with torch.no_grad():
            err = ((model(t) - t) ** 2).mean(dim=1).cpu().numpy()

        thr = np.quantile(err, 1.0 - contamination)     # top fraction = anomalies
        flags = np.where(err >= thr, -1, 1)
        z = (err - err.mean()) / (err.std() + 1e-9)
        scores = np.round(-z, 4)                          # negate: lower = worse
        return flags, scores
