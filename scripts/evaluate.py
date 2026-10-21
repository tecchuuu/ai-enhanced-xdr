#!/usr/bin/env python3
"""Train-once evaluation of the inference-slot models on labelled windows.

The live detectors refit every minute and flag a fixed share (contamination)
of whatever is in their buffer, so they flag ~15% of windows by construction —
fine for triage, meaningless as a measurement. This script measures the models
the defensible way (failure log Entry 36; docs/dataset_selection.md):

  1. Chronological split per scenario: train on the first --train-days (normal
     only), pick thresholds on the next --val-days (normal only), test on the
     rest (the attack day onwards).
  2. Each model is fitted ONCE on the training windows (models' fit/score mode);
     every model's threshold comes from the same rule — a percentile of its own
     scores on the validation day — fixed before the test labels are looked at.
  3. Reported on the test windows: PR-AUC and ROC-AUC (threshold-free), and at
     each operating point recall, precision, F1, false-positive rate, false
     alarms per day, whether the attack was detected at all, time to detect,
     and recall per attack step. No point-adjust.
  4. Baseline: a plain threshold on the window's event count (same rule).
     Ablation: every model again without the `hour` feature.

Input: CSVs from a dataset loader (scripts/ait_windows.py), each with a
<csv>.meta.json giving the simulation window. Models whose environment is
missing (torch for the autoencoder, the Morpheus conda env for dfencoder) are
skipped with a note, so the same command runs anywhere and runs fully in the
morpheus env on the SIAM VM.

    python scripts/evaluate.py results/eval/*_web.csv --out results/eval/web
"""
import argparse
import json
import sys
import time
from datetime import timedelta
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ai-stack" / "pipeline"))
from features import AUTH_FEATURES, WEB_FEATURES  # noqa: E402
from models import get_model  # noqa: E402

LANES = {"web": (WEB_FEATURES, "request_count"), "auth": (AUTH_FEATURES, "event_count")}
COUNT_BASELINE = "count_threshold"


def load(csv):
    meta = json.loads(Path(str(csv) + ".meta.json").read_text(encoding="utf-8"))
    df = pd.read_csv(csv)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    df["steps"] = df["steps"].fillna("")
    return df, meta


def split(df, meta, train_days, val_days):
    start = pd.Timestamp(meta["sim_start"])
    end = pd.Timestamp(meta["sim_end"])
    t_val = start + timedelta(days=train_days)
    t_test = t_val + timedelta(days=val_days)
    part = np.where(df.timestamp < t_val, "train", np.where(df.timestamp < t_test, "val", "test"))
    df = df.assign(split=part)
    leaked = df[(df.split != "test") & (df.label == 1)]
    if len(leaked):
        print(f"  ! {meta['scenario']}: {len(leaked)} attack windows before the test period — "
              f"dropped from training/validation")
        df = df.drop(leaked.index)
    test_days = (end - t_test) / timedelta(days=1)
    return df, test_days


def anomaly_scores(name, seed, tr, va, te, feats, count_col):
    """Higher = more anomalous. Returns (val, test, info) or None if unavailable."""
    if name == COUNT_BASELINE:
        return va[count_col].to_numpy(float), te[count_col].to_numpy(float), {"fit_sec": 0.0, "device": "-"}
    model = get_model(name, seed=seed)
    t0 = time.perf_counter()
    try:
        model.fit(tr[feats])
    except ImportError as e:
        return None, None, {"skip": f"{e.__class__.__name__}: {e}"}
    fit_sec = time.perf_counter() - t0
    info = {"fit_sec": round(fit_sec, 3), "device": getattr(model, "last_device", None) or "cpu"}
    return -np.asarray(model.score(va[feats])), -np.asarray(model.score(te[feats])), info


def at_threshold(y, a, thr, test_days, ts, steps):
    flag = a > thr
    tp = int((flag & (y == 1)).sum()); fp = int((flag & (y == 0)).sum())
    fn = int((~flag & (y == 1)).sum()); tn = int((~flag & (y == 0)).sum())
    precision = tp / (tp + fp) if tp + fp else float("nan")
    recall = tp / (tp + fn) if tp + fn else float("nan")
    f1 = 2 * precision * recall / (precision + recall) if tp else 0.0
    first_attack = ts[y == 1].min() if (y == 1).any() else None
    hits = ts[flag & (y == 1)]
    ttd = (hits.min() - first_attack) / timedelta(minutes=1) if len(hits) else float("nan")
    per_step = {}
    for i in np.flatnonzero(y == 1):
        for s in filter(None, steps[i].split(";")):
            n, c = per_step.get(s, (0, 0))
            per_step[s] = (n + 1, c + int(flag[i]))
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision, "recall": recall,
            "f1": f1, "fpr": fp / (fp + tn) if fp + tn else float("nan"),
            "fp_per_day": fp / test_days, "detected": int(tp > 0), "ttd_min": ttd}, per_step


def evaluate(csvs, models, seeds, percentiles, ablate, train_days, val_days):
    metrics, step_rows, score_rows = [], [], []
    for csv in csvs:
        df, meta = load(csv)
        lane = meta["lane"]
        feats_all, count_col = LANES[lane]
        df, test_days = split(df, meta, train_days, val_days)
        tr, va, te = (df[df.split == s].reset_index(drop=True) for s in ("train", "val", "test"))
        y = te.label.to_numpy()
        print(f"{meta['scenario']} [{lane}]: train {len(tr)} / val {len(va)} / test {len(te)} windows, "
              f"{int(y.sum())} attack windows, test span {test_days:.2f} days")
        configs = {"all": feats_all}
        for f in ablate:
            if f in feats_all:
                configs[f"no_{f}"] = [x for x in feats_all if x != f]
        for config, feats in configs.items():
            for name in models:
                runs = [0] if name == COUNT_BASELINE else range(seeds)
                if name == COUNT_BASELINE and config != "all":
                    continue                       # the baseline has no features to ablate
                for seed in runs:
                    a_val, a_test, info = anomaly_scores(name, seed, tr, va, te, feats, count_col)
                    if a_val is None:
                        print(f"  - {name}: skipped ({info['skip']})")
                        break
                    both = len(set(y)) == 2
                    base = {"scenario": meta["scenario"], "lane": lane, "config": config,
                            "model": name, "seed": seed, **info,
                            "pr_auc": average_precision_score(y, a_test) if both else float("nan"),
                            "roc_auc": roc_auc_score(y, a_test) if both else float("nan")}
                    for p in percentiles:
                        thr = float(np.percentile(a_val, p))
                        m, per_step = at_threshold(y, a_test, thr, test_days, te.timestamp, te.steps.to_numpy())
                        metrics.append({**base, "percentile": p, "threshold": thr, **m})
                        for s, (n, c) in per_step.items():
                            step_rows.append({"scenario": meta["scenario"], "config": config, "model": name,
                                              "seed": seed, "percentile": p, "step": s, "windows": n, "caught": c})
                    for part, frame, a in (("val", va, a_val), ("test", te, a_test)):
                        score_rows.append(pd.DataFrame({
                            "scenario": meta["scenario"], "config": config, "model": name, "seed": seed,
                            "split": part, "timestamp": frame.timestamp, "label": frame.label, "score": a}))
    scores = pd.concat(score_rows, ignore_index=True) if score_rows else pd.DataFrame()
    return pd.DataFrame(metrics), pd.DataFrame(step_rows), scores


def fmt(mean, sd, digits=2):
    if pd.isna(mean):
        return "–"
    return f"{mean:.{digits}f}" if pd.isna(sd) or sd == 0 else f"{mean:.{digits}f} ± {sd:.{digits}f}"


def summary(metrics, steps, primary, percentiles):
    out = [f"# Evaluation summary\n",
           f"Threshold rule: the {primary}th percentile of each model's scores on the normal "
           f"validation day (other operating points in the trade-off table). Mean ± sd over seeds.\n"]
    for (scen, config), g in metrics.groupby(["scenario", "config"], sort=False):
        out.append(f"\n## {scen} — features: {config}\n")
        out.append("| Model | PR-AUC | ROC-AUC | Recall | Precision | F1 | False alarms/day | Detected | Time to detect (min) | Fit (s) |")
        out.append("|---|---|---|---|---|---|---|---|---|---|")
        p = g[g.percentile == primary]
        for model, m in p.groupby("model", sort=False):
            agg = m.select_dtypes("number").agg(["mean", "std"])
            c = lambda k, d=2: fmt(agg.at["mean", k], agg.at["std", k], d)
            out.append(f"| {model} ({m.device.iloc[0]}) | {c('pr_auc')} | {c('roc_auc')} | {c('recall')} | "
                       f"{c('precision')} | {c('f1')} | {c('fp_per_day', 1)} | "
                       f"{int(m.detected.sum())}/{len(m)} | {c('ttd_min', 0)} | {c('fit_sec', 2)} |")
        out.append("\nTrade-off (mean over seeds): recall / false alarms per day at each threshold\n")
        out.append("| Model | " + " | ".join(f"p{q}" for q in percentiles) + " |")
        out.append("|---|" + "---|" * len(percentiles))
        for model, m in g.groupby("model", sort=False):
            cells = []
            for q in percentiles:
                mq = m[m.percentile == q]
                cells.append(f"{mq.recall.mean():.2f} / {mq.fp_per_day.mean():.1f}")
            out.append(f"| {model} | " + " | ".join(cells) + " |")
        s = steps[(steps.scenario == scen) & (steps.config == config) & (steps.percentile == primary)]
        if len(s):
            out.append(f"\nRecall per attack step (windows containing the step that were flagged, mean over seeds)\n")
            names = sorted(s.step.unique())
            out.append("| Model | " + " | ".join(names) + " |")
            out.append("|---|" + "---|" * len(names))
            for model, m in s.groupby("model", sort=False):
                r = (m.groupby("step").caught.mean() / m.groupby("step").windows.first())
                out.append(f"| {model} | " + " | ".join(f"{r.get(n, float('nan')):.2f}" for n in names) + " |")
            n_win = s.groupby("step").windows.first()
            out.append("| (windows) | " + " | ".join(str(int(n_win[n])) for n in names) + " |")
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("csv", nargs="+", type=Path, help="window CSVs (each with <csv>.meta.json)")
    ap.add_argument("--out", type=Path, required=True, help="output directory")
    ap.add_argument("--models", default="isolation_forest,autoencoder,morpheus_dfencoder")
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--percentiles", default="99,99.5,100", help="threshold percentiles of validation scores")
    ap.add_argument("--primary", type=float, default=99.5, help="percentile reported in the main table")
    ap.add_argument("--ablate", default="hour", help="comma list of features to drop in an extra run ('' = none)")
    ap.add_argument("--train-days", type=float, default=2)
    ap.add_argument("--val-days", type=float, default=1)
    a = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")   # "±" on non-UTF-8 consoles

    percentiles = [float(x) for x in a.percentiles.split(",")]
    if a.primary not in percentiles:
        percentiles.append(a.primary)
    models = [m.strip() for m in a.models.split(",") if m.strip()] + [COUNT_BASELINE]
    ablate = [f.strip() for f in a.ablate.split(",") if f.strip()]

    metrics, steps, scores = evaluate(a.csv, models, a.seeds, percentiles, ablate, a.train_days, a.val_days)
    a.out.mkdir(parents=True, exist_ok=True)
    metrics.to_csv(a.out / "metrics.csv", index=False)
    steps.to_csv(a.out / "steps.csv", index=False)
    scores.to_csv(a.out / "scores.csv", index=False)
    text = summary(metrics, steps, a.primary, percentiles)
    (a.out / "summary.md").write_text(text, encoding="utf-8")
    print("\n" + text)
    print(f"written: {a.out}/metrics.csv, steps.csv, scores.csv, summary.md")


if __name__ == "__main__":
    main()
