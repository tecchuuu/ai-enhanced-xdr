#!/usr/bin/env python3
"""Check this environment can run the Morpheus auth pipeline — before going live.

Runs the real pipeline code (auth_pipeline.py: the cuDF windows stage and the
dfencoder inference stage) through a real Morpheus LinearPipeline, fed by a
synthetic source instead of Kafka and with no OpenSearch sink. Then checks:

  1. the environment: Morpheus, cuDF, torch + GPU
  2. Morpheus runs the stages end to end (decorated source/stages, MessageMeta)
  3. the GPU windows equal the Python consumer's features on the same events
  4. dfencoder fitted on the GPU and flagged windows

    python ai-stack/morpheus/probe.py          # GPU mode (cuDF)
    python ai-stack/morpheus/probe.py --cpu    # Morpheus CPU mode (pandas)
"""
import argparse
import random
import sys
import traceback
from collections import defaultdict
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import auth_pipeline as ap  # noqa: E402  (also puts ai-stack/pipeline on sys.path)
import pandas as pd  # noqa: E402
from morpheus.config import Config, ExecutionMode  # noqa: E402
from morpheus.messages import MessageMeta  # noqa: E402
from morpheus.pipeline.stage_decorator import source, stage  # noqa: E402

import features as F  # noqa: E402
from auth_lane import parse_auth_event  # noqa: E402


@source(name="probe-source", execution_modes=ap.MODES)
def probe_source(*, lane: ap.Lane, batches: list) -> Iterator[MessageMeta]:
    for rows in batches:
        yield MessageMeta(lane.frame(rows))


@stage(name="probe-collect", execution_modes=ap.MODES)
def collect(message: MessageMeta, *, out: list) -> MessageMeta:
    with message.mutable_dataframe() as df:
        out.append(df.to_pandas() if hasattr(df, "to_pandas") else df.copy())
    return message


def synthetic_events(n=2000, minutes=100, seed=7):
    rnd = random.Random(seed)
    t0 = datetime(2026, 10, 21, 8, 0, tzinfo=timezone.utc)
    out = []
    for _ in range(n):
        d = {"srcip": rnd.choice(["10.20.0.11", "10.20.0.12", "10.20.0.13", "10.20.9.5"])}
        if rnd.random() < 0.6:
            d["srcuser"] = rnd.choice(["alice", "bob", "carol", "root"])
        out.append({"timestamp": (t0 + timedelta(seconds=rnd.randint(0, minutes * 60 - 1))).isoformat(),
                    "agent": {"id": "001", "name": "lab"}, "rule": {"level": rnd.choice([3, 5, 10])},
                    "data": d, "full_log": "Failed password for invalid user zed from x"})
    return sorted(out, key=lambda e: e["timestamp"])


def check(name, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""), flush=True)
    return ok


def main():
    ap_ = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap_.add_argument("--cpu", action="store_true")
    a = ap_.parse_args()
    ok = True

    print("1. environment")
    import morpheus
    print(f"     morpheus {getattr(morpheus, '__version__', '?')}")
    if a.cpu:
        df_pkg = pd
    else:
        import cudf as df_pkg
        print(f"     cudf {df_pkg.__version__}")
    import torch
    gpu = torch.cuda.get_device_name(0) if torch.cuda.is_available() else None
    ok &= check("torch sees a GPU" if not a.cpu else "torch imported", a.cpu or bool(gpu), gpu or "cpu")

    events = synthetic_events()
    rows = []
    for e in events:
        ev = parse_auth_event(e)
        rows.append((F.window_key(ev.dt), ev.srcip, ev.user, ev.level,
                     e["agent"]["id"], e["agent"]["name"]))
    third = len(rows) // 3
    batches = [rows[:third], rows[third:2 * third], [], rows[2 * third:]]   # one empty cycle

    print("2. Morpheus runs the pipeline stages")
    config = Config()
    config.execution_mode = ExecutionMode.CPU if a.cpu else ExecutionMode.GPU
    lane = ap.Lane(df_pkg, "morpheus_dfencoder", os_client=None)
    out = []
    try:
        pipe = ap.build(config, lane, source_stage=probe_source(config, lane=lane, batches=batches), sink=False)
        pipe.add_stage(collect(config, out=out))
        pipe.run()
        ok &= check("pipeline ran", len(out) == len(batches), f"{len(out)}/{len(batches)} messages through")
    except Exception:
        traceback.print_exc()
        check("pipeline ran", False, "see the traceback above — send it over")
        sys.exit(1)

    print("3. GPU windows == the Python consumer's features")
    wins = defaultdict(F.new_auth_window)
    for e in events:
        ev = parse_auth_event(e)
        F.fold_auth(wins[F.window_key(ev.dt)], ev.srcip, ev.level, ev.user)
    ref = pd.DataFrame([F.auth_row(k, w) for k, w in sorted(wins.items())])[["key"] + F.AUTH_FEATURES]
    got = out[-1][["key"] + F.AUTH_FEATURES].reset_index(drop=True)
    try:
        pd.testing.assert_frame_equal(ref.astype(float), got.astype(float))
        ok &= check("features identical", True, f"{len(got)} windows from {len(rows)} events")
    except AssertionError as err:
        ok &= check("features identical", False, str(err).splitlines()[0])

    print("4. dfencoder on the GPU")
    flagged = int((out[-1]["flag"] == -1).sum())
    ok &= check("model fitted and flagged windows", flagged > 0,
                f"{lane.model.label} on {getattr(lane.model, 'last_device', '?')}, "
                f"{flagged}/{len(out[-1])} flagged, fit {getattr(lane.model, 'last_fit_sec', '?')} s")

    print("\nALL PASS — ready to run auth_pipeline.py" if ok else "\nSOME CHECKS FAILED — send this output")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
