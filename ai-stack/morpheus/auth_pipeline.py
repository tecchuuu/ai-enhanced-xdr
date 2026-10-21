#!/usr/bin/env python3
"""
The auth (SSH) lane as an NVIDIA Morpheus pipeline, on the GPU.

The Morpheus-runtime twin of ai-stack/pipeline/detection_consumer.py. It runs
alongside the Python consumer on its own Kafka consumer group, so both see
every event: the Python consumer stays as the CPU baseline, this one is the
deployment the sponsor's stack is built around.

    Kafka wazuh-archives
      -> source   one scoring cycle of remote-auth events       MessageMeta(events)
      -> windows  1-minute features, a cuDF groupby on the GPU  MessageMeta(windows)
      -> infer    Morpheus dfencoder over the rolling buffer    + flag, score
      -> sink     new anomalies -> ai-detections-* ("pipeline": "morpheus"), heartbeat

Same event reading, features and detection document as the Python consumer
(auth_lane.py, features.py — the vectorised features are tested equal to the
consumer's one-by-one fold), so the console handles both alike and shows which
runtime wrote what. Live mode is the consumer's: refit on the rolling buffer
every cycle (fit_score). Train-once measurement is scripts/evaluate.py's job.

Run in the morpheus conda env (or the container, ai-stack/morpheus/Dockerfile):
    python ai-stack/morpheus/probe.py                  # check the environment first
    python ai-stack/morpheus/auth_pipeline.py          # GPU (cuDF)
    python ai-stack/morpheus/auth_pipeline.py --cpu    # Morpheus CPU mode (pandas)
"""
import argparse
import os
import sys
import time
from collections import Counter
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[1] / "pipeline"))      # ai-stack/pipeline

from dotenv import load_dotenv  # noqa: E402

load_dotenv(HERE.parents[2] / "dashboard" / ".env")       # one credential source

import pandas as pd  # noqa: E402
from morpheus.config import Config, ExecutionMode  # noqa: E402
from morpheus.messages import MessageMeta  # noqa: E402
from morpheus.pipeline import LinearPipeline  # noqa: E402
from morpheus.pipeline.stage_decorator import source, stage  # noqa: E402

from auth_lane import detection_doc, parse_auth_event  # noqa: E402
from consumer_common import ai_index, decode_event, fit_evidence, heartbeat, top_agent  # noqa: E402
from features import AUTH_FEATURES as FEATURES, auth_frame, window_key, window_start  # noqa: E402
from models import get_model  # noqa: E402

KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "localhost:9092")
TOPIC          = "wazuh-archives"
GROUP          = "xdr-morpheus-auth"   # own group: the Python consumer still gets every event
CYCLE_SEC      = 60                    # one source batch = one scoring cycle
MIN_WINDOWS    = int(os.environ.get("MIN_WINDOWS", "10"))
MAX_WINDOWS    = 120                   # rolling buffer, as the Python consumer
CONTAMINATION  = 0.15
CONSUMER_NAME  = "morpheus-auth"       # its status doc in ai-pipeline-status
PIPELINE       = "morpheus"            # ai.pipeline on its detections
MODES          = (ExecutionMode.GPU, ExecutionMode.CPU)

EVENT_COLUMNS  = ["key", "srcip", "user", "level", "agent_id", "agent_name"]


class Row(dict):
    """A window as detection_doc reads it: by attribute and by key."""
    __getattr__ = dict.__getitem__


class Lane:
    """What the stages share: the rolling event buffer (cuDF on the GPU, pandas
    in CPU mode), the model, the OpenSearch client, the heartbeat counters."""

    def __init__(self, df_pkg, model_name, os_client):
        self.df = df_pkg
        self.gpu = df_pkg.__name__ == "cudf"
        self.model = get_model(model_name)
        self.os = os_client
        self.events = self.frame([])
        self.n_windows = 0
        self.flagged = set()
        self.evidence = {}
        self.seen = self.written = 0
        self.last_event_at = None
        self.started_at = datetime.now(timezone.utc).isoformat()

    # ---- dataframes
    def frame(self, rows):
        """Event tuples -> a typed DataFrame of this mode's package (nulls kept)."""
        text = "str" if self.gpu else object
        cols = list(zip(*rows)) if rows else [[] for _ in EVENT_COLUMNS]
        dtypes = {"key": "int64", "level": "float64"}
        return self.df.DataFrame({c: self.df.Series(list(v), dtype=dtypes.get(c, text))
                                  for c, v in zip(EVENT_COLUMNS, cols)})

    def to_pandas(self, df):
        return df.to_pandas() if self.gpu else df.copy()

    def from_pandas(self, df):
        return self.df.from_pandas(df) if self.gpu else df

    def add(self, batch):
        """Append a cycle's events; keep the most recent MAX_WINDOWS windows."""
        events = self.df.concat([self.events, batch], ignore_index=True) if len(batch) else self.events
        keys = events["key"].drop_duplicates().sort_values()
        if len(keys) > MAX_WINDOWS:
            cutoff = int(keys.iloc[len(keys) - MAX_WINDOWS])
            events = events[events["key"] >= cutoff].reset_index(drop=True)
            keys = keys[keys >= cutoff]
        self.events, self.n_windows = events, len(keys)

    def context(self, keys):
        """Top source IPs and agent per flagged window, counted in arrival order
        (same tie order as the consumer's Counters)."""
        ev = self.to_pandas(self.events)
        ev = ev[ev["key"].isin(keys)]
        out = {}
        for key, g in ev.groupby("key", sort=False):
            agents = Counter((None if pd.isna(i) else i, None if pd.isna(n) else n)
                             for i, n in zip(g["agent_id"], g["agent_name"])
                             if not (pd.isna(i) and pd.isna(n)))
            out[key] = (Counter(g["srcip"]).most_common(5), top_agent(agents))
        return out

    # ---- status
    def beat(self, state, result):
        heartbeat(self.os, CONSUMER_NAME, state=state, last_result=result,
                  model=self.model.label, lane="auth", runtime="morpheus",
                  device=getattr(self.model, "last_device", None) or ("gpu" if self.gpu else "cpu"),
                  windows_buffered=self.n_windows, min_windows=MIN_WINDOWS,
                  events_seen=self.seen, detections_written=self.written,
                  last_event_at=self.last_event_at, started_at=self.started_at,
                  score_every_sec=CYCLE_SEC, kafka_bootstrap=KAFKA_BOOTSTRAP,
                  topic=TOPIC, index=ai_index())


# ----------------------------------------------------------------- stages
@source(name="wazuh-auth-source", execution_modes=MODES)
def wazuh_auth_source(*, lane: Lane) -> Iterator[MessageMeta]:
    """Poll Kafka for one cycle, keep the remote-auth events, emit them as one batch."""
    from kafka import KafkaConsumer

    consumer = KafkaConsumer(TOPIC, bootstrap_servers=KAFKA_BOOTSTRAP, group_id=GROUP,
                             auto_offset_reset="latest", value_deserializer=decode_event)
    lane.beat("starting", "connected to Kafka, waiting for events")
    while True:
        rows, end = [], time.time() + CYCLE_SEC
        while (left := end - time.time()) > 0:
            for records in consumer.poll(timeout_ms=int(min(left, 1.0) * 1000)).values():
                for rec in records:
                    lane.seen += 1
                    ev = parse_auth_event(rec.value)
                    if ev is None:
                        continue
                    agent = rec.value.get("agent") or {}
                    rows.append((window_key(ev.dt), ev.srcip, ev.user, ev.level,
                                 agent.get("id"), agent.get("name")))
                    lane.last_event_at = datetime.now(timezone.utc).isoformat()
        yield MessageMeta(lane.frame(rows))


@stage(name="cudf-windows", execution_modes=MODES)
def build_windows(message: MessageMeta, *, lane: Lane) -> MessageMeta:
    """Fold the batch into the rolling buffer; recompute every window's features
    (one groupby over the buffer — on the GPU in GPU mode)."""
    with message.mutable_dataframe() as batch:
        lane.add(batch.copy())
    return MessageMeta(auth_frame(lane.events))


@stage(name="dfp-inference", execution_modes=MODES)
def infer(message: MessageMeta, *, lane: Lane) -> MessageMeta:
    """Score the buffer with the inference-slot model (Morpheus dfencoder)."""
    with message.mutable_dataframe() as df:
        win = lane.to_pandas(df)
    if len(win) >= MIN_WINDOWS:
        win["flag"], win["score"] = lane.model.fit_score(win[FEATURES], CONTAMINATION)
        lane.evidence = fit_evidence(win, FEATURES)
    else:
        win["flag"], win["score"] = 1, 0.0
    return MessageMeta(lane.from_pandas(win))


@stage(name="opensearch-sink", execution_modes=MODES)
def write_detections(message: MessageMeta, *, lane: Lane) -> MessageMeta:
    """New anomalies -> ai-detections-*, then report status."""
    with message.mutable_dataframe() as df:
        win = lane.to_pandas(df)
    n = len(win)
    if n < MIN_WINDOWS:
        print(f"  [morpheus] {n}/{MIN_WINDOWS} windows — not enough to score yet", flush=True)
        lane.beat("warming_up", f"{n}/{MIN_WINDOWS} windows buffered — not enough to score yet")
        return message

    hits = win[(win["flag"] == -1) & ~win["key"].isin(lane.flagged)]
    if hits.empty:
        print(f"  [morpheus] {n} windows scored — no new anomalies", flush=True)
        lane.beat("scoring", f"{n} windows scored — no new anomalies")
        return message

    from opensearchpy import helpers

    ctx = lane.context(set(hits["key"]))
    index = ai_index()
    docs = []
    for h in hits.to_dict("records"):          # keeps each column's type (ints stay ints)
        lane.flagged.add(h["key"])
        top_ips, agent = ctx[h["key"]]
        r = Row(h, timestamp=window_start(h["key"]), top_ips=top_ips, agent=agent)
        docs.append(detection_doc(r, index, lane.model.label, PIPELINE, FEATURES, lane.evidence))
    helpers.bulk(lane.os, docs)
    lane.os.indices.refresh(index=index)
    lane.written += len(docs)

    print(f"  [morpheus] {n} windows scored — {len(docs)} NEW detection(s):", flush=True)
    for d in docs:
        a = d["_source"]["ai"]
        print(f"      {d['_source']['timestamp']}  score={a['anomaly_score']}  "
              f"events={a['event_count']}  users={a['distinct_users']}", flush=True)
    lane.beat("scoring", f"{n} windows scored — {len(docs)} new detection(s)")
    return message


# ----------------------------------------------------------------- main
def os_client():
    from opensearchpy import OpenSearch
    return OpenSearch(
        hosts=[{"host": os.environ.get("OS_HOST", "localhost"),
                "port": int(os.environ.get("OS_PORT", "9200"))}],
        http_auth=(os.environ.get("OS_USER", "admin"), os.environ.get("OS_PASS", "")),
        use_ssl=True, verify_certs=False, ssl_show_warn=False,
    )


def build(config, lane, source_stage=None, sink=True):
    """The pipeline; probe.py swaps the Kafka source and the OpenSearch sink."""
    pipe = LinearPipeline(config)
    pipe.set_source(source_stage or wazuh_auth_source(config, lane=lane))
    pipe.add_stage(build_windows(config, lane=lane))
    pipe.add_stage(infer(config, lane=lane))
    if sink:
        pipe.add_stage(write_detections(config, lane=lane))
    return pipe


def main():
    ap = argparse.ArgumentParser(description="Auth lane as a Morpheus pipeline")
    ap.add_argument("--cpu", action="store_true", help="Morpheus CPU mode (pandas) instead of GPU (cuDF)")
    ap.add_argument("--model", default=os.environ.get("MORPHEUS_MODEL", "morpheus_dfencoder"),
                    help="inference-slot model (default: Morpheus dfencoder)")
    a = ap.parse_args()

    config = Config()
    config.execution_mode = ExecutionMode.CPU if a.cpu else ExecutionMode.GPU
    if a.cpu:
        df_pkg = pd
    else:
        import cudf as df_pkg

    lane = Lane(df_pkg, a.model, os_client())
    print(f"Morpheus auth pipeline: '{TOPIC}' from {KAFKA_BOOTSTRAP} (group {GROUP}) -> "
          f"{lane.model.label} [{'cuDF/GPU' if lane.gpu else 'pandas/CPU'}] -> {ai_index()}")
    print(f"Windows: 60s | cycle {CYCLE_SEC}s | min {MIN_WINDOWS} windows\n", flush=True)
    build(config, lane).run()


if __name__ == "__main__":
    main()
