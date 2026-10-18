"""
Shared by both detection consumers (auth and web).

Two things every detector writes, whatever its features:

  evidence   — WHY a window was flagged: its feature values next to what the
               un-flagged windows looked like in the same fit, and the score
               cutoff that fit used. The dashboard's "Why it fired" panel and
               the LLM explainer read these off the detection document.
  heartbeat  — that the detector is alive and what it is doing (warming up,
               scoring, how much it has seen). The dashboard's Pipeline page
               reads these, so a quiet console can be told apart from a dead
               consumer.

Plus decode_event, the Kafka deserializer both use.
"""

import json
from datetime import datetime, timezone

STATUS_INDEX = "ai-pipeline-status"


def decode_event(raw):
    """Kafka message value -> event dict, or None for a line that isn't one
    (partial or garbled). Filebeat forwards archive lines as-is, so a bad line
    gets dropped here; raising instead would kill the consumer loop."""
    try:
        event = json.loads(raw)
    except ValueError:                   # bad JSON, and bad UTF-8 too
        return None
    return event if isinstance(event, dict) else None


def _num(v):
    """numpy/pandas scalar -> plain JSON number (or bool)."""
    if hasattr(v, "item"):
        v = v.item()
    if isinstance(v, bool):
        return v
    if isinstance(v, float):
        return round(v, 4)
    return v


def fit_evidence(df, features):
    """Baseline and cutoff from one fit over the rolling buffer.

    df has the fit's "flag" (-1 = anomaly) and "score" (lower = more anomalous)
    columns. The models flag by contamination — a fixed share of windows — not
    by a fixed score, so the cutoff moves with the buffer; recording it per
    detection is what lets the dashboard say how far past it a window was.

      threshold  the least anomalous score flagged in this fit
      baseline   per feature, median and p95 over the windows NOT flagged:
                 what "normal" looked like at scoring time
    """
    normal = df[df["flag"] != -1]
    flagged = df[df["flag"] == -1]
    baseline = {
        f: {"median": _num(round(float(normal[f].median()), 3)),
            "p95": _num(round(float(normal[f].quantile(0.95)), 3))}
        for f in features
    } if len(normal) else {}
    return {
        "threshold": _num(float(flagged["score"].max())) if len(flagged) else None,
        "baseline": baseline,
        "windows_scored": int(len(df)),
    }


def window_features(row, features):
    """This window's own feature vector, as the model saw it."""
    return {f: _num(row[f]) for f in features}


def top_agent(agents):
    """Most common (id, name) among a window's events -> the doc's agent field."""
    if not agents:
        return {"name": "unknown"}
    (agent_id, name), _ = agents.most_common(1)[0]
    return {k: v for k, v in (("id", agent_id), ("name", name)) if v}


def note_agent(window, event):
    """Count the event's agent into the window (call from ingest)."""
    a = event.get("agent") or {}
    if a.get("id") or a.get("name"):
        window["agents"][(a.get("id"), a.get("name"))] += 1


def ai_index():
    """Today's detections index. Computed per write, not once at startup, so a
    consumer left running past midnight rolls over to the new day's index."""
    return f"ai-detections-{datetime.now(timezone.utc):%Y.%m.%d}"


def heartbeat(os_client, name, **fields):
    """Overwrite this consumer's status document. Never raises: a failed status
    write must not take the detector down with it."""
    doc = {"consumer": name,
           "last_heartbeat": datetime.now(timezone.utc).isoformat(), **fields}
    try:
        os_client.index(index=STATUS_INDEX, id=name, body=doc)
    except Exception as e:
        print(f"  [status] heartbeat write failed: {e}")
