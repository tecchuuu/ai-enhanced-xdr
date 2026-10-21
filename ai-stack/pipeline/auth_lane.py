"""
The auth (SSH) lane's event reading and detection document.

Shared by the two runtimes of this lane — the Python consumer
(detection_consumer.py, CPU baseline) and the NVIDIA Morpheus pipeline
(ai-stack/morpheus/auth_pipeline.py) — so both pick the same events off Kafka
and write the same ai-detections-* document. Window features live in
features.py for the same reason.
"""
import re
from collections import namedtuple

import pandas as pd

from consumer_common import window_features
from features import WINDOW_SEC

RULE_ID = "100001"
USER_RE = re.compile(r"(?:invalid user |user )([A-Za-z0-9_.-]+)")

AuthEvent = namedtuple("AuthEvent", "dt srcip level user")


def parse_auth_event(event):
    """A Wazuh event -> AuthEvent, or None if it isn't a remote-auth event.

    Auth events carry srcip; web access events carry srcip AND url, and are
    left out so the web lane does not leak into the auth model (failure log
    Entry 22). `level` is passed through as Wazuh gave it (may be None)."""
    if event is None:                    # undecodable line (decode_event)
        return None
    ts = event.get("timestamp")
    if not ts:
        return None
    try:
        dt = pd.to_datetime(ts)
    except Exception:
        return None

    data = event.get("data", {})
    if "srcip" not in data or "url" in data:
        return None

    user = data.get("srcuser")
    if not user:
        m = USER_RE.search(event.get("full_log", "") or "")
        user = m.group(1) if m else None
    return AuthEvent(dt, data["srcip"], event.get("rule", {}).get("level", 0), user)


def categorize(r):
    """Heuristic post-classification of an anomalous window.

    The model only says "this window deviates from baseline"; these labels turn
    that into something an analyst can triage. Pattern -> (category, MITRE, label).
    """
    if r.events_per_user >= 10 and r.distinct_users <= 3:
        return "brute_force", "T1110.001", "brute-force pattern"
    if r.distinct_users >= 5 and r.events_per_user <= 5:
        return "password_spraying", "T1110.003", "password-spraying pattern"
    if r.hour < 6 or r.hour >= 22:
        return "suspicious_timing", "T1078", "off-hours activity"
    return "unclassified_anomaly", None, "unclassified deviation"


def severity(score):
    """Map anomaly score to a Wazuh-convention level (more negative = worse)."""
    if score < -0.60:
        return 12
    if score < -0.50:
        return 10
    return 7


def detection_doc(r, index, model_label, pipeline, features, evidence):
    """One flagged window -> its ai-detections-* bulk action.

    r: the window's row (timestamp, score, the features, top_ips, agent).
    pipeline: which runtime wrote it ("kafka-streaming" = Python consumer,
    "morpheus" = the Morpheus pipeline) — the console shows both."""
    category, mitre, label = categorize(r)
    return {
        "_index": index,
        "_source": {
            "timestamp": r.timestamp.isoformat(),
            "source": "morpheus_ai",
            "rule": {
                "id": RULE_ID,
                "level": severity(r.score),
                "description": f"AI: anomalous authentication behaviour — {label}",
            },
            "ai": {
                "model":           model_label,
                "pipeline":        pipeline,
                "anomaly_score":   float(r.score),
                "window":          f"{WINDOW_SEC}s",
                "event_count":     int(r.event_count),
                "distinct_users":  int(r.distinct_users),
                "events_per_user": float(r.events_per_user),
                "category":        category,
                "mitre":           mitre,
                "top_srcips":      [{"ip": ip, "count": n} for ip, n in r.top_ips],
                # why it fired: this window vs the un-flagged ones, and the cutoff
                "features":        window_features(r, features),
                **evidence,
            },
            "agent": r.agent,
        },
    }
