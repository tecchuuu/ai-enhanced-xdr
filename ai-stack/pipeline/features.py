"""
Window features — the one definition both lanes use.

A detector folds events into 1-minute windows and turns each window into a
feature row. That logic lives here rather than in the consumers, so the offline
evaluation (scripts/evaluate.py, fed by dataset loaders such as
scripts/ait_windows.py) computes features with exactly the code the live
detectors run: "evaluated on the same features" holds by construction.

The consumers keep what is theirs: reading Wazuh events off Kafka, noting which
agent a window came from, scoring, writing detections.
"""
import re
from collections import Counter
from datetime import datetime, timezone

WINDOW_SEC = 60


def window_key(dt):
    """Epoch-minute bucket of a timezone-aware timestamp."""
    return int(dt.timestamp()) // WINDOW_SEC


def window_start(key):
    return datetime.fromtimestamp(key * WINDOW_SEC, tz=timezone.utc)


# ----------------------------------------------------------------- web lane
WEB_FEATURES = ["request_count", "distinct_urls", "error_ratio",
                "not_found_count", "post_ratio", "requests_per_ip", "hour"]

INJECTION_RE = re.compile(
    r"(?i)(union\s+select|'\s*or\s*'?\s*1|<script|onerror=|\bexec\b|xp_cmdshell"
    r"|%27|%3cscript|\bsleep\(|benchmark\(|information_schema)"
)
TRAVERSAL_RE = re.compile(r"(\.\./|\.\.\\|%2e%2e|/etc/passwd|\bboot\.ini\b|%00)")


def new_web_window():
    return {"count": 0, "urls": Counter(), "ips": Counter(),
            "methods": Counter(), "statuses": Counter(),
            "injection": False, "traversal": False, "agents": Counter()}


def fold_web(w, url, method=None, status=None, srcip=None):
    """Count one access-log request into its window."""
    w["count"] += 1
    w["urls"][url] += 1
    if srcip:
        w["ips"][srcip] += 1
    if method:
        w["methods"][method.upper()] += 1
    try:
        code = int(status)
    except (TypeError, ValueError):
        code = 0
    if code:
        w["statuses"][code] += 1
    if INJECTION_RE.search(url):
        w["injection"] = True
    if TRAVERSAL_RE.search(url):
        w["traversal"] = True


def web_row(key, w):
    """One window -> its feature row (plus the context categorize() and the
    detection document use)."""
    dt = window_start(key)
    count = w["count"]
    distinct_ips = len(w["ips"])
    errors = sum(n for code, n in w["statuses"].items() if 400 <= code < 600)
    return {
        "key":             key,
        "timestamp":       dt,
        "request_count":   count,
        "distinct_urls":   len(w["urls"]),
        "error_ratio":     round(errors / count, 3) if count else 0.0,
        "not_found_count": w["statuses"].get(404, 0),
        "post_ratio":      round(w["methods"].get("POST", 0) / count, 3) if count else 0.0,
        "requests_per_ip": round(count / distinct_ips, 2) if distinct_ips else count,
        "hour":            dt.hour,
        "injection":       w["injection"],
        "traversal":       w["traversal"],
        "top_ips":         w["ips"].most_common(5),
        "top_urls":        w["urls"].most_common(5),
    }


# ----------------------------------------------------------------- auth lane
AUTH_FEATURES = ["event_count", "distinct_users", "max_level",
                 "hour", "events_per_user"]


def new_auth_window():
    return {"count": 0, "users": set(), "ips": Counter(),
            "max_level": 0, "agents": Counter()}


def fold_auth(w, srcip, level=0, user=None):
    """Count one remote-auth event (it has a source IP) into its window."""
    w["count"] += 1
    w["max_level"] = max(w["max_level"], level or 0)
    w["ips"][srcip] += 1
    if user:
        w["users"].add(user)


def auth_row(key, w):
    dt = window_start(key)
    users = len(w["users"])
    return {
        "key":             key,
        "timestamp":       dt,
        "event_count":     w["count"],
        "distinct_users":  users,
        "max_level":       w["max_level"],
        "hour":            dt.hour,
        "events_per_user": round(w["count"] / users, 2) if users else w["count"],
        "top_ips":         w["ips"].most_common(5),
    }
