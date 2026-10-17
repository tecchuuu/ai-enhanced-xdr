import ipaddress
import os
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv

load_dotenv()  # before wazuh_api reads its env vars

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from opensearchpy import OpenSearch
from pydantic import BaseModel

import explainer
import wazuh_api

app = FastAPI(title="AI-XDR Dashboard API")

# allow the frontend (served from anywhere in dev) to call this API
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

client = OpenSearch(
    hosts=[{"host": os.environ.get("OS_HOST", "localhost"),
            "port": int(os.environ.get("OS_PORT", "9200"))}],
    http_auth=(os.environ.get("OS_USER", "admin"), os.environ.get("OS_PASS", "")),
    use_ssl=True, verify_certs=False, ssl_show_warn=False,
)

RULE_INDEX = "wazuh-alerts-4.x-*"
AI_INDEX = "ai-detections-*"
# Wazuh level at which a rule alert declares an attack — the rule side of every
# rule-vs-AI comparison (combined feed, histogram, metrics) counts from here
ATTACK_LEVEL = 10


def _first(x):
    """Wazuh mitre fields are lists; take the first entry."""
    return x[0] if isinstance(x, list) and x else (x or None)


def _fmt_rule(hit):
    s = hit["_source"]
    rule = s.get("rule", {})
    mitre = rule.get("mitre", {})
    groups = rule.get("groups") or []
    return {
        "id":          f"rule:{hit['_id']}",
        "timestamp":   s.get("@timestamp") or s.get("timestamp"),
        "rule_id":     rule.get("id"),
        "level":       rule.get("level"),
        "description": rule.get("description"),
        "agent":       s.get("agent", {}).get("name"),
        "srcip":       s.get("data", {}).get("srcip"),
        "srcuser":     s.get("data", {}).get("srcuser"),
        "dstuser":     s.get("data", {}).get("dstuser"),
        "source":      "rule",          # <-- the tag that separates rule vs AI
        # category: MITRE tactic when tagged, else the most specific rule group
        "category":    _first(mitre.get("tactic")) or (groups[-1] if groups else None),
        "mitre":       _first(mitre.get("id")),
    }


def _fmt_ai(hit):
    s = hit["_source"]
    ai = s.get("ai", {})
    top_ips = ai.get("top_srcips") or []
    return {
        "id":          f"ai:{hit['_id']}",
        "timestamp":   s.get("timestamp"),
        "rule_id":     s.get("rule", {}).get("id"),
        "level":       s.get("rule", {}).get("level"),
        "description": s.get("rule", {}).get("description"),
        "agent":       s.get("agent", {}).get("name"),
        "source":      "ai",
        "model":       ai.get("model"),
        "pipeline":    ai.get("pipeline"),
        "window":      ai.get("window"),
        "score":       ai.get("anomaly_score"),
        "event_count": ai.get("event_count"),
        "distinct_users": ai.get("distinct_users"),
        "events_per_user": ai.get("events_per_user"),
        # web lane (rule 100002) window features; absent on auth detections
        "request_count":   ai.get("request_count"),
        "distinct_urls":   ai.get("distinct_urls"),
        "error_ratio":     ai.get("error_ratio"),
        "not_found_count": ai.get("not_found_count"),
        "post_ratio":      ai.get("post_ratio"),
        "top_urls":        ai.get("top_urls") or [],
        # why it fired — written by the consumers since batch 4, absent on older
        # detections: this window's features, the un-flagged windows' median/p95,
        # and the score cutoff of the fit that flagged it
        "features":        ai.get("features"),
        "baseline":        ai.get("baseline"),
        "threshold":       ai.get("threshold"),
        "windows_scored":  ai.get("windows_scored"),
        "category":    ai.get("category"),
        "mitre":       ai.get("mitre"),
        "srcip":       top_ips[0]["ip"] if top_ips else None,
        "top_srcips":  top_ips,
        "explanation": ai.get("explanation"),
        "explained_by": ai.get("explained_by"),
    }


def _get_hit(index, doc_id):
    """One document by _id across an index pattern, or an HTTPException the
    caller lets raise."""
    try:
        res = client.search(index=index, body={
            "size": 1, "query": {"ids": {"values": [doc_id]}},
        })
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"OpenSearch query failed: {e}")
    hits = res["hits"]["hits"]
    if not hits:
        raise HTTPException(status_code=404, detail="document not found")
    return hits[0]


def _get_alert_hit(alert_id):
    """Resolve a console alert id ("rule:<_id>" / "ai:<_id>") to its document."""
    source, _, doc_id = alert_id.partition(":")
    index = {"rule": RULE_INDEX, "ai": AI_INDEX}.get(source)
    if not index or not doc_id:
        raise HTTPException(status_code=400, detail=f"bad alert id '{alert_id}'")
    return _get_hit(index, doc_id)


# ----------------------------------------------------------------- query filters
# Every list/chart endpoint takes the same scope from the console's header: a
# time range (start/end, ISO — the client resolves the date picker's "now-24h"
# before sending), an agent name, and on the feeds a free-text search.

_TZ_NO_COLON = re.compile(r"([+-]\d{2})(\d{2})$")


def _parse_ts(value):
    """ISO timestamp -> aware datetime, or None. Accepts Wazuh's "+0000" offsets."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(
            _TZ_NO_COLON.sub(r"\1:\2", str(value).replace("Z", "+00:00")))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _window(start, end, default_hours):
    """The requested range as datetimes; a missing bound falls back to
    now / now - default_hours."""
    end_dt = _parse_ts(end) or datetime.now(timezone.utc)
    start_dt = _parse_ts(start) or end_dt - timedelta(hours=default_hours)
    return start_dt, end_dt


def _time_filter(start_dt, end_dt):
    return {"range": {"timestamp": {"gte": start_dt.isoformat(),
                                    "lte": end_dt.isoformat()}}}


def _optional_time_filter(start, end):
    """Feeds are all-time unless a range is passed; the console always passes one."""
    if not (start or end):
        return []
    return [_time_filter(*_window(start, end, default_hours=24))]


def _agent_filter(agent):
    # match_phrase, not term: agent.name is a keyword in wazuh-alerts but an
    # analyzed text field in the dynamically mapped ai-detections index
    return [{"match_phrase": {"agent.name": agent}}] if agent else []


RULE_SEARCH_FIELDS = ["rule.description", "rule.id", "rule.groups", "data.srcip",
                      "data.dstip", "data.srcuser", "data.dstuser", "agent.name",
                      "full_log"]
AI_SEARCH_FIELDS = ["rule.description", "ai.category", "ai.mitre", "ai.model",
                    "ai.top_srcips.ip", "ai.top_urls.url", "agent.name"]


def _search_filter(q, fields):
    """The feed search box: an IP, user, rule id or words; every term must
    match some field. lenient so a word against an ip/number field is a
    non-match rather than an error."""
    if not q:
        return []
    return [{"simple_query_string": {"query": q, "fields": fields,
                                     "default_operator": "and", "lenient": True}}]


# (name, seconds), smallest first; the histogram picks the first that keeps the
# chart at or under ~60 bars (24h -> 30m, 7d -> 3h, 30d -> 12h)
_INTERVALS = [("1m", 60), ("5m", 300), ("10m", 600), ("30m", 1800), ("1h", 3600),
              ("3h", 10800), ("12h", 43200), ("1d", 86400), ("7d", 604800)]


def _auto_interval(start_dt, end_dt, max_buckets=60):
    span = (end_dt - start_dt).total_seconds()
    for name, secs in _INTERVALS:
        if span / secs <= max_buckets:
            return name
    return _INTERVALS[-1][0]


# ----------------------------------------------------------------- triage state
# Analyst workflow state (status / assignee / note / false-positive flag) lives
# in its own mutable index, keyed by the alert's stable id. Same pattern as the
# ai-responses audit index — a small side store the console owns, distinct from
# the immutable alert/detection documents.
TRIAGE_INDEX = "ai-alert-triage"
TRIAGE_STATES = ("new", "investigating", "resolved", "false_positive")


def _triage_map(alert_ids):
    """{alert_id: triage_doc} for the given ids."""
    if not alert_ids:
        return {}
    try:
        res = client.search(index=TRIAGE_INDEX, body={
            "size": len(alert_ids), "query": {"ids": {"values": list(alert_ids)}},
        })
    except Exception:
        return {}
    return {h["_id"]: h["_source"] for h in res["hits"]["hits"]}


def _merge_triage(alerts):
    """Attach triage fields to a list of formatted alerts, in place."""
    tmap = _triage_map([a["id"] for a in alerts if a.get("id")])
    for a in alerts:
        t = tmap.get(a.get("id"))
        a["triage_status"] = (t or {}).get("status", "new")
        a["assignee"] = (t or {}).get("assignee")
        a["triage_note"] = (t or {}).get("note")
        a["false_positive"] = bool((t or {}).get("false_positive"))
    return alerts

@app.get("/api/health")
def health():
    return {"status": "ok", "cluster": client.info()["cluster_name"]}

@app.get("/api/alerts/rule")
def rule_alerts(limit: int = 50, min_level: int = 0, start: str | None = None,
                end: str | None = None, agent: str | None = None,
                q: str | None = None):
    """Rule-based alerts from Wazuh, newest first, in the console's scope."""
    body = {
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": [
            {"range": {"rule.level": {"gte": min_level}}},
            *_optional_time_filter(start, end),
            *_agent_filter(agent),
            *_search_filter(q, RULE_SEARCH_FIELDS),
        ]}},
    }
    res = client.search(index=RULE_INDEX, body=body)
    return {
        "count": res["hits"]["total"]["value"],
        "alerts": _merge_triage([_fmt_rule(h) for h in res["hits"]["hits"]]),
    }

@app.get("/api/alerts/ai")
def ai_alerts(limit: int = 50, min_level: int = 0, start: str | None = None,
              end: str | None = None, agent: str | None = None,
              q: str | None = None):
    """AI-detected anomalies (source=morpheus_ai), newest first, in scope."""
    try:
        res = client.search(index=AI_INDEX, body={
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"bool": {"filter": [
                {"range": {"rule.level": {"gte": min_level}}},
                *_optional_time_filter(start, end),
                *_agent_filter(agent),
                *_search_filter(q, AI_SEARCH_FIELDS),
            ]}},
        })
    except Exception:
        return {"count": 0, "alerts": []}      # index may not exist yet

    return {
        "count": res["hits"]["total"]["value"],
        "alerts": _merge_triage([_fmt_ai(h) for h in res["hits"]["hits"]]),
    }

@app.get("/api/alerts/histogram")
def histogram(start: str | None = None, end: str | None = None,
              agent: str | None = None, min_level: int = ATTACK_LEVEL):
    """Alert counts over time, split rule vs AI — feeds the overview time chart.
    The bucket size follows the range (see _auto_interval)."""
    start_dt, end_dt = _window(start, end, default_hours=24)
    interval = _auto_interval(start_dt, end_dt)

    def bucket_counts(index, extra_filters):
        body = {
            "size": 0,
            "query": {"bool": {"filter": [
                _time_filter(start_dt, end_dt),
                *_agent_filter(agent),
                *extra_filters,
            ]}},
            "aggs": {"t": {"date_histogram": {
                "field": "timestamp",
                "fixed_interval": interval,
                "min_doc_count": 0,
                "extended_bounds": {
                    "min": int(start_dt.timestamp() * 1000),
                    "max": int(end_dt.timestamp() * 1000),
                },
            }}},
        }
        try:
            res = client.search(index=index, body=body)
            return {b["key"]: b["doc_count"]
                    for b in res["aggregations"]["t"]["buckets"]}
        except Exception:
            return {}

    rule = bucket_counts(RULE_INDEX,
                         [{"range": {"rule.level": {"gte": min_level}}}])
    ai = bucket_counts(AI_INDEX, [])
    keys = sorted(set(rule) | set(ai))
    return {"interval": interval, "buckets": [
        {"time": k, "rule": rule.get(k, 0), "ai": ai.get(k, 0)} for k in keys
    ]}


@app.get("/api/alerts/top_srcips")
def top_srcips(start: str | None = None, end: str | None = None,
               agent: str | None = None, size: int = 10):
    """Most active source IPs across all alert levels — feeds the overview bar chart."""
    start_dt, end_dt = _window(start, end, default_hours=24)
    body = {
        "size": 0,
        "query": {"bool": {"filter": [
            _time_filter(start_dt, end_dt),
            *_agent_filter(agent),
            {"exists": {"field": "data.srcip"}},
        ]}},
        "aggs": {"ips": {"terms": {"field": "data.srcip", "size": size}}},
    }
    try:
        res = client.search(index=RULE_INDEX, body=body)
        return {"ips": [{"ip": b["key"], "count": b["doc_count"]}
                        for b in res["aggregations"]["ips"]["buckets"]]}
    except Exception:
        return {"ips": []}


@app.get("/api/alerts/combined")
def combined(limit: int = 100, start: str | None = None, end: str | None = None,
             agent: str | None = None):
    """Both streams merged, newest first (rules at attack level only)."""
    scope = {"limit": limit, "start": start, "end": end, "agent": agent, "q": None}
    rules = rule_alerts(min_level=ATTACK_LEVEL, **scope)["alerts"]
    ai    = ai_alerts(min_level=0, **scope)["alerts"]
    merged = sorted(rules + ai, key=lambda a: a["timestamp"] or "", reverse=True)
    return {
        "rule_count": len(rules),
        "ai_count":   len(ai),
        "alerts":     merged[:limit],
    }


# ----------------------------------------------------------------- investigation

@app.get("/api/alerts/doc")
def alert_doc(alert_id: str):
    """The stored document behind one console alert, untouched — the list
    endpoints return a flattened subset (no full_log, decoder, location...)."""
    hit = _get_alert_hit(alert_id)
    return {"index": hit["_index"], "id": hit["_id"], "source": hit["_source"]}


RELATED_MARGIN = timedelta(minutes=5)


def _window_seconds(window):
    """The detection's aggregation window ("60s") in seconds; 60 if unknown."""
    m = re.fullmatch(r"(\d+)s", str(window or ""))
    return int(m.group(1)) if m else 60


@app.get("/api/alerts/related")
def related_events(alert_id: str, limit: int = 200):
    """Rule alerts at any level around one alert, from the same source IPs —
    or, with no IP on the alert, the same agent. For an AI detection these are
    the decoded events behind the anomalous window; for a rule alert, what else
    that source did around it."""
    hit = _get_alert_hit(alert_id)
    s = hit["_source"]
    ts = _parse_ts(s.get("timestamp") or s.get("@timestamp"))
    if ts is None:
        raise HTTPException(status_code=422, detail="alert has no timestamp")

    if alert_id.startswith("ai:"):
        ai = s.get("ai", {})
        ips = [t["ip"] for t in ai.get("top_srcips") or [] if t.get("ip")]
        span = timedelta(seconds=_window_seconds(ai.get("window")))
    else:
        ip = s.get("data", {}).get("srcip")
        ips = [ip] if ip else []
        span = timedelta(0)
    agent = s.get("agent", {}).get("name")
    start_dt, end_dt = ts - RELATED_MARGIN, ts + span + RELATED_MARGIN
    result = {"basis": "srcip" if ips else "agent", "ips": ips, "agent": agent,
              "start": start_dt.isoformat(), "end": end_dt.isoformat()}

    if ips:
        basis = {"bool": {"should": [{"match_phrase": {"data.srcip": ip}} for ip in ips],
                          "minimum_should_match": 1}}
    elif agent:
        basis = {"match_phrase": {"agent.name": agent}}
    else:
        return {**result, "basis": None, "count": 0, "events": []}

    query = {"bool": {"filter": [_time_filter(start_dt, end_dt), basis]}}
    if alert_id.startswith("rule:"):
        query["bool"]["must_not"] = [{"ids": {"values": [hit["_id"]]}}]
    try:
        res = client.search(index=RULE_INDEX, body={
            "size": limit, "sort": [{"timestamp": {"order": "asc"}}], "query": query,
        })
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"OpenSearch query failed: {e}")
    return {**result, "count": res["hits"]["total"]["value"],
            "events": [_fmt_rule(h) for h in res["hits"]["hits"]]}


def _agg_time(res, name):
    """A min/max date aggregation's value as ISO, or None."""
    v = ((res or {}).get("aggregations", {}).get(name) or {}).get("value")
    return datetime.fromtimestamp(v / 1000, tz=timezone.utc).isoformat() if v else None


@app.get("/api/entities/ip/{ip}")
def ip_entity(ip: str, limit: int = 200):
    """Everything the console has on one source IP, all time: its rule alerts
    (any level) and AI detections, the accounts it targeted, when it was first
    and last seen, and whether it is blocked — behind every clickable IP."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"'{ip}' is not a valid IP")

    def _search(index, field, aggs):
        try:
            return client.search(index=index, body={
                "size": limit,
                "sort": [{"timestamp": {"order": "desc"}}],
                "query": {"match_phrase": {field: ip}},
                "aggs": {"first": {"min": {"field": "timestamp"}},
                         "last": {"max": {"field": "timestamp"}}, **aggs},
            })
        except Exception:
            return None            # index missing: the IP simply has no hits there

    terms = lambda f: {"terms": {"field": f, "size": 20}}
    r = _search(RULE_INDEX, "data.srcip", {"src_users": terms("data.srcuser"),
                                            "dst_users": terms("data.dstuser"),
                                            "agents": terms("agent.name")})
    a = _search(AI_INDEX, "ai.top_srcips.ip", {})

    hits = lambda res: (res or {}).get("hits", {}).get("hits", [])
    total = lambda res: (res or {}).get("hits", {}).get("total", {}).get("value", 0)
    buckets = lambda name: ((r or {}).get("aggregations", {}).get(name) or {}).get("buckets", [])

    users = {}
    for name in ("src_users", "dst_users"):
        for b in buckets(name):
            users[b["key"]] = users.get(b["key"], 0) + b["doc_count"]
    seen = [t for t in (_agg_time(r, "first"), _agg_time(a, "first"),
                        _agg_time(r, "last"), _agg_time(a, "last")) if t]

    alerts = _merge_triage([_fmt_rule(h) for h in hits(r)] + [_fmt_ai(h) for h in hits(a)])
    alerts.sort(key=lambda x: x["timestamp"] or "", reverse=True)
    return {
        "ip": ip,
        "first_seen": min(seen) if seen else None,
        "last_seen": max(seen) if seen else None,
        "rule_count": total(r),
        "ai_count": total(a),
        "users": [{"user": u, "count": n}
                  for u, n in sorted(users.items(), key=lambda kv: -kv[1])],
        "agents": [b["key"] for b in buckets("agents")],
        "blocked": next((b for b in blocked_ips()["blocked"] if b["srcip"] == ip), None),
        "alerts": alerts,
    }


# ----------------------------------------------------------------- response actions

RESPONSE_INDEX = "ai-responses"


@app.get("/api/agents")
def agents():
    """Agent inventory proxied from the Wazuh manager API."""
    try:
        return {"agents": wazuh_api.get_agents()}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Wazuh API unreachable: {e}")


class BlockRequest(BaseModel):
    agent_id: str
    srcip: str
    alert_ref: str | None = None   # what triggered this (rule id / detection desc)
    reason: str | None = None


def _audit(action, req, status, detail=""):
    doc = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "agent_id": req.agent_id,
        "srcip": req.srcip,
        "alert_ref": req.alert_ref,
        "reason": req.reason,
        "status": status,
        "detail": detail,
        "initiated_by": "dashboard",
    }
    idx = f"{RESPONSE_INDEX}-{datetime.now(timezone.utc):%Y.%m.%d}"
    client.index(index=idx, body=doc, refresh=True)
    return doc


@app.post("/api/response/block-ip")
def block_ip(req: BlockRequest):
    """Trigger firewall-drop active response on the agent, with guardrails."""
    try:
        ip = ipaddress.ip_address(req.srcip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"'{req.srcip}' is not a valid IP")

    # refuse blocks that would sever the agent's own plumbing
    if ip.is_loopback:
        _audit("block-ip", req, "refused", "loopback address")
        raise HTTPException(
            status_code=400,
            detail="Refusing to block a loopback address — that would drop the "
                   "agent's own local traffic. (Mock attacks from localhost are "
                   "not blockable; attack from another host to demo this.)",
        )

    try:
        res = wazuh_api.block_ip(req.agent_id, req.srcip)
    except Exception as e:
        _audit("block-ip", req, "failed", str(e))
        raise HTTPException(status_code=502, detail=f"Active response failed: {e}")

    doc = _audit("block-ip", req, "executed",
                 f"firewall-drop sent to agent {req.agent_id}")
    return {"ok": True, "wazuh": res.get("message"), "audit": doc}


@app.get("/api/response/log")
def response_log(limit: int = 100):
    """Audit trail of response actions taken from this console."""
    try:
        res = client.search(index=f"{RESPONSE_INDEX}-*", body={
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
        })
    except Exception:
        return {"count": 0, "actions": []}
    return {
        "count": res["hits"]["total"]["value"],
        "actions": [h["_source"] for h in res["hits"]["hits"]],
    }


@app.get("/api/response/blocked")
def blocked_ips():
    """Currently-blocked IPs, derived from the response audit log:
    executed blocks minus executed unblocks, latest state per (agent, ip).
    An unblock Wazuh did not accept keeps the row, flagged, since the drop
    may still be in place on the agent.

    action/status are matched here rather than in the query: the audit index
    is dynamically mapped, so they are text fields, and an exact term such as
    "block-ip" never matches the analyzed tokens ("block", "ip")."""
    try:
        res = client.search(index=f"{RESPONSE_INDEX}-*", body={
            "size": 5000,
            "sort": [{"timestamp": {"order": "asc"}}],
        })
    except Exception:
        return {"blocked": []}

    state = {}
    for h in res["hits"]["hits"]:
        s = h["_source"]
        key = f"{s.get('agent_id')}|{s.get('srcip')}"
        action, status = s.get("action"), s.get("status")
        if action == "block-ip" and status == "executed":
            state[key] = {**s, "unblock_unconfirmed": False}
        elif action == "unblock-ip" and key in state:
            if status == "executed":
                del state[key]
            elif status == "unconfirmed":
                state[key]["unblock_unconfirmed"] = True
    return {"blocked": [
        {"agent_id": v.get("agent_id"), "srcip": v.get("srcip"),
         "since": v.get("timestamp"), "alert_ref": v.get("alert_ref"),
         "reason": v.get("reason"), "unblock_unconfirmed": v["unblock_unconfirmed"]}
        for v in state.values()
    ]}


class UnblockRequest(BaseModel):
    agent_id: str
    srcip: str
    reason: str | None = None


@app.post("/api/response/unblock-ip")
def unblock_ip(req: UnblockRequest):
    """Best-effort unblock. Wazuh has no first-class 'undo firewall-drop' over the
    manager API — this attempts the paired delete on the agent. If Wazuh does not
    accept it, the action is audited as 'unconfirmed' and the IP stays in the
    blocked view, flagged, rather than being shown as unblocked while the drop
    may persist."""
    try:
        ipaddress.ip_address(req.srcip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"'{req.srcip}' is not a valid IP")

    audit_req = BlockRequest(agent_id=req.agent_id, srcip=req.srcip,
                             reason=req.reason or "manual unblock from dashboard")
    try:
        res = wazuh_api.unblock_ip(req.agent_id, req.srcip)
        wazuh_msg, status = res.get("message"), "executed"
        detail = f"firewall-drop delete sent to agent {req.agent_id}"
    except Exception as e:
        wazuh_msg, status = None, "unconfirmed"
        detail = (f"delete not confirmed ({e}). The drop may persist — remove it on "
                  "the agent (iptables -D) or install the firewall-drop delete "
                  "active-response, then retry.")

    doc = _audit("unblock-ip", audit_req, status, detail)
    return {"ok": True, "confirmed": status == "executed", "wazuh": wazuh_msg,
            "audit": doc}


# ----------------------------------------------------------------- triage API

class TriageUpdate(BaseModel):
    alert_id: str
    status: str = "investigating"
    assignee: str | None = None
    note: str | None = None
    false_positive: bool = False
    alert_ref: str | None = None
    alert_timestamp: str | None = None
    alert_source: str | None = None
    alert_agent: str | None = None


@app.get("/api/triage")
def triage_list(limit: int = 500):
    """Every triage record, newest first. Not read by the console yet (metrics
    query the index directly); here for a 'my queue' view and ad-hoc checks."""
    try:
        res = client.search(index=TRIAGE_INDEX, body={
            "size": limit,
            "sort": [{"updated_at": {"order": "desc"}}],
        })
    except Exception:
        return {"count": 0, "items": []}
    return {
        "count": res["hits"]["total"]["value"],
        "items": [{**h["_source"], "alert_id": h["_id"]}
                  for h in res["hits"]["hits"]],
    }


@app.post("/api/triage")
def triage_set(req: TriageUpdate):
    """Create or update the triage record for one alert (keyed by alert id)."""
    if req.status not in TRIAGE_STATES:
        raise HTTPException(status_code=400,
                            detail=f"status must be one of {list(TRIAGE_STATES)}")

    now = datetime.now(timezone.utc).isoformat()
    try:
        existing = client.get(index=TRIAGE_INDEX, id=req.alert_id)["_source"]
    except Exception:
        existing = {}

    # The first close sets resolved_at; later edits to a closed alert (a note,
    # an assignee) keep it, or MTTR would grow with every touch. Records closed
    # before this field existed fall back to their last update.
    closed = ("resolved", "false_positive")
    resolved_at = None
    if req.status in closed:
        if existing.get("status") in closed:
            resolved_at = existing.get("resolved_at") or existing.get("updated_at")
        resolved_at = resolved_at or now

    doc = {
        "status": req.status,
        "assignee": req.assignee,
        "note": req.note,
        "false_positive": req.false_positive or req.status == "false_positive",
        "alert_ref": req.alert_ref or existing.get("alert_ref"),
        "alert_timestamp": req.alert_timestamp or existing.get("alert_timestamp"),
        "alert_source": req.alert_source or existing.get("alert_source"),
        "alert_agent": req.alert_agent or existing.get("alert_agent"),
        "created_at": existing.get("created_at", now),
        "updated_at": now,
        "resolved_at": resolved_at,
    }
    client.index(index=TRIAGE_INDEX, id=req.alert_id, body=doc, refresh=True)
    return {"ok": True, "alert_id": req.alert_id, "triage": doc}


# ----------------------------------------------------------------- metrics

@app.get("/api/metrics")
def metrics(start: str | None = None, end: str | None = None,
            agent: str | None = None):
    """The rule-vs-AI comparison plus SOC workflow metrics (FP rate, MTTR).
    This endpoint is the live version of the Claim B evidence table."""
    start_dt, end_dt = _window(start, end, default_hours=168)
    scope = [_time_filter(start_dt, end_dt), *_agent_filter(agent)]
    attack = {"range": {"rule.level": {"gte": ATTACK_LEVEL}}}

    def _count(index, filters):
        try:
            return client.count(index=index,
                                body={"query": {"bool": {"filter": filters}}})["count"]
        except Exception:
            return 0

    rule_total = _count(RULE_INDEX, [*scope, attack])
    # the all-levels volume, for the alert-fatigue comparison (R8)
    rule_all = _count(RULE_INDEX, scope)
    ai_total = _count(AI_INDEX, scope)

    def _minutes(index, filters):
        try:
            res = client.search(index=index, body={
                "size": 0,
                "query": {"bool": {"filter": filters}},
                "aggs": {"m": {"date_histogram": {
                    "field": "timestamp", "fixed_interval": "1m", "min_doc_count": 1,
                }}},
            })
            return {b["key"] for b in res["aggregations"]["m"]["buckets"]}
        except Exception:
            return set()

    rule_min = _minutes(RULE_INDEX, [*scope, attack])
    ai_min = _minutes(AI_INDEX, scope)

    try:
        tres = client.search(index=TRIAGE_INDEX, body={"size": 2000})
        tdocs = [h["_source"] for h in tres["hits"]["hits"]]
    except Exception:
        tdocs = []

    # triage records carry the alert's time (and, since alert_agent was added,
    # its agent), so they can be scoped like the counts above. Under an agent
    # filter, records written before alert_agent existed are left out.
    def _in_scope(t):
        ts = _parse_ts(t.get("alert_timestamp"))
        return (ts is not None and start_dt <= ts <= end_dt
                and (not agent or t.get("alert_agent") == agent))

    tdocs = [t for t in tdocs if _in_scope(t)]
    fp = sum(1 for t in tdocs if t.get("false_positive") and t.get("alert_source") == "ai")

    resolve_secs = []
    for t in tdocs:
        if t.get("status") in ("resolved", "false_positive"):
            done = _parse_ts(t.get("resolved_at") or t.get("updated_at"))  # pre-resolved_at records
            if done:
                resolve_secs.append((done - _parse_ts(t["alert_timestamp"])).total_seconds())

    # which model in the inference slot produced them — counted from _source,
    # so it doesn't depend on how ai.model happens to be mapped
    try:
        mres = client.search(index=AI_INDEX, body={
            "size": 10000, "_source": ["ai.model"],
            "query": {"bool": {"filter": scope}},
        })
        by_model = Counter((h["_source"].get("ai") or {}).get("model") or "unknown"
                           for h in mres["hits"]["hits"])
    except Exception:
        by_model = Counter()

    return {
        "start": start_dt.isoformat(),
        "end": end_dt.isoformat(),
        "rule_alerts": rule_total,
        "rule_alerts_all_levels": rule_all,
        "ai_detections": ai_total,
        "overlap_minutes": {
            "both": len(rule_min & ai_min),
            "ai_only": len(ai_min - rule_min),
            "rule_only": len(rule_min - ai_min),
        },
        "false_positives": fp,
        "false_positive_rate": round(fp / ai_total, 3) if ai_total else 0.0,
        "mttr_seconds": round(sum(resolve_secs) / len(resolve_secs))
                        if resolve_secs else None,
        "triaged": len(tdocs),
        "ai_by_model": [{"model": m, "count": n} for m, n in by_model.most_common()],
    }


# ----------------------------------------------------------------- pipeline health

STATUS_INDEX = "ai-pipeline-status"   # one heartbeat doc per consumer (consumer_common.py)
STALE_CYCLES = 3                       # missed scoring cycles before a consumer counts as stale


def _latest_ts(index):
    """Newest document timestamp in an index pattern, as ISO, or None."""
    try:
        res = client.search(index=index, body={
            "size": 1, "sort": [{"timestamp": {"order": "desc"}}],
            "_source": ["timestamp"],
        })
    except Exception:
        return None
    hits = res["hits"]["hits"]
    ts = _parse_ts(hits[0]["_source"].get("timestamp")) if hits else None
    return ts.isoformat() if ts else None


@app.get("/api/pipeline/status")
def pipeline_status():
    """Is each part of the pipeline alive? OpenSearch, the Wazuh API, every
    detection consumer's last heartbeat, how fresh the data is, and the
    explainer — so a quiet console can be told apart from a broken pipeline."""
    now = datetime.now(timezone.utc)

    try:
        h = client.cluster.health()
        opensearch = {"ok": h["status"] in ("green", "yellow"), "status": h["status"],
                      "cluster": h.get("cluster_name")}
    except Exception as e:
        opensearch = {"ok": False, "status": "unreachable", "detail": str(e)}

    try:
        endpoints = [a for a in wazuh_api.get_agents() if a.get("id") != "000"]
        wazuh = {"ok": True, "agents_total": len(endpoints),
                 "agents_active": sum(a.get("status") == "active" for a in endpoints)}
    except Exception as e:
        wazuh = {"ok": False, "detail": str(e)}

    consumers = []
    try:
        res = client.search(index=STATUS_INDEX, body={"size": 50})
        for hit in res["hits"]["hits"]:
            s = hit["_source"]
            last = _parse_ts(s.get("last_heartbeat"))
            age = (now - last).total_seconds() if last else None
            consumers.append({
                **s,
                "age_seconds": round(age) if age is not None else None,
                "stale": age is None or age > STALE_CYCLES * (s.get("score_every_sec") or 60),
            })
    except Exception:
        pass                            # index absent: no consumer has reported yet

    return {
        "checked_at": now.isoformat(),
        "opensearch": opensearch,
        "wazuh_api": wazuh,
        "consumers": sorted(consumers, key=lambda c: c.get("consumer", "")),
        "data": {"last_rule_alert": _latest_ts(RULE_INDEX),
                 "last_ai_detection": _latest_ts(AI_INDEX)},
        "explainer": explainer.status(),
    }


# ----------------------------------------------------------------- explanation

class ExplainRequest(BaseModel):
    alert_id: str                 # "ai:<opensearch _id>"
    provider: str | None = None   # override EXPLAINER_PROVIDER for this call


@app.post("/api/explain")
def explain_alert(req: ExplainRequest):
    """Generate a plain-English analyst note for one AI detection and write it
    back onto the detection document (ai.explanation). On-demand only — the
    explainer is a reader, never in the detection path."""
    if not req.alert_id.startswith("ai:"):
        raise HTTPException(status_code=400,
                            detail="explanations are only generated for AI detections")
    hit = _get_alert_hit(req.alert_id)
    doc_id = hit["_id"]

    try:
        text, provider_used = explainer.explain(hit["_source"], provider=req.provider)
    except Exception as e:
        name = req.provider or explainer.PROVIDER
        raise HTTPException(status_code=502,
                            detail=f"explainer '{name}' failed: {e}")

    patch = {"explanation": text, **explainer.metadata(provider_used)}
    try:
        client.update(index=hit["_index"], id=doc_id,
                      body={"doc": {"ai": patch}}, refresh=True)
    except Exception as e:
        # explanation still returned to the caller even if the writeback fails
        return {"ok": True, "explanation": text, "provider": provider_used,
                "persisted": False, "detail": str(e)}

    return {"ok": True, "explanation": text, "provider": provider_used,
            "persisted": True}


class ChatMessage(BaseModel):
    role: str
    content: str


class ExplainChatRequest(BaseModel):
    alert_id: str
    messages: list[ChatMessage]
    provider: str | None = None


@app.post("/api/explain/chat")
def explain_chat(req: ExplainChatRequest):
    """Follow-up Q&A about one AI detection. The thread lives in the client;
    the server injects the detection as context and returns the next reply."""
    if not req.alert_id.startswith("ai:"):
        raise HTTPException(status_code=400,
                            detail="chat is only available for AI detections")
    if len(req.messages) > 20:
        raise HTTPException(status_code=400, detail="thread too long")
    hit = _get_alert_hit(req.alert_id)

    thread = [{"role": m.role, "content": m.content} for m in req.messages]
    try:
        reply, provider_used = explainer.chat(hit["_source"], thread,
                                              provider=req.provider)
    except Exception as e:
        name = req.provider or explainer.PROVIDER
        raise HTTPException(status_code=502, detail=f"explainer '{name}' failed: {e}")

    return {"ok": True, "reply": reply, "provider": provider_used}
