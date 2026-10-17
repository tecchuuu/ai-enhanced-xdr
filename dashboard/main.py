import ipaddress
import os
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
        "category":    ai.get("category"),
        "mitre":       ai.get("mitre"),
        "srcip":       top_ips[0]["ip"] if top_ips else None,
        "top_srcips":  top_ips,
        "explanation": ai.get("explanation"),
        "explained_by": ai.get("explained_by"),
    }


def _get_detection(doc_id):
    """One ai-detections hit by _id, or an HTTPException the caller lets raise."""
    try:
        res = client.search(index=AI_INDEX, body={
            "size": 1, "query": {"ids": {"values": [doc_id]}},
        })
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"OpenSearch query failed: {e}")
    hits = res["hits"]["hits"]
    if not hits:
        raise HTTPException(status_code=404, detail="detection not found")
    return hits[0]


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
def rule_alerts(limit: int = 50, min_level: int = 0):
    """Rule-based alerts from Wazuh."""
    body = {
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"range": {"rule.level": {"gte": min_level}}},
    }
    res = client.search(index=RULE_INDEX, body=body)
    return {
        "count": res["hits"]["total"]["value"],
        "alerts": _merge_triage([_fmt_rule(h) for h in res["hits"]["hits"]]),
    }

@app.get("/api/stats")
def stats():
    """All-time totals for the legacy split view (dashboard.html). The console
    reads /api/metrics instead, which is time-ranged."""
    total = client.count(index=RULE_INDEX)["count"]
    try:
        ai_total = client.count(index=AI_INDEX)["count"]
    except Exception:
        ai_total = 0

    return {"rule_alerts": total, "ai_alerts": ai_total}

@app.get("/api/alerts/ai")
def ai_alerts(limit: int = 50):
    """AI-detected anomalies (source=morpheus_ai)."""
    try:
        res = client.search(index=AI_INDEX, body={
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
        })
    except Exception:
        return {"count": 0, "alerts": []}      # index may not exist yet

    return {
        "count": res["hits"]["total"]["value"],
        "alerts": _merge_triage([_fmt_ai(h) for h in res["hits"]["hits"]]),
    }

@app.get("/api/alerts/histogram")
def histogram(hours: int = 24, interval: str = "30m", min_level: int = ATTACK_LEVEL):
    """Alert counts over time, split rule vs AI — feeds the overview time chart."""
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)

    def bucket_counts(index, extra_filters):
        body = {
            "size": 0,
            "query": {"bool": {"filter": [
                {"range": {"timestamp": {"gte": start.isoformat()}}},
                *extra_filters,
            ]}},
            "aggs": {"t": {"date_histogram": {
                "field": "timestamp",
                "fixed_interval": interval,
                "min_doc_count": 0,
                "extended_bounds": {
                    "min": int(start.timestamp() * 1000),
                    "max": int(now.timestamp() * 1000),
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
    return {"buckets": [
        {"time": k, "rule": rule.get(k, 0), "ai": ai.get(k, 0)} for k in keys
    ]}


@app.get("/api/alerts/top_srcips")
def top_srcips(hours: int = 24, size: int = 10):
    """Most active source IPs across all alert levels — feeds the overview bar chart."""
    start = datetime.now(timezone.utc) - timedelta(hours=hours)
    body = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"timestamp": {"gte": start.isoformat()}}},
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
def combined(limit: int = 100):
    """Both streams merged, newest first — what the dashboard renders."""
    rules = rule_alerts(limit=limit, min_level=ATTACK_LEVEL)["alerts"]
    ai    = ai_alerts(limit=limit)["alerts"]
    merged = sorted(rules + ai, key=lambda a: a["timestamp"] or "", reverse=True)
    return {
        "rule_count": len(rules),
        "ai_count":   len(ai),
        "alerts":     merged[:limit],
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
        "created_at": existing.get("created_at", now),
        "updated_at": now,
        "resolved_at": resolved_at,
    }
    client.index(index=TRIAGE_INDEX, id=req.alert_id, body=doc, refresh=True)
    return {"ok": True, "alert_id": req.alert_id, "triage": doc}


# ----------------------------------------------------------------- metrics

@app.get("/api/metrics")
def metrics(hours: int = 168):
    """The rule-vs-AI comparison plus SOC workflow metrics (FP rate, MTTR).
    This endpoint is the live version of the Claim B evidence table."""
    now = datetime.now(timezone.utc)
    start = (now - timedelta(hours=hours)).isoformat()

    def _count(index, filters):
        try:
            return client.count(index=index,
                                body={"query": {"bool": {"filter": filters}}})["count"]
        except Exception:
            return 0

    rule_total = _count(RULE_INDEX, [
        {"range": {"timestamp": {"gte": start}}},
        {"range": {"rule.level": {"gte": ATTACK_LEVEL}}},
    ])
    # the all-levels volume, for the alert-fatigue comparison (R8)
    rule_all = _count(RULE_INDEX, [{"range": {"timestamp": {"gte": start}}}])
    ai_total = _count(AI_INDEX, [{"range": {"timestamp": {"gte": start}}}])

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

    rule_min = _minutes(RULE_INDEX, [
        {"range": {"timestamp": {"gte": start}}},
        {"range": {"rule.level": {"gte": ATTACK_LEVEL}}},
    ])
    ai_min = _minutes(AI_INDEX, [{"range": {"timestamp": {"gte": start}}}])

    try:
        tres = client.search(index=TRIAGE_INDEX, body={"size": 2000})
        tdocs = [h["_source"] for h in tres["hits"]["hits"]]
    except Exception:
        tdocs = []

    def _in_window(ts):
        return bool(ts) and ts >= start

    fp = sum(1 for t in tdocs
             if t.get("false_positive") and t.get("alert_source") == "ai"
             and _in_window(t.get("alert_timestamp")))

    resolve_secs = []
    for t in tdocs:
        if t.get("status") in ("resolved", "false_positive") \
           and _in_window(t.get("alert_timestamp")):
            try:
                a = datetime.fromisoformat(t["alert_timestamp"].replace("Z", "+00:00"))
                done = t.get("resolved_at") or t["updated_at"]   # pre-resolved_at records
                r = datetime.fromisoformat(done.replace("Z", "+00:00"))
                resolve_secs.append((r - a).total_seconds())
            except Exception:
                pass

    return {
        "window_hours": hours,
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
    doc_id = req.alert_id.split(":", 1)[1]
    hit = _get_detection(doc_id)

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
    hit = _get_detection(req.alert_id.split(":", 1)[1])

    thread = [{"role": m.role, "content": m.content} for m in req.messages]
    try:
        reply, provider_used = explainer.chat(hit["_source"], thread,
                                              provider=req.provider)
    except Exception as e:
        name = req.provider or explainer.PROVIDER
        raise HTTPException(status_code=502, detail=f"explainer '{name}' failed: {e}")

    return {"ok": True, "reply": reply, "provider": provider_used}
