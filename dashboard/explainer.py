"""
Alert explanation — turns an anomaly detection into a plain-English note for a
tier-1 analyst.

This is ROADMAP rule 3: the explainer is a READER, never a pipeline stage. It
consumes an existing ai-detections-* document and produces 2-3 sentences; a
slow or dead explainer can never delay detection. It is invoked on demand (the
"Explain" button in the alert flyout), not on every detection.

Provider is selected by the EXPLAINER_PROVIDER env var (default "mock"):

  mock       Deterministic template built from the detection's own fields.
             No model, no network — works now, and is the honest fallback for
             the report ("explanation layer implemented; model deferred").
  ollama     Local model via the Ollama HTTP API (http://localhost:11434).
             The "when RAM arrives" target — a small model (llama3.2:3b,
             qwen2.5:1.5b) is enough for this task. Untested here.
  anthropic  Hosted Claude API. Fast and good, but it sends detection fields
             (source IPs, usernames) off-box — a data-egress decision to make
             explicitly in the report. Requires `pip install anthropic` and
             ANTHROPIC_API_KEY. Untested here.

Swapping providers changes one env var; the prompt and the writeback are shared.
"""

import os
from datetime import datetime, timezone

import requests

PROVIDER       = os.environ.get("EXPLAINER_PROVIDER", "mock")
OLLAMA_URL     = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL   = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")
# claude-opus-5 is the SDK default; claude-haiku-4-5 is plenty for a 2-sentence
# explanation and ~5x cheaper — set ANTHROPIC_MODEL to switch.
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-opus-5")

SYSTEM_PROMPT = (
    "You are a SOC analyst assistant. Given one anomaly detection from an "
    "unsupervised model, write 2-3 plain-English sentences for a tier-1 analyst: "
    "what the pattern looks like, why it was flagged, and what to check next. "
    "Be concrete and tie your explanation to the numbers provided. Do not invent "
    "details that are not in the data. No preamble, no bullet points."
)

CHAT_SYSTEM = (
    "You are a SOC analyst assistant helping triage ONE anomaly detection. The "
    "detection's fields are given below — answer the analyst's questions using "
    "only that data and general security knowledge. If something isn't in the "
    "data (e.g. history of this IP, other alerts), say so plainly rather than "
    "guessing. Keep answers short and practical.\n\n{context}"
)


# ----------------------------------------------------------------- prompt
def _summarise(doc):
    """Flatten an ai-detections document into a labelled block for the model."""
    ai = doc.get("ai", {})
    rule = doc.get("rule", {})
    lines = [
        f"Detection: {rule.get('description', 'anomalous behaviour')}",
        f"Heuristic category: {ai.get('category', 'unclassified')}"
        + (f" (MITRE {ai['mitre']})" if ai.get("mitre") else ""),
        f"Anomaly score: {ai.get('anomaly_score')}  "
        f"(more negative = more anomalous; ~-0.5 is the flag threshold)",
        f"Aggregation window: {ai.get('window', '60s')}",
        f"Time: {doc.get('timestamp')}",
    ]

    if ai.get("pipeline") == "web-streaming":
        lines += [
            f"Requests in window: {ai.get('request_count')}",
            f"Distinct URLs: {ai.get('distinct_urls')}",
            f"Error ratio: {ai.get('error_ratio')}",
            f"404 count: {ai.get('not_found_count')}",
            f"POST ratio: {ai.get('post_ratio')}",
        ]
        if ai.get("top_urls"):
            lines.append("Top URLs: "
                         + ", ".join(f"{u['url']} ({u['count']})" for u in ai["top_urls"]))
    else:
        lines += [
            f"Events in window: {ai.get('event_count')}",
            f"Distinct users: {ai.get('distinct_users')}",
            f"Events per user: {ai.get('events_per_user')}",
        ]

    if ai.get("top_srcips"):
        lines.append("Top source IPs: "
                     + ", ".join(f"{i['ip']} ({i['count']})" for i in ai["top_srcips"]))
    return "\n".join(lines)


# ----------------------------------------------------------------- providers
_MOCK_TEMPLATES = {
    "brute_force":
        "The model flagged a {window} window with {events_per_user} events per user "
        "across only {distinct_users} account(s) — far above the learned baseline and "
        "consistent with a brute-force attempt{ip_clause}. Check whether that source is "
        "a known host and review the targeted account(s) for lockout or a successful login.",
    "password_spraying":
        "This window shows {distinct_users} distinct users each seeing only a few "
        "attempts — a spraying pattern that stays under per-account rate thresholds. "
        "Confirm the source{ip_clause} is expected and check every sprayed account for a "
        "successful authentication.",
    "web_injection":
        "Requests in this {window} window carried SQL or script-injection markers in the "
        "URL, and the model saw an abnormal error ratio of {error_ratio}. Review the "
        "targeted endpoint's input handling and check whether any malicious request "
        "returned a 200.",
    "path_traversal":
        "URLs in this window contained directory-traversal sequences (../ or encoded "
        "equivalents). Confirm the web server did not serve any file outside its root and "
        "identify the source{ip_clause}.",
    "content_discovery":
        "{not_found_count} responses were 404s across {distinct_urls} distinct paths — "
        "automated content discovery or directory brute force. Identify the scanning "
        "source{ip_clause} and confirm nothing sensitive returned a 200.",
    "web_brute_force":
        "The window is dominated by POST requests ({post_ratio} of traffic) to very few "
        "endpoints — a login brute-force shape. Check the target form's accounts for "
        "lockouts or a successful login and confirm the source{ip_clause}.",
    "vulnerability_scan":
        "A high error ratio ({error_ratio}) spread across {distinct_urls} URLs indicates "
        "an automated vulnerability scan. Identify the source{ip_clause}; the scan itself "
        "is noise, but note anything that returned a 200.",
    "suspicious_timing":
        "Activity in this window falls outside normal working hours and deviates from the "
        "baseline the model learned for this environment. Verify whether the account and "
        "source{ip_clause} have a legitimate reason to be active now.",
}

_MOCK_GENERIC = (
    "The anomaly model scored this {window} window at {score}, past the flag threshold — "
    "the aggregate behaviour deviates from the learned baseline without matching a known "
    "signature. Review the source{ip_clause} and the events in the window to decide "
    "whether this is benign drift or the start of an incident."
)


def _mock(doc):
    ai = doc.get("ai", {})
    top = ai.get("top_srcips") or []
    ip_clause = f" ({top[0]['ip']})" if top else ""
    fields = {
        "window":          ai.get("window", "60s"),
        "score":           ai.get("anomaly_score"),
        "events_per_user": ai.get("events_per_user"),
        "distinct_users":  ai.get("distinct_users"),
        "distinct_urls":   ai.get("distinct_urls"),
        "error_ratio":     ai.get("error_ratio"),
        "not_found_count": ai.get("not_found_count"),
        "post_ratio":      ai.get("post_ratio"),
        "ip_clause":       ip_clause,
    }
    template = _MOCK_TEMPLATES.get(ai.get("category"), _MOCK_GENERIC)
    try:
        return template.format(**fields)
    except Exception:
        return _MOCK_GENERIC.format(**fields)


_CHAT_HINTS = [
    (("what should i do", "next step", "how do i respond", "remediat", "mitigat"),
     "Confirm the source is not a shared gateway/NAT, then: check the targeted "
     "asset(s) for a successful login or a served file, block the source from "
     "the Block action if it's hostile, and set this alert's triage state. "
     "Escalate if there's any sign the attempt succeeded."),
    (("false positive", "benign", "legit", "real?", "is this real"),
     "The model has no labels — it flags deviation from the learned baseline, "
     "and the contamination setting means it always flags a small fraction of "
     "windows. Judge it against the numbers: a strongly negative score plus a "
     "matching category pattern is more likely genuine; a borderline score on a "
     "sparse window is often the contamination parameter, not an attack."),
    (("history", "before", "yesterday", "seen this", "same ip", "other alert",
      "related", "previous"),
     "I only have this one detection — I can't see history, other alerts, or "
     "what this source did outside the window. Pivot in Security events / "
     "OpenSearch on the source IP over a wider range to answer that."),
    (("block", "firewall", "ban"),
     "Use the Block action on the alert — it sends Wazuh's firewall-drop active "
     "response to the agent. Check first that the IP isn't a shared egress "
     "point; unblocking is best-effort."),
]


def _chat_mock(doc, messages):
    """Deterministic stand-in: match the last question against a few intents."""
    last = (messages[-1]["content"] if messages else "").lower()
    for keys, reply in _CHAT_HINTS:
        if any(k in last for k in keys):
            return reply
    return (
        "[mock explainer — set EXPLAINER_PROVIDER=ollama or anthropic for real "
        "answers] " + _mock(doc) + " Ask about the score, the pattern, what to "
        "check, or how to respond."
    )


def _llm_ollama(system, messages):
    res = requests.post(
        f"{OLLAMA_URL}/api/chat",
        json={
            "model": OLLAMA_MODEL,
            "stream": False,
            "messages": [{"role": "system", "content": system}, *messages],
        },
        timeout=45,
    )
    res.raise_for_status()
    return res.json()["message"]["content"].strip()


def _llm_anthropic(system, messages):
    import anthropic  # optional dependency — only needed for this provider

    client = anthropic.Anthropic()
    resp = client.messages.create(
        model=ANTHROPIC_MODEL,
        max_tokens=512,
        system=system,
        output_config={"effort": "low"},
        messages=[{"role": m["role"], "content": m["content"]} for m in messages],
    )
    return "".join(b.text for b in resp.content if b.type == "text").strip()


# ----------------------------------------------------------------- entry points
def explain(doc, provider=None):
    """Return (explanation_text, provider_used) for one ai-detections document."""
    name = provider or PROVIDER
    if name == "mock":
        return _mock(doc), name
    if name == "ollama":
        return _llm_ollama(SYSTEM_PROMPT, [{"role": "user", "content": _summarise(doc)}]), name
    if name == "anthropic":
        return _llm_anthropic(SYSTEM_PROMPT, [{"role": "user", "content": _summarise(doc)}]), name
    raise ValueError(f"unknown explainer provider '{name}' "
                     f"(expected mock, ollama, or anthropic)")


def chat(doc, messages, provider=None):
    """Answer a follow-up thread about one detection.

    `messages` is the running [{role, content}, ...] thread from the flyout
    (roles: user / assistant). The detection is injected as system context;
    the thread is not persisted server-side.
    """
    name = provider or PROVIDER
    if not messages or messages[-1].get("role") != "user":
        raise ValueError("last message must be from the user")
    if name == "mock":
        return _chat_mock(doc, messages), name
    system = CHAT_SYSTEM.format(context=_summarise(doc))
    if name == "ollama":
        return _llm_ollama(system, messages), name
    if name == "anthropic":
        return _llm_anthropic(system, messages), name
    raise ValueError(f"unknown explainer provider '{name}' "
                     f"(expected mock, ollama, or anthropic)")


def metadata(provider_used):
    return {
        "explained_by": provider_used,
        "explained_at": datetime.now(timezone.utc).isoformat(),
    }
