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
             Live on the SIAM H100 since 2026-10-10 with gemma3:12b (R15).
             Detection fields never leave the box. Note that Ollama's default
             131072-token context must be lowered (OLLAMA_CONTEXT_LENGTH) or
             model load crashes — see failure log; 4096 is ample here.
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
OLLAMA_MODEL   = os.environ.get("OLLAMA_MODEL", "gemma3:12b")
# claude-opus-5 is the SDK default; claude-haiku-4-5 is plenty for a 2-sentence
# explanation and ~5x cheaper — set ANTHROPIC_MODEL to switch.
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-opus-5")
# Detections now carry the cutoff their own fit used (ai.threshold). This is the
# fallback for ones written before that field existed: roughly where the
# consumers flag. Either way the verdict is computed here, not left to the model.
FLAG_THRESHOLD  = float(os.environ.get("FLAG_THRESHOLD", "-0.5"))

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
def _score_line(score, threshold=None):
    """State the score's relation to the threshold outright.

    Left to infer it, a small model reads "-0.71" against a "-0.5 threshold"
    and reports the detection as borderline — the sign flips the comparison and
    it gets it backwards (observed with gemma3:12b, R15). Computing the verdict
    here costs nothing and removes the only grounding error seen in testing.
    `threshold` is the cutoff recorded by the fit that flagged the window.

    Both are given flipped (higher = more unusual), the way the console shows
    them, so the assistant's numbers match the screen the analyst is reading.
    """
    if score is None:
        return "Anomaly score: unavailable"
    cutoff = FLAG_THRESHOLD if threshold is None else threshold
    margin = cutoff - score                  # positive = past the threshold
    shown, shown_cutoff = -score, -cutoff
    verdict = (f"{margin:.2f} ABOVE the flag cutoff of {shown_cutoff:.2f} — a clear detection"
               if margin > 0.1 else
               f"only {abs(margin):.2f} from the flag cutoff of {shown_cutoff:.2f} — borderline")
    return (f"Anomaly score: {shown:.2f} (higher = more unusual). "
            f"This score is {verdict}.")


def _baseline_lines(ai):
    """This minute next to what the un-flagged minutes looked like in the same
    fit — the 'why' behind the score, so the model needn't guess what normal is."""
    feats, base = ai.get("features") or {}, ai.get("baseline") or {}
    lines = []
    for name, value in feats.items():
        b = base.get(name)
        if b and name != "hour":
            lines.append(f"  {name}: {value} (typical {b['median']}, usually below {b['p95']})")
    if not lines:
        return []
    n = ai.get("windows_scored")
    return [f"This minute vs the normal minutes{f' (of {n} scored)' if n else ''}:", *lines]


def _summarise(doc):
    """Flatten an ai-detections document into a labelled block for the model."""
    ai = doc.get("ai", {})
    rule = doc.get("rule", {})
    lines = [
        f"Detection: {rule.get('description', 'anomalous behaviour')}",
        f"Heuristic category: {ai.get('category', 'unclassified')}"
        + (f" (MITRE {ai['mitre']})" if ai.get("mitre") else ""),
        _score_line(ai.get("anomaly_score"), ai.get("threshold")),
        f"Time span: one minute ({ai.get('window', '60s')})",
        f"Time: {doc.get('timestamp')}",
    ]

    if ai.get("pipeline") == "web-streaming":
        lines += [
            f"Requests in this minute: {ai.get('request_count')}",
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
            f"Events in this minute: {ai.get('event_count')}",
            f"Distinct users: {ai.get('distinct_users')}",
            f"Events per user: {ai.get('events_per_user')}",
        ]

    if ai.get("top_srcips"):
        lines.append("Top source IPs: "
                     + ", ".join(f"{i['ip']} ({i['count']})" for i in ai["top_srcips"]))
    lines += _baseline_lines(ai)
    return "\n".join(lines)


# ----------------------------------------------------------------- providers
_MOCK_TEMPLATES = {
    "brute_force":
        "The model flagged a minute with {events_per_user} events per user "
        "across only {distinct_users} account(s) — far above the learned baseline and "
        "consistent with a brute-force attempt{ip_clause}. Check whether that source is "
        "a known host and review the targeted account(s) for lockout or a successful login.",
    "password_spraying":
        "This minute shows {distinct_users} distinct users each seeing only a few "
        "attempts — a spraying pattern that stays under per-account rate thresholds. "
        "Confirm the source{ip_clause} is expected and check every sprayed account for a "
        "successful authentication.",
    "web_injection":
        "Requests in this minute carried SQL or script-injection markers in the "
        "URL, and the model saw an abnormal error ratio of {error_ratio}. Review the "
        "targeted endpoint's input handling and check whether any malicious request "
        "returned a 200.",
    "path_traversal":
        "URLs in this minute contained directory-traversal sequences (../ or encoded "
        "equivalents). Confirm the web server did not serve any file outside its root and "
        "identify the source{ip_clause}.",
    "content_discovery":
        "{not_found_count} responses were 404s across {distinct_urls} distinct paths — "
        "automated content discovery or directory brute force. Identify the scanning "
        "source{ip_clause} and confirm nothing sensitive returned a 200.",
    "web_brute_force":
        "This minute is dominated by POST requests ({post_ratio} of traffic) to very few "
        "endpoints — a login brute-force shape. Check the target form's accounts for "
        "lockouts or a successful login and confirm the source{ip_clause}.",
    "vulnerability_scan":
        "A high error ratio ({error_ratio}) spread across {distinct_urls} URLs indicates "
        "an automated vulnerability scan. Identify the source{ip_clause}; the scan itself "
        "is noise, but note anything that returned a 200.",
    "suspicious_timing":
        "Activity in this minute falls outside normal working hours and deviates from the "
        "baseline the model learned for this environment. Verify whether the account and "
        "source{ip_clause} have a legitimate reason to be active now.",
}

_MOCK_GENERIC = (
    "The anomaly model scored this minute at {score} (higher = more unusual), past its "
    "flag cutoff — the activity deviates from the learned baseline without matching a "
    "Wazuh rule. Review the source{ip_clause} and the events in this minute to decide "
    "whether this is benign drift or the start of an incident."
)


def _mock(doc):
    ai = doc.get("ai", {})
    top = ai.get("top_srcips") or []
    ip_clause = f" ({top[0]['ip']})" if top else ""
    fields = {
        # shown flipped, as in the console: higher = more unusual
        "score":           (f"{-ai['anomaly_score']:.2f}"
                            if isinstance(ai.get("anomaly_score"), (int, float)) else "n/a"),
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
     "and it always flags a small share of the most unusual minutes. Judge it "
     "against the numbers: a score clearly above the cutoff plus a matching "
     "attack-type pattern is more likely genuine; a borderline score on a quiet "
     "minute is often just that fixed share, not an attack."),
    (("history", "before", "yesterday", "seen this", "same ip", "other alert",
      "related", "previous"),
     "I only have this one detection — I can't see history, other alerts, or "
     "what this source did outside this minute. Click the source IP (or search "
     "it under Wazuh alerts) over a wider time range to answer that."),
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


def status():
    """Provider, model, and whether it can answer right now — for the
    dashboard's Pipeline page. Cheap: lists Ollama's models, never generates,
    and never calls the hosted API (that would cost tokens on every poll)."""
    if PROVIDER == "mock":
        return {"provider": "mock", "model": None, "ok": True,
                "detail": "template explanations, no model"}
    if PROVIDER == "ollama":
        try:
            res = requests.get(f"{OLLAMA_URL}/api/tags", timeout=2)
            res.raise_for_status()
            names = [m.get("name") for m in res.json().get("models", [])]
        except Exception as e:
            return {"provider": "ollama", "model": OLLAMA_MODEL, "ok": False,
                    "detail": f"Ollama unreachable at {OLLAMA_URL} ({e})"}
        pulled = OLLAMA_MODEL in names
        return {"provider": "ollama", "model": OLLAMA_MODEL, "ok": pulled,
                "detail": "model pulled" if pulled else f"{OLLAMA_MODEL} not pulled"}
    if PROVIDER == "anthropic":
        has_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
        return {"provider": "anthropic", "model": ANTHROPIC_MODEL, "ok": has_key,
                "detail": "API key set" if has_key else "ANTHROPIC_API_KEY not set"}
    return {"provider": PROVIDER, "model": None, "ok": False,
            "detail": "unknown provider (expected mock, ollama or anthropic)"}
