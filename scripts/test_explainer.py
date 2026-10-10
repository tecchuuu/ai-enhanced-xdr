#!/usr/bin/env python3
"""Exercise the explainer against a representative detection, per provider.

Lets the explanation layer be tested on its own — no Wazuh, no Kafka, no
OpenSearch — which is how the ollama provider was validated on the SIAM H100.
The two sample documents are shaped exactly like real ai-detections-* docs
(one per lane), so what the model sees here is what it sees in production.

Run:  python scripts/test_explainer.py [provider ...]      # default: mock ollama
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "dashboard"))
import explainer  # noqa: E402

AUTH_DOC = {
    "timestamp": "2026-10-10T13:05:00+00:00",
    "rule": {"id": "100001", "level": 10,
             "description": "AI: anomalous authentication pattern — brute force"},
    "ai": {
        "model": "Autoencoder", "pipeline": "auth-streaming", "window": "60s",
        "anomaly_score": -0.71, "category": "brute_force", "mitre": "T1110",
        "event_count": 34, "distinct_users": 2, "events_per_user": 17.0,
        "top_srcips": [{"ip": "192.168.1.133", "count": 34}],
    },
}

WEB_DOC = {
    "timestamp": "2026-10-10T13:12:00+00:00",
    "rule": {"id": "100002", "level": 12,
             "description": "AI: anomalous web traffic — many 404s across many paths"},
    "ai": {
        "model": "Autoencoder", "pipeline": "web-streaming", "window": "60s",
        "anomaly_score": -0.64, "category": "content_discovery", "mitre": "T1595.003",
        "request_count": 412, "distinct_urls": 388, "error_ratio": 0.94,
        "not_found_count": 371, "post_ratio": 0.02,
        "top_srcips": [{"ip": "192.168.1.133", "count": 412}],
        "top_urls": [{"url": "/admin", "count": 3}, {"url": "/.git/config", "count": 2}],
    },
}

providers = sys.argv[1:] or ["mock", "ollama"]

for provider in providers:
    print(f"\n{'=' * 72}\nPROVIDER: {provider}")
    if provider == "ollama":
        print(f"model: {explainer.OLLAMA_MODEL}  endpoint: {explainer.OLLAMA_URL}")
    for label, doc in (("auth / brute_force", AUTH_DOC),
                       ("web / content_discovery", WEB_DOC)):
        print(f"\n--- {label} ---")
        t0 = time.perf_counter()
        try:
            text, used = explainer.explain(doc, provider=provider)
        except Exception as exc:
            print(f"FAILED: {type(exc).__name__}: {exc}")
            continue
        print(f"[{used}, {time.perf_counter() - t0:.2f}s]\n{text}")

    # the follow-up path shares the provider but a different system prompt
    print("\n--- follow-up question (chat) ---")
    t0 = time.perf_counter()
    try:
        text, used = explainer.chat(
            AUTH_DOC,
            [{"role": "user", "content": "Is this a false positive? What should I check first?"}],
            provider=provider,
        )
        print(f"[{used}, {time.perf_counter() - t0:.2f}s]\n{text}")
    except Exception as exc:
        print(f"FAILED: {type(exc).__name__}: {exc}")
