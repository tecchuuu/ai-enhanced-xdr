# SAD Diagrams — บทที่ 3
### AI-Enhanced XDR: Wazuh + Anomaly Detection Pipeline

These diagrams describe the system **as built**, not as originally proposed. Differences from the proposal are noted where they exist.

**Rendering:** paste any block into <https://mermaid.live>, export PNG/SVG, insert into the report. Or use a Mermaid-capable editor. The source is kept here so diagrams can be regenerated when the system changes.

---

## 1. Context Diagram (DFD Level 0)

The system as a single process, with the external entities it exchanges data with.

```mermaid
flowchart LR
    EP["Monitored Endpoint<br/><i>Ubuntu host</i>"]
    AT["Attacker<br/><i>authentication attempts</i>"]
    AN["SOC Analyst"]
    GPU["GPU Environment<br/><i>SIAM AI H100 80GB / Morpheus</i><br/>(provisioned Sep–Nov 2026)"]

    SYS(("AI-Enhanced XDR<br/>System"))

    AT -->|"login attempts<br/>(normal / malicious)"| EP
    EP -->|"authentication &<br/>system log events"| SYS
    SYS -->|"agent configuration,<br/>active response"| EP

    SYS -->|"rule alerts,<br/>AI detections,<br/>anomaly scores"| AN
    AN -->|"queries, filters,<br/>severity threshold"| SYS

    SYS -.->|"feature vectors<br/>(future)"| GPU
    GPU -.->|"inference results<br/>(future)"| SYS

    classDef ext fill:#1B1926,stroke:#E8A33D,stroke-width:2px,color:#E8E5F2
    classDef sys fill:#232032,stroke:#6BE1C4,stroke-width:3px,color:#E8E5F2
    classDef fut fill:#1B1926,stroke:#8E88A6,stroke-width:1px,stroke-dasharray:5 5,color:#8E88A6
    class EP,AT,AN ext
    class SYS sys
    class GPU fut
```

**Note for the report:** the GPU environment is drawn with dashed edges to mark the boundary between the locally-built core and the Morpheus deployment on external (SIAM AI) hardware. As of Sep 2026 that hardware is **provisioned** — an H100 80GB, passthrough, available 2 Sep – 30 Nov 2026 — so this is an active deployment target, not a hypothetical one. The earlier framing (development GPU is AMD / no CUDA) no longer applies; that constraint was lifted when SIAM AI provided the H100. Once Morpheus is running on it, redraw these edges solid. *(The host also carries a BlueField-3 DPU. It is not shown because the network lane it was intended for is out of scope.)*

---

## 2. Data Flow Diagram — Level 1

The seven processes actually implemented, with the four data stores they use.

```mermaid
flowchart TD
    EP["Monitored Endpoint"]
    AN["SOC Analyst"]

    P1["1.0<br/>Log Collection<br/><i>wazuh-agent</i>"]
    P2["2.0<br/>Decode &<br/>Rule Analysis<br/><i>analysisd</i>"]
    P3["3.0<br/>Event Archiving<br/><i>logall_json</i>"]
    P4["4.0<br/>Stream Publishing<br/><i>Filebeat</i>"]
    P5["5.0<br/>Feature Engineering<br/>& Inference<br/><i>detection_consumer.py</i>"]
    P6["6.0<br/>Alert Storage<br/><i>OpenSearch</i>"]
    P7["7.0<br/>Presentation<br/><i>FastAPI + dashboard</i>"]

    D1[("D1 archives.json<br/><i>all events</i>")]
    D2[("D2 Kafka topic<br/><i>wazuh-archives</i>")]
    D3[("D3 wazuh-alerts-*<br/><i>rule alerts</i>")]
    D4[("D4 ai-detections-*<br/><i>model detections</i>")]

    EP -->|"raw log events<br/>(journald)"| P1
    P1 -->|"forwarded events<br/>:1514/tcp"| P2

    P2 -->|"matched events<br/>(rule.level assigned)"| P6
    P2 -->|"ALL decoded events<br/>(matched + unmatched)"| P3

    P3 --> D1
    D1 -->|"read (filestream)"| P4
    P4 --> D2
    D2 -->|"consume"| P5

    P5 -->|"flagged windows<br/>(source=morpheus_ai)"| P6

    P6 --> D3
    P6 --> D4
    D3 -->|"rule alerts"| P7
    D4 -->|"AI detections"| P7

    P7 -->|"merged, source-tagged<br/>alert stream"| AN

    classDef ext fill:#1B1926,stroke:#E8A33D,stroke-width:2px,color:#E8E5F2
    classDef proc fill:#232032,stroke:#6BE1C4,stroke-width:2px,color:#E8E5F2
    classDef store fill:#12111A,stroke:#8E88A6,stroke-width:2px,color:#E8E5F2
    class EP,AN ext
    class P1,P2,P3,P4,P5,P6,P7 proc
    class D1,D2,D3,D4 store
```

### The critical path in this diagram

Process **2.0** has two outputs, and the distinction is the basis of the entire project:

- **to 6.0 (alerts)** — only events that matched a rule. This is what a conventional SIEM deployment stores.
- **to 3.0 (archive)** — *every* decoded event, matched or not. This path exists only because `logall_json` is enabled.

The AI branch (3.0 → 4.0 → 5.0) consumes the **archive**, not the alerts. If it consumed alerts, it could only ever see events the ruleset had already caught, and could not detect what the ruleset misses.

### Implementation note for §3.3

Process **4.0** is a **second Filebeat instance** with a Kafka output, in its own container. The manager's built-in Filebeat cannot do it: Filebeat supports a single output at a time and that one already ships rule alerts to the indexer, so adding Kafka there would mean dropping the indexer output (and with it the Wazuh dashboard). The second instance reads the manager's archive from its log volume, read-only.

Until 2026-10-18 a Python tailer (`archive_producer.py`, `tail -F` via `docker exec`) stood in for it. It was replaced because it only read new lines from the moment it started: events written while it was down never reached Kafka. Filebeat records its read position and resumes from it.

---

## 3. Data Dictionary

Fields actually used by the system, as opposed to the full Wazuh schema.

### 3.1 Archived event (input to the AI pipeline) — `archives.json`

| Field | Type | Description | Example |
|---|---|---|---|
| `timestamp` | ISO 8601 datetime | Event time, UTC | `2026-07-19T01:47:12.084+0000` |
| `agent.id` | string(3) | Reporting agent identifier | `001` |
| `agent.name` | string | Agent hostname | `ubuntu-vm` |
| `manager.name` | string | Receiving manager | `wazuh.manager` |
| `rule.id` | string | Matched rule identifier; absent if no rule matched | `5710` |
| `rule.level` | integer 0–15 | Severity assigned by the ruleset | `5` |
| `rule.description` | string | Human-readable rule description | `sshd: Attempt to login using a non-existent user` |
| `decoder.name` | string | Decoder that parsed the event | `sshd` |
| `data.srcip` | string (IPv4) | Source address of the attempt | `127.0.0.1` |
| `data.srcuser` | string | Username attempted; **absent for PAM events** | `admin` |
| `full_log` | string | Original unparsed log line | `Failed password for invalid user admin from 127.0.0.1 port 54990 ssh2` |
| `location` | string | Collection source | `journald` |

**Note:** `data.srcuser` is populated by the `sshd` decoder but not by the `pam` decoder. The feature-engineering stage recovers the username from `full_log` by pattern match when the field is absent. See failure log Entry 9 — the omission silently produced a distinct-user count of zero, which removed the strongest slow-attack signal.

### 3.2 Derived feature vector (input to the model)

One record per time window.

| Field | Type | Derivation | Purpose |
|---|---|---|---|
| `window_start` | datetime | Event time truncated to window size | Window identity |
| `event_count` | integer | Count of auth events in the window | Volume signal — detects bursts |
| `distinct_users` | integer | Unique `srcuser` values in the window | Username-cycling signal — **rate-independent**, so it survives slow attacks |
| `max_level` | integer 0–15 | Highest `rule.level` in the window | Severity signal |
| `hour` | integer 0–23 | Hour of day, UTC | Temporal signal — off-hours activity |
| `events_per_user` | float | `event_count / distinct_users` | Repetition per identity |
| `user_diversity` | float | `distinct_users / event_count` | Breadth of identities attempted |

**Excluded:** `srcip` is constant (`127.0.0.1`) across the lab dataset and therefore carries no information. Stated as a limitation in บทที่ 5.

### 3.3 AI detection record (output) — `ai-detections-*`

| Field | Type | Description | Example |
|---|---|---|---|
| `timestamp` | ISO 8601 datetime | Start of the flagged window | `2026-07-19T01:47:00+00:00` |
| `source` | string | Origin tag distinguishing AI from rule alerts | `morpheus_ai` |
| `rule.id` | string | Custom identifier, 100000+ range per §3.5 | `100001` |
| `rule.level` | integer | Assigned severity | `10` |
| `rule.description` | string | Detection description | `AI: anomalous authentication behaviour detected` |
| `ai.model` | string | Model that produced the detection | `IsolationForest` |
| `ai.pipeline` | string | Execution path | `kafka-streaming` |
| `ai.anomaly_score` | float (negative) | Isolation Forest score; **lower is more anomalous** | `-0.7240` |
| `ai.window` | string | Aggregation window size | `60s` |
| `ai.event_count` | integer | Events in the flagged window | `5` |
| `ai.distinct_users` | integer | Distinct usernames in the window | `2` |
| `agent.name` | string | Source agent | `ubuntu-vm` |

**Design note:** `source` and the 100000+ rule ID range together implement the alert-deduplication scheme in §3.5, allowing AI detections and rule alerts to be stored together yet distinguished at query and presentation time.

---

## 4. State Diagram — Event and Alert Lifecycle

Traced from observed behaviour, not designed in the abstract.

```mermaid
stateDiagram-v2
    [*] --> Generated: authentication attempt<br/>on endpoint

    Generated --> Collected: agent reads journald
    Collected --> Decoded: manager decodes<br/>(srcip, srcuser extracted)

    Decoded --> RuleEvaluation: ruleset applied

    state RuleEvaluation <<choice>>
    RuleEvaluation --> RuleAlert: matched<br/>(rule.level assigned)
    RuleEvaluation --> Unmatched: no rule matched

    RuleAlert --> Archived: logall_json
    Unmatched --> Archived: logall_json

    note right of Archived
        Both matched and unmatched
        events reach the archive.
        This is what makes detection
        beyond the ruleset possible.
    end note

    RuleAlert --> Indexed_Rule: written to<br/>wazuh-alerts-*

    Archived --> Streamed: published to<br/>Kafka topic
    Streamed --> Buffered: consumer aggregates<br/>into time windows

    Buffered --> Buffered: fewer than 10 windows<br/>(insufficient to score)
    Buffered --> Scored: >= 10 windows buffered<br/>Isolation Forest fitted

    state Scored <<choice>>
    Scored --> Normal: within learned baseline
    Scored --> Anomalous: outside baseline<br/>(score below threshold)

    Normal --> [*]

    Anomalous --> Indexed_AI: written to ai-detections-*<br/>source=morpheus_ai, rule 100001

    Indexed_Rule --> Presented: merged by API
    Indexed_AI --> Presented: merged by API

    Presented --> Triaged: analyst reviews,<br/>ranked by score / level
    Triaged --> [*]
```

### States worth explaining in the report

**`Unmatched`** — events that match no rule. Under a default Wazuh deployment these are discarded. Enabling `logall_json` routes them to the archive, which is the precondition for detecting activity the ruleset does not describe.

**`Buffered` self-transition** — the consumer refuses to score until at least ten windows have accumulated. Isolation Forest fitted on fewer samples produces output that appears valid but is not statistically meaningful (failure log Entry 9). The guard is deliberate.

**Two paths to `Presented`** — rule alerts and AI detections converge at presentation but are stored separately and remain distinguishable by their `source` tag. This is what allows the dashboard to display the difference between them, which is the project's central comparison.

---

## Divergences from the original proposal

State these in §3.3 so the built system and the documented design agree.

| Proposal (Figure 3.1) | As built | Reason |
|---|---|---|
| Morpheus performs inference | Isolation Forest on CPU (core build); Morpheus deployment on provided H100 (Sep–Nov 2026) | Original local GPU (AMD RX 5700 XT) could not run CUDA, so the method was first proven on CPU. SIAM AI then provided an H100 80GB, so Morpheus moves from documented target to actual deployment. The CPU implementation stands as the equivalence baseline. |
| Triton in the data path | Not implemented | Triton is a model-serving service invoked by request/response, not a stage data flows through. Correction already applied to §3.3. |
| AI alerts returned via Wazuh REST API | Written directly to OpenSearch (`ai-detections-*`) | The REST API on port 55000 is a management interface, not an alert-ingestion path. |
| Pre-trained model, no training | Baseline fitted on local data | DFP requires a baseline fitted per environment; no pre-trained model can encode this system's normal behaviour. See §2.1.3. |
