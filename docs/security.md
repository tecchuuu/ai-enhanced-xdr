# Security considerations

A SOC console is a target in its own right: it shows every alert, it can mark
them resolved, and it can push firewall blocks to endpoints. This page lists
what the system protects against today, what it does not, and how a production
deployment would differ from the lab one. Code references are to this repo.

## Threat model

| Who | What they could want |
|---|---|
| An attacker whose activity is being logged | Their text (URLs, usernames, user agents) lands in the logs, so they control part of what the console and the LLM read. Goal: run script in an analyst's browser, or mislead the explainer. |
| Anyone who can reach the console or the APIs on the network | Blind the SOC (resolve or hide alerts), or turn **Block IP** into a weapon against legitimate addresses. |
| Anyone holding the console key | Everything the console can do — there are no per-user roles. |
| Other users of the shared lab VM | Same Docker daemon, same host network (see *Limitations*). |

## What is protected

| Protection | How | Where |
|---|---|---|
| **Console access** | Optional shared key: when `DASHBOARD_API_KEY` is set, every `/api/` call except `/api/health` must send it in `X-API-Key`, compared in constant time. The console asks for it once per browser. | `dashboard/main.py` `require_api_key` |
| **Cross-origin calls** | CORS allows only listed origins (`ALLOWED_ORIGINS`, default the local dev server), only `GET`/`POST`, only the three headers the console sends. Served from the API itself, the console is same-origin and needs no CORS at all. | `main.py` CORS middleware |
| **Block IP can't be turned on ourselves** | Refused, with the reason recorded: loopback; unspecified / multicast / link-local / reserved addresses; anything in `BLOCK_ALLOWLIST`; the address the console is used from; the target agent's own address; the Wazuh manager's address; an IP already blocked on that agent (409). Private ranges are *not* refused on purpose — lab attackers come from them. | `main.py` `_block_refusal` |
| **Every response action is audited** | Block and unblock attempts are written to `ai-responses-*` — executed, failed **and refused** — with the analyst name, the alert they came from and the reason. The console's Response log shows them. | `main.py` `_audit` |
| **A human decides every block** | Blocking needs an explicit confirm in a modal naming the IP and target agent. Nothing blocks automatically — not the model, not the LLM. | `BlockIpModal.jsx` |
| **Attacker-controlled log text can't run in the browser** (stored XSS through logs — a classic SIEM attack) | React renders every field as text. The console has no `innerHTML`, `dangerouslySetInnerHTML` or markdown/HTML rendering, and builds no links from log data (the only external link is MITRE ATT&CK, from the rule's technique ID). | `dashboard/frontend/src` |
| **The LLM can't decide or act** | Flagged-or-not is computed in code from the score and the fit's own threshold, then *given* to the model. The explanation is display-only text; the model has no tools and triggers nothing. | `dashboard/explainer.py` |
| **Secrets stay out of git and images** | Credentials live in `dashboard/.env` (git-ignored). The Docker build context excludes every `.env`; containers get it as a read-only mount at run time. | `.gitignore`, `.dockerignore`, `ai-stack/ai-stack.yml` |
| **The pipeline reads only our manager** | Filebeat mounts the manager's log volume read-only, by an explicit name — a wrong name fails startup rather than reading another group's Wazuh. | `ai-stack/ai-stack.yml` |

## Limitations

Known gaps, accepted for a lab build. Each says what a production deployment
would do instead.

| Gap | Risk | Production answer |
|---|---|---|
| **Shipped default credentials.** Wazuh's compose file comes with documented default passwords for the Wazuh API user (`wazuh-wui`) and the dashboard's indexer user (`kibanaserver`); SETUP §3 changes only the indexer `admin`. | The Wazuh API can run active response directly, bypassing every console guardrail above. | Change all of them before deployment; keep them in `.env`, not the compose file. |
| **One shared key, no user accounts or roles.** | Anyone with the key can block, unblock and triage. | SSO (OIDC) with roles: viewer / analyst / responder. |
| **Analyst names are self-declared** (`X-Analyst`). | Audit entries record who *said* they did it — attribution, not authentication. | Identity from the SSO session. |
| **Plain HTTP.** | The key and the alert data cross the network unencrypted. Access is over the SIAM VPN, which covers the outer network. | HTTPS (reverse proxy with a certificate). |
| **Key kept in browser `localStorage`.** | Readable by any script on the page — acceptable only because the console has no script-injection path (above). | Short-lived session cookies (`HttpOnly`). |
| **The API uses the OpenSearch `admin` user.** | Whoever controls the API host has full control of the indexer. | A role limited to reading the alert indices and writing triage / responses. |
| **Prompt injection.** Top URLs from web detections go into the LLM prompt, and the attacker chooses them. | A crafted URL could steer the explanation. Contained: the verdict comes from code and the LLM can't act — but the text an analyst reads could still be misleading. | Mark log fields as untrusted data in the prompt; test with hostile inputs. |
| **No rate limit on key attempts.** | Guessing is possible in principle. | A long random key makes it impractical; production adds rate limiting at the proxy. |
| **Ports published on all interfaces** (indexer, Wazuh API, console). | Reachable from the VM's network, not just the VM. | Bind to an internal network; only the console's HTTPS port faces analysts. |
| **Shared lab VM.** Both groups use one Docker daemon. | Membership of the `docker` group is root-equivalent: each group can inspect and control the other's containers and volumes. Nothing in this repo can fix that. | One host (or tenant) per deployment. |

**Out of scope** for this project, listed as future work: SSO and roles,
TLS, rate limiting, a secrets manager, image signing, and a penetration test.

## Production deployment: separate the tiers

The lab runs everything on one VM. In production each tier would sit on its own
host or network segment, with firewall rules allowing only the flows below.
The point is containment: a compromised endpoint can only talk to the manager's
agent ports, and a compromised console host can reach only what the console
itself needs.

| Tier | Runs | Accepts connections from |
|---|---|---|
| Endpoints | Wazuh agent | nothing — agents only connect *out*, to the manager |
| Collection | Wazuh manager, Filebeat (×2) | endpoints on 1514/1515 (events, enrolment); the console on 55000 (Wazuh API) |
| Data + analytics (GPU) | Indexer, Kafka, detectors / Morpheus | the manager (indexer, Kafka); the console (indexer) |
| Presentation | API + console, Wazuh dashboard | analysts, over HTTPS from the SOC network or VPN only |

Separating hosts is only half of it. The console still holds credentials for
the indexer and the Wazuh API, so a compromised console reaches both — unless
those credentials are least-privilege: a read-mostly indexer role, and a Wazuh
API user limited by Wazuh's RBAC to listing agents and running the block
command. Separate hosts plus narrow credentials is what stops an attacker
pivoting from one tier to the next.
