# Admin API and dashboard

The admin server is a separate listener (default `127.0.0.1:9091`) that serves the security dashboard at `/` and a JSON API under `/api/`. It is off unless `admin.enabled: true` is set. See [configuration](configuration.md#admin-and-intelligence) for the settings.

## Authentication and roles

Every `/api/` request needs `Authorization: Bearer <token>`. Tokens are configured as SHA-256 hex digests (`token_sha256`) or read from an environment variable (`token_env`), never stored in clear in the config. Ten failed attempts per minute from one address return `429`.

| Role | Can |
| --- | --- |
| `viewer` | Read overview, events, alerts, rules, policy, controls, AI status |
| `analyst` | Viewer, plus label events, review labels, acknowledge alerts, request AI analysis and summaries |
| `operator` | Analyst, plus add and remove IP blocks and allows |
| `admin` | Operator, plus validate, simulate, apply and roll back policy, approve changes, export datasets, read the admin audit log |

Every state-changing call is written to the admin audit log with the actor, role, action, target and result.

When `admin.require_second_approver: true`, policy applies, rollbacks and IP blocks longer than `admin.approval_threshold_s` create a pending change that a **different** admin must approve.

## Conventions

- Times are Unix epoch **milliseconds** (`ts`).
- Errors: non-2xx status with `{"error": "message"}`.
- `range` accepts `5m`, `15m`, `1h`, `6h`, `24h`, `7d`.
- All text fields from requests (paths, headers, bodies, AI explanations) are untrusted. The dashboard renders them as text, never as HTML.

## Endpoints

### Health

| Method | Path | Auth | Response |
| --- | --- | --- | --- |
| GET | `/healthz` | none | `{"status":"ok"}` |
| GET | `/readyz` | none | `{"ready":true,"components":{"store":"ok","policy":"ok","ai":"disabled"\|"ok"\|"degraded"\|"open"}}` |
| GET | `/api/me` | any | `{"name":"alice","role":"admin"}` |

### Overview

`GET /api/overview?range=1h`

```json
{
  "range_ms": 3600000, "bucket_ms": 60000, "now": 1761400000000,
  "totals": {"requests": 1200, "pass": 1000, "allow": 50, "block": 120, "challenge": 30,
             "suspicious": 14, "status_5xx": 3, "bytes_in": 1048576, "bytes_out": 9437184},
  "rps_current": 21.5,
  "latency_ms": {"p50": 1.2, "p95": 4.8, "p99": 9.9},
  "series": [{"t": 1761396400000, "total": 20, "pass": 17, "allow": 0, "block": 2, "challenge": 1,
              "suspicious": 0, "p95_ms": 4.1}],
  "top_ips": [{"ip": "203.0.113.5", "count": 300, "blocked": 120, "country": "NL", "anomaly_score": 0.82}],
  "top_paths": [{"path": "/login", "count": 400, "blocked": 90}],
  "top_rules": [{"id": "block-sqli-args", "count": 80}],
  "status_codes": {"2xx": 1000, "3xx": 10, "4xx": 187, "5xx": 3},
  "methods": {"GET": 900, "POST": 300},
  "countries": {"NL": 300, "US": 200},
  "ai": {"state": "ok", "queue": 0, "analyzed": 40, "failures": 1, "cache_hits": 12, "cost_usd": 0.004}
}
```

`suspicious` counts events with `anomaly_score >= 0.5` or an AI verdict of `suspicious`/`malicious`.

The overview also carries `alerts_open` (unresolved alerts: `open` total plus counts per severity, and `acknowledged`), `detection_only` (monitoring-only mode), `policy_version`, and `pipeline` (event queue and storage counters, including `dropped` and `store_dropped`). The dashboard's status line is built from these.

### Events

`GET /api/events?limit=100&before=<ts>&action=block&ip=1.2.3.4&path=/login&rule=block-sqli-args&q=text&min_anomaly=0.5&ai_category=malicious`

```json
{"events": [EventSummary], "next_before": 1761399999000}
```

`EventSummary`:

```json
{"id": "uuid", "ts": 1761400000000, "client_ip": "203.0.113.5", "country": "NL",
 "method": "GET", "host": "app.example", "path": "/search", "query": "q=%5BREDACTED%5D",
 "status": 403, "duration_ms": 0.8, "action": "block", "rules": ["block-sqli-args"],
 "anomaly_score": 0.7,
 "ai": {"category": "malicious", "risk": 0.92, "confidence": 0.8, "recommended_action": "block_candidate"},
 "label": "MALICIOUS_CONFIRMED"}
```

`ai` and `label` may be `null`.

`GET /api/events/{id}` returns `EventSummary` fields plus:

```json
{"protocol": "HTTP/1.1", "bytes_in": 0, "bytes_out": 9, "user_agent": "curl/8",
 "headers": {"user-agent": "curl/8", "authorization": "[REDACTED] len=20"},
 "body_excerpt": null, "scores": {"sqli": 10},
 "matched_rules": [{"id": "block-sqli-args", "action": "block"}],
 "anomaly": {"score": 0.7, "reasons": [{"kind": "rate_spike", "detail": "52 req/10s vs baseline 3", "weight": 0.5}]},
 "ai_verdicts": [{"ts": 0, "model": "gemini-…", "model_version": "…", "prompt_version": "v1",
                  "category": "malicious", "risk": 0.92, "confidence": 0.8,
                  "explanation": "…", "evidence": ["query.q", "rule:block-sqli-args"],
                  "recommended_action": "block_candidate", "latency_ms": 900, "cached": false,
                  "status": "ok"}],
 "labels": [{"id": 3, "label": "MALICIOUS_CONFIRMED", "source": "operator", "reviewer": "alice",
             "status": "approved", "note": "", "ts": 0}],
 "related": [EventSummary],
 "client": {"ip": "203.0.113.5", "first_seen": 0, "requests": 300, "blocked": 120,
            "anomaly_score": 0.82, "blocked_now": false}}
```

### Live stream

`GET /api/stream` returns `text/event-stream`. Use `fetch` with the `Authorization` header and read the body stream (`EventSource` cannot send headers).

| SSE event | Data |
| --- | --- |
| `event` | `EventSummary` for every recorded request (sampled to at most `admin.stream_max_per_sec` per second) |
| `stats` | Every second: `{"t": ts, "total": 30, "pass": 25, "allow": 0, "block": 4, "challenge": 1, "suspicious": 1, "p95_ms": 3.1}` |
| `alert` | `Alert` when one is raised |
| `ai` | `{"event_id": "uuid", "ai": {...}}` when a verdict arrives |

### Alerts

`GET /api/alerts?status=open` → `{"alerts": [Alert]}`

```json
{"id": 7, "ts": 0, "kind": "rate_spike", "subject": "203.0.113.5", "severity": "high",
 "detail": {"rate_10s": 52, "baseline": 3}, "status": "open", "summary": null, "count": 4}
```

`kind`: `rate_spike`, `scanning`, `attack_burst`, `error_burst`, `traffic_spike`, `ai_malicious`, `ai_degraded`. `severity`: `low`, `medium`, `high`, `critical`.

| Method | Path | Role | Effect |
| --- | --- | --- | --- |
| POST | `/api/alerts/{id}/ack` | analyst | status `ack` |
| POST | `/api/alerts/{id}/resolve` | analyst | status `resolved` |
| POST | `/api/alerts/{id}/summarize` | analyst | AI incident summary; `{"summary": "…"}` |

### Controls (dynamic IP blocks and allows)

`GET /api/controls` → `{"ip_blocks": [Control], "ip_allows": [Control]}`; `Control` = `{"value": "203.0.113.0/24", "expires_at": ts|null, "reason": "…", "actor": "alice", "created_at": ts}`.

| Method | Path | Role | Body |
| --- | --- | --- | --- |
| POST | `/api/controls/ip-block` | operator | `{"value": "1.2.3.4" or CIDR, "ttl_s": 3600, "reason": "…"}` |
| DELETE | `/api/controls/ip-block/{value}` | operator | — (`/` in a CIDR is URL-encoded) |
| POST | `/api/controls/ip-allow` | operator | same as block; an allowed address is exempt from dynamic blocks |
| DELETE | `/api/controls/ip-allow/{value}` | operator | — |

A dynamic block returns `403` before rules run and is recorded with the rule id `dynamic:ip_block`. Responses are `{"status": "applied"}` or, with second-approver mode, `{"status": "pending", "change_id": 4}`.

### Rules and policy

| Method | Path | Role | Notes |
| --- | --- | --- | --- |
| GET | `/api/rules` | viewer | `{"rules": [{"id","ruleset","phase","action","enabled","description","hits_1h"}], "detection_only": false, "version": 3}` |
| GET | `/api/policy` | viewer | `{"version": 3, "yaml": "…", "applied_at": ts, "actor": "alice", "source": "api"}` |
| GET | `/api/policy/versions` | viewer | `{"versions": [{"version","ts","actor","comment","source","status","rule_count"}]}` |
| GET | `/api/policy/versions/{v}` | viewer | `{"version": 2, "yaml": "…"}` |
| POST | `/api/policy/validate` | admin | `{"yaml"}` → `{"ok": true, "rule_count": 9}` or `{"ok": false, "error": "…"}` |
| POST | `/api/policy/simulate` | admin | `{"yaml"}` → `{"replayed": 2000, "changed": 12, "current": {"block": 40, …}, "candidate": {"block": 52, …}, "diffs": [{"event_id","path","current","candidate","rule"}]}` |
| POST | `/api/policy/apply` | admin | `{"yaml", "comment"}` → `{"status": "applied", "version": 4}` or pending |
| POST | `/api/policy/rollback` | admin | `{"version": 2, "comment"}` → applied or pending |
| GET | `/api/changes?status=pending` | admin | `{"changes": [{"id","ts","kind","summary","requested_by","status","decided_by"}]}` |
| POST | `/api/changes/{id}/approve` | admin | must differ from the requester |
| POST | `/api/changes/{id}/reject` | admin | — |

Secret values in a policy (`turnstile_secret_key`, `cookie_secret`, and private JWK members) are never returned: `GET /api/policy` and `GET /api/policy/versions/{v}` show `__secret_unchanged__` in their place. Sending that placeholder back to validate, simulate or apply keeps the current value; a placeholder where the current policy has no value is rejected.

The policy YAML holds only WAF keys (`rulesets`, `lists`, `scores`, `detection_only`, …). Server keys such as `listen` are rejected. Switching on `detection_only` is how to put the firewall into monitoring-only mode. Applying a policy resets rate-limit counters.

### Labels and datasets

| Method | Path | Role | Notes |
| --- | --- | --- | --- |
| POST | `/api/events/{id}/label` | analyst | `{"label": "FALSE_POSITIVE", "note": "…"}`; label must be one of the values below |
| GET | `/api/labels?status=candidate` | analyst | `{"labels": [{"id","event_id","label","source","reviewer","status","note","ts","event": EventSummary}]}` |
| POST | `/api/labels/{id}/approve` | analyst | a reviewer cannot approve their own label |
| POST | `/api/labels/{id}/reject` | analyst | — |
| GET | `/api/datasets` | analyst | `{"datasets": [{"version","ts","actor","stats"}]}` |
| POST | `/api/datasets/export` | admin | `{"split": "temporal"\|"entity", "include_candidates": false}` → `{"version", "stats"}` |
| GET | `/api/datasets/{version}/{split}` | admin | JSONL download; `split` is `train`, `validation`, `test` or `manifest` |

Labels: `ALLOWED_NORMAL`, `ALLOWED_UNUSUAL`, `SUSPICIOUS`, `MALICIOUS_CONFIRMED`, `POLICY_VIOLATION`, `FALSE_POSITIVE`, `FALSE_NEGATIVE`, `UNKNOWN`, `NEEDS_REVIEW`.

Label `source`: `operator` (a person), `ai_candidate` (a model suggestion, never ground truth until a person approves it), `rule` (derived from a rule match). `status`: `candidate`, `approved`, `rejected`.

### AI

| Method | Path | Role | Notes |
| --- | --- | --- | --- |
| GET | `/api/ai/status` | viewer | `{"enabled","provider","model","state":"ok"\|"degraded"\|"open"\|"disabled","queue","queue_capacity","analyzed","failures","invalid_outputs","cache_hits","dropped","tokens_in","tokens_out","cost_usd","budget":{"calls_today","max_calls_per_day"},"latency_ms":{"p50","p95"},"last_error"}` |
| POST | `/api/ai/analyze/{event_id}` | analyst | queue one event for analysis now; `{"status":"queued"}` |

### Admin audit

`GET /api/audit?limit=200` (admin) → `{"entries": [{"id","ts","actor","role","action","target","detail","result","ip"}]}`
