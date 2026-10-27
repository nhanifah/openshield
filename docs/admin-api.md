# Admin API and dashboard

The admin server is a separate listener (default `127.0.0.1:9091`) that serves the security dashboard at `/` and a JSON API under `/api/`. It is off unless `admin.enabled: true` is set. See [configuration](configuration.md#admin-and-intelligence) for the settings.

## Authentication and roles

Every `/api/` request needs `Authorization: Bearer <token>`. Users come from three places:

- **Config file** (`admin.users`): tokens as SHA-256 digests (`token_sha256`) or read from an environment variable (`token_env`). Not editable in the dashboard.
- **Dashboard** (Settings, Users & tokens): an admin creates the user and receives a random `osk_…` token once. Only its SHA-256 digest is stored.
- **First-run setup**: when no admin exists anywhere, the server writes a one-time token to `openshield-setup-token` (mode 0600) next to the database. Sign in with it and create an admin. The setup token stops working once that admin signs in, and the file is deleted.

**Passkeys.** Any user except the setup account can add passkeys (Touch ID, Windows Hello, a phone, a security key) from the account menu, the name at the top right of the dashboard. Signing in with one returns a session token (`oss_…`) used exactly like an admin token. It lasts 12 hours, ends at sign-out, and is kept in memory only, so a restart signs everyone out. Its role is read on every request, so a role change or a deleted user takes effect at once. Passkeys must verify the user (PIN or biometric). Only public keys are stored.

Passkeys are bound to a host name, never an IP address. By default that is `localhost` with the dashboard's port, so open `http://localhost:<port>/` rather than `http://127.0.0.1:<port>/`. Behind a real domain, set the domain and the exact origins under Settings, Security. Changing the domain makes existing passkeys unusable.

Ten failed attempts per minute from one address return `429`. Failed passkey sign-ins count toward the same limit.

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

Each event has at most one current label. A label set by a person applies at once: no review step. It can be changed or removed at any time, and every change is kept as history and written to the audit log. Only AI suggestions wait for a person, who accepts, dismisses or overrides them (by setting a different label).

| Method | Path | Role | Notes |
| --- | --- | --- | --- |
| PUT | `/api/events/{id}/label` | analyst | `{"label": "FALSE_POSITIVE", "note": "…"}` sets or changes the label; `{"label": null}` removes it. (`POST` is accepted too.) |
| POST | `/api/labels/bulk` | analyst | `{"event_ids": [...], "label": "…" \| null, "note"}`, up to 500 events → `{"labeled", "not_found"}` |
| GET | `/api/labels?view=suggested\|confirmed\|history&label=` | analyst | `{"labels": [{"id","event_id","label","source","status","created_by","reviewer","note","ts","decided_ts","event": EventSummary,"ai"}], "counts": {status: n}}` |
| POST | `/api/labels/{id}/accept` | analyst | Accept an AI suggestion: the event gets that label. `409` if it was already acted on |
| POST | `/api/labels/{id}/dismiss` | analyst | Dismiss an AI suggestion; the event stays unlabeled |
| GET | `/api/datasets` | analyst | `{"datasets": [{"version","ts","actor","stats"}]}` |
| POST | `/api/datasets/export` | admin | `{"split": "temporal"\|"entity", "include_candidates": false}` → `{"version", "stats"}`. Splits hold current labels only; waiting suggestions go to a separate `candidates.jsonl` when asked |
| GET | `/api/datasets/{version}/{split}` | admin | JSONL download; `split` is `train`, `validation`, `test` or `manifest` |

Labels: `ALLOWED_NORMAL`, `ALLOWED_UNUSUAL`, `SUSPICIOUS`, `MALICIOUS_CONFIRMED`, `POLICY_VIOLATION`, `FALSE_POSITIVE`, `FALSE_NEGATIVE`, `UNKNOWN`, `NEEDS_REVIEW` (the dashboard shows them as Normal, Unusual but fine, Suspicious, Malicious, and so on).

Label `source`: `operator` (a person) or `ai`. `status`:
- `confirmed`: the event's current label.
- `superseded`: replaced by a later label.
- `cleared`: the label was removed.
- `suggested`: an AI suggestion waiting for a person.
- `accepted`, `overridden`, `dismissed`: what a person did with a suggestion. These also measure how often the model is right.

Labels from the earlier review flow (`candidate` / `approved` / `rejected`) are migrated on start: a person's labels become `confirmed`, newest per event.

### AI

| Method | Path | Role | Notes |
| --- | --- | --- | --- |
| GET | `/api/ai/status` | viewer | `{"enabled","provider","model","state":"ok"\|"degraded"\|"open"\|"disabled","queue","queue_capacity","analyzed","failures","invalid_outputs","cache_hits","dropped","tokens_in","tokens_out","cost_usd","budget":{"calls_today","max_calls_per_day"},"latency_ms":{"p50","p95"},"last_error"}` |
| POST | `/api/ai/analyze/{event_id}` | analyst | queue one event for analysis now; `{"status":"queued"}` |

### Admin audit

`GET /api/audit?limit=200` (admin) → `{"entries": [{"id","ts","actor","role","action","target","detail","result","ip"}]}`

### Settings (admin)

Values saved here replace the config file's values for that section until reset, and apply without a restart. Secret values are write-only: responses say only whether one is set, who set it and when.

| Method | Path | Body / response |
| --- | --- | --- |
| GET | `/api/settings` | `{"ai": {"values", "source", "api_key": {"set", "source"}, "running", "off_reason"}, "storage": {"values", "source"}, "challenge": {"enabled", "site_key", "secret_key_set", "cookie_secret_set", "challenge_path", "cookie_ttl"}, "security": {"encryption", "secret_key_source", "setup_mode"}}` |
| PUT | `/api/settings/ai` | `{"enabled", "model", "base_url", "timeout_ms", "requests_per_minute", "max_calls_per_day", "triggers", "send_body", "price_per_mtok_in", "price_per_mtok_out", "api_key"?}`. Leave out `api_key` to keep the current key; `""` removes it. Rebuilds the AI supervisor. |
| DELETE | `/api/settings/ai` | Back to the config file's values (a saved key stays until removed) |
| POST | `/api/settings/ai/test` | One small call with the saved settings: `{"ok", "latency_ms", "model_version"}` or `{"ok": false, "error"}` |
| PUT | `/api/settings/storage` | `{"store_all_events", "benign_sample_rate", "per_client_per_sec", "retention_days", "max_events", "body_excerpt_bytes"}` |
| DELETE | `/api/settings/storage` | Back to the config file's values |
| PUT | `/api/settings/challenge` | `{"enabled", "site_key", "secret_key"?, "challenge_path", "cookie_ttl", "rotate_cookie_secret"}`. Saved as a new policy version (or a pending change in second-approver mode). A cookie signing key is generated when none exists. |

### Users (admin)

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/api/users` | Config and dashboard users, no token data |
| POST | `/api/users` | `{"name", "role"}` → `{"name", "role", "token"}`; the token is shown only here |
| POST | `/api/users/{name}/rotate` | New token, shown once; the old one stops working |
| PUT | `/api/users/{name}` | `{"role"}`; you cannot change your own role or demote the last admin |
| DELETE | `/api/users/{name}` | Revoke; you cannot revoke yourself or the last admin |

Config-file users cannot be changed through these endpoints. Revoking a user also removes their passkeys and ends their passkey sessions.

### Geo data and geo rules

| Method | Path | Role | Notes |
| --- | --- | --- | --- |
| GET | `/api/geo` | any | Database status (loaded files, types, build dates, last download), the active geo rules and the policy version. File paths only for admins |
| POST | `/api/geo/impact` | any | Body: one rule. Requests, clients and already-blocked requests it would have matched in the last 24 h, from the statistics |
| PUT | `/api/geo/rules` | admin | `{"rules": [...]}` replaces the list as a new policy version (or a pending change with second-admin approval) |
| PUT | `/api/settings/geo` | admin | `{"city_mmdb", "asn_mmdb", "auto_update"}`; reloads at once |
| DELETE | `/api/settings/geo` | admin | Back to the config file |
| POST | `/api/geo/update` | admin | `202`: downloads DB-IP Lite City and ASN into `<data dir>/geo`, checks them and switches to them. Progress and result in `GET /api/geo` |

Events carry `country`, `region` (`ID-JK` or `ID:Jakarta`), `asn`, `as_org` and `private_ip`; the event detail adds `location` (country, region and city names). `GET /api/events` filters by `country`, `region` and `asn` (`13335` or `AS13335`). The overview adds `top_countries`, `top_regions` and `top_asns` with request and blocked counts.

### Error pages

| Method | Path | Role | Notes |
| --- | --- | --- | --- |
| GET | `/api/error-pages` | any | The `error_pages` settings, the default texts per language and page, and the placeholders |
| PUT | `/api/error-pages` | admin | The whole `error_pages` object; a new policy version (or a pending change). `{}` restores the defaults |
| POST | `/api/error-pages/preview` | admin | `{"config", "kind"}` renders a draft; returns `{"url": "/preview/<id>"}` |
| GET | `/preview/{id}` | none | The draft page, for 2 minutes, framable only by the dashboard and with scripts blocked |

### Passkeys

| Method | Path | Auth | Notes |
| --- | --- | --- | --- |
| POST | `/api/auth/passkey/options` | none | Starts a sign-in: `{"challenge", "rpId", "origins", "userVerification", "timeout"}`. The challenge is single use and expires after 5 minutes |
| POST | `/api/auth/passkey` | none | `{"id", "client_data_json", "authenticator_data", "signature"}` (base64url) → `{"token", "expires_in_s", "user", "role"}`. `401` with the reason on failure |
| POST | `/api/auth/logout` | any | Ends the caller's passkey session |
| GET | `/api/passkeys` | any | Your passkeys, the domain and the allowed origins. `?all=true` (admin) lists everyone's |
| POST | `/api/passkeys/options` | any | Starts a registration: options for `navigator.credentials.create()` |
| POST | `/api/passkeys` | any | `{"client_data_json", "attestation_object", "transports", "label"}` (base64url) |
| DELETE | `/api/passkeys/{id}` | owner or admin | Removes a passkey; it can no longer sign in |
| PUT | `/api/settings/passkeys` | admin | `{"rp_id", "origins"}`: a host name, and origins on it (https, or http for localhost) |
| DELETE | `/api/settings/passkeys` | admin | Back to `localhost` and the dashboard's port |

Accepted algorithms: ES256, EdDSA (Ed25519) and RS256. Attestation is not requested. A signature counter that does not increase on an authenticator that counts is refused as a possible cloned key.

### Encryption at rest

AES-256-GCM, with a random nonce for each value and the value's name bound as associated data. Encrypted: the AI API key, every stored policy version (it can hold the Turnstile secret, cookie signing key and private JWK members), and pending change payloads. Admin tokens are stored as SHA-256 digests. The key comes from `OPENSHIELD_SECRET_KEY` (32 bytes, base64) or the file `openshield-secret.key` next to the database, created with mode 0600 on first start; a key file readable by other users is refused.
