# Configuration

OpenShield reads YAML from `config.yaml`, or the file passed with `-c`:

```bash
./target/release/openshield -c config.yaml
```

Only `listen` and `upstream` are required. Without a root ruleset, OpenShield forwards requests without WAF inspection.

The proxy, TLS, logging and metrics settings below belong to the proxy. Every other key configures the WAF itself, and is the part another host of the `openshield-core` library consumes.

```yaml
listen: "127.0.0.1:8080"
upstream: "http://127.0.0.1:3000"
```

Relative file paths resolve from the directory where OpenShield starts.

## Proxy settings

| Setting                   | Default                        | Description                                                                            |
| ------------------------- | ------------------------------ | -------------------------------------------------------------------------------------- |
| `listen`                  | Required                       | Address for incoming requests                                                          |
| `upstream`                | Required                       | Upstream host with an optional port and `http://` or `https://` scheme; omit URL paths |
| `workers`                 | CPU count                      | Number of worker threads                                                               |
| `detection_only`          | `false`                        | Log WAF matches without enforcing blocks or challenges                                 |
| `upstream_keepalive_pool` | Pingora default                | Upstream connection pool size                                                          |
| `pid_file`                | `/tmp/openshield.pid`          | Process ID file                                                                        |
| `upgrade_sock`            | `/tmp/openshield_upgrade.sock` | Socket for transferring listeners during reloads                                       |
| `max_request_header_bytes` | `65536`                       | Requests with a larger header block get `431`                                          |
| `trusted_proxies`         | `[]`                           | Peers (addresses or CIDRs) allowed to name the client in `client_ip_header`. Empty: the TCP peer is the client |
| `client_ip_header`        | `X-Forwarded-For`              | Header read from trusted proxies; the rightmost untrusted address is the client         |

## Body inspection

Request body inspection runs when a `request_body` rule exists. Response body inspection requires a `response_body` rule and `inspect_response_body: true`.

| Setting                      | Default                 |
| ---------------------------- | ----------------------- |
| `max_request_body_buffer`    | `1048576` bytes (1 MiB) |
| `request_body_limit_action`  | `process_partial`       |
| `inspect_response_body`      | `false`                 |
| `max_response_body_buffer`   | `1048576` bytes (1 MiB) |
| `response_body_limit_action` | `process_partial`       |

The limit action controls what happens when an inspected body exceeds its buffer:

- `process_partial`: inspect the buffered portion, then stream the remainder uninspected if the rules allow it.
- `reject`: return `413` for an oversized request or suppress an oversized response body.

## TLS

Add `tls` to serve HTTPS. Omit it to serve plain HTTP.

```yaml
tls:
  cert: ./cert.pem
  key: ./key.pem
```

## GeoIP

Provide both MaxMind databases to populate GeoIP fields in rule expressions:

```yaml
geoip:
  city_mmdb: ./GeoLite2-City.mmdb
  asn_mmdb: ./GeoLite2-ASN.mmdb
```

## Logs and metrics

These are the default log settings:

```yaml
logging:
  format: json # json or text
  access_log: /dev/stdout
  audit_log: /dev/stderr
```

Log lines are buffered and written every 200 ms, so a crash or `kill -9` can lose the last 200 ms of lines.

Audit and access logs mask secrets by default: authorization and cookie headers, query, form and JSON fields whose names look sensitive (password, token, key, session, and similar), and tokens, keys, emails and card numbers in free text. Adjust with `redaction`:

```yaml
redaction:
  enabled: true
  headers: [authorization, proxy-authorization, cookie, set-cookie, x-api-key]  # replaces the default list
  fields: [password, token, secret]                                            # substrings of field names
```

Set the top-level `log_payloads: true` to include, in each audit entry, the field values referenced by the rules that matched. It defaults to `false`.

Add `metrics` to expose Prometheus metrics. The values below are the defaults when the block is present:

```yaml
metrics:
  enabled: true
  listen: "127.0.0.1:9090"
```

See [operations](operations.md) for log contents, application log levels, and metric names.

## Rules and challenges

Define WAF behavior with `rulesets`, named IP or string collections with `lists`, and per-request counters with `scores`. See [rules](rules.md) for examples and the expression reference.

Rules with `action: challenge` also require a `challenge` block. See [Turnstile challenges](challenges.md) for setup.

To verify JSON Web Tokens and use their claims in rules, add `token_configurations`. See [JWT validation](jwt.md) for setup.

To check requests against an OpenAPI document, add `schemas`. See [schema validation](schema-validation.md) for setup.

## Admin and intelligence

The intelligence layer records security events, scores them for anomalies, can ask an AI model for an advisory opinion, and serves the dashboard and [admin API](admin-api.md). It is off unless `intel.enabled: true`. With it on, the WAF policy is managed at runtime: API changes are versioned in the store and survive restarts while the config file's WAF keys are unchanged.

```yaml
intel:
  enabled: true
  store:
    path: /var/lib/openshield/intel.db   # SQLite; created with mode 0600
    retention_days: 14
    max_events: 2000000
    store_all_events: false   # store notable events plus a sample of the rest
    benign_sample_rate: 0.01  # share of ordinary requests stored
    per_client_per_sec: 50    # stored events per client per second (0: no limit)
    body_excerpt_bytes: 2048  # redacted body kept for rule matches
  events:
    queue_capacity: 8192        # events waiting for the pipeline; full means dropped and counted
    recent_capacity: 5000       # events kept in memory for the live views
    snapshot_capacity: 2000     # recent requests kept for policy simulation
    snapshot_benign_sample: 1.0 # share of ordinary requests kept as snapshots
  anomaly:
    window_s: 10
    rate_threshold: 100
    scan_404_threshold: 20
    block_burst_threshold: 10
    auto_block: {enabled: false, blocks_in_window: 50, ttl_s: 600}
  ai:
    enabled: false
    model: "<gemini model id>" # required; any generateContent model
    api_key_env: GEMINI_API_KEY # the key is read from this variable, never from the file
    timeout_ms: 8000
    requests_per_minute: 30
    max_calls_per_day: 2000
    triggers: [block, challenge, anomaly]
    send_body: false
    pseudonymize_ip: true

admin:
  enabled: true
  listen: 127.0.0.1:9091
  require_second_approver: false
  users:
    # Optional: leave empty to create users in the dashboard (first-run setup).
    - {name: alice, role: admin, token_sha256: "<sha256 of the token, hex>"}
    - {name: soc, role: analyst, token_env: OPENSHIELD_SOC_TOKEN}
```

**Notable events** are those with a rule match, an anomaly score above zero, a 5xx status, or an error. They are always candidates for storage; ordinary traffic is stored at `benign_sample_rate`. Statistics, alerts and the live stream see every request regardless of what is stored.

**Performance.** Measured in [reports/PERFORMANCE_COMPARISON.md](../reports/PERFORMANCE_COMPARISON.md). `store_all_events: true` with `per_client_per_sec: 0` writes every request to SQLite and costs much more throughput than the defaults.

**AI.** Analysis is asynchronous and advisory: verdicts never change what the proxy does, and an outage, timeout or exhausted budget only leaves events without a verdict. Requests sent to the provider contain an allow-list of redacted fields and a keyed hash instead of the client IP. Pick the model id from your provider's current model list.

**Dashboard settings.** AI (API key, model, limits), event storage, Turnstile keys and admin users can all be managed under **Settings** in the dashboard. A section saved there overrides the config file until you reset it; changes apply without a restart. Secrets are encrypted at rest (see [admin API](admin-api.md#encryption-at-rest)). Back up `openshield-secret.key` separately from the database: without it, saved secrets cannot be read and must be entered again. Set `OPENSHIELD_SECRET_KEY` (32 random bytes, base64) to keep the key out of the data directory entirely.

**First run.** With `admin.users` empty, the server writes a one-time setup token to `openshield-setup-token` (mode 0600) next to the database and logs where it is. Sign in with it, create an admin under Settings, then sign in with the admin's token. Read it with:

```bash
cat /var/lib/openshield/openshield-setup-token
```

**Admin users in the config file.** Generate a token and store only its hash:

```bash
openssl rand -hex 32 | tee /dev/stderr | tr -d '\n' | shasum -a 256
```
