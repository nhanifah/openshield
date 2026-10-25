#!/usr/bin/env python3
# =============================================================================
#  DEVELOPMENT FIXTURE ONLY -- NOT PRODUCTION CODE.
#
#  A throwaway mock of the OpenShield admin API (docs/admin-api.md) with
#  generated sample data so the dashboard in crates/openshield-intel/assets
#  can be exercised in a browser. Tokens are hard-coded, nothing is persisted,
#  and there is no real security here. Never expose it beyond localhost.
#
#  Usage:  python3 tests/dashboard/mock_api.py [--port 9099] [--rate 20]
#                                              [--second-approver]
#  Tokens: dev-admin (admin), dev-admin2 (admin, for approving changes),
#          dev-operator, dev-analyst, dev-viewer
#  Dev-only extra endpoint: POST /api/_dev/inject  (admin) body = partial
#  EventSummary fields; records and streams one event with those overrides.
# =============================================================================

import argparse
import json
import math
import os
import queue
import random
import threading
import time
import uuid
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

ROOT = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.normpath(os.path.join(ROOT, "..", "..", "crates", "openshield-intel", "assets"))

TOKENS = {
    "dev-admin": {"name": "alice", "role": "admin"},
    "dev-admin2": {"name": "bob", "role": "admin"},
    "dev-operator": {"name": "oscar", "role": "operator"},
    "dev-analyst": {"name": "ana", "role": "analyst"},
    "dev-viewer": {"name": "victor", "role": "viewer"},
}
RANK = {"viewer": 0, "analyst": 1, "operator": 2, "admin": 3}
LABELS = ["ALLOWED_NORMAL", "ALLOWED_UNUSUAL", "SUSPICIOUS", "MALICIOUS_CONFIRMED", "POLICY_VIOLATION",
          "FALSE_POSITIVE", "FALSE_NEGATIVE", "UNKNOWN", "NEEDS_REVIEW"]
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")

def now_ms():
    return int(time.time() * 1000)

# ----------------------------------------------------------------------------- data

GOOD_IPS = ["198.51.100.%d" % i for i in range(2, 40)] + ["2001:db8::%x" % i for i in range(1, 8)]
BAD_IPS = ["203.0.113.5", "203.0.113.77", "192.0.2.14", "192.0.2.200", "185.220.101.9"]
COUNTRIES = ["US", "NL", "DE", "GB", "FR", "SG", "BR", "IN", "JP", "ID", None]
IP_COUNTRY = {ip: random.choice(COUNTRIES) for ip in GOOD_IPS + BAD_IPS}
IP_COUNTRY["203.0.113.5"] = "NL"
PATHS = ["/", "/login", "/search", "/api/v1/users", "/api/v1/orders", "/static/app.js", "/static/site.css",
         "/products/42", "/checkout", "/healthz"]
ATTACK_PATHS = ["/wp-login.php", "/.env", "/admin", "/../../etc/passwd", "/search", "/login", "/cgi-bin/luci"]
RULES = [
    ("block-admin", "main", "request", "block", "Block direct access to /admin"),
    ("block-sqli-args", "main", "request", "block", "SQL injection in query arguments"),
    ("block-xss-args", "main", "request", "block", "XSS in query arguments"),
    ("block-sqli-headers", "main", "request", "block", "SQL injection in headers"),
    ("block-bad-ua", "main", "request", "block", "Known scanner user agents"),
    ("ratelimit-login", "main", "request", "block", "Login rate limit 5/10s per IP"),
    ("challenge-bot-ua", "main", "request", "challenge", "JS challenge for automation UAs"),
    ("block-sqli-form", "main", "request_body", "block", "SQL injection in form bodies"),
    ("allow-healthcheck", "main", "request", "allow", "Skip rules for health checks"),
    ("redact-secret", "main", "response_body", "block", "Stop secret leakage in responses"),
]
UAS = ["Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/605.1.15",
       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0 Safari/537.36", "curl/8.7.1",
       "sqlmap/1.8#stable (https://sqlmap.org)", "python-requests/2.32", "Go-http-client/1.1"]
QUERIES = ["", "", "", "page=2", "q=shoes&sort=asc", "id=42"]
ATTACK_QUERIES = ["q=%5BREDACTED%5D", "id=1%27%20OR%201%3D1--", "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
                  "file=..%2F..%2Fetc%2Fpasswd", ""]

LOCK = threading.RLock()
EVENTS = deque(maxlen=20000)       # newest at the right
EVENT_INDEX = {}
STATS = {}                         # second (epoch s) -> counts
CLIENTS = set()
START = now_ms()
SEQ = [0]
AI_STATE = {"analyzed": 412, "failures": 3, "invalid_outputs": 1, "cache_hits": 97, "dropped": 0,
            "tokens_in": 182344, "tokens_out": 40211, "cost_usd": 0.0731, "calls_today": 418}

def unique_ts():
    with LOCK:
        t = now_ms()
        if t <= SEQ[0]:
            t = SEQ[0] + 1
        SEQ[0] = t
        return t

def make_event(ts=None, overrides=None):
    r = random.random()
    bad = r < 0.18
    ip = random.choice(BAD_IPS) if bad else random.choice(GOOD_IPS)
    if bad:
        roll = random.random()
        action = "block" if roll < 0.62 else ("challenge" if roll < 0.9 else "pass")
    else:
        action = "allow" if random.random() < 0.05 else "pass"
    path = random.choice(ATTACK_PATHS if bad else PATHS)
    if path == "/healthz":
        action = "allow"
    method = "POST" if path in ("/login", "/checkout", "/api/v1/orders") and random.random() < 0.7 else (
        random.choice(["GET", "GET", "GET", "HEAD", "PUT", "DELETE"]) if random.random() < 0.08 else "GET")
    rules = []
    if action == "block":
        rules = [random.choice(["block-sqli-args", "block-xss-args", "block-bad-ua", "block-admin",
                                "ratelimit-login", "dynamic:ip_block"])]
    elif action == "challenge":
        rules = ["challenge-bot-ua"]
    elif action == "allow":
        rules = ["allow-healthcheck"] if path == "/healthz" else []
    status = {"block": 403, "challenge": 403}.get(action)
    if status is None:
        status = random.choices([200, 200, 200, 304, 302, 404, 500, 502], [70, 10, 10, 4, 3, 3, 0.6, 0.4])[0]
    if rules and rules[0] == "ratelimit-login":
        status = 429
    anomaly = round(min(1.0, random.uniform(0.45, 0.98)), 2) if bad else round(random.uniform(0, 0.3), 2)
    ai = None
    if bad and random.random() < 0.35:
        cat = random.choice(["malicious", "malicious", "suspicious"])
        ai = {"category": cat, "risk": round(random.uniform(0.5, 0.99), 2),
              "confidence": round(random.uniform(0.5, 0.95), 2),
              "recommended_action": "block_candidate" if cat == "malicious" else "review"}
    elif not bad and random.random() < 0.02:
        ai = {"category": "legitimate", "risk": 0.05, "confidence": 0.9, "recommended_action": "none"}
    ev = {
        "id": str(uuid.uuid4()), "ts": ts if ts is not None else unique_ts(), "client_ip": ip,
        "country": IP_COUNTRY.get(ip), "method": method,
        "host": random.choice(["app.example", "api.example", "shop.example"]),
        "path": path, "query": random.choice(ATTACK_QUERIES if bad else QUERIES),
        "status": status, "duration_ms": round(random.lognormvariate(0.2, 0.8), 2),
        "action": action, "rules": rules, "anomaly_score": anomaly, "ai": ai, "label": None,
    }
    if overrides:
        ev.update({k: v for k, v in overrides.items() if k != "id"})
    return ev

def record(ev, broadcast=True):
    with LOCK:
        if len(EVENTS) == EVENTS.maxlen:
            old = EVENTS.popleft()
            EVENT_INDEX.pop(old["id"], None)
        EVENTS.append(ev)
        EVENT_INDEX[ev["id"]] = ev
        sec = ev["ts"] // 1000
        s = STATS.setdefault(sec, {"total": 0, "pass": 0, "allow": 0, "block": 0, "challenge": 0,
                                    "suspicious": 0, "lat": []})
        s["total"] += 1
        if ev["action"] in s:
            s[ev["action"]] += 1
        if is_suspicious(ev):
            s["suspicious"] += 1
        if len(s["lat"]) < 400:
            s["lat"].append(ev["duration_ms"])
    if broadcast:
        publish("event", ev)

def is_suspicious(ev):
    return (ev.get("anomaly_score") or 0) >= 0.5 or ((ev.get("ai") or {}).get("category") in ("suspicious", "malicious"))

def publish(name, data):
    msg = ("event: %s\ndata: %s\n\n" % (name, json.dumps(data))).encode()
    with LOCK:
        clients = list(CLIENTS)
    for q in clients:
        try:
            q.put_nowait(msg)
        except queue.Full:
            pass

def p95(vals):
    if not vals:
        return 0.0
    v = sorted(vals)
    return round(v[min(len(v) - 1, int(len(v) * 0.95))], 2)

# prefill history: ~6000 events over the last 3 hours (not counted in STATS)
def prefill():
    t0 = START - 3 * 3600 * 1000
    for i in range(6000):
        ts = t0 + int(i * (3 * 3600 * 1000) / 6000) + i % 7
        ev = make_event(ts=ts)
        with LOCK:
            EVENTS.append(ev)
            EVENT_INDEX[ev["id"]] = ev
    for ev in random.sample(list(EVENTS), 40):
        add_label(ev, random.choice(["SUSPICIOUS", "MALICIOUS_CONFIRMED", "FALSE_POSITIVE"]),
                  "ai_candidate", None, "candidate", "model suggestion")
    for ev in random.sample(list(EVENTS), 15):
        add_label(ev, random.choice(LABELS), "operator", "alice", "approved", "reviewed during triage")
    for ev in random.sample(list(EVENTS), 6):
        add_label(ev, "FALSE_POSITIVE", "operator", "ana", "candidate", "looks like a legit partner crawler")
    for ev in random.sample(list(EVENTS), 5):
        add_label(ev, "NEEDS_REVIEW", "rule", None, "rejected", "")

LABEL_STORE = []
def add_label(ev, label, source, reviewer, status, note):
    lid = len(LABEL_STORE) + 1
    LABEL_STORE.append({"id": lid, "event_id": ev["id"], "label": label, "source": source,
                        "reviewer": reviewer, "status": status, "note": note, "ts": now_ms() - random.randint(0, 3600000)})
    if status == "approved" or source == "operator":
        ev["label"] = label
    return lid

# ----------------------------------------------------------------------------- state

POLICY_V1 = """# OpenShield WAF policy (WAF keys only)
detection_only: false
rulesets:
  - name: main
    kind: root
    rules:
      - id: block-admin
        action: block
        expression: 'http.request.uri.path == "/admin"'
      - id: block-sqli-args
        action: block
        expression: "any(detect_sqli(url_decode_uni(http.request.uri.args.values[*])))"
      - id: block-xss-args
        action: block
        expression: "any(detect_xss(url_decode_uni(http.request.uri.args.values[*])))"
      - id: block-bad-ua
        action: block
        expression: 'lower(http.user_agent) contains "sqlmap"'
      - id: challenge-bot-ua
        action: challenge
        expression: 'lower(http.user_agent) contains "python-requests"'
      - id: ratelimit-login
        action: block
        expression: 'http.request.uri.path == "/login"'
        ratelimit:
          characteristics: [ip.src]
          period: 10
          requests_per_period: 5
"""
POLICIES = {
    1: {"yaml": POLICY_V1.replace("      - id: challenge-bot-ua\n        action: challenge\n        expression: 'lower(http.user_agent) contains \"python-requests\"'\n", ""),
        "ts": START - 86400000 * 3, "actor": "alice", "comment": "initial import", "source": "file", "status": "superseded"},
    2: {"yaml": POLICY_V1.replace("detection_only: false", "detection_only: true"),
        "ts": START - 86400000 * 2, "actor": "alice", "comment": "monitoring-only during rollout", "source": "api", "status": "superseded"},
    3: {"yaml": POLICY_V1, "ts": START - 3600000 * 5, "actor": "bob", "comment": "enforce + bot challenge", "source": "api", "status": "active"},
}
STATE = {"policy_version": 3}
CONTROLS = {
    "ip_blocks": [
        {"value": "203.0.113.77", "expires_at": START + 45 * 60000, "reason": "credential stuffing on /login", "actor": "oscar", "created_at": START - 15 * 60000},
        {"value": "192.0.2.0/24", "expires_at": None, "reason": "abusive hosting range", "actor": "alice", "created_at": START - 86400000},
        {"value": "185.220.101.9", "expires_at": START + 90000, "reason": "scanner <b>bold?</b>", "actor": "oscar", "created_at": START - 600000},
    ],
    "ip_allows": [
        {"value": "198.51.100.10", "expires_at": None, "reason": "uptime monitor", "actor": "alice", "created_at": START - 7 * 86400000},
    ],
}
CHANGES = []
ALERTS = [
    {"id": 1, "ts": START - 600000, "kind": "rate_spike", "subject": "203.0.113.5", "severity": "high",
     "detail": {"rate_10s": 52, "baseline": 3}, "status": "open", "summary": None, "count": 4},
    {"id": 2, "ts": START - 1800000, "kind": "scanning", "subject": "192.0.2.14", "severity": "medium",
     "detail": {"distinct_paths_60s": 118, "status_404": 97}, "status": "open", "summary": None, "count": 2},
    {"id": 3, "ts": START - 3600000, "kind": "attack_burst", "subject": "/search", "severity": "critical",
     "detail": {"blocked_60s": 340, "rule": "block-sqli-args"}, "status": "ack", "summary": None, "count": 9},
    {"id": 4, "ts": START - 7200000, "kind": "ai_degraded", "subject": "gemini", "severity": "low",
     "detail": {"failures_5m": 4}, "status": "resolved", "summary": "Provider timeouts for 6 minutes; breaker recovered.", "count": 1},
    {"id": 5, "ts": START - 300000, "kind": "error_burst", "subject": "/api/v1/orders", "severity": "medium",
     "detail": {"status_5xx_60s": 31}, "status": "open", "summary": None, "count": 1},
]
DATASETS = [
    {"version": 1, "ts": START - 86400000, "actor": "alice",
     "stats": {"rows": 4210, "split": "temporal", "include_candidates": False,
               "train": 2947, "validation": 631, "test": 632,
               "labels": {"ALLOWED_NORMAL": 3100, "MALICIOUS_CONFIRMED": 820, "FALSE_POSITIVE": 290}}},
]
AUDIT = []
FAILS = {}

def audit(actor, role, action, target, detail, result, ip):
    AUDIT.append({"id": len(AUDIT) + 1, "ts": now_ms(), "actor": actor, "role": role, "action": action,
                  "target": target, "detail": detail, "result": result, "ip": ip})

for i, (a, act, tgt) in enumerate([("alice", "policy.apply", "version 3"), ("oscar", "controls.ip_block", "203.0.113.77"),
                                    ("ana", "label.create", "event"), ("alice", "datasets.export", "version 1")]):
    AUDIT.append({"id": i + 1, "ts": START - (5 - i) * 3600000, "actor": a, "role": "admin" if a == "alice" else ("operator" if a == "oscar" else "analyst"),
                  "action": act, "target": tgt, "detail": {"note": "seed"}, "result": "ok", "ip": "127.0.0.1"})

# ----------------------------------------------------------------------------- generator

def generator(rate):
    tick_sec = int(time.time())
    carry = 0.0
    while True:
        time.sleep(0.05)
        wave = 1 + 0.5 * math.sin(time.time() / 20.0)
        carry += rate * wave * 0.05
        n = int(carry)
        carry -= n
        for _ in range(n):
            record(make_event())
        sec = int(time.time())
        if sec != tick_sec:
            with LOCK:
                s = STATS.get(tick_sec, {"total": 0, "pass": 0, "allow": 0, "block": 0, "challenge": 0, "suspicious": 0, "lat": []})
                tick = {k: s[k] for k in ("total", "pass", "allow", "block", "challenge", "suspicious")}
                tick["t"] = tick_sec * 1000
                tick["p95_ms"] = p95(s["lat"])
                for old in [k for k in STATS if k < sec - 7200]:
                    STATS.pop(old, None)
            publish("stats", tick)
            tick_sec = sec
            if random.random() < 0.01:
                raise_alert()
            if random.random() < 0.3:
                ai_verdict()

def raise_alert():
    kind = random.choice(["rate_spike", "scanning", "attack_burst", "traffic_spike", "ai_malicious"])
    with LOCK:
        al = {"id": max([a["id"] for a in ALERTS] + [0]) + 1, "ts": now_ms(), "kind": kind,
              "subject": random.choice(BAD_IPS) if kind != "attack_burst" else "/login",
              "severity": random.choice(["low", "medium", "high", "critical"]),
              "detail": {"rate_10s": random.randint(20, 90), "baseline": random.randint(1, 6)},
              "status": "open", "summary": None, "count": 1}
        ALERTS.append(al)
    publish("alert", al)

def ai_verdict(ev=None):
    with LOCK:
        if ev is None:
            cands = [e for e in list(EVENTS)[-200:] if e["action"] in ("block", "challenge") and not e.get("ai")]
            if not cands:
                return
            ev = random.choice(cands)
        ev["ai"] = {"category": random.choice(["malicious", "suspicious"]), "risk": round(random.uniform(0.6, 0.99), 2),
                    "confidence": round(random.uniform(0.55, 0.9), 2), "recommended_action": "block_candidate"}
        AI_STATE["analyzed"] += 1
    publish("ai", {"event_id": ev["id"], "ai": ev["ai"]})

# ----------------------------------------------------------------------------- overview

RANGES = {"5m": (300000, 5000), "15m": (900000, 15000), "1h": (3600000, 60000), "6h": (21600000, 300000),
          "24h": (86400000, 900000), "7d": (604800000, 7200000)}

def synthetic(t, bucket_ms, rate):
    day = 2 * math.pi * (t / 86400000.0)
    rnd = random.Random(t // bucket_ms)
    eps = rate * (1 + 0.45 * math.sin(day)) * rnd.uniform(0.8, 1.2)
    total = eps * bucket_ms / 1000.0
    burst = 3.0 if rnd.random() < 0.05 else 1.0
    block = total * 0.11 * burst
    challenge = total * 0.05
    allow = total * 0.04
    pas = max(0.0, total - block - challenge - allow)
    tot = int(pas) + int(allow) + int(block) + int(challenge)
    return {"t": t, "total": tot, "pass": int(pas), "allow": int(allow), "block": int(block),
            "challenge": int(challenge), "suspicious": int(block * 0.6), "p95_ms": round(rnd.uniform(3, 9), 2)}

def overview(rng, rate):
    range_ms, bucket_ms = RANGES.get(rng, RANGES["1h"])
    now = now_ms()
    first = (now - range_ms) // bucket_ms * bucket_ms + bucket_ms
    series = []
    with LOCK:
        stats = dict(STATS)
        evs = [e for e in EVENTS if e["ts"] >= now - range_ms]
    t = first
    while t <= now:
        if t + bucket_ms <= START:
            series.append(synthetic(t, bucket_ms, rate))
        else:
            b = {"t": t, "total": 0, "pass": 0, "allow": 0, "block": 0, "challenge": 0, "suspicious": 0}
            lat = []
            for sec in range(t // 1000, (t + bucket_ms) // 1000):
                s = stats.get(sec)
                if s:
                    for k in ("total", "pass", "allow", "block", "challenge", "suspicious"):
                        b[k] += s[k]
                    lat.extend(s["lat"])
            b["p95_ms"] = p95(lat)
            series.append(b)
        t += bucket_ms
    totals = {k: sum(b[k] for b in series) for k in ("pass", "allow", "block", "challenge", "suspicious")}
    totals["requests"] = sum(b["total"] for b in series)
    totals["status_5xx"] = sum(1 for e in evs if e["status"] >= 500) + int(totals["requests"] * 0.001)
    totals["bytes_in"] = totals["requests"] * 812
    totals["bytes_out"] = totals["requests"] * 9310
    def top(key, extra):
        agg = {}
        for e in evs:
            k = e[key]
            a = agg.setdefault(k, {"count": 0, "blocked": 0})
            a["count"] += 1
            if e["action"] == "block":
                a["blocked"] += 1
        out = sorted(agg.items(), key=lambda kv: -kv[1]["count"])[:10]
        return [dict({"ip" if key == "client_ip" else "path": k, **v}, **extra(k)) for k, v in out]
    top_ips = top("client_ip", lambda ip: {"country": IP_COUNTRY.get(ip),
                                           "anomaly_score": round(random.Random(ip).uniform(0.55, 0.95), 2) if ip in BAD_IPS else round(random.Random(ip).uniform(0, 0.25), 2)})
    top_paths = top("path", lambda p: {})
    rules = {}
    status_codes = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}
    methods, countries = {}, {}
    for e in evs:
        for r in e["rules"]:
            rules[r] = rules.get(r, 0) + 1
        status_codes["%dxx" % (e["status"] // 100)] = status_codes.get("%dxx" % (e["status"] // 100), 0) + 1
        methods[e["method"]] = methods.get(e["method"], 0) + 1
        if e["country"]:
            countries[e["country"]] = countries.get(e["country"], 0) + 1
    rps = series[-1]["total"] / (bucket_ms / 1000.0) if series else 0
    if series and len(series) > 1:
        rps = series[-2]["total"] / (bucket_ms / 1000.0)
    return {
        "range_ms": range_ms, "bucket_ms": bucket_ms, "now": now, "totals": totals,
        "rps_current": round(rps, 1), "latency_ms": {"p50": 1.2, "p95": 4.8, "p99": 9.9},
        "series": series, "top_ips": top_ips, "top_paths": top_paths,
        "top_rules": [{"id": k, "count": v} for k, v in sorted(rules.items(), key=lambda kv: -kv[1])[:10]],
        "status_codes": status_codes, "methods": methods, "countries": countries,
        "ai": {"state": "ok", "queue": random.randint(0, 6), "analyzed": AI_STATE["analyzed"], "failures": AI_STATE["failures"],
               "cache_hits": AI_STATE["cache_hits"], "cost_usd": AI_STATE["cost_usd"]},
    }

def event_detail(ev):
    rnd = random.Random(ev["id"])
    headers = {"host": ev["host"], "user-agent": rnd.choice(UAS), "accept": "*/*",
               "authorization": "[REDACTED] len=%d" % rnd.randint(16, 64), "cookie": "[REDACTED] len=41",
               "x-forwarded-for": ev["client_ip"], "x-probe": "<script>alert('hdr')</script>"}
    body = None
    if ev["method"] in ("POST", "PUT"):
        body = '{"username":"admin\' OR 1=1--","password":"[REDACTED]","note":"<img src=x onerror=alert(2)>"}'
    with LOCK:
        related = [e for e in reversed(EVENTS) if e["client_ip"] == ev["client_ip"] and e["id"] != ev["id"]][:8]
        cl_events = [e for e in EVENTS if e["client_ip"] == ev["client_ip"]]
        labels = [{k: l[k] for k in ("id", "label", "source", "reviewer", "status", "note", "ts")}
                  for l in LABEL_STORE if l["event_id"] == ev["id"]]
        blocked_now = any(c["value"] == ev["client_ip"] for c in CONTROLS["ip_blocks"])
    verdicts = []
    if ev.get("ai"):
        verdicts.append({"ts": ev["ts"] + 900, "model": "gemini-2.5-flash", "model_version": "2.5-flash-001",
                         "prompt_version": "v1", "category": ev["ai"]["category"], "risk": ev["ai"]["risk"],
                         "confidence": ev["ai"]["confidence"],
                         "explanation": "Query argument contains a tautology (' OR 1=1--) typical of SQL injection; "
                                        "client shows a request rate far above baseline. <b>not bold</b>",
                         "evidence": ["query.q", "rule:%s" % (ev["rules"][0] if ev["rules"] else "none"), "anomaly:rate_spike"],
                         "recommended_action": ev["ai"]["recommended_action"], "latency_ms": rnd.randint(400, 2000),
                         "cached": rnd.random() < 0.2, "status": "ok"})
    d = dict(ev)
    d.update({
        "protocol": rnd.choice(["HTTP/1.1", "HTTP/2"]), "bytes_in": len(body or "") + 300, "bytes_out": rnd.randint(9, 40000),
        "user_agent": headers["user-agent"], "headers": headers, "body_excerpt": body,
        "scores": {"sqli": 10, "xss": 0} if ev["action"] == "block" else {},
        "matched_rules": [{"id": r, "action": ev["action"]} for r in ev["rules"]],
        "anomaly": {"score": ev["anomaly_score"], "reasons": ([
            {"kind": "rate_spike", "detail": "52 req/10s vs baseline 3", "weight": 0.5},
            {"kind": "new_client", "detail": "first seen 4 minutes ago", "weight": 0.2}] if ev["anomaly_score"] >= 0.5 else [])},
        "ai_verdicts": verdicts, "labels": labels, "related": related,
        "client": {"ip": ev["client_ip"], "first_seen": min([e["ts"] for e in cl_events] or [ev["ts"]]),
                   "requests": len(cl_events), "blocked": sum(1 for e in cl_events if e["action"] == "block"),
                   "anomaly_score": ev["anomaly_score"], "blocked_now": blocked_now},
    })
    return d

# ----------------------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = "openshield-mock"

    def log_message(self, fmt, *args):
        if os.environ.get("MOCK_VERBOSE"):
            BaseHTTPRequestHandler.log_message(self, fmt, *args)

    def send_json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def err(self, code, msg):
        self.send_json(code, {"error": msg})

    def serve_asset(self, name, ctype):
        try:
            with open(os.path.join(ASSETS, name), "rb") as f:
                body = f.read()
        except OSError:
            return self.err(404, "asset missing: " + name)
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def auth(self):
        h = self.headers.get("Authorization", "")
        ip = self.client_address[0]
        t = time.time()
        fails = [x for x in FAILS.get(ip, []) if t - x < 60]
        FAILS[ip] = fails
        if len(fails) >= 10:
            self.err(429, "too many failed attempts")
            return None
        tok = h[7:] if h.startswith("Bearer ") else ""
        user = TOKENS.get(tok)
        if not user:
            fails.append(t)
            self.err(401, "unauthorized")
            return None
        return user

    def need(self, user, role):
        if RANK[user["role"]] < RANK[role]:
            self.err(403, "requires role %s" % role)
            return False
        return True

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n))
        except ValueError:
            return None

    def do_GET(self):
        self.dispatch("GET")

    def do_POST(self):
        self.dispatch("POST")

    def do_DELETE(self):
        self.dispatch("DELETE")

    def dispatch(self, method):
        u = urlparse(self.path)
        path, qs = u.path, {k: v[-1] for k, v in parse_qs(u.query).items()}
        if method == "GET" and path in ("/", "/index.html"):
            return self.serve_asset("index.html", "text/html; charset=utf-8")
        if method == "GET" and path == "/app.css":
            return self.serve_asset("app.css", "text/css; charset=utf-8")
        if method == "GET" and path == "/app.js":
            return self.serve_asset("app.js", "text/javascript; charset=utf-8")
        if path == "/healthz":
            return self.send_json(200, {"status": "ok"})
        if path == "/readyz":
            return self.send_json(200, {"ready": True, "components": {"store": "ok", "policy": "ok", "ai": "ok"}})
        if not path.startswith("/api/"):
            return self.err(404, "not found")
        user = self.auth()
        if not user:
            return
        parts = [unquote(p) for p in path[5:].split("/") if p]
        try:
            self.route(method, parts, qs, user)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def ok_write(self, user, action, target, detail=None, result="ok"):
        audit(user["name"], user["role"], action, target, detail or {}, result, self.client_address[0])

    def route(self, m, p, qs, user):
        R = lambda *a: tuple(p) == a
        if m == "GET" and R("me"):
            return self.send_json(200, user)
        if m == "GET" and R("overview"):
            return self.send_json(200, overview(qs.get("range", "1h"), self.server.rate))
        if m == "GET" and R("stream"):
            return self.stream()
        if m == "GET" and R("events"):
            return self.events(qs)
        if len(p) == 2 and p[0] == "events" and m == "GET":
            ev = EVENT_INDEX.get(p[1])
            return self.send_json(200, event_detail(ev)) if ev else self.err(404, "event not found")
        if len(p) == 3 and p[0] == "events" and p[2] == "label" and m == "POST":
            if not self.need(user, "analyst"):
                return
            ev = EVENT_INDEX.get(p[1])
            b = self.body() or {}
            if not ev:
                return self.err(404, "event not found")
            if b.get("label") not in LABELS:
                return self.err(400, "invalid label")
            lid = add_label(ev, b["label"], "operator", user["name"], "candidate", str(b.get("note") or "")[:500])
            ev["label"] = b["label"]
            self.ok_write(user, "label.create", ev["id"], {"label": b["label"]})
            return self.send_json(200, {"id": lid, "status": "candidate"})
        if m == "GET" and R("alerts"):
            st = qs.get("status")
            with LOCK:
                al = [a for a in ALERTS if not st or a["status"] == st]
            return self.send_json(200, {"alerts": sorted(al, key=lambda a: -a["ts"])})
        if len(p) == 3 and p[0] == "alerts" and m == "POST":
            if not self.need(user, "analyst"):
                return
            al = next((a for a in ALERTS if str(a["id"]) == p[1]), None)
            if not al:
                return self.err(404, "alert not found")
            if p[2] == "ack":
                al["status"] = "ack"
            elif p[2] == "resolve":
                al["status"] = "resolved"
            elif p[2] == "summarize":
                time.sleep(0.6)
                al["summary"] = ("%s on %s: %d occurrences. Requests from this source hit mostly blocked paths; "
                                 "consider a temporary block. (Advisory AI summary) <script>x</script>"
                                 % (al["kind"], al["subject"], al["count"]))
                self.ok_write(user, "alert.summarize", str(al["id"]))
                return self.send_json(200, {"summary": al["summary"]})
            else:
                return self.err(404, "not found")
            self.ok_write(user, "alert." + p[2], str(al["id"]))
            return self.send_json(200, {"status": al["status"]})
        if m == "GET" and R("controls"):
            t = now_ms()
            with LOCK:
                for k in CONTROLS:
                    CONTROLS[k] = [c for c in CONTROLS[k] if c["expires_at"] is None or c["expires_at"] > t]
                return self.send_json(200, CONTROLS)
        if len(p) >= 2 and p[0] == "controls" and p[1] in ("ip-block", "ip-allow"):
            if not self.need(user, "operator"):
                return
            key = "ip_blocks" if p[1] == "ip-block" else "ip_allows"
            if m == "POST":
                b = self.body() or {}
                val = str(b.get("value") or "").strip()
                if not val or any(ch not in "0123456789abcdefABCDEF.:/" for ch in val):
                    return self.err(400, "invalid IP or CIDR")
                ttl = b.get("ttl_s")
                if ttl is not None and (not isinstance(ttl, int) or ttl <= 0):
                    return self.err(400, "ttl_s must be a positive integer")
                if self.server.second_approver and (ttl is None or ttl > 86400):
                    cid = len(CHANGES) + 1
                    CHANGES.append({"id": cid, "ts": now_ms(), "kind": "ip_block" if key == "ip_blocks" else "ip_allow",
                                    "summary": "%s %s for %ss: %s" % (p[1], val, ttl, b.get("reason") or ""),
                                    "requested_by": user["name"], "status": "pending", "decided_by": None,
                                    "_apply": ("control", key, val, ttl, b.get("reason") or "", user["name"])})
                    self.ok_write(user, "controls." + p[1], val, {"ttl_s": ttl}, "pending")
                    return self.send_json(200, {"status": "pending", "change_id": cid})
                apply_control(key, val, ttl, b.get("reason") or "", user["name"])
                self.ok_write(user, "controls." + p[1], val, {"ttl_s": ttl})
                return self.send_json(200, {"status": "applied"})
            if m == "DELETE" and len(p) == 3:
                with LOCK:
                    before = len(CONTROLS[key])
                    CONTROLS[key] = [c for c in CONTROLS[key] if c["value"] != p[2]]
                    if len(CONTROLS[key]) == before:
                        return self.err(404, "no such entry")
                self.ok_write(user, "controls.remove_" + p[1], p[2])
                return self.send_json(200, {"status": "applied"})
        if m == "GET" and R("rules"):
            pol = POLICIES[STATE["policy_version"]]["yaml"]
            rules = [{"id": r[0], "ruleset": r[1], "phase": r[2], "action": r[3], "enabled": ("id: " + r[0]) in pol or r[0] in ("allow-healthcheck",),
                      "description": r[4], "hits_1h": sum(1 for e in list(EVENTS)[-5000:] if r[0] in e["rules"])} for r in RULES]
            return self.send_json(200, {"rules": rules, "detection_only": "detection_only: true" in pol, "version": STATE["policy_version"]})
        if m == "GET" and R("policy"):
            v = STATE["policy_version"]
            pv = POLICIES[v]
            return self.send_json(200, {"version": v, "yaml": pv["yaml"], "applied_at": pv["ts"], "actor": pv["actor"], "source": pv["source"]})
        if m == "GET" and R("policy", "versions"):
            vs = [{"version": v, "ts": d["ts"], "actor": d["actor"], "comment": d["comment"], "source": d["source"],
                   "status": "active" if v == STATE["policy_version"] else d["status"],
                   "rule_count": d["yaml"].count("- id:")} for v, d in sorted(POLICIES.items(), reverse=True)]
            return self.send_json(200, {"versions": vs})
        if m == "GET" and len(p) == 3 and p[:2] == ["policy", "versions"]:
            try:
                v = int(p[2])
            except ValueError:
                return self.err(400, "bad version")
            if v not in POLICIES:
                return self.err(404, "no such version")
            return self.send_json(200, {"version": v, "yaml": POLICIES[v]["yaml"]})
        if m == "POST" and len(p) == 2 and p[0] == "policy":
            if not self.need(user, "admin"):
                return
            b = self.body() or {}
            if p[1] in ("validate", "simulate", "apply"):
                y = b.get("yaml")
                if not isinstance(y, str):
                    return self.err(400, "yaml required")
                verr = validate_yaml(y)
                if p[1] == "validate":
                    return self.send_json(200, {"ok": False, "error": verr} if verr else {"ok": True, "rule_count": y.count("- id:")})
                if verr:
                    return self.err(400, verr)
                if p[1] == "simulate":
                    time.sleep(0.4)
                    return self.send_json(200, simulate(y))
                if not str(b.get("comment") or "").strip():
                    return self.err(400, "comment required")
                if self.server.second_approver:
                    cid = len(CHANGES) + 1
                    CHANGES.append({"id": cid, "ts": now_ms(), "kind": "policy_apply", "summary": "apply policy: " + b["comment"],
                                    "requested_by": user["name"], "status": "pending", "decided_by": None,
                                    "_apply": ("policy", y, b["comment"], user["name"])})
                    self.ok_write(user, "policy.apply", "new version", {"comment": b["comment"]}, "pending")
                    return self.send_json(200, {"status": "pending", "change_id": cid})
                v = apply_policy(y, b["comment"], user["name"])
                self.ok_write(user, "policy.apply", "version %d" % v, {"comment": b["comment"]})
                return self.send_json(200, {"status": "applied", "version": v})
            if p[1] == "rollback":
                v = b.get("version")
                if v not in POLICIES:
                    return self.err(404, "no such version")
                if not str(b.get("comment") or "").strip():
                    return self.err(400, "comment required")
                nv = apply_policy(POLICIES[v]["yaml"], "rollback to v%d: %s" % (v, b["comment"]), user["name"])
                self.ok_write(user, "policy.rollback", "version %d" % v, {"new_version": nv})
                return self.send_json(200, {"status": "applied", "version": nv})
        if m == "GET" and R("changes"):
            if not self.need(user, "admin"):
                return
            st = qs.get("status")
            out = [{k: v for k, v in c.items() if not k.startswith("_")} for c in CHANGES if not st or c["status"] == st]
            return self.send_json(200, {"changes": sorted(out, key=lambda c: -c["ts"])})
        if m == "POST" and len(p) == 3 and p[0] == "changes":
            if not self.need(user, "admin"):
                return
            c = next((c for c in CHANGES if str(c["id"]) == p[1]), None)
            if not c or c["status"] != "pending":
                return self.err(404, "no pending change")
            if p[2] == "approve":
                if c["requested_by"] == user["name"]:
                    return self.err(403, "approver must differ from the requester")
                a = c["_apply"]
                if a[0] == "control":
                    apply_control(*a[1:])
                else:
                    apply_policy(a[1], a[2], a[3])
                c["status"] = "approved"
            elif p[2] == "reject":
                c["status"] = "rejected"
            else:
                return self.err(404, "not found")
            c["decided_by"] = user["name"]
            self.ok_write(user, "change." + p[2], str(c["id"]))
            return self.send_json(200, {"status": c["status"]})
        if m == "GET" and R("labels"):
            if not self.need(user, "analyst"):
                return
            st = qs.get("status")
            out = []
            for l in reversed(LABEL_STORE):
                if st and l["status"] != st:
                    continue
                d = dict(l)
                ev = EVENT_INDEX.get(l["event_id"])
                d["event"] = ev
                out.append(d)
            return self.send_json(200, {"labels": out[:500]})
        if m == "POST" and len(p) == 3 and p[0] == "labels":
            if not self.need(user, "analyst"):
                return
            l = next((l for l in LABEL_STORE if str(l["id"]) == p[1]), None)
            if not l:
                return self.err(404, "no such label")
            if p[2] == "approve":
                if l["reviewer"] == user["name"]:
                    return self.err(403, "a reviewer cannot approve their own label")
                l["status"] = "approved"
                l["reviewer"] = user["name"]
                ev = EVENT_INDEX.get(l["event_id"])
                if ev:
                    ev["label"] = l["label"]
            elif p[2] == "reject":
                l["status"] = "rejected"
            else:
                return self.err(404, "not found")
            self.ok_write(user, "label." + p[2], str(l["id"]))
            return self.send_json(200, {"status": l["status"]})
        if m == "GET" and R("datasets"):
            if not self.need(user, "analyst"):
                return
            return self.send_json(200, {"datasets": sorted(DATASETS, key=lambda d: -d["version"])})
        if m == "POST" and R("datasets", "export"):
            if not self.need(user, "admin"):
                return
            b = self.body() or {}
            split = b.get("split")
            if split not in ("temporal", "entity"):
                return self.err(400, "split must be temporal or entity")
            inc = bool(b.get("include_candidates"))
            approved = [l for l in LABEL_STORE if l["status"] == "approved" or (inc and l["status"] == "candidate")]
            n = len(approved)
            v = max(d["version"] for d in DATASETS) + 1
            counts = {}
            for l in approved:
                counts[l["label"]] = counts.get(l["label"], 0) + 1
            stats = {"rows": n, "split": split, "include_candidates": inc, "train": int(n * 0.7),
                     "validation": int(n * 0.15), "test": n - int(n * 0.7) - int(n * 0.15), "labels": counts}
            DATASETS.append({"version": v, "ts": now_ms(), "actor": user["name"], "stats": stats})
            self.ok_write(user, "datasets.export", "version %d" % v, {"split": split, "include_candidates": inc})
            return self.send_json(200, {"version": v, "stats": stats})
        if m == "GET" and len(p) == 3 and p[0] == "datasets":
            if not self.need(user, "admin"):
                return
            if p[2] not in ("train", "validation", "test", "manifest"):
                return self.err(404, "bad split")
            if not any(str(d["version"]) == p[1] for d in DATASETS):
                return self.err(404, "no such dataset")
            lines = [json.dumps({"event_id": l["event_id"], "label": l["label"], "source": l["source"]}) for l in LABEL_STORE[:20]]
            if p[2] == "manifest":
                lines = [json.dumps({"version": p[1], "generated_by": "mock"})]
            body = ("\n".join(lines) + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if m == "GET" and R("ai", "status"):
            return self.send_json(200, {"enabled": True, "provider": "gemini", "model": "gemini-2.5-flash",
                                        "state": random.choice(["ok"] * 8 + ["degraded"]), "queue": random.randint(0, 12),
                                        "queue_capacity": 256, **{k: AI_STATE[k] for k in ("analyzed", "failures", "invalid_outputs", "cache_hits", "dropped", "tokens_in", "tokens_out", "cost_usd")},
                                        "budget": {"calls_today": AI_STATE["calls_today"], "max_calls_per_day": 5000},
                                        "latency_ms": {"p50": 840, "p95": 2210}, "last_error": "timeout after 8000ms <provider>"})
        if m == "POST" and len(p) == 3 and p[:2] == ["ai", "analyze"]:
            if not self.need(user, "analyst"):
                return
            ev = EVENT_INDEX.get(p[2])
            if not ev:
                return self.err(404, "event not found")
            threading.Timer(1.5, ai_verdict, args=(ev,)).start()
            self.ok_write(user, "ai.analyze", ev["id"])
            return self.send_json(200, {"status": "queued"})
        if m == "GET" and R("audit"):
            if not self.need(user, "admin"):
                return
            lim = int(qs.get("limit", "200"))
            return self.send_json(200, {"entries": list(reversed(AUDIT))[:lim]})
        if m == "POST" and R("_dev", "inject"):
            if not self.need(user, "admin"):
                return
            b = self.body() or {}
            ev = make_event(overrides=b)
            record(ev)
            return self.send_json(200, {"id": ev["id"]})
        return self.err(404, "not found")

    def events(self, qs):
        try:
            limit = max(1, min(1000, int(qs.get("limit", "100"))))
            before = int(qs["before"]) if qs.get("before") else None
            min_an = float(qs["min_anomaly"]) if qs.get("min_anomaly") else None
        except ValueError:
            return self.err(400, "bad parameter")
        q = (qs.get("q") or "").lower()
        out = []
        with LOCK:
            items = list(EVENTS)
        more = False
        for e in reversed(items):
            if before is not None and e["ts"] >= before:
                continue
            if qs.get("action") and e["action"] != qs["action"]:
                continue
            if qs.get("ip") and e["client_ip"] != qs["ip"]:
                continue
            if qs.get("path") and e["path"] != qs["path"]:
                continue
            if qs.get("rule") and qs["rule"] not in e["rules"]:
                continue
            if min_an is not None and (e["anomaly_score"] or 0) < min_an:
                continue
            if qs.get("ai_category") and (e.get("ai") or {}).get("category") != qs["ai_category"]:
                continue
            if q and q not in (e["path"] + " " + e["query"] + " " + e["client_ip"] + " " + e["host"] + " " + " ".join(e["rules"])).lower():
                continue
            if len(out) == limit:
                more = True
                break
            out.append(e)
        return self.send_json(200, {"events": out, "next_before": out[-1]["ts"] if more and out else None})

    def stream(self):
        q = queue.Queue(maxsize=5000)
        with LOCK:
            CLIENTS.add(q)
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            while True:
                try:
                    chunk = [q.get(timeout=15)]
                    while len(chunk) < 500:
                        try:
                            chunk.append(q.get_nowait())
                        except queue.Empty:
                            break
                    self.wfile.write(b"".join(chunk))
                except queue.Empty:
                    self.wfile.write(b": ping\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with LOCK:
                CLIENTS.discard(q)

def validate_yaml(y):
    if "\t" in y:
        return "line %d: tabs are not allowed in YAML indentation" % (y[:y.index("\t")].count("\n") + 1)
    for key in ("listen:", "upstream:", "admin:", "workers:"):
        for i, line in enumerate(y.splitlines()):
            if line.startswith(key):
                return "line %d: server key '%s' is not allowed in policy" % (i + 1, key[:-1])
    if "rulesets:" not in y:
        return "missing 'rulesets'"
    return None

def simulate(y):
    rnd = random.Random(len(y))
    with LOCK:
        sample = list(EVENTS)[-2000:]
    cur = {"pass": 0, "allow": 0, "block": 0, "challenge": 0}
    for e in sample:
        cur[e["action"]] = cur.get(e["action"], 0) + 1
    cand = dict(cur)
    diffs = []
    det = "detection_only: true" in y
    for e in sample:
        newa = e["action"]
        if det and e["action"] in ("block", "challenge"):
            newa = "pass"
        elif e["action"] == "pass" and rnd.random() < 0.006:
            newa = "block"
        if newa != e["action"]:
            cand[e["action"]] -= 1
            cand[newa] += 1
            diffs.append({"event_id": e["id"], "path": e["path"], "current": e["action"], "candidate": newa,
                          "rule": (e["rules"] or ["block-xss-args"])[0]})
    return {"replayed": len(sample), "changed": len(diffs), "current": cur, "candidate": cand, "diffs": diffs[:500]}

def apply_policy(y, comment, actor):
    with LOCK:
        old = STATE["policy_version"]
        POLICIES[old]["status"] = "superseded"
        v = max(POLICIES) + 1
        POLICIES[v] = {"yaml": y, "ts": now_ms(), "actor": actor, "comment": comment, "source": "api", "status": "active"}
        STATE["policy_version"] = v
        return v

def apply_control(key, val, ttl, reason, actor):
    with LOCK:
        CONTROLS[key] = [c for c in CONTROLS[key] if c["value"] != val]
        CONTROLS[key].append({"value": val, "expires_at": now_ms() + ttl * 1000 if ttl else None,
                              "reason": reason, "actor": actor, "created_at": now_ms()})

def main():
    ap = argparse.ArgumentParser(description="OpenShield dashboard mock API (dev fixture)")
    ap.add_argument("--port", type=int, default=9099)
    ap.add_argument("--rate", type=float, default=20.0, help="generated events per second")
    ap.add_argument("--second-approver", action="store_true", help="policy applies and long blocks become pending changes")
    a = ap.parse_args()
    prefill()
    threading.Thread(target=generator, args=(a.rate,), daemon=True).start()
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    srv.daemon_threads = True
    srv.rate = a.rate
    srv.second_approver = a.second_approver
    print("DEV FIXTURE: OpenShield mock admin API on http://127.0.0.1:%d (rate %.0f ev/s)" % (a.port, a.rate), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
