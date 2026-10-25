#!/usr/bin/env python3
"""End-to-end functional and security tests for OpenShield.

Starts the echo upstream and two proxy instances (JSON and text logging),
sends real HTTP traffic over raw sockets, and records each result.

Each test has an expectation describing the *secure* behaviour. A failing
test is a finding, not a harness error. Results are written as JSON so
baseline and later runs can be compared.

Usage:
    python3 tests/e2e/run_e2e.py --tag baseline
Requires release builds of `openshield` and `echo-upstream`.
"""

import argparse
import concurrent.futures
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "target" / "release"
CONFIGS = Path(__file__).resolve().parent / "configs"

PROXY = ("127.0.0.1", 18080)
PROXY_TEXT = ("127.0.0.1", 18081)
UPSTREAM = ("127.0.0.1", 13000)


# --------------------------------------------------------------------------
# HTTP over raw sockets
# --------------------------------------------------------------------------


class Resp:
    def __init__(self, raw: bytes):
        self.raw = raw
        head, _, self.body = raw.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        self.status = 0
        self.headers = {}
        if lines and lines[0].startswith(b"HTTP/"):
            try:
                self.status = int(lines[0].split()[1])
            except (IndexError, ValueError):
                pass
        for line in lines[1:]:
            k, _, v = line.partition(b":")
            self.headers.setdefault(k.strip().lower().decode("latin-1"), []).append(
                v.strip().decode("latin-1")
            )
        if "chunked" in ",".join(self.headers.get("transfer-encoding", [])):
            self.body = dechunk(self.body)

    def header(self, name):
        v = self.headers.get(name.lower())
        return v[0] if v else None

    def json(self):
        return json.loads(self.body.decode("utf-8", "replace"))


def dechunk(data: bytes) -> bytes:
    out = b""
    while data:
        size_line, _, rest = data.partition(b"\r\n")
        try:
            size = int(size_line.split(b";")[0], 16)
        except ValueError:
            return out + data
        if size == 0:
            break
        out += rest[:size]
        data = rest[size + 2 :]
    return out


def send_raw(raw: bytes, addr=PROXY, timeout=5.0) -> Resp:
    with socket.create_connection(addr, timeout=timeout) as s:
        s.sendall(raw)
        chunks = []
        try:
            while True:
                c = s.recv(65536)
                if not c:
                    break
                chunks.append(c)
        except socket.timeout:
            pass
        return Resp(b"".join(chunks))


def request(method, path, headers=None, body=b"", addr=PROXY, timeout=5.0) -> Resp:
    headers = dict(headers or {})
    headers.setdefault("Host", "app.test")
    headers.setdefault("Connection", "close")
    if body or method in ("POST", "PUT", "PATCH"):
        headers.setdefault("Content-Length", str(len(body)))
    head = f"{method} {path} HTTP/1.1\r\n"
    raw = head.encode() + b"".join(
        (k.encode("latin-1") if isinstance(k, str) else k)
        + b": "
        + (v.encode("latin-1") if isinstance(v, str) else v)
        + b"\r\n"
        for k, v in headers.items()
    )
    raw += b"\r\n" + body
    return send_raw(raw, addr, timeout)


# --------------------------------------------------------------------------
# Process management
# --------------------------------------------------------------------------


def wait_port(addr, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(addr, timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


class Stack:
    def __init__(self, logdir: Path, extra_configs=()):
        self.logdir = logdir
        self.procs = []
        self.extra_configs = extra_configs

    def start(self):
        up = subprocess.Popen(
            [str(BIN / "echo-upstream"), f"{UPSTREAM[0]}:{UPSTREAM[1]}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.procs.append(up)
        assert wait_port(UPSTREAM), "upstream did not start"
        for name, addr in [("e2e.yaml", PROXY), ("e2e-text.yaml", PROXY_TEXT), *self.extra_configs]:
            cfg = (CONFIGS / name).read_text().replace("__LOGDIR__", str(self.logdir))
            cfg_path = self.logdir / name
            cfg_path.write_text(cfg)
            stderr = open(self.logdir / f"{name}.stderr", "wb")
            p = subprocess.Popen(
                [str(BIN / "openshield"), "-c", str(cfg_path)],
                stdout=stderr,
                stderr=stderr,
                env={**os.environ, "RUST_LOG": "openshield=warn,pingora=warn"},
            )
            self.procs.append(p)
            assert wait_port(addr), f"proxy {name} did not start"
        time.sleep(0.6)  # logs are flushed every 200 ms

    def alive(self, index):
        return self.procs[index].poll() is None

    def stop(self):
        for p in self.procs:
            if p.poll() is None:
                p.send_signal(signal.SIGTERM)
        for p in self.procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------

RESULTS = []


def test(test_id, category, title, severity="info"):
    def deco(fn):
        fn.meta = dict(id=test_id, category=category, title=title, severity=severity)
        TESTS.append(fn)
        return fn

    return deco


TESTS = []


@test("F01", "functional", "Benign GET is proxied to the upstream")
def t_benign(ctx):
    r = request("GET", "/echo/hello?q=shoes")
    ok = r.status == 200 and r.json()["path"] == "/echo/hello"
    return ok, f"status={r.status}"


@test("F02", "functional", "SQL injection in a query argument is blocked")
def t_sqli_query(ctx):
    r = request("GET", "/echo?id=1%27%20OR%20%271%27%3D%271")
    return r.status == 403, f"status={r.status}"


@test("F03", "functional", "XSS in a query argument is blocked")
def t_xss_query(ctx):
    r = request("GET", "/echo?q=%3Cscript%3Ealert(1)%3C/script%3E")
    return r.status == 403, f"status={r.status}"


@test("F04", "functional", "SQL injection in a form body is blocked (request_body phase)")
def t_sqli_form(ctx):
    body = b"user=admin&pass=x' OR '1'='1"
    r = request("POST", "/echo", {"Content-Type": "application/x-www-form-urlencoded"}, body)
    return r.status == 403, f"status={r.status}"


@test("F05", "functional", "Path rule blocks /admin")
def t_admin(ctx):
    r = request("GET", "/admin")
    return r.status == 403, f"status={r.status}"


@test("F06", "functional", "Rate limit returns 429 after 5 requests per 10 s")
def t_ratelimit(ctx):
    codes = [request("GET", "/login").status for _ in range(7)]
    ok = codes[:5] == [200] * 5 and all(c == 429 for c in codes[5:])
    return ok, f"codes={codes}"


@test("F07", "functional", "Response body rule redacts a leaked secret")
def t_response_redact(ctx):
    r = request("GET", "/secret")
    ok = b"secret-token" not in r.body and b"[redacted]" in r.body
    return ok, f"status={r.status} body={r.body[:60]!r}"


@test("F08", "functional", "X-Forwarded-For and X-Real-IP reach the upstream")
def t_xff(ctx):
    r = request("GET", "/echo/xff", {"X-Forwarded-For": "203.0.113.9"})
    hdrs = {k: v for k, v in r.json()["headers"]}
    ok = hdrs.get("x-forwarded-for") == "203.0.113.9, 127.0.0.1" and hdrs.get("x-real-ip") == "127.0.0.1"
    return ok, f"xff={hdrs.get('x-forwarded-for')} real-ip={hdrs.get('x-real-ip')}"


@test("F09", "functional", "Body over max_request_body_buffer is rejected with 413")
def t_body_limit(ctx):
    body = b"a=" + b"b" * 70000
    r = request("POST", "/echo", {"Content-Type": "application/x-www-form-urlencoded"}, body, timeout=10)
    return r.status == 413, f"status={r.status}"


@test("F10", "functional", "Malformed request line gets 400")
def t_malformed(ctx):
    r = send_raw(b"GARBAGE\r\n\r\n")
    return r.status == 400 or r.raw == b"", f"status={r.status} raw_len={len(r.raw)}"


@test("F11", "functional", "SQL injection in a multipart field is blocked")
def t_multipart(ctx):
    body = (
        b"--XX\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n"
        b"1' UNION SELECT password FROM users--\r\n--XX--\r\n"
    )
    r = request("POST", "/echo", {"Content-Type": "multipart/form-data; boundary=XX"}, body)
    return r.status == 403, f"status={r.status}"


@test("F12", "functional", "200 concurrent benign requests all succeed")
def t_concurrency(ctx):
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        codes = list(ex.map(lambda i: request("GET", f"/echo/c{i}").status, range(200)))
    bad = [c for c in codes if c != 200]
    return not bad, f"non-200={len(bad)}"


@test("F13", "functional", "Upstream error status is passed through")
def t_status_passthrough(ctx):
    r = request("GET", "/status/503")
    return r.status == 503, f"status={r.status}"


@test("F14", "functional", "Access log records every request as JSON with a request id")
def t_access_log(ctx):
    request("GET", "/echo/logcheck")
    time.sleep(0.6)  # logs are flushed every 200 ms
    lines = (ctx.logdir / "access.log").read_text().splitlines()
    entries = [json.loads(line) for line in lines if line.strip()]
    hit = [e for e in entries if e.get("path") == "/echo/logcheck"]
    ok = bool(hit) and bool(hit[-1].get("request_id"))
    return ok, f"entries={len(entries)} matched={len(hit)}"


@test("F15", "functional", "Blocked request produces an audit entry naming the rule")
def t_audit_log(ctx):
    request("GET", "/admin?auditcheck=1")
    time.sleep(0.6)  # logs are flushed every 200 ms
    lines = (ctx.logdir / "audit.log").read_text().splitlines()
    entries = [json.loads(line) for line in lines if line.strip()]
    hit = [e for e in entries if e["request"]["query"] == "auditcheck=1"]
    ok = bool(hit) and hit[-1]["waf_matched_rules"][0]["id"] == "block-admin"
    return ok, f"matched={len(hit)}"


# ---- Security -------------------------------------------------------------


@test("S01", "security", "Non-UTF-8 header value cannot hide an injection from header rules", "high")
def t_header_bypass(ctx):
    # A control: the same payload with only ASCII is blocked.
    ctl = request("GET", "/echo", {"X-Search": "1' OR '1'='1"})
    # obs-text byte (0xE9) makes the value non-visible-ASCII.
    r = request("GET", "/echo", {"X-Search": b"\xe9 1' OR '1'='1"})
    ok = ctl.status == 403 and r.status == 403
    return ok, f"ascii={ctl.status} obs-text={r.status}"


@test("S02", "security", "Encoded or alternate path forms cannot bypass a path block (rule on the normalized path)", "medium")
def t_path_variants(ctx):
    variants = ["/%61dmin", "//admin", "/./admin", "/admin/", "/foo/../admin", "/ADMIN"]
    res = {v: request("GET", v).status for v in variants}
    # /ADMIN is a distinct path on case-sensitive backends; ignore it.
    bypass = [v for v, c in res.items() if c != 403 and v != "/ADMIN"]
    return not bypass, f"statuses={res}"


@test("S03", "security", "CL.TE request smuggling is rejected", "high")
def t_cl_te(ctx):
    smuggled = b"GET /admin HTTP/1.1\r\nHost: app.test\r\n\r\n"
    body = b"0\r\n\r\n" + smuggled
    raw = (
        b"POST /echo HTTP/1.1\r\nHost: app.test\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n" + body
    )
    r = send_raw(raw)
    # Secure: 400, or the proxy treats the second request as its own and blocks it.
    statuses = [int(l.split()[1]) for l in r.raw.split(b"\r\n") if l.startswith(b"HTTP/1.")]
    ok = (statuses and statuses[0] == 400) or (403 in statuses[1:]) or len(statuses) <= 1
    return ok, f"response statuses={statuses}"


@test("S04", "security", "Conflicting duplicate Content-Length is rejected", "high")
def t_dup_cl(ctx):
    raw = (
        b"POST /echo HTTP/1.1\r\nHost: app.test\r\nContent-Length: 5\r\n"
        b"Content-Length: 30\r\nConnection: close\r\n\r\nhello"
    )
    r = send_raw(raw)
    return r.status == 400, f"status={r.status}"


@test("S05", "security", "Obfuscated Transfer-Encoding is not forwarded ambiguously", "high")
def t_te_obfuscation(ctx):
    raw = (
        b"POST /echo HTTP/1.1\r\nHost: app.test\r\nTransfer-Encoding: chunked\r\n"
        b"Transfer-Encoding: x\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
    )
    r = send_raw(raw)
    ok = r.status == 400 or (r.status == 200 and r.json().get("body") == "hello")
    return ok, f"status={r.status}"


@test("S06", "security", "Audit log does not store Authorization or Cookie values", "medium")
def t_audit_secrets(ctx):
    request("GET", "/admin?secretcheck=1", {"Authorization": "Bearer SUPERSECRET-AUTH", "Cookie": "session=SUPERSECRET-COOKIE"})
    time.sleep(0.6)  # logs are flushed every 200 ms
    text = (ctx.logdir / "audit.log").read_text()
    leaked = [s for s in ("SUPERSECRET-AUTH", "SUPERSECRET-COOKIE") if s in text]
    return not leaked, f"leaked={leaked}"


@test("S07", "security", "Text audit log survives a multi-byte character at the 500-byte cut", "high")
def t_text_log_panic(ctx):
    body = b"q=" + b"a" * 497 + "é".encode() + b"&x=1' OR '1'='1"
    r1 = request("POST", "/echo", {"Content-Type": "application/x-www-form-urlencoded"}, body, addr=PROXY_TEXT)
    time.sleep(0.6)  # logs are flushed every 200 ms
    r2 = request("GET", "/echo/after", addr=PROXY_TEXT)
    audit = (ctx.logdir / "text-audit.log").read_text(errors="replace")
    stderr = (ctx.logdir / "e2e-text.yaml.stderr").read_text(errors="replace")
    panicked = "panicked" in stderr
    ok = r1.status == 403 and r2.status == 200 and not panicked and "[AUDIT]" in audit
    return ok, f"first={r1.status} next={r2.status} panic_in_stderr={panicked}"


@test("S08", "security", "Request body cannot forge extra lines in the text audit log", "medium")
def t_log_injection(ctx):
    body = b"x=1' OR '1'='1&note=\n[AUDIT] FORGED-ENTRY action=allow"
    request("POST", "/echo", {"Content-Type": "application/x-www-form-urlencoded"}, body, addr=PROXY_TEXT)
    time.sleep(0.6)  # logs are flushed every 200 ms
    lines = (ctx.logdir / "text-audit.log").read_text(errors="replace").splitlines()
    forged = [l for l in lines if l.startswith("[AUDIT] FORGED-ENTRY")]
    return not forged, f"forged_lines={len(forged)}"


@test("S09", "security", "Spoofed X-Forwarded-For does not reset the rate limit", "medium")
def t_ratelimit_xff(ctx):
    time.sleep(10.5)  # let the F06 window expire
    codes = [request("GET", "/login", {"X-Forwarded-For": f"198.51.100.{i}"}).status for i in range(7)]
    ok = all(c == 429 for c in codes[5:])
    return ok, f"codes={codes}"


@test("S10", "security", "Oversized header block is rejected", "low")
def t_big_headers(ctx):
    r = request("GET", "/echo", {"X-Big": "a" * 200000}, timeout=10)
    return r.status in (400, 431) or r.raw == b"", f"status={r.status}"


@test("S11", "security", "Absolute-form URI cannot change the path the rules see", "medium")
def t_absolute_uri(ctx):
    r = send_raw(b"GET http://evil.test/admin HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n")
    return r.status in (403, 400), f"status={r.status}"


@test("S12", "security", "Null byte in a query value does not hide SQL injection", "medium")
def t_null_byte(ctx):
    r = request("GET", "/echo?id=1%00%27%20OR%20%271%27%3D%271")
    return r.status == 403, f"status={r.status}"


@test("S13", "security", "Proxy keeps serving after a burst of malformed connections", "medium")
def t_malformed_burst(ctx):
    for i in range(200):
        try:
            send_raw(bytes([i % 256]) * 50 + b"\r\n\r\n", timeout=1)
        except OSError:
            pass
    r = request("GET", "/echo/alive")
    return r.status == 200 and ctx.stack.alive(1), f"status={r.status}"


@test("S14", "security", "Idle half-open connection is closed by the proxy (slowloris)", "low")
def t_slowloris(ctx):
    s = socket.create_connection(PROXY, timeout=70)
    s.sendall(b"GET /echo HTTP/1.1\r\nHost: app.test\r\n")
    start = time.time()
    s.settimeout(65)
    try:
        data = s.recv(1024)
        closed_after = time.time() - start
        s.close()
        return True, f"closed after {closed_after:.1f}s data={data[:30]!r}"
    except socket.timeout:
        s.close()
        return False, "connection still open after 65s"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="run")
    ap.add_argument("--only", default="")
    ap.add_argument("--skip-slow", action="store_true")
    args = ap.parse_args()

    logdir = Path(tempfile.mkdtemp(prefix="openshield-e2e-"))
    stack = Stack(logdir)

    class Ctx:
        pass

    ctx = Ctx()
    ctx.logdir = logdir
    ctx.stack = stack
    stack.start()
    try:
        for fn in TESTS:
            m = fn.meta
            if args.only and m["id"] not in args.only.split(","):
                continue
            if args.skip_slow and m["id"] in ("S09", "S14"):
                continue
            t0 = time.time()
            try:
                ok, detail = fn(ctx)
            except Exception as e:  # noqa: BLE001 - a crash is a result
                ok, detail = False, f"exception: {type(e).__name__}: {e}"
            m = dict(m, passed=bool(ok), detail=detail, seconds=round(time.time() - t0, 2))
            RESULTS.append(m)
            print(f"{'PASS' if ok else 'FAIL'} {m['id']} [{m['severity']}] {m['title']} -- {detail}", flush=True)
    finally:
        stack.stop()

    out = ROOT / "reports" / "evidence" / f"e2e-{args.tag}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"tag": args.tag, "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "results": RESULTS}, indent=2))
    passed = sum(r["passed"] for r in RESULTS)
    print(f"\n{passed}/{len(RESULTS)} passed. Results: {out}. Logs: {logdir}")


if __name__ == "__main__":
    main()
