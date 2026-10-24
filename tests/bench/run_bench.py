#!/usr/bin/env python3
"""Reproducible throughput and latency benchmark for OpenShield.

Runs `oha` against the echo upstream directly and through the proxy with
several configurations and traffic mixes, samples the proxy's CPU and RSS
with `ps` during each run, and writes the median of N runs as JSON.

Usage:
    python3 tests/bench/run_bench.py --tag baseline [--duration 10] [--runs 3]
Requires: release builds of `openshield` and `echo-upstream`, and `oha`.
The load generator shares the machine with the proxy, so absolute numbers are
a lower bound; compare runs made on the same machine.
"""

import argparse
import json
import os
import platform
import shutil
import signal
import socket
import statistics
import subprocess
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "target" / "release"
UPSTREAM = "127.0.0.1:13100"
PROXY = "127.0.0.1:18100"

BASE = f"""
listen: "{PROXY}"
upstream: "http://{UPSTREAM}"
workers: __WORKERS__
pid_file: "/tmp/openshield-bench.pid"
upgrade_sock: "/tmp/openshield-bench-upgrade.sock"
logging:
  format: json
  access_log: "__LOGDIR__/access.log"
  audit_log: "__LOGDIR__/audit.log"
"""

RULES = """
max_request_body_buffer: 65536
log_payloads: true
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
      - id: block-sqli-headers
        action: block
        expression: "any(detect_sqli(http.request.headers.values[*]))"
      - id: block-bad-ua
        action: block
        expression: 'lower(http.user_agent) contains "sqlmap"'
      - id: ratelimit-api
        action: block
        expression: 'starts_with(http.request.uri.path, "/api/")'
        ratelimit:
          characteristics: [ip.src]
          period: 60
          requests_per_period: 100000000
      - id: block-sqli-form
        phase: request_body
        action: block
        expression: "any(detect_sqli(http.request.body.form.values[*]))"
"""

FORM_BODY = "&".join(f"field{i}=value{i}" for i in range(40))  # ~0.6 KB

SCENARIOS = [
    # name, target, config rules, oha extra args
    ("direct_upstream_get", "upstream", None, ["/echo-free"]),
    ("proxy_norules_get", "proxy", "", ["/"]),
    ("proxy_rules_benign_get", "proxy", RULES, ["/api/products?id=42&q=shoes"]),
    ("proxy_rules_attack_get", "proxy", RULES, ["/search?q=1%27%20OR%20%271%27%3D%271"]),
    (
        "proxy_rules_form_post",
        "proxy",
        RULES,
        ["-m", "POST", "-T", "application/x-www-form-urlencoded", "-d", FORM_BODY, "/submit"],
    ),
]


def wait_port(addr, timeout=10):
    host, port = addr.split(":")
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((host, int(port)), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def sample(pid, stop, out):
    while not stop.is_set():
        try:
            r = subprocess.run(["ps", "-o", "%cpu=,rss=", "-p", str(pid)], capture_output=True, text=True)
            cpu, rss = r.stdout.split()
            out.append((float(cpu), int(rss)))
        except Exception:  # noqa: BLE001
            pass
        stop.wait(0.5)


def run_oha(url_path, extra, duration, conns, target):
    host = UPSTREAM if target == "upstream" else PROXY
    args = [a for a in extra if not a.startswith("/")]
    path = [a for a in extra if a.startswith("/")][0]
    cmd = ["oha", "-z", f"{duration}s", "-c", str(conns), "--no-tui", "--output-format", "json", *args, f"http://{host}{path}"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(r.stdout)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="run")
    ap.add_argument("--duration", type=int, default=10)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--conns", type=int, default=64)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--only", default="")
    ap.add_argument("--extra-config", default="", help="YAML appended to every proxy config")
    args = ap.parse_args()

    logdir = Path(tempfile.mkdtemp(prefix="openshield-bench-"))
    up = subprocess.Popen([str(BIN / "echo-upstream"), UPSTREAM], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert wait_port(UPSTREAM)
    results = {}
    try:
        for name, target, rules, extra in SCENARIOS:
            if args.only and name not in args.only.split(","):
                continue
            proxy = None
            if target == "proxy":
                cfg = BASE.replace("__WORKERS__", str(args.workers)).replace("__LOGDIR__", str(logdir)) + rules + "\n" + args.extra_config
                cfg_path = logdir / f"{name}.yaml"
                cfg_path.write_text(cfg)
                proxy = subprocess.Popen(
                    [str(BIN / "openshield"), "-c", str(cfg_path)],
                    stdout=subprocess.DEVNULL,
                    stderr=open(logdir / f"{name}.stderr", "wb"),
                )
                assert wait_port(PROXY), f"proxy failed for {name}"
                time.sleep(0.3)
            # Warm-up
            run_oha(None, extra, 2, args.conns, target)
            runs = []
            for _ in range(args.runs):
                samples, stop = [], threading.Event()
                th = None
                if proxy:
                    th = threading.Thread(target=sample, args=(proxy.pid, stop, samples))
                    th.start()
                res = run_oha(None, extra, args.duration, args.conns, target)
                stop.set()
                if th:
                    th.join()
                s = res["summary"]
                lat = res["latencyPercentiles"]
                codes = res.get("statusCodeDistribution", {})
                runs.append(
                    {
                        "rps": s["requestsPerSec"],
                        "success_rate": s["successRate"],
                        "p50_ms": lat["p50"] * 1000,
                        "p95_ms": lat["p95"] * 1000,
                        "p99_ms": lat["p99"] * 1000,
                        "status_codes": codes,
                        "cpu_pct_avg": statistics.mean(c for c, _ in samples) if samples else None,
                        "rss_mb_max": max(r for _, r in samples) / 1024 if samples else None,
                        "requests": sum(int(v) for v in codes.values()),
                        "errors": res.get("errorDistribution", {}),
                    }
                )
            med = lambda k: statistics.median(r[k] for r in runs if r[k] is not None) if any(r[k] is not None for r in runs) else None  # noqa: E731
            results[name] = {
                "runs": runs,
                "median": {k: med(k) for k in ("rps", "p50_ms", "p95_ms", "p99_ms", "cpu_pct_avg", "rss_mb_max")},
            }
            m = results[name]["median"]
            print(
                f"{name:28s} rps={m['rps']:>9.0f} p50={m['p50_ms']:.2f}ms p95={m['p95_ms']:.2f}ms "
                f"p99={m['p99_ms']:.2f}ms cpu={m['cpu_pct_avg'] or 0:.0f}% rss={m['rss_mb_max'] or 0:.1f}MB "
                f"codes={runs[-1]['status_codes']}",
                flush=True,
            )
            if proxy:
                proxy.send_signal(signal.SIGTERM)
                try:
                    proxy.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proxy.kill()
                time.sleep(0.5)
    finally:
        up.send_signal(signal.SIGTERM)
        up.wait()

    meta = {
        "tag": args.tag,
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "machine": f"{platform.machine()} {platform.platform()}",
        "cpu_count": os.cpu_count(),
        "duration_s": args.duration,
        "runs": args.runs,
        "connections": args.conns,
        "proxy_workers": args.workers,
        "load_generator": subprocess.run(["oha", "--version"], capture_output=True, text=True).stdout.strip(),
        "git": subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, cwd=ROOT).stdout.strip(),
    }
    out = ROOT / "reports" / "evidence" / f"bench-{args.tag}.json"
    out.write_text(json.dumps({"meta": meta, "results": results}, indent=2))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
