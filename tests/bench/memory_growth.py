#!/usr/bin/env python3
"""Measure proxy RSS growth when every request carries a unique rate-limit key.

A rule rate-limits per path with `requests_per_period: 0` and a long
`mitigation_timeout`, so every unique path enters mitigation. With an
unbounded mitigation table, RSS grows with the number of unique keys.

Usage: python3 tests/bench/memory_growth.py --tag baseline [--requests 300000]
"""

import argparse
import json
import signal
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "target" / "release"

CFG = """
listen: "127.0.0.1:18200"
upstream: "http://127.0.0.1:13200"
workers: 4
pid_file: "/tmp/openshield-mem.pid"
upgrade_sock: "/tmp/openshield-mem-upgrade.sock"
logging: {format: json, access_log: "/dev/null", audit_log: "/dev/null"}
rulesets:
  - name: main
    kind: root
    rules:
      - id: rl-path
        action: block
        expression: 'true'
        logging: {enabled: false}
        ratelimit:
          characteristics: [http.request.uri.path]
          period: 60
          requests_per_period: 0
          mitigation_timeout: 3600
"""


def rss_mb(pid):
    out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True).stdout
    return int(out.strip()) / 1024


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="run")
    ap.add_argument("--requests", type=int, default=300000)
    ap.add_argument("--bin", default=str(BIN / "openshield"), help="openshield binary to test")
    args = ap.parse_args()
    d = Path(tempfile.mkdtemp())
    (d / "c.yaml").write_text(CFG)
    up = subprocess.Popen([str(BIN / "echo-upstream"), "127.0.0.1:13200"], stderr=subprocess.DEVNULL)
    px = subprocess.Popen([args.bin, "-c", str(d / "c.yaml")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    points = []
    try:
        # Warm up with a fixed path so allocator pools are populated.
        subprocess.run(["oha", "-n", "20000", "-c", "32", "--no-tui", "http://127.0.0.1:18200/warm"], capture_output=True)
        time.sleep(0.5)
        points.append({"unique_keys": 0, "rss_mb": rss_mb(px.pid)})
        step = args.requests // 3
        for i in range(1, 4):
            subprocess.run(
                ["oha", "-n", str(step), "-c", "32", "--no-tui", "--rand-regex-url", "http://127[.]0[.]0[.]1:18200/[a-z0-9]{24}"],
                capture_output=True,
            )
            time.sleep(0.5)
            points.append({"unique_keys": step * i, "rss_mb": rss_mb(px.pid)})
            print(points[-1], flush=True)
    finally:
        px.kill()
        up.send_signal(signal.SIGTERM)
        px.wait()
        up.wait()
    growth = points[-1]["rss_mb"] - points[0]["rss_mb"]
    res = {"tag": args.tag, "points": points, "growth_mb": growth, "bytes_per_key": growth * 1024 * 1024 / max(1, points[-1]["unique_keys"])}
    print(json.dumps(res, indent=2))
    (ROOT / "reports" / "evidence" / f"memory-growth-{args.tag}.json").write_text(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
