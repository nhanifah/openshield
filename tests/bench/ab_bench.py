#!/usr/bin/env python3
"""Interleaved A/B benchmark: baseline vs current (vs current with intel on).

Earlier runs were taken minutes apart, and the direct-to-upstream control
moved by up to 26% between them, so machine state (heat, background load)
was mixed into the comparison. This script removes that by alternating
variants inside each round, rotating their order every round, and measuring
the direct upstream every round as a drift control. Report medians across
rounds; compare variants within the same run only.

Usage:
    python3 tests/bench/ab_bench.py --baseline-bin PATH [--rounds 5] [--duration 10] [--tag ab]
`--baseline-bin` is an `openshield` binary built from the baseline commit.
"""

import argparse
import json
import os
import platform
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_bench import BASE, BIN, PROXY, ROOT, RULES, SCENARIOS, UPSTREAM, run_oha, sample, wait_port  # noqa: E402

INTEL = """
intel:
  enabled: true
  store:
    path: "__LOGDIR__/intel.db"
"""


def run_proxy_scenario(binary, cfg_text, extra, args, logdir):
    proc = subprocess.Popen([binary, "-c", str(cfg_text)], stdout=subprocess.DEVNULL, stderr=open(logdir / "proxy.stderr", "ab"))
    try:
        if not wait_port(PROXY):
            raise RuntimeError(f"proxy did not start: {binary}")
        time.sleep(0.3)
        run_oha(None, extra, 2, args.conns, "proxy")  # warm-up
        samples, stop = [], threading.Event()
        th = threading.Thread(target=sample, args=(proc.pid, stop, samples))
        th.start()
        res = run_oha(None, extra, args.duration, args.conns, "proxy")
        stop.set()
        th.join()
        return res, samples
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()  # pingora's graceful shutdown can wait for idle peers
            proc.wait()
        time.sleep(0.5)


def summarize(res, samples):
    s, lat = res["summary"], res["latencyPercentiles"]
    return {
        "rps": s["requestsPerSec"],
        "success_rate": s["successRate"],
        "p50_ms": lat["p50"] * 1000,
        "p95_ms": lat["p95"] * 1000,
        "p99_ms": lat["p99"] * 1000,
        "cpu_pct_avg": statistics.mean(c for c, _ in samples) if samples else None,
        "rss_mb_max": max(r for _, r in samples) / 1024 if samples else None,
        "status_codes": res.get("statusCodeDistribution", {}),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline-bin", required=True)
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--duration", type=int, default=10)
    ap.add_argument("--conns", type=int, default=64)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--tag", default="ab")
    args = ap.parse_args()

    variants = [
        ("baseline", args.baseline_bin, False),
        ("current", str(BIN / "openshield"), False),
        ("current_intel", str(BIN / "openshield"), True),
    ]
    logdir = Path(tempfile.mkdtemp(prefix="openshield-ab-"))
    up = subprocess.Popen([str(BIN / "echo-upstream"), UPSTREAM], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert wait_port(UPSTREAM)
    runs = []
    try:
        for r in range(args.rounds):
            # Drift control: the upstream alone.
            direct = [s for s in SCENARIOS if s[1] == "upstream"][0]
            run_oha(None, direct[3], 2, args.conns, "upstream")
            res = run_oha(None, direct[3], args.duration, args.conns, "upstream")
            runs.append({"round": r, "scenario": direct[0], "variant": "upstream_direct", **summarize(res, [])})
            print(f"round {r} {direct[0]:28s} upstream_direct rps={runs[-1]['rps']:.0f}", flush=True)
            order = variants[r % 3:] + variants[: r % 3]
            for name, target, rules, extra in SCENARIOS:
                if target != "proxy":
                    continue
                for vname, binary, intel in order:
                    rundir = logdir / f"r{r}-{name}-{vname}"
                    rundir.mkdir()
                    cfg = BASE.replace("__WORKERS__", str(args.workers)).replace("__LOGDIR__", str(rundir)) + rules
                    if intel:
                        cfg += INTEL.replace("__LOGDIR__", str(rundir))
                    cfg_path = rundir / "c.yaml"
                    cfg_path.write_text(cfg)
                    res, samples = run_proxy_scenario(binary, cfg_path, extra, args, rundir)
                    runs.append({"round": r, "scenario": name, "variant": vname, **summarize(res, samples)})
                    m = runs[-1]
                    print(f"round {r} {name:28s} {vname:14s} rps={m['rps']:>8.0f} p50={m['p50_ms']:.2f} p95={m['p95_ms']:.2f} p99={m['p99_ms']:.2f} cpu={m['cpu_pct_avg'] or 0:.0f}% rss={m['rss_mb_max'] or 0:.0f}MB", flush=True)
                    if intel:
                        shutil.rmtree(rundir, ignore_errors=True)
    finally:
        up.send_signal(signal.SIGTERM)
        up.wait()

    med = {}
    for run in runs:
        key = (run["scenario"], run["variant"])
        med.setdefault(key, []).append(run)
    summary = []
    for (scen, var), rs in med.items():
        def m(k):
            vals = [x[k] for x in rs if x[k] is not None]
            return statistics.median(vals) if vals else None
        summary.append({"scenario": scen, "variant": var, "n": len(rs),
                        **{k: m(k) for k in ("rps", "p50_ms", "p95_ms", "p99_ms", "cpu_pct_avg", "rss_mb_max")},
                        "rps_min": min(x["rps"] for x in rs), "rps_max": max(x["rps"] for x in rs)})
    meta = {
        "tag": args.tag, "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "machine": f"{platform.machine()} {platform.platform()}", "cpu_count": os.cpu_count(),
        "rounds": args.rounds, "duration_s": args.duration, "connections": args.conns, "proxy_workers": args.workers,
        "baseline_bin": args.baseline_bin, "method": "variants interleaved per round, order rotated each round; medians across rounds",
        "git": subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, cwd=ROOT).stdout.strip(),
    }
    out = ROOT / "reports" / "evidence" / f"bench-{args.tag}.json"
    out.write_text(json.dumps({"meta": meta, "summary": summary, "runs": runs}, indent=2))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
