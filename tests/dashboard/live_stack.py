#!/usr/bin/env python3
"""Run the real dashboard against live traffic, for UI development.

Starts echo-upstream, mock-gemini (a test double, not a model), and the
proxy with intel and admin on, then sends a steady mix of normal requests,
blocked attacks, a challenged path, scanning bursts and occasional floods
from a range of client addresses (named via X-Forwarded-For through the
trusted local peer).

Dev tokens are generated per run and written, with mode 0600, to the file
given by --token-file (default: a temp file). The script prints only the
file's path, never the tokens.

Usage: python3 tests/dashboard/live_stack.py [--token-file PATH] [--rps 20]
Dashboard: http://127.0.0.1:19190/
"""

import argparse
import json
import os
import random
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "target" / "release"
CFG = ROOT / "tests" / "e2e" / "configs" / "e2e-intel.yaml"


def wait_port(port, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def send(path, ip, method="GET", headers=None, body=b""):
    h = {"Host": "shop.example", "X-Forwarded-For": ip, "Connection": "close",
         "User-Agent": random.choice(["Mozilla/5.0 (Macintosh) Safari/605.1", "Mozilla/5.0 (Windows NT 10.0) Chrome/130.0", "curl/8.7.1"])}
    h.update(headers or {})
    if body:
        h["Content-Length"] = str(len(body))
    raw = f"{method} {path} HTTP/1.1\r\n".encode() + b"".join(f"{k}: {v}\r\n".encode() for k, v in h.items()) + b"\r\n" + body
    try:
        with socket.create_connection(("127.0.0.1", 18090), timeout=3) as s:
            s.sendall(raw)
            while s.recv(65536):
                pass
    except OSError:
        pass


NORMAL = ["/", "/echo/products", "/echo/products/42", "/echo/cart", "/echo/api/v1/orders/1007", "/search?q=running+shoes",
          "/echo/account", "/echo/static/app.js", "/echo/api/v1/products?page=2", "/status/404", "/slow?ms=40", "/status/500"]
ATTACKS = ["/echo/products?id=1%27%20OR%20%271%27%3D%271", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "/admin", "/%61dmin",
           "/echo/products?id=1%20UNION%20SELECT%20password%20FROM%20users"]


def traffic(rps, stop):
    clients = [f"203.0.113.{i}" for i in range(1, 60)] + [f"198.51.100.{i}" for i in range(1, 30)]
    attackers = ["192.0.2.66", "192.0.2.77", "198.51.100.200"]
    tick = 1.0 / rps
    n = 0
    while not stop.is_set():
        n += 1
        r = random.random()
        if r < 0.80:
            send(random.choice(NORMAL), random.choice(clients))
        elif r < 0.93:
            send(random.choice(ATTACKS), random.choice(attackers))
        elif r < 0.97:
            send("/protected/report", random.choice(clients))
        else:
            # a scanner probing missing paths
            ip = random.choice(attackers)
            for i in range(15):
                send(f"/status/404?probe={i}", ip)
        if n % 900 == 0:
            ip = f"203.0.113.{random.randint(100, 120)}"
            for _ in range(60):
                send("/echo/flood", ip)
        time.sleep(tick)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--token-file", default=str(Path(tempfile.gettempdir()) / "openshield-dashboard-tokens.json"))
    ap.add_argument("--rps", type=float, default=20)
    args = ap.parse_args()
    tokens = {k: "dev-" + secrets.token_hex(16) for k in ("alice", "bob", "ana", "val")}
    tf = Path(args.token_file)
    tf.write_text(json.dumps(tokens))
    os.chmod(tf, 0o600)
    logdir = Path(tempfile.mkdtemp(prefix="openshield-dashboard-"))
    env = {**os.environ, "RUST_LOG": "openshield=warn,pingora=warn", "OS_E2E_GEMINI_KEY": "dev-key-" + secrets.token_hex(8),
           "OS_E2E_ADMIN": tokens["alice"], "OS_E2E_ADMIN2": tokens["bob"], "OS_E2E_ANALYST": tokens["ana"], "OS_E2E_VIEWER": tokens["val"]}
    procs = [
        subprocess.Popen([str(BIN / "echo-upstream"), "127.0.0.1:13000"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
        subprocess.Popen([str(BIN / "mock-gemini"), "127.0.0.1:13900"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
    ]
    (logdir / "intel.yaml").write_text(CFG.read_text().replace("__LOGDIR__", str(logdir)))
    procs.append(subprocess.Popen([str(BIN / "openshield"), "-c", str(logdir / "intel.yaml")], env=env,
                                  stdout=open(logdir / "proxy.log", "wb"), stderr=subprocess.STDOUT))
    if not (wait_port(18090) and wait_port(19190)):
        print("proxy failed to start; see", logdir / "proxy.log", flush=True)
        sys.exit(1)
    print(f"Dashboard: http://127.0.0.1:19190/  tokens: {tf}  logs: {logdir}", flush=True)
    stop = threading.Event()
    th = threading.Thread(target=traffic, args=(args.rps, stop), daemon=True)
    th.start()

    def shutdown(*_):
        stop.set()
        for p in procs:
            p.send_signal(signal.SIGTERM)
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    while True:
        time.sleep(1)
        if procs[-1].poll() is not None:
            print("proxy exited", flush=True)
            shutdown()


if __name__ == "__main__":
    main()
