#!/usr/bin/env python3
"""Print one script that defines window.__uiAudit (from ui_audit.js) and
then runs ui_sweep.js, for pasting into a browser tool's JavaScript runner.

Usage: python3 tests/dashboard/inject_audit.py [--audit-only]
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
audit = "\n".join(l for l in (HERE / "ui_audit.js").read_text().splitlines() if not l.lstrip().startswith("//")).strip().rstrip(";")
out = "window.__uiAudit = () => " + audit + ";\n"
if "--audit-only" in sys.argv:
    out += "window.__uiAudit();\n"
else:
    out += (HERE / "ui_sweep.js").read_text()
sys.stdout.write(out)
