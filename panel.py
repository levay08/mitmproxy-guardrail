#!/usr/bin/env python3
"""Status panel for the running guardrail; prints only on change."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

APP = Path(sys.argv[1])
PORT = sys.argv[2]
LOCK = APP / "data" / "locked.json"
REPORTED = APP / "data" / "reported.json"
EVENTS = APP / "data" / "router-state.json"


def read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _label(entry: dict) -> str:
    """One clean name per program, never a placeholder."""
    name = (entry.get("app") or "").strip()
    return name if name and not name.startswith("pid ") else f"pid {entry.get('pid')}"


def listening() -> bool:
    """Asked of ss, which reports the listening sockets directly."""
    try:
        out = subprocess.run(["ss", "-ltnH", f"sport = :{PORT}"], capture_output=True, text=True,
                             timeout=5)
        return bool(out.stdout.strip())
    except (OSError, subprocess.TimeoutExpired):
        return False


def pid_alive(pidfile: Path) -> bool:
    try:
        pid = int(pidfile.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return False
    return Path(f"/proc/{pid}").exists()


def panel() -> str:
    up = listening()
    router = pid_alive(APP / "data" / "router.pid")
    lock = read_json(LOCK)
    reported = read_json(REPORTED)
    event = read_json(EVENTS)
    mode_file = APP / "data" / "mode"
    mode = mode_file.read_text(encoding="utf-8").strip() if mode_file.exists() else "default from guardrail.yaml"
    entries = lock.get("locked") or []
    direct = [e for e in entries if e.get("direct")]
    quiet = [e for e in entries if not e.get("direct")]
    learned = read_json(APP / "data" / "endpoints-learned.json")
    lines = [
        f"guardrail : {'UP' if up else 'DOWN'} on 127.0.0.1:{PORT}   mode: {mode}",
        f"router    : {'running silently, scanning every second' if router else 'not running'}",
        f"locked    : {len(direct)} agents active"
        + (" (" + ", ".join(_label(e) + (" this session, protected" if e.get("protected") else "")
                            for e in direct) + ")" if direct else "")
        + f" | {len(quiet)} programs idle",
        f"reported  : {len(reported)} program(s) talking straight to a provider",
    ]
    if learned.get("hosts"):
        last_host = (learned.get("last") or {}).get("host")
        lines.append(f"learned   : {len(learned['hosts'])} endpoint(s) added by the scanner"
                     + (f" | last: {last_host}" if last_host else ""))
    if event.get("event"):
        lines.append(f"last      : {event['event']}  ({event.get('at', '-')})")
    return "\n".join(lines)


def main() -> int:
    print("run.sh: status panel (Ctrl-C exits; the guardrail and router keep running)", flush=True)
    print("        start an AI program through the guardrail with: run.sh -- <command>", flush=True)
    last = None
    try:
        while True:
            now = panel()
            if now != last:
                print(now, flush=True)
                last = now
            time.sleep(2)
    except KeyboardInterrupt:
        print("\npanel closed. The guardrail and router are still running; 'run.sh --stop' stops them.")
    finally:
        (APP / "data" / "panel.pid").unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
