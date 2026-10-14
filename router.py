#!/usr/bin/env python3
"""Router worker: reports uncovered AI traffic, never stops a program."""
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

APP = Path(sys.argv[1])
ONCE = os.environ.get("GUARDRAIL_ONCE") == "1"
SHOW = os.environ.get("GUARDRAIL_SHOW") == "1"
PORT = os.environ.get("GUARDRAIL_PORT", "8899")
SYSTEM = os.environ.get("GUARDRAIL_SYSTEM", "0")   # "1" = installed layout owns the port
LOCK = APP / "data" / "locked.json"
STATE = APP / "data" / "reported.json"
EVENTS = APP / "data" / "router-state.json"
TICK = 1.0
GUARDRAIL_LOG = Path("/tmp/guardrail-run.log")
sys.path.insert(0, str(APP))
import rules

rules.load_config()
INSTALLED = {app["app"] for app in rules.detect_ai_apps()}   # what is really here, with evidence


def say(text: str) -> None:
    if SHOW:
        print(text, flush=True)


def read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def write_json(path: Path, data) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=1), encoding="utf-8")
    except OSError:
        pass


last_lock = ""


def note(event: str, **extra) -> None:
    """The one line run.sh shows as 'last event'."""
    write_json(EVENTS, {"at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "event": event, **extra})


def ancestors_of(pid: int) -> set:
    """This process and everything that started it."""
    seen, walk = set(), pid
    while walk and walk not in seen:
        seen.add(walk)
        try:
            walk = int(Path(f"/proc/{walk}/stat").read_text().rsplit(")", 1)[1].split()[1])
        except (OSError, IndexError, ValueError):
            break
    return seen


def pidfile_pid(name: str) -> int:
    """The pid a stop-file holds, trusted while it is ours."""
    try:
        pid = int((APP / "data" / f"{name}.pid").read_text(encoding="utf-8").strip())
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().decode("utf-8", "replace")
    except (OSError, ValueError):
        return 0
    if str(APP) in cmdline or "mitmdump" in cmdline:
        return pid
    return 0


def protected() -> set:
    """Our own programs and their starter sessions, never reported."""
    pids = {pid for pid in (pidfile_pid(n) for n in ("guardrail", "router", "panel")) if pid}
    pids |= ancestors_of(os.getpid())
    for pid in (pidfile_pid("panel"), pidfile_pid("guardrail")):
        if pid:
            pids |= ancestors_of(pid)
    return pids


def write_lock(direct: list, running: list, never_stop: set) -> None:
    """Written only when the picture changes, not every second."""
    global last_lock
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    locked = [{"pid": c["pid"], "app": c["app"], "cmdline": c["cmdline"], "argv": c.get("argv") or [],
               "endpoint": f"{c['host']}:{c['port']}", "direct": True,
               "protected": c["pid"] in never_stop,
               "locked_at": stamp} for c in direct]
    locked = [e for e in locked if os.path.exists(f"/proc/{e['pid']}")]
    locked += [{"pid": a["pid"], "app": a["app"], "cmdline": a.get("cmdline") or "",
                "argv": a.get("argv") or [], "endpoint": "", "direct": False,
                "locked_at": stamp}
               for a in running
               if a["pid"] not in {c["pid"] for c in direct} and os.path.exists(f"/proc/{a['pid']}")]
    signature = json.dumps([{k: v for k, v in e.items() if k != "locked_at"} for e in locked],
                           sort_keys=True)
    if signature == last_lock:
        return
    last_lock = signature
    write_json(LOCK, {"locked": locked, "at": stamp})


def port_open() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", int(PORT)), timeout=0.5):
            return True
    except OSError:
        return False


def keep_proxy_alive() -> None:
    """The proxy is the point: restart it, and say so."""
    if port_open():
        return
    time.sleep(1.5)                       # a proxy still binding its port is not dead
    if port_open():
        return
    if SYSTEM == "1":
        # helper starts the installed proxy; ours would loop its traffic
        try:
            subprocess.run(["sudo", "-n", "/usr/local/sbin/guardrail-adm", "proxy-start"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
        except (OSError, subprocess.SubprocessError):
            pass
        for _ in range(20):
            time.sleep(0.5)
            if port_open():
                say("  system proxy restarted (guardrail-proxy)")
                note("system proxy restarted by the router")
                return
        note("the system proxy would not start: sudo /usr/local/sbin/guardrail-adm proxy-start")
        return
    try:
        os.chmod(GUARDRAIL_LOG, 0o600)
    except OSError:
        pass
    # created 0600: this log carries request headers
    log_fd = os.open(GUARDRAIL_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    subprocess.Popen([str(APP / ".venv/bin/mitmdump"), "--set", "flow_detail=1"], cwd=str(APP),
                     stdout=log_fd, stderr=subprocess.STDOUT,
                     start_new_session=True)
    for _ in range(40):
        time.sleep(0.25)
        if port_open():
            say("  guardrail restarted by the router")
            note("guardrail restarted by the router")
            return
    note("the guardrail would not start: check /tmp/guardrail-run.log")


def report(entry: dict) -> None:
    """Say what is not going through the guardrail; stop nothing."""
    pid = entry["pid"]
    where = f"{entry['host']}:{entry['port']}"
    if not pid:
        # real traffic, no owner: turn the desktop proxy on
        rules.set_desktop_proxy(True, rules.pac_file())
        note(f"AI traffic from an unowned connection -> {where} (desktop proxy turned on)",
             host=entry["host"], pid=None)
        say(f"  unowned: -> {where} (desktop proxy turned on)")
        return
    if not os.path.exists(f"/proc/{pid}"):
        note("the program exited before it could be reported", app=entry["app"], pid=pid)
        return
    command = (entry.get("cmdline") or "").strip()
    if not command:
        # no name: browser or unlisted app; desktop proxy covers it
        rules.set_desktop_proxy(True, rules.pac_file())
        note(f"AI traffic (pid {pid}) -> {where} from a program that could not be named "
             f"(desktop proxy turned on)", pid=pid, host=entry["host"], endpoint=where)
        say(f"  unnamed: pid {pid} -> {where} (desktop proxy turned on)")
        return
    if entry["app"] not in INSTALLED:
        # same name, not installed: a look-alike, not the program
        rules.set_desktop_proxy(True, rules.pac_file())
        note(f"AI traffic (pid {pid}) -> {where} from a process named '{entry['app']}', which is not "
             f"installed here (desktop proxy turned on)", pid=pid, host=entry["host"],
             endpoint=where, looked_like=entry["app"])
        say(f"  look-alike: pid {pid} -> {where} (named '{entry['app']}', not installed here)")
        return
    if rules.process_kind(pid, command) == "desktop":
        # browser reads the system proxy; PAC covers the next connection
        rules.set_desktop_proxy(True, rules.pac_file())
        note(f"{entry['app']} (pid {pid}) -> {where} covered by the desktop proxy",
             app=entry["app"], pid=pid, endpoint=where, mode="desktop")
        say(f"  desktop: {entry['app']} (pid {pid}) -> system proxy turned on")
        return
    note(f"{entry['app']} (pid {pid}) -> {where} is talking straight to the provider and is left "
         f"running. Start it through the guardrail as: run.sh -- {command}",
         app=entry["app"], pid=pid, endpoint=where, where="left running",
         rerun=f"run.sh -- {command}")
    say(f"  not routed: {entry['app']} (pid {pid}) -> {where}")
    say(f"              start it as: run.sh -- {command}")


def own_traffic(direct: list, ours: set) -> list:
    """Drop our own connections and unnamed ones."""
    return [c for c in direct
            if c.get("pid") not in ours
            and str(APP) not in (c.get("cmdline") or "")
            and "mitmdump" not in (c.get("cmdline") or "")
            and not (c.get("cmdline") or "").startswith("pid ")]


def learn_endpoints(direct: list) -> None:
    """Write down an endpoint the list does not know yet."""
    for c in direct:
        if c.get("host") and rules.learn_endpoint(c["host"], reason="traffic to an AI endpoint",
                                                  source=c["app"]):
            say(f"  new endpoint added: {c['host']}")
            note(f"new endpoint added: {c['host']}", host=c["host"], app=c["app"])


def announce(direct: list, ours: set, seen: set, state: dict) -> None:
    """Report each active agent once, and stop nothing."""
    for entry in direct:
        pid = entry["pid"]
        if pid in ours or pid in seen:
            continue
        key = hashlib.sha256((entry.get("cmdline") or "").encode()).hexdigest()[:12]
        if key in state:
            seen.add(pid)
            continue
        seen.add(pid)
        say(f"  active agent: {entry['app']} (pid {pid}) -> {entry['host']}:{entry['port']}")
        report(entry)
        state[key] = {"at": time.time(), "app": entry["app"],
                      "endpoint": f"{entry['host']}:{entry['port']}"}
        write_json(STATE, state)


def main() -> int:
    state = read_json(STATE)
    seen: set = set()
    try:
        (APP / "data" / "router.pid").write_text(str(os.getpid()), encoding="utf-8")
    except OSError:
        pass
    note("scan started")
    while True:
        keep_proxy_alive()
        direct = rules.uncovered_ai_traffic()
        ours = protected()
        direct = own_traffic(direct, ours)
        learn_endpoints(direct)
        write_lock(direct, rules.running_ai_apps(), ours)
        announce(direct, ours, seen, state)
        if ONCE:
            return 0
        time.sleep(TICK)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(0)
