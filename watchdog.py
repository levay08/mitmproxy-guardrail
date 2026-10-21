"""Watch the armed proxy; revert after a countdown.

    python3 -I watchdog.py start|stop|status|once|run|banners

Started by `guardrail-adm arm` as the owner, stopped by `disarm`. It watches the
proxy: listener, and one health request through the regular port. It never
scans traffic, never touches a rule or a verdict. Its one read of the audit log
is the banner follower: new MASK and BLOCK lines, and requests forwarded because the
attack rules were not loaded, become a desktop banner built
from host, action and rule labels only, never from prompt text.
Busy is not dead: a health request that times out while both ports accept and the
proxy process lives is logged as busy and never counts as a miss. Only a closed
port (after retries with backoff) or a gone process is a death verdict.
No AI, no model call, no agent page anywhere here: script and log only.
Knobs: WATCHDOG_INTERVAL (5s) WATCHDOG_TIMEOUT (30s) WATCHDOG_FAILS (3)
WATCHDOG_PROC (mitmdump) WATCHDOG_RETRIES (3)
WATCHDOG_COUNTDOWN (10s) WATCHDOG_DRY=1 observe only, WATCHDOG_NO_NOTIFY=1.
Banners: WATCHDOG_AUDIT (audit path) WATCHDOG_BANNER_COOL (60s per key)
WATCHDOG_BANNER_MAX (6 per minute) WATCHDOG_BANNER_SCOPE=all|person WATCHDOG_BANNERS=0 off
WATCHDOG_BANNER_FROM_START=1 reads the audit from the beginning instead of the end.
"""
import collections
import json
import math
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def knob(name: str, default: float, low: float) -> float:
    """A numeric knob; a bad value stops the start."""
    raw = os.environ.get(name, "")
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        sys.exit(f"watchdog: {name}={raw!r} is not a number")
    if not value >= low:
        sys.exit(f"watchdog: {name}={raw} is below the minimum {low:g}")
    return value


PORT = int(knob("GUARDRAIL_PORT", 8899, 1))
REGULAR_PORT = int(knob("GUARDRAIL_REGULAR_PORT", 8898, 1))
INTERVAL = knob("WATCHDOG_INTERVAL", 5, 0.2)
TIMEOUT = knob("WATCHDOG_TIMEOUT", 30, 0.2)
RETRIES = int(knob("WATCHDOG_RETRIES", 3, 1))
PROC_NEEDLE = os.environ.get("WATCHDOG_PROC", "mitmdump")
FAILS = int(knob("WATCHDOG_FAILS", 3, 1))
COUNTDOWN = int(knob("WATCHDOG_COUNTDOWN", 10, 1))
RULE_EVERY = knob("WATCHDOG_RULE_EVERY", 300, 1)
DRY = os.environ.get("WATCHDOG_DRY", "0") == "1"
NO_NOTIFY = os.environ.get("WATCHDOG_NO_NOTIFY", "0") == "1"
# any neutral address answering means the network is up
NEUTRAL = [t.strip() for t in os.environ.get(
    "WATCHDOG_NEUTRAL", "1.1.1.1:443,9.9.9.9:443,8.8.8.8:443").split(",") if t.strip()]
ROUTER_PID = Path(os.environ.get("WATCHDOG_ROUTER_PID", HERE / "data" / "router.pid"))
HELPERS = [os.environ["WATCHDOG_HELPER"]] if os.environ.get("WATCHDOG_HELPER") else [
    "/usr/local/sbin/guardrail-adm", "/usr/local/sbin/guardrail-root"]
# tests swap sudo for a stub helper
SUDO = shlex.split(os.environ.get("WATCHDOG_SUDO", "sudo -n"))
STOP = threading.Event()
BAD_RULE_POLLS = 2
NET_RETRY = knob("WATCHDOG_NET_RETRY", 30, 1)
AUDIT = Path(os.environ.get("WATCHDOG_AUDIT", "/var/log/guardrail/audit.jsonl"))
BANNER_COOL = knob("WATCHDOG_BANNER_COOL", 60, 1)
BANNER_MAX = int(knob("WATCHDOG_BANNER_MAX", 6, 1))
BANNER_POLL = knob("WATCHDOG_BANNER_POLL", 0.5, 0.1)
BANNERS_ON = os.environ.get("WATCHDOG_BANNERS", "1") != "0"
BANNER_SCOPE = os.environ.get("WATCHDOG_BANNER_SCOPE", "all")
BANNER_FROM_START = os.environ.get("WATCHDOG_BANNER_FROM_START", "0") == "1"
BANNER_SEEN: dict[str, float] = {}
BANNER_WINDOW: collections.deque = collections.deque()


def _banner_new_lines(offset: int) -> tuple[list[dict], int]:
    """Records written after offset; a rotated file restarts at zero."""
    try:
        size = AUDIT.stat().st_size
    except OSError:
        return [], offset
    if size < offset:
        offset = 0
    try:
        with AUDIT.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(offset)
            data = fh.read()
            offset = fh.tell()
    except OSError:
        return [], offset
    records = []
    for line in data.splitlines():
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records, offset


def _banner_for(record: dict) -> tuple[str, str] | None:
    """Title and body for one decision; labels only, never text."""
    action = str(record.get("action") or "").upper()
    host = str(record.get("host") or "?")
    if action not in ("MASK", "BLOCK"):
        state = record.get("external_state") or {}
        if isinstance(state, dict) and state.get("skipped") == "atr-not-ready":
            return "Guardrail UNCHECKED", f"{host} | attack rules not loaded, forwarded unchecked"
        return None
    if BANNER_SCOPE == "person" and not (record.get("masked_user_kinds")
                                        or record.get("user_warn")
                                        or record.get("masked_kinds")):
        return None
    labels = sorted({str(x) for x in (record.get("findings") or []) if str(x).strip()})
    return f"Guardrail {action}", f"{host} | {', '.join(labels[:6]) or '-'}"


def banner_loop() -> None:
    """Each new audit MASK or BLOCK line becomes one banner."""
    offset = 0
    if not BANNER_FROM_START:
        try:
            offset = AUDIT.stat().st_size
        except OSError:
            offset = 0
    while not STOP.is_set():
        records, offset = _banner_new_lines(offset)
        now = time.monotonic()
        for record in records:
            pair = _banner_for(record)
            if not pair:
                continue
            key = ("unchecked" if pair[0] == "Guardrail UNCHECKED"
                   else f"{record.get('host')}|{record.get('action')}")
            if now - BANNER_SEEN.get(key, -BANNER_COOL) < BANNER_COOL:
                continue
            while BANNER_WINDOW and now - BANNER_WINDOW[0] > 60:
                BANNER_WINDOW.popleft()
            if len(BANNER_WINDOW) >= BANNER_MAX:
                continue
            BANNER_SEEN[key] = now
            BANNER_WINDOW.append(now)
            notify(pair[0], pair[1])
        STOP.wait(BANNER_POLL)


def banners() -> int:
    """Run the banner follower alone (tests and by hand)."""
    banner_loop()
    return 0


def state_dir() -> Path:
    """Owner-only folder for pid, log and the reverting marker."""
    env = os.environ.get("WATCHDOG_DIR")
    uid = os.getuid()
    if env:
        path = Path(env)
    elif Path(f"/run/user/{uid}").is_dir():
        path = Path(f"/run/user/{uid}/guardrail-watchdog")
    else:
        path = Path(f"/tmp/guardrail-watchdog-{uid}")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if path.is_symlink() or info.st_uid != uid or info.st_mode & 0o077:
        sys.exit(f"watchdog: {path} is not a private folder of this user")
    return path


DIR = state_dir()
PIDFILE = DIR / "watchdog.pid"
LOGFILE = DIR / "watchdog.log"
REVERTING = DIR / "reverting"


def log(line: str, echo: bool = True) -> None:
    text = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {line}"
    fd = os.open(LOGFILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as handle:
        handle.write(text + "\n")
    if echo:
        print(text, flush=True)


def notify(title: str, body: str, urgent: bool = False) -> None:
    """One desktop banner as the owner; the log records delivery."""
    log(f"banner: {title} | {body}", echo=False)
    if NO_NOTIFY:
        log("  banner suppressed (WATCHDOG_NO_NOTIFY=1)", echo=False)
        return
    exe = shutil.which("notify-send")
    if not exe:
        log("  banner NOT shown: notify-send not found", echo=False)
        return
    env = dict(os.environ)
    bus = f"/run/user/{os.getuid()}/bus"
    if "DBUS_SESSION_BUS_ADDRESS" not in env and os.path.exists(bus):
        env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus}"
    if "DBUS_SESSION_BUS_ADDRESS" not in env:
        log("  banner NOT shown: no session bus for this user", echo=False)
        return
    cmd = [exe, "-a", "Guardrail", "-t", str(COUNTDOWN * 1000 if urgent else 6000),
           "-u", "critical" if urgent else "normal", title, body]
    try:
        done = subprocess.run(cmd, env=env, capture_output=True, timeout=5, check=False)
        ok = done.returncode == 0
        log("  banner shown" if ok else f"  banner NOT shown: rc {done.returncode}", echo=False)
    except (OSError, subprocess.SubprocessError) as exc:
        log(f"  banner NOT shown: {exc.__class__.__name__}", echo=False)


def proxy_process_alive() -> bool:
    """Any process whose cmdline holds the needle."""
    me = os.getpid()
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or int(entry.name) == me:
            continue
        try:
            if PROC_NEEDLE.encode() in (entry / "cmdline").read_bytes():
                return True
        except OSError:
            continue
    return False


def port_accepts(port: int, timeout: float) -> bool:
    try:
        socket.create_connection(("127.0.0.1", port), timeout).close()
        return True
    except OSError:
        return False


def probe_state(timeout: float = TIMEOUT) -> tuple[str, str]:
    """('ok'|'busy'|'dead', reason); busy never counts as death."""
    for attempt in range(RETRIES):
        if port_accepts(PORT, min(timeout, 2.0)):
            break
        if attempt < RETRIES - 1:
            time.sleep(min(0.25 * 2 ** attempt, timeout))
    else:
        return "dead", f"no listener on :{PORT} after {RETRIES} tries"
    try:
        with socket.create_connection(("127.0.0.1", REGULAR_PORT), timeout) as conn:
            conn.settimeout(timeout)
            conn.sendall(b"CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n")
            head = conn.recv(16)
    except socket.timeout:
        if proxy_process_alive() and port_accepts(PORT, 2.0):
            return "busy", f"health request slow for {timeout:g}s; process alive, :{PORT} listening"
        return "dead", f"health request hung for {timeout:g}s and the proxy process is gone"
    except OSError as exc:
        if port_accepts(REGULAR_PORT, 2.0):
            return "busy", f"health request failed ({exc.__class__.__name__}) but :{REGULAR_PORT} still accepts"
        return "dead", f"regular port :{REGULAR_PORT} closed ({exc.__class__.__name__})"
    if head.startswith(b"HTTP/"):
        return "ok", ""
    return "dead", f"health answer was not HTTP: {head[:8]!r}"


def probe(timeout: float = TIMEOUT) -> str | None:
    """None if alive (ok or busy), else why dead."""
    state, why = probe_state(timeout)
    return why if state == "dead" else None


def network_up() -> bool:
    """Any neutral address answering clears the machine's network."""
    for target in NEUTRAL:
        host, _, port = target.rpartition(":")
        try:
            socket.create_connection((host, int(port)), 2).close()
            return True
        except (OSError, ValueError):
            continue
    return False


def helper() -> str | None:
    return next((h for h in HELPERS if os.access(h, os.X_OK)), None)


def sudo(*verb: str, timeout: int = 90) -> tuple[int, str]:
    """A password-free helper verb; the output goes to the log."""
    exe = helper()
    if not exe:
        return 127, "helper not found"
    try:
        done = subprocess.run([*SUDO, exe, *verb], capture_output=True, text=True,
                              timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, exc.__class__.__name__
    return done.returncode, (done.stdout + done.stderr).strip()


def rule_present() -> bool | None:
    """True or False from the helper's status; None if unreadable."""
    code, out = sudo("status", timeout=30)
    if code != 0:
        return None
    return "redirect to" in out or "udp dport 443" in out


def our_process(pid: int, needle: str) -> bool:
    """A live process of ours whose cmdline has the needle."""
    try:
        cmd = Path(f"/proc/{pid}/cmdline").read_bytes()
        return needle.encode() in cmd and os.stat(f"/proc/{pid}").st_uid == os.getuid()
    except OSError:
        return False


def stop_router() -> None:
    try:
        pid = int(ROUTER_PID.read_text().strip())
    except (OSError, ValueError):
        log("  no router pid on file, nothing to stop")
        return
    if pid > 1 and (our_process(pid, "run.sh") or our_process(pid, "router.py")
                    or our_process(pid, str(ROUTER_PID.parent.parent))):
        os.kill(pid, signal.SIGTERM)
        time.sleep(1)
        if Path(f"/proc/{pid}").exists():
            os.kill(pid, signal.SIGKILL)
        log(f"  router stopped (pid {pid}): it would have restarted the proxy")
    else:
        log(f"  pid {pid} in {ROUTER_PID} is not our router; left alone")
    for name in (ROUTER_PID.name, "panel.pid"):
        (ROUTER_PID.parent / name).unlink(missing_ok=True)


def revert() -> bool:
    """Panic order: rule and failsafe, router, proxy, desktop proxy."""
    REVERTING.write_text(str(os.getpid()))
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, signal.SIG_IGN)
    log("REVERT: releasing the rule and failsafe (disarm)")
    code, out = sudo("disarm")
    log(f"  disarm rc {code}: {out[-300:]!r}")
    log("REVERT: stopping the router")
    stop_router()
    log("REVERT: stopping the proxy (proxy-stop)")
    code, out = sudo("proxy-stop")
    log(f"  proxy-stop rc {code}: {out[-300:]!r}")
    if "restored" not in out.lower():
        host = HERE / "rules.py"
        if host.is_file():
            done = subprocess.run([sys.executable, "-I", str(host), "desktop-proxy", "off"],
                                  capture_output=True, text=True, timeout=30, check=False)
            log(f"  desktop-proxy off rc {done.returncode}: {(done.stdout + done.stderr).strip()[-200:]!r}")
    listening = socket_open(PORT)
    rule = rule_present()
    clean = not listening and rule is False
    log("REVERT: " + ("done, nothing is diverted and the proxy is stopped" if clean
                      else f"INCOMPLETE (listener {listening}, rule {rule}); run: sudo bash run.sh panic"))
    return clean


def socket_open(port: int) -> bool:
    try:
        socket.create_connection(("127.0.0.1", port), 1).close()
        return True
    except OSError:
        return False


def countdown(reason: str) -> str:
    """Outcome: reverted, recovered, no-network, dry or stopped."""
    if not network_up():
        log("the machine has no network at all; the guardrail is not the cause; touching nothing")
        notify("Guardrail watchdog", "No network at all on this machine: not the guardrail, nothing changed")
        return "no-network"
    log(f"VERDICT dead (not busy): {reason}")
    log(f"ANOMALY: {reason}; reverting in {COUNTDOWN}s unless the proxy answers again")
    notify("Guardrail ANOMALY", f"{reason}. Reverting to normal in {COUNTDOWN}s", urgent=True)
    deadline = time.monotonic() + COUNTDOWN
    shown = None
    while True:
        left = math.ceil(deadline - time.monotonic())
        if left <= 0:
            break
        log(f"  revert in {left}s")
        if left == COUNTDOWN // 2 and left != shown:
            shown = left
            notify("Guardrail ANOMALY", f"Reverting to normal in {left}s", urgent=True)
        tick = time.monotonic() + 1
        if probe_state(1.0)[0] != "dead":
            log("  the proxy answers again; revert cancelled")
            notify("Guardrail watchdog", "Proxy answers again: revert cancelled")
            return "recovered"
        if STOP.wait(max(0.0, tick - time.monotonic())):
            return "stopped"
    if not network_up():
        log("the machine lost its network during the countdown; touching nothing")
        return "no-network"
    if DRY:
        log("DRY: would revert now (WATCHDOG_DRY=1); nothing changed")
        notify("Guardrail watchdog (dry run)", "Would revert now; dry run, nothing changed")
        return "dry"
    notify("Guardrail ANOMALY", "Reverting to normal now", urgent=True)
    clean = revert()
    notify("Guardrail reverted to normal" if clean else "Guardrail revert INCOMPLETE",
           "Rule released, proxy stopped, desktop proxy direct" if clean
           else "Something is still in the path: sudo bash run.sh panic", urgent=not clean)
    return "reverted"


def run() -> int:
    if os.geteuid() == 0:
        print("watchdog: refusing to run as root; arm starts it as the owner", file=sys.stderr)
        return 2
    if PIDFILE.exists():
        try:
            old = int(PIDFILE.read_text().strip())
        except (OSError, ValueError):
            old = 0
        if old and old != os.getpid() and our_process(old, "watchdog.py"):
            print(f"watchdog already running (pid {old})")
            return 0
    PIDFILE.write_text(str(os.getpid()))
    REVERTING.unlink(missing_ok=True)
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, lambda *_: STOP.set())
    log(f"watchdog started pid {os.getpid()}: every {INTERVAL:g}s, timeout {TIMEOUT:g}s, "
        f"{FAILS} misses in a row, countdown {COUNTDOWN}s, dry {int(DRY)}")
    if BANNERS_ON:
        threading.Thread(target=banner_loop, name="banner-follower", daemon=True).start()
        log(f"banner follower started on {AUDIT}, scope {BANNER_SCOPE}, "
            f"cool {BANNER_COOL:g}s, max {BANNER_MAX}/min")
    notify("Guardrail watchdog ON", f"Watching the proxy on :{PORT}; anomaly means revert after {COUNTDOWN}s")
    reason = "stopped on request"
    rule = rule_present()
    if rule is False and not DRY:
        reason = "no redirect rule is installed, nothing to watch"
    else:
        pending = probe()
        if pending is None:
            state = {True: "armed", None: "rule state unreadable"}.get(rule, "dry run, no rule")
            log(f"{state}: proxy active, watchdog active")
            notify("Guardrail ARMED", f"{state}; proxy active on :{PORT}; watchdog active")
        misses, bad_rule, probes, last_rule = 0, 0, 0, time.monotonic()
        suppressed, retry_at, busy_log = False, 0.0, -60.0
        while not STOP.is_set():
            if probes == 0:
                why_not, state = pending, "dead" if pending else "ok"
            else:
                state, why = probe_state()
                why_not = why if state == "dead" else None
            probes += 1
            if state == "busy" and time.monotonic() - busy_log >= 60:
                busy_log = time.monotonic()
                log(f"busy, not dead, rule kept: {why}")
            if why_not is None:
                if misses:
                    log(f"proxy answers again after {misses} miss(es)")
                misses, suppressed = 0, False
            else:
                misses += 1
                if misses <= FAILS:
                    log(f"miss {misses} of {FAILS}: {why_not}")
                if misses >= FAILS and not suppressed and time.monotonic() >= retry_at:
                    outcome = countdown(why_not)
                    if outcome == "reverted":
                        reason = "reverted to normal after an anomaly"
                        break
                    if outcome == "stopped":
                        break
                    if outcome == "no-network":
                        retry_at = time.monotonic() + NET_RETRY
                    elif outcome == "dry":
                        suppressed = True
            if time.monotonic() - last_rule >= RULE_EVERY:
                last_rule = time.monotonic()
                present = rule_present()
                bad_rule = bad_rule + 1 if present is False else 0
                log(f"heartbeat: {probes} probes, {misses} miss(es) now, rule {present}")
                if bad_rule >= BAD_RULE_POLLS and not DRY:
                    reason = "the redirect rule is gone, nothing left to watch"
                    break
            if STOP.wait(INTERVAL):
                break
    log(f"watchdog stopped: {reason}")
    notify("Guardrail watchdog OFF", reason)
    if PIDFILE.exists() and PIDFILE.read_text().strip() == str(os.getpid()):
        PIDFILE.unlink(missing_ok=True)
    REVERTING.unlink(missing_ok=True)
    return 0


def running_pid() -> int | None:
    try:
        pid = int(PIDFILE.read_text().strip())
    except (OSError, ValueError):
        return None
    return pid if our_process(pid, "watchdog.py") else None


def start() -> int:
    pid = running_pid()
    if pid:
        print(f"watchdog already running (pid {pid})")
        return 0
    PIDFILE.unlink(missing_ok=True)
    subprocess.Popen([sys.executable, "-I", str(Path(__file__).resolve()), "run"],
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True, env=dict(os.environ))
    for _ in range(40):
        time.sleep(0.1)
        pid = running_pid()
        if pid:
            print(f"watchdog started (pid {pid}); log {LOGFILE}")
            return 0
    print(f"watchdog did not start; see {LOGFILE}", file=sys.stderr)
    return 1


def stop() -> int:
    pid = running_pid()
    if not pid:
        PIDFILE.unlink(missing_ok=True)
        print("watchdog is not running")
        return 0
    if REVERTING.exists():
        print(f"watchdog (pid {pid}) is reverting; it ends by itself")
        return 0
    os.kill(pid, signal.SIGTERM)
    for _ in range(50):
        time.sleep(0.1)
        if not Path(f"/proc/{pid}").exists():
            print("watchdog stopped")
            return 0
    if REVERTING.exists():
        print(f"watchdog (pid {pid}) is reverting; it ends by itself")
        return 0
    os.kill(pid, signal.SIGKILL)
    PIDFILE.unlink(missing_ok=True)
    log(f"watchdog pid {pid} did not answer SIGTERM in 5s; killed")
    notify("Guardrail watchdog OFF", "Killed: it did not stop on request")
    print("watchdog killed")
    return 0


def status() -> int:
    pid = running_pid()
    print(f"watchdog: {'running (pid %d)' % pid if pid else 'not running'}")
    try:
        for line in LOGFILE.read_text(encoding="utf-8").splitlines()[-4:]:
            print("  " + line)
    except OSError:
        pass
    return 0 if pid else 1


def once() -> int:
    why_not = probe()
    print("proxy ok" if why_not is None else f"proxy anomaly: {why_not}")
    return 0 if why_not is None else 1


VERBS = {"run": run, "start": start, "stop": stop, "status": status, "once": once,
         "banners": banners}

if __name__ == "__main__":
    verb = sys.argv[1] if len(sys.argv) > 1 else "status"
    if verb not in VERBS:
        sys.exit(f"usage: watchdog.py {'|'.join(VERBS)}")
    sys.exit(VERBS[verb]())
