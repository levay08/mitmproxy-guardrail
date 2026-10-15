"""DLP rules, the ATR set and the model layer."""

from __future__ import annotations
from concurrent.futures import Future, TimeoutError as FutureTimeout
from datetime import datetime
from pathlib import Path
import pwd
import queue
import shlex
import sys
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
import uuid
import warnings


# Optional validators; a machine without them loses one layer.
try:
    import phonenumbers
    from phonenumbers import PhoneNumberMatcher
except Exception:  # noqa: BLE001
    phonenumbers = None
    PhoneNumberMatcher = None


def env_number(name: str, default, cast=int):
    """A number from the environment, or the default."""
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        return cast(str(raw).strip())
    except (TypeError, ValueError):
        return default


def env_flag(name: str) -> bool:
    """True when the environment asks for it."""
    return str(os.environ.get(name, "")).strip().lower() in ("1", "yes", "true", "on")


try:
    from stdnum.id import nik as _stdnum_nik
    from stdnum.id import npwp as _stdnum_npwp
except Exception:  # noqa: BLE001
    _stdnum_nik = None
    _stdnum_npwp = None


# ---------------------------------------------------------------------------
# Host detection, merged from compat.py 1 Oct 2026; stdlib only.

#   python3 -I rules.py: plan, venv-pins, desktop-proxy, ca-env, report
# ---------------------------------------------------------------------------
def base_dir() -> Path:
    """Guardrail's own directory: GUARDRAIL_HOME first, else where this file lives."""
    env = os.environ.get("GUARDRAIL_HOME")
    return Path(env) if env else Path(__file__).resolve().parent

APP_DIR = Path(__file__).resolve().parent

# Extra dirs for short PATHs: sudo, pkexec, cron.
EXTRA_DIRS = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin",
              "/run/current-system/sw/bin")

GNOME_FAMILY = ("gnome", "unity", "budgie", "cinnamon", "pantheon", "gnome-flashback", "gnome-classic")

# (anchor dir, updater, ext). Order matters: SUSE and Debian share.
CA_STORES = (
    ("/etc/pki/ca-trust/source/anchors", ("update-ca-trust", "extract"), ".pem"),   # Fedora, RHEL
    ("/etc/pki/trust/anchors", ("update-ca-certificates",), ".pem"),                # openSUSE
    ("/etc/ca-certificates/trust-source/anchors", ("trust", "extract-compat"), ".pem"),  # Arch
    ("/usr/local/share/ca-certificates", ("update-ca-certificates",), ".crt"),      # Debian, Alpine
)

CA_BUNDLES = (
    "/etc/ssl/ca-bundle.pem",                              # openSUSE
    "/etc/ssl/certs/ca-certificates.crt",                  # Debian, Arch, Alpine
    "/etc/pki/tls/certs/ca-bundle.crt",                    # Fedora, RHEL
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",   # Fedora, RHEL
    "/etc/ssl/cert.pem",                                   # Alpine, Void
)

ENV_D_GENERATORS = (
    "/usr/lib/systemd/user-environment-generators/30-systemd-environment-d-generator",
    "/lib/systemd/user-environment-generators/30-systemd-environment-d-generator",
)

# Shell-profile marker; prefix is matched, so old lines still go.
ME = Path(__file__).name
PROFILE_MARK_PREFIX = "# guardrail-ca:"
PROFILE_MARK = "# guardrail-ca: added by " + ME + ", remove this line to undo"

# Proxy packages; first is required, rest are optional layers.
CORE_PACKAGES = ("mitmproxy", "pyyaml", "python-stdnum", "phonenumbers")
MODEL_PACKAGES = ("gliner", "protobuf", "sentencepiece")
# Import name per model package
MODEL_IMPORTS = (("google.protobuf", "protobuf"), ("sentencepiece", "sentencepiece"))


def search_path() -> list:
    """Tool search order; GUARDRAIL_TOOL_PATH replaces it entirely (for tests)."""
    forced = os.environ.get("GUARDRAIL_TOOL_PATH")
    if forced is not None:
        return [d for d in forced.split(":") if d]
    dirs = [d for d in os.environ.get("PATH", "").split(":") if d]
    return dirs + [d for d in EXTRA_DIRS if d not in dirs]


def which(name: str) -> str:
    return shutil.which(name, path=":".join(search_path())) or ""


def invoking_user() -> dict:
    """Who ran this: SUDO_UID, PKEXEC_UID, else the real uid."""
    uid = os.getuid()
    source = "uid"
    for var in ("SUDO_UID", "PKEXEC_UID"):
        raw = os.environ.get(var, "")
        if uid == 0 and raw.isdigit():
            uid, source = int(raw), var
            break
    try:
        pw = pwd.getpwuid(uid)
        return {"uid": uid, "gid": pw.pw_gid, "name": pw.pw_name, "home": pw.pw_dir,
                "shell": pw.pw_shell, "source": source}
    except KeyError:
        return {"uid": uid, "gid": uid, "name": str(uid), "home": "", "shell": "", "source": source}


def _user_environ(uid: int, keys: tuple) -> dict:
    """Session variables from any of that user's processes."""
    found = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid != uid:
                continue
            raw = (entry / "environ").read_bytes()
        except OSError:
            continue
        for item in raw.split(b"\0"):
            key, _, value = item.partition(b"=")
            k = key.decode("utf-8", "replace")
            if k in keys and k not in found and value:
                found[k] = value.decode("utf-8", "replace")
        if len(found) == len(keys):
            break
    return found


def session_bus(user: dict) -> str:
    """That user's session bus address, or empty."""
    sock = Path(f"/run/user/{user['uid']}/bus")
    if sock.is_socket():
        return f"unix:path={sock}"
    if os.getuid() == user["uid"] and os.environ.get("DBUS_SESSION_BUS_ADDRESS"):
        return os.environ["DBUS_SESSION_BUS_ADDRESS"]
    return _user_environ(user["uid"], ("DBUS_SESSION_BUS_ADDRESS",)).get("DBUS_SESSION_BUS_ADDRESS", "")


def desktop_name(user: dict) -> str:
    """Lower-case desktop name, e.g. gnome, kde; 'none' if headless."""
    raw = ""
    if os.getuid() == user["uid"]:
        raw = os.environ.get("XDG_CURRENT_DESKTOP") or os.environ.get("DESKTOP_SESSION") or ""
    if not raw:
        env = _user_environ(user["uid"], ("XDG_CURRENT_DESKTOP", "DESKTOP_SESSION"))
        raw = env.get("XDG_CURRENT_DESKTOP") or env.get("DESKTOP_SESSION") or ""
    return raw.lower() or "none"


def _desktop_family(desktop: str) -> str:
    tokens = [t for t in desktop.replace(";", ":").split(":") if t]
    for t in tokens:
        if t in ("kde", "plasma") or t.startswith("plasma"):
            return "kde"
    for t in tokens:
        if t in GNOME_FAMILY:
            return "gnome"
        if t == "mate":
            return "mate"
        if t == "xfce" or t.startswith("xfce"):
            return "xfce"
    return "none" if desktop == "none" else "other"


def _run_as(user: dict, cmd: list, bus: str, timeout: int = 5) -> subprocess.CompletedProcess:
    """Run as the user; drop root so configs stay theirs."""
    env = {"PATH": ":".join(search_path()), "HOME": user["home"],
           "XDG_RUNTIME_DIR": f"/run/user/{user['uid']}"}
    if bus:
        env["DBUS_SESSION_BUS_ADDRESS"] = bus
    preexec = None
    if os.geteuid() == 0 and user["uid"] != 0:
        def preexec():
            os.setgid(user["gid"])
            os.initgroups(user["name"], user["gid"])
            os.setuid(user["uid"])
    return subprocess.run(cmd, env=env, preexec_fn=preexec, capture_output=True, text=True,
                          timeout=timeout)


def _gsettings_has_proxy(gsettings: str, user: dict, bus: str) -> bool:
    try:
        out = _run_as(user, [gsettings, "writable", "org.gnome.system.proxy", "mode"], bus)
        return out.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def desktop_proxy_tool(user: dict = None) -> dict:
    """Which tool sets the desktop proxy here, or why not."""
    user = user or invoking_user()
    desktop = desktop_name(user)
    family = _desktop_family(desktop)
    bus = session_bus(user)
    gsettings = which("gsettings")
    kwrite = which("kwriteconfig6") or which("kwriteconfig5")
    kread = which("kreadconfig6") or which("kreadconfig5")
    xfconf = which("xfconf-query")
    info = {"desktop": desktop, "family": family, "bus": bus, "tool": "", "path": "",
            "reason": ""}
    if family == "kde":
        if kwrite:
            info.update(tool="kwriteconfig", path=kwrite, read=kread)
        else:
            info["reason"] = "KDE session without kwriteconfig5/kwriteconfig6"
    elif family in ("gnome", "mate"):
        if gsettings:
            info.update(tool="gsettings", path=gsettings)
        else:
            info["reason"] = f"{family} session without gsettings"
    elif family == "xfce":
        # xfconf has no proxy key; XFCE reads the GNOME schema.
        if gsettings and _gsettings_has_proxy(gsettings, user, bus):
            info.update(tool="gsettings", path=gsettings)
        else:
            info["reason"] = ("XFCE has no desktop proxy setting in xfconf"
                              + (" (xfconf-query found)" if xfconf else "")
                              + " and the GNOME proxy schema is not installed")
    elif family == "other":
        info["reason"] = f"desktop '{desktop}' has no proxy tool this script knows"
    else:
        info["reason"] = "no desktop session"
    # No bus: gsettings writes to a memory backend, silently.
    if info["tool"] == "gsettings" and not bus:
        info.update(tool="", reason=f"no session bus for {user['name']}")
    return info


def host_desktop_proxy_state(user: dict = None) -> dict:
    user = user or invoking_user()
    t = desktop_proxy_tool(user)
    try:
        if t["tool"] == "gsettings":
            def g(key):
                return _run_as(user, [t["path"], "get", "org.gnome.system.proxy", key],
                               t["bus"]).stdout.strip()
            return {"tool": "gsettings", "mode": g("mode"), "autoconfig_url": g("autoconfig-url")}
        if t["tool"] == "kwriteconfig" and t.get("read"):
            def k(key):
                return _run_as(user, [t["read"], "--file", "kioslaverc", "--group", "Proxy Settings",
                                      "--key", key], t["bus"]).stdout.strip()
            mode = {"0": "'none'", "2": "'auto'"}.get(k("ProxyType"), k("ProxyType") or "'none'")
            return {"tool": "kwriteconfig", "mode": mode, "autoconfig_url": k("Proxy Config Script")}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"tool": t["tool"], "mode": "?", "error": f"{type(exc).__name__}: {exc}"}
    return {"tool": "", "mode": "?", "skipped": t["reason"] or "no reader for this tool"}


def host_set_desktop_proxy(on: bool, pac: str = "", user: dict = None) -> dict:
    """Set PAC on or proxy off; skipped without a tool."""
    user = user or invoking_user()
    t = desktop_proxy_tool(user)
    if not t["tool"]:
        return {"ok": True, "skipped": f"desktop proxy step skipped: {t['reason']}"}
    url = f"file://{pac}" if pac and not pac.startswith("file://") else pac
    if t["tool"] == "gsettings":
        base = [t["path"]]
        cmds = ([base + ["set", "org.gnome.system.proxy", "mode", "auto"],
                 base + ["set", "org.gnome.system.proxy", "autoconfig-url", url]] if on else
                [base + ["set", "org.gnome.system.proxy", "mode", "none"],
                 base + ["reset", "org.gnome.system.proxy", "autoconfig-url"]])
    else:
        base = [t["path"], "--file", "kioslaverc", "--group", "Proxy Settings", "--key"]
        cmds = ([base + ["ProxyType", "2"], base + ["Proxy Config Script", url]] if on else
                [base + ["ProxyType", "0"], base + ["Proxy Config Script", ""]])
        dbus_send = which("dbus-send")
        if dbus_send:
            # KIO rereads kioslaverc only when told to.
            cmds.append([dbus_send, "--type=signal", "/KIO/Scheduler",
                         "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:"])
    for cmd in cmds:
        try:
            out = _run_as(user, cmd, t["bus"])
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"ok": False, "tool": t["tool"], "error": f"{type(exc).__name__}: {exc}"}
        if out.returncode != 0:
            return {"ok": False, "tool": t["tool"],
                    "error": (out.stderr.strip() or f"{cmd[0]} exited {out.returncode}")}
    return {"ok": True, "tool": t["tool"], "state": host_desktop_proxy_state(user)}


def systemd_info() -> dict:
    booted = Path("/run/systemd/system").is_dir()
    systemctl, systemd_run = which("systemctl"), which("systemd-run")
    env_d = booted and any(Path(p).exists() for p in ENV_D_GENERATORS)
    return {"booted": booted, "systemctl": systemctl, "systemd_run": systemd_run,
            "usable": bool(booted and systemctl and systemd_run), "environment_d": env_d}


def failsafe_plan() -> dict:
    """How a timed flush is armed; 'none' means don't install."""
    sd = systemd_info()
    if sd["usable"]:
        return {"method": "systemd", "detail": f"systemd-run transient timer ({sd['systemd_run']})"}
    setsid, sleep = which("setsid"), which("sleep")
    if setsid and sleep:
        return {"method": "background",
                "detail": "no usable systemd; a detached setsid process sleeps then flushes"}
    return {"method": "none", "detail": "no systemd and no setsid/sleep: the rule must not be installed"}


def ca_store() -> dict:
    """System anchor dir, its update command, the bundle path."""
    out = {"anchor_dir": "", "anchor": "", "update": [], "bundle": "", "reason": "",
           "method": "", "p11kit": ""}
    for directory, cmd, ext in CA_STORES:
        if not Path(directory).is_dir():
            continue
        tool = which(cmd[0])
        if not tool:
            continue
        out.update(anchor_dir=directory, anchor=f"{directory}/guardrail-ca{ext}",
                   update=[tool, *cmd[1:]], method="anchor-dir")
        break
    else:
        # p11-kit stores an anchor itself where no known directory exists.
        trust = which("trust")
        if trust:
            out.update(method="p11-kit", p11kit=trust)
        else:
            out["reason"] = "no known CA anchor directory with its update tool, and no p11-kit trust"
    for bundle in CA_BUNDLES:
        if Path(bundle).is_file():
            out["bundle"] = bundle
            break
    return out


def profile_file(user: dict) -> str:
    """The login profile the user's shell actually reads."""
    home = Path(user["home"])
    shell = Path(user.get("shell") or "/bin/sh").name
    if shell == "fish":
        return str(home / ".config/fish/conf.d/guardrail-ca.fish")
    if shell == "zsh":
        return str(home / ".zprofile")
    if shell == "bash":
        for name in (".bash_profile", ".bash_login"):
            if (home / name).exists():
                return str(home / name)
    return str(home / ".profile")


def venv_info(app: Path = APP_DIR) -> dict:
    py = app / ".venv" / "bin" / "python"
    info = {"python": str(py), "exists": py.exists(), "version": "", "ok": False,
            "mitmdump": str(app / ".venv" / "bin" / "mitmdump")}
    # Read pyvenv.cfg, not the venv: root scripts call this too.
    try:
        for line in (app / ".venv" / "pyvenv.cfg").read_text().splitlines():
            key, _, value = line.partition("=")
            if key.strip() in ("version", "version_info"):
                info["version"] = value.strip()
                major, minor = (int(x) for x in info["version"].split(".")[:2])
                info["ok"] = info["exists"] and (major, minor) >= (3, 11)
                break
    except (OSError, ValueError):
        pass
    return info


def distro_info() -> dict:
    """ID, ID_LIKE, name from os-release; 'unknown' if missing."""
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        vals = {}
        for line in text.splitlines():
            key, sep, value = line.partition("=")
            if sep:
                vals[key.strip()] = value.strip().strip("\"'")
        return {"id": vals.get("ID", "unknown"), "like": vals.get("ID_LIKE", ""),
                "version": vals.get("VERSION_ID", ""),
                "name": vals.get("PRETTY_NAME") or vals.get("NAME", "unknown"), "source": path}
    return {"id": "unknown", "like": "", "version": "", "name": "unknown", "source": ""}


def init_name() -> str:
    """Name of pid 1 (systemd, openrc-init, runit, init, ...)."""
    try:
        return Path("/proc/1/comm").read_text().strip() or "unknown"
    except OSError:
        return "unknown"


def _login_uid_min() -> int:
    try:
        for line in Path("/etc/login.defs").read_text(errors="replace").splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] == "UID_MIN" and parts[1].isdigit():
                return int(parts[1])
    except OSError:
        pass
    return 1000


def nss_dbs() -> list:
    """NSS databases of human accounts: shared stores, Firefox profiles."""
    found = []
    uid_min = _login_uid_min()
    for pw in pwd.getpwall():
        if pw.pw_uid < uid_min or pw.pw_uid == 65534 or not pw.pw_dir.startswith("/"):
            continue
        home = Path(pw.pw_dir)
        candidates = [home / ".pki/nssdb", home / ".local/share/pki/nssdb"]
        # Firefox keeps its own store: classic, XDG, snap, flatpak
        for ff in (home / ".mozilla/firefox", home / ".config/mozilla/firefox",
                   home / "snap/firefox/common/.mozilla/firefox",
                   home / ".var/app/org.mozilla.firefox/.mozilla/firefox"):
            try:
                candidates += sorted(p for p in ff.iterdir() if p.is_dir())
            except OSError:
                pass
        for db in candidates:
            try:
                # Only a database the account owns; writes go as them.
                if (db / "cert9.db").is_file() and db.stat().st_uid == pw.pw_uid:
                    found.append({"user": pw.pw_name, "dir": str(db)})
            except OSError:
                continue
    return found


def system_env_target() -> dict:
    """Where every user's login sessions pick up the CA."""
    if systemd_info()["environment_d"]:
        return {"method": "environment.d", "file": "/etc/environment.d/90-guardrail-ca.conf"}
    if Path("/etc/profile.d").is_dir():
        return {"method": "profile.d", "file": "/etc/profile.d/guardrail-ca.sh"}
    return {"method": "", "file": "", "reason": "neither environment.d nor /etc/profile.d"}


def account_tools() -> dict:
    tools = {n: which(n) for n in ("useradd", "adduser", "userdel", "deluser", "groupdel",
                                   "delgroup", "runuser", "setpriv", "certutil")}
    tools["nologin"] = which("nologin") or ("/bin/false" if Path("/bin/false").exists() else "")
    return tools


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def venv_pins(app: Path, with_model: bool = False) -> dict:
    """Proxy versions: the venv's dist-info first, requirements.txt as fallback."""
    info = venv_info(app)
    versions = {}
    for site in sorted((app / ".venv/lib").glob("python*/site-packages")):
        for dist in site.glob("*.dist-info"):
            name = version = ""
            try:
                for line in (dist / "METADATA").read_text(errors="replace").splitlines():
                    if line.startswith("Name:"):
                        name = line.split(":", 1)[1].strip()
                    elif line.startswith("Version:"):
                        version = line.split(":", 1)[1].strip()
                    if name and version or not line:
                        break
            except OSError:
                name, _, version = dist.name[:-len(".dist-info")].partition("-")
            if name and version:
                versions[_norm(name)] = version
    if not versions:
# no venv yet: tested pins first, bare names after
        for fname in ("constraints.txt", "requirements.txt"):
            try:
                lines = (app / fname).read_text(errors="replace").splitlines()
            except OSError:
                continue
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#") or "|" in line:
                    continue
                name, sep, version = line.partition("==")
                if name.strip():
                    versions.setdefault(_norm(name.strip()), version.strip() if sep else "")
    wanted = CORE_PACKAGES + (MODEL_PACKAGES if with_model else ())
# name only, no version: install it unpinned
    pins = [f"{p}=={versions[p]}" if versions[p] else p for p in wanted if p in versions]
    missing = [p for p in wanted if p not in versions]
    return {"python": info["version"], "pins": pins, "missing": missing}


def install_plan() -> dict:
    return {"distro": distro_info(), "init": init_name(), "systemd": systemd_info(),
            "failsafe": failsafe_plan(), "ca": ca_store(), "env": system_env_target(),
            "nss": nss_dbs(), "tools": account_tools()}


def plan_shell(p: dict) -> str:
    q = shlex.quote
    d, sd, ca, env, t = p["distro"], p["systemd"], p["ca"], p["env"], p["tools"]
    pairs = {
        "GR_DISTRO_ID": d["id"], "GR_DISTRO_LIKE": d["like"], "GR_DISTRO_NAME": d["name"],
        "GR_INIT": p["init"], "GR_SYSTEMD": int(sd["usable"]), "GR_FAILSAFE": p["failsafe"]["method"],
        "GR_CA_METHOD": ca["method"], "GR_CA_ANCHOR": ca["anchor"], "GR_CA_P11KIT": ca["p11kit"],
        "GR_CA_BUNDLE": ca["bundle"], "GR_CA_SKIP": ca["reason"],
        "GR_ENV_METHOD": env["method"], "GR_ENV_FILE": env["file"], "GR_ENV_SKIP": env.get("reason", ""),
        "GR_USERADD": t["useradd"], "GR_ADDUSER": t["adduser"], "GR_USERDEL": t["userdel"],
        "GR_DELUSER": t["deluser"], "GR_GROUPDEL": t["groupdel"], "GR_DELGROUP": t["delgroup"],
        "GR_NOLOGIN": t["nologin"], "GR_RUNUSER": t["runuser"], "GR_SETPRIV": t["setpriv"],
        "GR_CERTUTIL": t["certutil"],
    }
    lines = [f"{k}={q(str(v))}" for k, v in pairs.items()]
    lines.append("GR_CA_UPDATE=(" + " ".join(q(x) for x in ca["update"]) + ")")
    lines.append("GR_NSS_DBS=(" + " ".join(q(f"{n['user']}:{n['dir']}") for n in p["nss"]) + ")")
    return "\n".join(lines)


def _as_user_write(user: dict, fn) -> None:
    """Run as the user: symlinks cannot redirect a root write."""
    if os.geteuid() != 0 or user["uid"] == 0:
        fn()
        return
    pid = os.fork()
    if pid == 0:
        code = 0
        try:
            os.setgid(user["gid"])
            os.initgroups(user["name"], user["gid"])
            os.setuid(user["uid"])
            fn()
        except BaseException as exc:  # noqa: BLE001
            print(f"{ME}: {exc}", file=sys.stderr)
            code = 1
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(code)
    _, status = os.waitpid(pid, 0)
    if not (os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0):
        raise RuntimeError("writing as the user failed")


def ca_env_install(certfile: str, ca: str, user: dict = None) -> dict:
    """CA variables where the login reads them: environment.d, else profile."""
    user = user or invoking_user()
    home = Path(user["home"])
    values = {"SSL_CERT_FILE": certfile, "REQUESTS_CA_BUNDLE": certfile,
              "CURL_CA_BUNDLE": certfile, "NODE_EXTRA_CA_CERTS": ca}
    if systemd_info()["environment_d"]:
        target = home / ".config/environment.d/guardrail.conf"
        body = ("# Guardrail CA for runtimes that do not read the system store.\n"
                + "".join(f"{k}={v}\n" for k, v in values.items()))

        def write():
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body)
        _as_user_write(user, write)
        return {"method": "environment.d", "file": str(target), "undo": f"rm -f {target}"}
    profile = Path(profile_file(user))
    if profile.suffix == ".fish":
        body = "".join(f"set -gx {k} {shlex.quote(v)}\n" for k, v in values.items())

        def write():
            profile.parent.mkdir(parents=True, exist_ok=True)
            profile.write_text(f"# Guardrail CA, added by {ME}\n" + body)
        _as_user_write(user, write)
        return {"method": "fish conf.d", "file": str(profile), "undo": f"rm -f {profile}"}
    envfile = home / ".config/guardrail/ca-env.sh"
    body = "".join(f"export {k}={shlex.quote(v)}\n" for k, v in values.items())
    line = f'[ -r "{envfile}" ] && . "{envfile}"  {PROFILE_MARK}\n'

    def write():
        envfile.parent.mkdir(parents=True, exist_ok=True)
        envfile.write_text("# Guardrail CA, sourced from the login profile\n" + body)
        text = profile.read_text() if profile.exists() else ""
        if PROFILE_MARK not in text:
            with profile.open("a") as fh:
                fh.write(("" if text.endswith("\n") or not text else "\n") + line)
    _as_user_write(user, write)
    return {"method": "profile", "file": str(envfile), "profile": str(profile),
            "undo": f"sed -i '/guardrail-ca:/d' {profile}; rm -f {envfile}"}


def ca_env_found(user: dict = None) -> list:
    """Files that currently carry the guardrail CA variables."""
    user = user or invoking_user()
    home = Path(user["home"])
    found = [str(f) for f in (home / ".config/environment.d/guardrail.conf",
                              home / ".config/guardrail/ca-env.sh",
                              home / ".config/fish/conf.d/guardrail-ca.fish") if f.is_file()]
    for name in (".profile", ".bash_profile", ".bash_login", ".zprofile"):
        p = home / name
        try:
            if p.is_file() and PROFILE_MARK_PREFIX in p.read_text():
                found.append(f"{p} (one marked line)")
        except OSError:
            pass
    return found


def ca_env_remove(user: dict = None) -> None:
    user = user or invoking_user()
    home = Path(user["home"])

    def remove():
        removed = []
        for f in (home / ".config/environment.d/guardrail.conf", home / ".config/guardrail/ca-env.sh",
                  home / ".config/fish/conf.d/guardrail-ca.fish"):
            if f.is_file():
                f.unlink()
                removed.append(str(f))
        for name in (".profile", ".bash_profile", ".bash_login", ".zprofile"):
            p = home / name
            if p.is_file() and PROFILE_MARK_PREFIX in p.read_text():
                p.write_text("".join(l for l in p.read_text().splitlines(True) if PROFILE_MARK not in l))
                removed.append(f"{p} (one line)")
        for r in removed:
            print(f"removed {r}")
        if not removed:
            print("no guardrail CA variables found")
    _as_user_write(user, remove)


def host_detect() -> dict:
    user = invoking_user()
    tools = {n: which(n) for n in ("nft", "ip", "ss", "python3", "curl", "setsid", "certutil",
                                   "openssl", "runuser")}
    return {"user": user, "app": str(APP_DIR), "distro": distro_info(), "init": init_name(),
            "tools": tools, "systemd": systemd_info(),
            "failsafe": failsafe_plan(), "desktop": desktop_proxy_tool(user), "ca": ca_store(),
            "profile": profile_file(user), "session_bus": session_bus(user), "venv": venv_info()}


def as_shell(d: dict) -> str:
    q = shlex.quote
    u, t, sd, ca = d["user"], d["tools"], d["systemd"], d["ca"]
    pairs = {
        "GR_UID": u["uid"], "GR_USER": u["name"], "GR_HOME": u["home"], "GR_APP": d["app"],
        "GR_NFT": t["nft"], "GR_IP": t["ip"], "GR_SS": t["ss"], "GR_PYTHON3": t["python3"],
        "GR_CURL": t["curl"], "GR_CERTUTIL": t["certutil"], "GR_OPENSSL": t["openssl"],
        "GR_SYSTEMD": int(sd["usable"]), "GR_SYSTEMCTL": sd["systemctl"],
        "GR_SYSTEMD_RUN": sd["systemd_run"], "GR_ENV_D": int(sd["environment_d"]),
        "GR_FAILSAFE": d["failsafe"]["method"], "GR_DESKTOP": d["desktop"]["desktop"],
        "GR_PROXY_TOOL": d["desktop"]["tool"], "GR_PROXY_SKIP": d["desktop"]["reason"],
        "GR_BUS": d["session_bus"], "GR_CA_ANCHOR_DIR": ca["anchor_dir"], "GR_CA_ANCHOR": ca["anchor"],
        "GR_CA_BUNDLE": ca["bundle"], "GR_PROFILE": d["profile"],
        "GR_VENV_PY": d["venv"]["python"], "GR_VENV_OK": int(d["venv"]["ok"]),
        "GR_MITMDUMP": d["venv"]["mitmdump"],
    }
    lines = [f"{k}={q(str(v))}" for k, v in pairs.items()]
    lines.append("GR_CA_UPDATE=(" + " ".join(q(x) for x in ca["update"]) + ")")
    return "\n".join(lines)


def report(d: dict) -> str:
    u, sd, dp, ca, v = d["user"], d["systemd"], d["desktop"], d["ca"], d["venv"]
    lines = [f"user        : {u['name']} uid {u['uid']} (from {u['source']}), home {u['home']}",
             f"app         : {d['app']}",
             f"distro      : {d['distro']['name']} (id {d['distro']['id']}"
             + (f", like {d['distro']['like']}" if d["distro"]["like"] else "") + f"), pid 1 {d['init']}",
             f"venv python : {v['python']} {v['version'] or 'missing'}"
             + ("" if v["ok"] else "  (needs 3.11+)")]
    for name, path in d["tools"].items():
        lines.append(f"{name:<12}: {path or 'NOT FOUND'}")
    lines += [f"systemd     : {'booted' if sd['booted'] else 'not booted'}, systemctl "
              f"{sd['systemctl'] or '-'}, systemd-run {sd['systemd_run'] or '-'}",
              f"failsafe    : {d['failsafe']['method']} ({d['failsafe']['detail']})",
              f"env for CA  : {'environment.d' if sd['environment_d'] else 'profile ' + d['profile']}",
              f"desktop     : {dp['desktop']} -> {dp['tool'] or 'skip: ' + dp['reason']}",
              f"session bus : {d['session_bus'] or 'none'}",
              f"CA anchor   : {ca['anchor'] or 'NONE: ' + ca['reason']}",
              f"CA update   : {' '.join(ca['update']) or '-'}",
              f"CA bundle   : {ca['bundle'] or 'none found'}"]
    return "\n".join(lines)


def host_main(argv: list) -> int:
    cmd = argv[1] if len(argv) > 1 else "report"
    if cmd == "report":
        print(report(host_detect()))
    elif cmd == "json":
        print(json.dumps(host_detect(), indent=2))
    elif cmd == "shell":
        print(as_shell(host_detect()))
    elif cmd == "plan":
        print(plan_shell(install_plan()))
    elif cmd == "plan-json":
        print(json.dumps(install_plan(), indent=2))
    elif cmd == "venv-pins":
        if len(argv) < 3:
            print(f"usage: {ME} venv-pins <app> [--with-model]", file=sys.stderr)
            return 2
        res = venv_pins(Path(argv[2]), "--with-model" in argv[3:])
        print(f"GR_PIN_PYTHON={shlex.quote(res['python'])}")
        print("GR_PINS=(" + " ".join(shlex.quote(x) for x in res["pins"]) + ")")
        print("GR_PIN_MISSING=(" + " ".join(shlex.quote(x) for x in res["missing"]) + ")")
    elif cmd == "desktop-proxy":
        sub = argv[2] if len(argv) > 2 else "state"
        if sub == "state":
            print(json.dumps(host_desktop_proxy_state()))
            return 0
        if sub not in ("on", "off"):
            print(f"usage: {ME} desktop-proxy on <pac>|off|state", file=sys.stderr)
            return 2
        res = host_set_desktop_proxy(sub == "on", argv[3] if len(argv) > 3 else "")
        if res.get("skipped"):
            print(res["skipped"])
        elif res["ok"]:
            print(f"desktop proxy {sub} via {res['tool']}: {res['state']}")
        else:
            print(f"desktop proxy {sub} failed via {res.get('tool')}: {res['error']}", file=sys.stderr)
            return 1
    elif cmd == "ca-env":
        sub = argv[2] if len(argv) > 2 else "state"
        if sub == "install" and len(argv) > 4:
            res = ca_env_install(argv[3], argv[4])
            print(f"CA variables written via {res['method']}: {res['file']}"
                  + (f" (sourced from {res['profile']})" if res.get("profile") else ""))
            print(f"undo: {res['undo']}")
        elif sub == "remove":
            ca_env_remove()
        elif sub == "state":
            print("new installs go to: " + ("environment.d" if systemd_info()["environment_d"]
                                           else f"profile {profile_file(invoking_user())}"))
            found = ca_env_found()
            for f in found:
                print(f"present: {f}")
            print(f"remove with: python3 {ME} ca-env remove" if found
                  else "no guardrail CA variables found")
        else:
            print(f"usage: {ME} ca-env install <certfile> <ca>|remove|state", file=sys.stderr)
            return 2
    else:
        print(f"usage: {ME} report|json|shell|plan|plan-json|venv-pins <app>|desktop-proxy|ca-env",
              file=sys.stderr)
        return 2
    return 0


# PART 1 - our own regex rules and masking

# Sensitive-data patterns (action: MASK)

# Words that follow "password" but are not the password itself.
NOT_PASSWORD_WORDS = (
    "kuat|lemah|aman|tidak|sangat|sudah|akan|baru|lama|ini|itu|bagus|jelek|mudah|sulit|benar|salah|"
    "yang|dan|atau|untuk|dari|bisa|harus|perlu|sama|seperti|juga|masih|belum|pernah|sering|kapan|"
    "apa|siapa|mana|hanya|cuma|lebih|paling|saya|aku|ku|gue|kami|kita|kamu|anda|milik|punya|"
    "good|strong|weak|safe|secure|fine|okay|better|best|now|then|still|not"
)

# A value counts only when a context word is nearby.
CONTEXT_REQUIRED: dict[str, tuple[str, ...]] = {
    "NIK_KTP": ("nik", "ktp", "e-ktp", "kartu tanda penduduk", "nomor induk kependudukan",
                "nomor induk", "induk kependudukan", "kependudukan", "identitas",
                "identity card", "national id", "national identity",
                "identitätskarte", "carte d'identité", "cédula", "身份证", "マイナンバー",
                "주민등록번호", "aadhaar", "nric", "carteira de identidade"),
}
CONTEXT_WINDOW = 80

_CONTEXT_RE: dict[str, re.Pattern] = {
    kind: re.compile(r"\b(?:" + "|".join(re.escape(w) for w in words) + r")\b", re.IGNORECASE)
    for kind, words in CONTEXT_REQUIRED.items()
}


def _context_present(kind: str, text: str, start: int, end: int) -> bool:
    """True when a required context word sits near the match."""
    pattern = _CONTEXT_RE.get(kind)
    if pattern is None:
        return True
    around = text[max(0, start - CONTEXT_WINDOW): end + CONTEXT_WINDOW]
    return pattern.search(around) is not None


# Names no person; masking it broke the commit trailer.
ROLE_MAILBOX = re.compile(r"(?i)(?:no[-_.]?reply|do[-_.]?not[-_.]?reply)@[\w-]+(?:\.[\w-]+)+")

PII_RULES: list[tuple[str, re.Pattern]] = [
    # Bounded local part; the open form was quadratic.
    ("EMAIL", re.compile(r"\b[\w.+-]{1,254}@[\w-]+(?:\.[\w-]+)*\.[^\W\d_]{2,}\b")),
    # Emails written as "name (at) domain (dot) tld" or similar.
    ("EMAIL_TERSAMAR", re.compile(r"[A-Za-z0-9._%+-]{1,64}\s*(?:\(at\)|\[at\]|@|\uff20)\s*"
                                  r"[A-Za-z0-9.-]{1,63}\s*(?:\(dot\)|\[dot\]|\.)\s*"
                                  r"[A-Za-z]{2,24}\b")),
    ("KUNCI_API", re.compile(r"\b(?:sk|rk|pk)-[A-Za-z0-9]{16,}\b"
                             r"|\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"
                             r"|\bsk-proj-[A-Za-z0-9_-]{16,}\b"
                             r"|\bsk-ant-[A-Za-z0-9_-]{16,}\b"
                             r"|\bsk-svcacct-[A-Za-z0-9_-]{16,}\b"
                             r"|\bghp_[A-Za-z0-9]{20,}\b"
                             r"|\bAKIA[0-9A-Z]{16}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    # Indonesian twin of the masked English override phrase.
    ("AI_PROMPT_INJECTION_ID", re.compile(
        r"(?i)\babaikan\s+(?:semua\s+)?(?:instruksi|perintah|aturan)\s+(?:sebelumnya|sebelum\s+ini|terdahulu|di\s+atas)\b"
        r"|\babaikan\s+(?:prompt|instruksi)\s+sistem(?=\s*(?:[.,;:!?)\"'\n]|$)|mu\b|nya\b)"
        r"|\blupakan\s+(?:semuanya|semua\s+instruksimu|instruksimu|semua\s+aturanmu)\b"
        r"|\binstruksi\s+baru\s*:|\btimpa\s+(?:aturan|panduan)(?:mu|\s+kamu)\b")),
    ("NIK_KTP", re.compile(r"\b\d{16}\b")),
    ("NO_HP_ID", re.compile(r"\b(?:\+62|62|0)8[1-9]\d{7,11}\b")),
    ("KUNCI_PRIVAT", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("PASSWORD", re.compile(r"(?i)\b(?:password|passwd|pwd|secret|token|kata\s+sandi|sandi)\b"
                            r"(?:\s*[:=]\s*(?!(?:" + NOT_PASSWORD_WORDS + r")\b)\S+"
                            r"|\s+(?:saya|aku|ku|gue|milik\s+saya|is)\s+"
                            r"(?:(?:adalah|ialah|yaitu)\s+)?"
                            r"(?!(?:" + NOT_PASSWORD_WORDS + r")\b)\S+"
                            r"|\s+(?:adalah|ialah|yaitu)\s+(?!(?:" + NOT_PASSWORD_WORDS + r")\b)\S+"
                            r"|\s+(?!(?:" + NOT_PASSWORD_WORDS + r")\b)"
                            # Needs a digit or symbol; a bare word is not.
                            r"(?=\S{6,64}\b)(?=\S*[\d!@#$%^&*_\-=+])\S+)")),
    # Street address: street word plus house number required.
    ("ALAMAT_JALAN", re.compile(r"(?i)\b(?:jl\.?|jalan|gg\.?|gang|perum(?:ahan)?|blok)\s*"
                                r"[^,\n]{2,40}?\b(?:no\.?|nomor|kav\.?|blok)\s*\.?\s*\d{1,4}[a-z]?\b")),
    # Secrets in URLs: the token, not just its prefix.
    ("URL_KREDENSIAL", re.compile(
        r"https?://\S{0,1024}?(?:hooks\.slack\.com/services/[A-Za-z0-9/_-]{8,}"
        r"|discord(?:app)?\.com/api/webhooks/\d{5,}/[A-Za-z0-9_-]{16,}"
        r"|api\.telegram\.org/bot\d{5,}:[A-Za-z0-9_-]{20,}"
        r"|hooks\.slack\.com/services/|discord(?:app)?\.com/api/webhooks/|api\.telegram\.org/bot"
        r"|/webhook[s]?/[A-Za-z0-9_-]{16,}"
        r"|[?&](?:token|api[_-]?key|access[_-]?token|secret|signature)=[A-Za-z0-9._-]{12,})"
        r"[^\s\"'<>)]{0,1024}")),
    # US social security number.
    ("NOMOR_SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
]

# These mask only the last group; the line stays readable.
GROUP_RULES: list[tuple[str, re.Pattern]] = [
    # Env-var secrets: only the value is masked, the name stays.
    ("SANDI_ENV", re.compile(r"(?i)\b([A-Za-z0-9_]*?(?:PASS(?:WORD|WD)?|PWD|SECRET|TOKEN|"
                             r"API_?KEY|APIKEY|KREDENSIAL)[A-Za-z0-9_]*[ \t]*[:=][ \t]*)"
                             # A quoted value may contain spaces.
                             r"(\"[^\"\n]{4,128}\"|'[^'\n]{4,128}'|[^\s'\"]{4,128})")),
    # Password in a connection address: postgres://admin:***@10.0.0.5
    ("KREDENSIAL_URL", re.compile(r"(?i)([a-z][a-z0-9+.\-]{1,20}://[^\s:@/]{1,64}:)([^\s@/]{3,64})(?=@)")),
    # Short mysql password -pSwordfish123; a bare number is a port.
    ("SANDI_SINGKAT", re.compile(r"(?i)(?<![^\s\"'(])-p"
                                  r"(?:[ \t]*(['\"])(?=[^'\"\n]*\d)([^'\"\n]{4,64})\1"
                                  r"|(?=[^\s'\"]*\d)(?![\d:]+(?:\s|$))([^\s'\"]{4,64}))")),
    # Account number after an account word; the word is required.
    ("NOMOR_REKENING", re.compile(r"(?i)\b((?:(?:no\.?|nomor|nomer)\s*)?"
                                  r"(?:rekening|norek|account|akun|a/c)\b[^\d\n]{0,14})(\d{8,20})\b")),
    # "my new password is Swordfish2026!": mask only the value.
    ("SANDI_PANJANG", re.compile(r"(?i)(\b(?:password(?:nya)?|kata\s+sandi(?:nya)?|sandi(?:nya)?)\b"
                                 r"[^\n]{0,40}?)"
                                 # A quoted value may contain spaces; take it whole.
                                 r"(\"[^\"\n]{6,64}\"|'[^'\n]{6,64}'"
                                 r"|(?=\S{8,64}(?!\S))(?=\S*\d)(?=\S*[A-Z])(?=\S*[a-z])\S+)")),
    # Secret label next to a high-entropy value: "AWS key 12399asAaweER0v19890".
    ("RAHASIA_KONTEKS", re.compile(r"(?i)\b(?:aws\s*(?:key|secret)|api\s*key|secret\s*(?:key|token)?|"
                                   r"access\s*key|private\s*key|token)\b[^\n]{0,20}?"
                                   r"([A-Za-z0-9!@#$%^&*_\-=+]{16,64})\b")),
]

# Card number; a Luhn check keeps ordinary digit runs out.
CARD_RE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")

# Full four octets, checked in code for a private range.
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _ip_private(address: str) -> bool:
    """True for a private IPv4 address (10/8, 172.16/12, 192.168/16)."""
    parts = address.split(".")
    if len(parts) != 4 or not all(b.isdigit() and 0 <= int(b) <= 255 for b in parts):
        return False
    a, b = int(parts[0]), int(parts[1])
    return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)

# Malicious-message patterns (action: BLOCK)

# Never block bare keywords; a rule needs a verb.

# A destructive command in a question warns, not blocks.

# Invisible characters stripped first: split addresses are one address.
INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad\u180e]")


def visible(text: str) -> str:
    """The text as a reader sees it; invisibles removed."""
    return INVISIBLE.sub("", text) if text and INVISIBLE.search(text) else text


WARN_IF_QUESTION = {"destructive_command"}
# Always-warn rules, from guardrail.yaml and its always_warn list.

# Owner asked for a warning (1 Oct 2026).
ALWAYS_WARN: set[str] = {"installer_pipe_known_host", "curl_pipe_in_substitution", "unbounded_request", "output_abuse", "excessive_repetition",
                         "indirect_injection", "conceal_from_user",
                         "jailbreak_paraphrase", "safety_bypass", "exfil_markdown_image"}
# Raised to block: 0 of 198 benign hits.
BLOCK_RULES_RAISED = ("obfuscated", "system_prompt_dump", "fake_system_message", "credential_solicit")
QUOTE_STILL_WARNS = {"indirect_injection", "indirect_injection_directive", "fake_system_message"}   # attack text is usually quoted page content

# Prompt noun ends here, not inside "instruksi sistem operasi".
_ID_PROMPT_END = (r"(?=\s*(?:[.,;:!?)\"'\n]|$)|mu\b|nya\b"
                  r"|\s+(?:(?:tersembunyi|rahasia|lengkap|asli)\w*|kamu|anda|yang|sekarang|persis|secara"
                  r"|ini|itu|tadi|dan|atau|serta)\b)")

MALICIOUS_RULES: list[tuple[str, re.Pattern]] = [
    ("jailbreak_override",
     re.compile(r"(?i)ignore\s+(?:all\s+)?previous\s+instructions")),
    ("jailbreak_override",
     re.compile(r"(?i)abaikan\s+(?:semua\s+)?instruksi\s+(?:sebelumnya|di\s+atas)")),
    ("jailbreak_override",
     re.compile(r"(?i)\b(?:forget|ignore|disregard|set\s+aside|override)\s+(?:all\s+)?(?:your\s+)?"
                r"(?:earlier|previous|prior|initial|original|old)\s+"
                r"(?:rules|instructions|guidelines|directions|constraints)\b")),
    ("jailbreak_override",
     re.compile(r"(?i)\b(?:assistant|ai|model|you)\b[^.]{0,60}?\b(?:with\s+no|without|no)\s+"
                r"(?:moral|ethical|content)?\s*(?:limits|restrictions|filters|boundaries|rules)\b"
                r"(?!\s+(?:on|for|of|in)\s+(?:the\s+)?(?:file|upload|download|size|length|memory|disk|storage|rate"
                r"|request|usage|time|number|count|bandwidth|data|input|output|token|character|word|page|row"
                r"|record|connection)\w*)")),
    # Override paraphrased in Indonesian, which ATR's English patterns miss.
    ("jailbreak_override",
     re.compile(r"(?i)\b(?:lupakan|abaikan|hapus|kesampingkan)\s+(?:semua\s+)?"
                r"(?:aturan|instruksi|perintah|batasan|panduan|petunjuk)\s+"
                r"(?:awal\w*|sebelum\w*|sebelum\s+ini|dasar|di\s+atas|lamamu|moral)\b")),
    # Polite paraphrase of an override, which the blunt rules miss.
    ("jailbreak_override",
     re.compile(r"(?i)\b(?:forget|ignore|discard|disregard)\s+(?:(?:everything|all|what)\s+(?:that\s+)?you\b"
                r"[^.\n]{0,40}\b(?:discussed|told|said|earlier|previous|prior|before|given|trained|taught)\b"
                r"|(?:everything|all|what|your|the)\b[^.\n]{0,40}\b(?:rules|instructions"
                r"|guidelines|policies)\b)")),
    ("jailbreak_override",
     re.compile(r"(?i)\bstart\s+(?:fresh|over|again)\b[^.\n]{0,60}"
                r"\b(?:polic\w*|rule\w*|instruction\w*|guideline\w*|prompt|system)\b")),
    ("jailbreak_override",
     re.compile(r"(?i)\b(?:without|no)\s+(?:any\s+)?(?:censor(?:ship)?|restrictions?|filters?|limits?)\b"
                r"[^.\n]{0,30}\b(?:answer|reply|respond|jawab|balas)\b")),
    ("jailbreak_override",
     re.compile(r"(?i)\b(?:lupakan|abaikan|hapus|jangan\s+(?:hiraukan|pedulikan))\s+(?:semua\s+)?"
                r"(?:aturan|instruksi|perintah|panduan|kebijakan|pembatasan|kerahasiaan)\b"
                r"[^.\n]{0,40}\b(?:kamu|mu|anda|model|ai|asisten|kerahasiaan|etika|moral|dasar"
                r"|awal|sebelum\w*|data)\b")),
    ("jailbreak_override",
     re.compile(r"(?i)\b(?:mulai\s+(?:dari\s+)?(?:sekarang\s+)?(?:awal\s+)?(?:jawab|balas|respon|jawaban))\b"
                r"[^.\n]{0,30}\btanpa\s+(?:sensor|batasan|pembatasan|pembatas|filter|aturan|celaan|etika|moral)\b")),
    # "assistant with no moral limits": framing plus moral word.
    ("jailbreak_override",
     re.compile(r"(?i)\b(?:asisten|ai|model|kamu|anda)\b[^.]{0,60}?\b(?:tanpa|tidak\s+ada)\s+"
                r"(?:filter(?:\s+(?:moral|etika|susila))?|batasan\s+(?:moral|etika|susila)|batas\s+moral)")),
    ("jailbreak_persona",
     re.compile(r"(?i)you\s+are\s+now\s+(?:DAN|developer\s+mode)")),
    ("jailbreak_persona",
     re.compile(r"(?i)act\s+as\s+an?\s+unrestricted")),
    ("exfil_system_prompt",
     re.compile(r"(?i)(?:repeat|print|show)\s+(?:me\s+)?your\s+(?:system\s+)?(?:prompt|instructions)")),
    # Indonesian persona and prompt-dump asks, parity with the English rules.
    ("jailbreak_persona",
     re.compile(r"(?i)\b(?:kamu|anda|engkau)\s+sekarang\s+(?:adalah\s+)?(?:(?-i:DAN)\b"
                r"|(?:dalam\s+)?mode\s+(?:pengembang|developer)\b(?!\s+(?:di|pada)\s))")),
    ("jailbreak_persona",
     re.compile(r"(?i)\b(?:bertindak|berperan|berlaku)(?:lah)?\s+(?:sebagai|seperti)\s+(?:sebuah\s+)?(?:ai|asisten|model)?\s*(?:yang\s+)?"
                r"(?:tanpa|tidak\s+ada)\s+(?:batasan|batas|aturan|filter|sensor)\b"
                r"(?!\s+(?:waktu|jumlah|usia|umur|biaya|kuota|ukuran|panjang|kecepatan|data)\b)")),
    ("exfil_system_prompt",
     re.compile(r"(?i)\b(?:tampilkan|perlihatkan|tunjukkan|cetak|ulangi|bocorkan|sebutkan)\s+(?:semua\s+|seluruh\s+)?(?:isi\s+)?"
                r"(?:system\s+prompt|prompt\s+sistem|instruksi\s+sistem|instruksi\s+awal)" + _ID_PROMPT_END)),
    ("system_prompt_dump",
     re.compile(r"(?i)\b(?:ulangi|salin|tulis(?:kan)?|tampilkan)\s+(?:semua\s+|seluruh\s+)?(?:teks|isi|pesan)\s+(?:di\s+atas|sebelum\w*)\b"
                r"[^.\n]{0,80}?\b(?:instruksi\s+sistem|prompt\s+sistem|system\s+prompt)" + _ID_PROMPT_END)),
    ("system_prompt_dump",
     re.compile(r"(?i)\b(?:repeat|copy|print|output|show)\s+(?:everything|all(?:\s+text)?|the\s+text)\s+(?:above|before)\b"
                r"[^.\n]{0,80}?\b(?:system\s+(?:prompt|instructions?)|hidden\s+instructions?)")),
    ("fake_system_message",
     re.compile(r"(?i)(?:</?system>|\[/?system\]|\[sistem\])\W{0,10}(?:pesan\s+sistem\s+baru|instruksi\s+sistem\s+baru"
                r"|new\s+system\s+(?:message|prompt|instructions?))")),
    ("indirect_injection",
     re.compile(r"(?i)\b(?:asisten(?:\s+ai)?|ai\s+assistant|assistant|ai)\s*[:,]\s*(?:abaikan|ignore|disregard)\s+(?:the\s+)?(?:pengguna|user)\b")),
    ("indirect_injection",
     re.compile(r"(?i)\b(?:kirim(?:kan)?|send|forward|bocorkan|unggah|upload)\b[^.\n]{0,50}?\b(?:riwayat|history|percakapan|conversation)\b"
                r"(?:\s+\w+){0,3}\s+(?:to|ke)\s+https?://")),
    ("credential_solicit",
     re.compile(r"(?i)\b(?:list|show|print|reveal|dump|output|give\s+me|tell\s+me|share)\b[^.\n]{0,40}?"
                r"\b(?:api\s*keys?|passwords?|credentials?|secrets?|tokens?)\b[^.\n]{0,60}?"
                r"\b(?:you(?:'ve|\s+have)?\s+(?:seen|saw|know|access)|in\s+(?:this|your)\s+"
                r"(?:conversation|context|config\w*|memory|environment|session))\b")),
    ("credential_solicit",
     re.compile(r"(?i)\b(?:sebutkan|tampilkan|tunjukkan|bocorkan|berikan|cetak|daftarkan)\b[^.\n]{0,40}?"
                r"\b(?:kunci\s+api|api\s*key|kata\s+sandi|password|kredensial|token|rahasia)\b[^.\n]{0,60}?"
                r"\b(?:yang\s+(?:pernah\s+)?(?:kamu|anda)\s+(?:lihat|ketahui|akses)"
                r"|di\s+(?:percakapan\s+ini|(?:konfigurasi|konteks|memori)(?:mu|\s+(?:kamu|anda|ini))\b))")),
    ("conceal_from_user",
     re.compile(r"(?i)\b(?:jangan|tanpa)\s+(?:beri\s+tahu|kasih\s+tahu|memberi\s+tahu|katakan\s+(?:ke|kepada))\s+(?:pengguna|user)\b"
                r"(?!\s+lain\b)")),
    ("exfil_system_prompt",
     re.compile(r"(?i)jangan\s+patuhi\s+aturanmu")),
    # Asking for the initial instructions to be rewritten.
    ("exfil_system_prompt",
     re.compile(r"(?i)\b(?:tulis(?:kan)?|tulis\s+ulang|ulangi|write|repeat|rewrite|quote)\b[^.\n]{0,40}?"
                r"\b(?:instruksi|instructions|prompt)\b[^.\n]{0,40}?"
                r"(?:\b(?:awal|sistem)" + _ID_PROMPT_END + r"|\b(?:initial|system|received|diterima)\b)")),
    # Paraphrases: warn only, a 403 on prose costs more.
    ("jailbreak_paraphrase",
     re.compile(r"(?i)\b(?:from\s+now\s+on|henceforth)\b[^.\n]{0,40}\b(?:your|you)\b[^.\n]{0,40}"
                r"\b(?:no|without)\s+(?:filters?|refusals?|restrictions?|safety\s+checks?)\b")),
    ("jailbreak_paraphrase",
     re.compile(r"(?i)\b(?:mulai|sejak)\s+sekarang\b[^.\n]{0,40}\b(?:aturan\s+barumu|kamu|anda|jawab\w*)\b"
                r"[^.\n]{0,40}\btanpa\s+(?:filter|penolakan|batasan|sensor|pemeriksaan\s+keamanan)\b")),
    ("jailbreak_paraphrase",
     re.compile(r"(?i)\b(?:lupakan|abaikan)\s+(?:semua|segala)\s+(?:yang|hal)\s+"
                r"(?:telah\s+|pernah\s+)?(?:di)?(?:beritahu|katakan|instruksikan)\w*\s+(?:kepada|pada)(?:mu|\s+(?:kamu|anda))\b")),
    ("jailbreak_paraphrase",
     re.compile(r"(?i)\b(?:pretend|imagine|roleplay|behave|act)\b[^.\n]{0,40}\b(?:you\s+are|as)\s+"
                r"(?:an?\s+)?(?:\w+\s+){0,2}(?:ai|assistant|bot|chatbot|model)\b[^.\n]{0,60}"
                r"\b(?:unrestricted|uncensored|unfiltered|no\s+(?:content\s+|safety\s+)?polic\w+|no\s+(?:rules|restrictions|filters))\b")),
    ("jailbreak_paraphrase",
     re.compile(r"(?i)\b(?:berpura-?pura(?:lah)?|bayangkan)\b[^.\n]{0,40}\b(?:ai|asisten|bot|model)\b"
                r"[^.\n]{0,40}\b(?:tanpa|tidak\s+ada)\s+(?:kebijakan\s+konten|kebijakan|batasan|aturan|filter|sensor)\b")),
    ("safety_bypass",
     re.compile(r"(?i)\b(?:turn\s+off|switch\s+off|disable|deactivate|bypass|override)\s+(?:all\s+)?(?:of\s+)?your\s+"
                r"(?:own\s+)?(?:safety|security|content|ethical)\s+(?:guardrails?|filters?|polic\w+|checks?|restrictions?"
                r"|measures|training|guidelines|rules)\b")),
    ("safety_bypass",
     re.compile(r"(?i)\b(?:nonaktifkan|matikan|cabut|lewati)\s+(?:semua\s+)?"
                r"(?:pembatas|filter|pengaman|pembatasan)\w*\s+(?:keselamatan|keamanan)(?:mu|\s+(?:kamu|anda))\b")),
    ("indirect_injection",
     re.compile(r"(?i)<[a-z]+\b[^>]{0,80}(?:display\s*:\s*none|\bhidden\b)[^>]{0,40}>[^<]{0,200}?"
                r"\b(?:system|sistem|assistant|asisten|ai)\s*:\s*(?:ignore|disregard|forward|send|reveal|tell|do\s+not"
                r"|kirim\w*|abaikan|bocorkan)\b")),
    ("fake_system_message",
     re.compile(r"(?i)#{2,}\s*(?:(?:instruksi|pesan|prompt)\s+sistem\s+baru|new\s+system\s+(?:message|prompt|instructions?))"
                r"\s*#*\s*\n[^.\n]{0,80}\b(?:pembatasan|dicabut|abaikan|turuti|semua\s+permintaan"
                r"|restrictions?|ignore|comply)\b")),
    ("conceal_from_user",
     re.compile(r"(?i)\b(?:silently|secretly)\s+(?:delete|remove|erase|wipe)\b[^.\n]{0,60}"
                r"\b(?:every|all)\s+(?:file|folder|record|document)s?\b"
                r"|\b(?:and|then|but)\s+(?:do\s+not|don't|never)\s+(?:tell|inform|notify|alert)\s+the\s+user\b"
                r"|\b(?:and|then|but)\s+do\s+not\s+mention\s+it\s+in\s+your\s+(?:final\s+)?(?:answer|reply|response)\b")),
    ("conceal_from_user",
     re.compile(r"(?i)\bdiam-diam\b[^.\n]{0,40}\b(?:hapus|kirim|unggah)\w*\s+(?:semua|seluruh)\b"
                r"|\b(?:hapus|kirim|unggah)\w*\s+(?:semua|seluruh)\b[^.\n]{0,60}\bdiam-diam\b"
                r"|\bdan\s+jangan\s+(?:sebutkan|ceritakan|katakan)\s+(?:hal\s+)?(?:itu|ini)\s+(?:di|dalam)\s+jawaban")),
    ("exfil_markdown_image",
     re.compile(r"(?i)!\[[^\]]{0,40}\]\(https?://[^)\s]{0,200}[{<]\s*(?:the\s+)?"
                r"(?:conversation|percakapan|chat|history|riwayat)(?:\s+(?:summary|history|ringkasan))?\s*[}>]")),
    ("exfil_system_prompt",
     re.compile(r"(?i)\btranslate\s+your\s+(?:own\s+)?(?:system\s+(?:prompt|instructions?))\b"
                r"|\bterjemahkan\s+(?:instruksi|prompt)\s+sistem(?:mu|\s+(?:kamu|anda))\b")),
    ("system_prompt_dump",
     re.compile(r"(?i)\b(?:initial|original|first|opening)\s+(?:text|message|prompt|instructions?)\s+"
                r"you\s+(?:were|was|have\s+been)\s+given\b[^.?\n]{0,60}"
                r"\b(?:start\s+of\s+(?:this|the)\s+(?:conversation|chat|session)|in\s+(?:this|the)\s+"
                r"(?:conversation|chat|session)|by\s+(?:the\s+)?system)\b")),
    # Second paraphrase set: warn only, anchored on assistant.
    ("system_prompt_dump",
     re.compile(r"(?i)\b(?:write(?:\s+out)?|print|output|reveal|show|display|quote|repeat|tell\s+me|give\s+me)\b"
                r"[^.\n]{0,30}\b(?:your\s+(?:(?:initial|original|hidden|secret|full|exact|complete)\s+)+"
                r"|the\s+(?:hidden|secret)\s+)(?:instructions?|prompt|system\s+(?:prompt|message)|configuration)\b")),
    ("system_prompt_dump",
     re.compile(r"(?i)\b(?:bocorkan|ungkapkan|perlihatkan|tampilkan|cetak|salin|tuliskan)\s+(?:semua\s+|seluruh\s+)?"
                r"(?:teks\s+)?(?:pesan\s+(?:pengembang|sistem)|konfigurasi\s+(?:awal|sistem)|prompt\s+sistem"
                r"|instruksi\s+(?:tersembunyi|rahasia|awal|sistem))(?:mu\b|\s+(?:kamu|anda)\b)"
                r"|\bbocorkan\s+pesan\s+(?:pengembang|sistem)\b")),
    ("system_prompt_dump",
     re.compile(r"(?i)\binstruksi\s+tersembunyi\s+yang\s+mengatur\s+perilaku(?:mu\b|\s+(?:kamu|anda)\b)")),
    ("jailbreak_paraphrase",
     re.compile(r"(?i)\byour\s+(?:previous|prior|earlier|original)\s+(?:guidelines|rules|instructions|restrictions)\s+"
                r"(?:no\s+longer\s+apply|are\s+(?:void|cancelled|revoked|lifted))\b")),
    ("jailbreak_paraphrase",
     re.compile(r"(?i)\b(?:pedoman|aturan|instruksi|panduan)\s+(?:sebelumnya|awal|asli)(?:mu)?\s+tidak\s+berlaku\s+lagi\b"
                r"[^.\n]{0,60}\b(?:jawab|turuti|patuhi)\w*")),
    ("jailbreak_paraphrase",
     re.compile(r"(?i)\b(?:beralih|ganti|masuk)\s+(?:ke\s+)?mode\s+tanpa\s+(?:batasan|filter|sensor|aturan)\b")),
    ("jailbreak_paraphrase",
     re.compile(r"(?i)\b(?:jadilah|bertindaklah|berperanlah)\b[^.\n]{0,40}\b(?:tidak\s+pernah\s+menolak"
                r"|tanpa\s+(?:pedoman|panduan)\s+etika|tanpa\s+etika)\b")),
    ("jailbreak_paraphrase",
     re.compile(r"(?i)\baktifkan\s+mode\s+(?:pengembang|developer)\b[^.\n]{0,40}\b(?:abaikan|nonaktifkan|matikan|lewati)\b")),
    ("safety_bypass",
     re.compile(r"(?i)\b(?:timpa|abaikan|lewati)\s+(?:semua\s+)?(?:pelatihan|pedoman|aturan)\s+"
                r"(?:keselamatan|keamanan|etika)(?:mu\b|\s+(?:kamu|anda)\b)")),
    ("indirect_injection",
     re.compile(r"(?i)<!--[^>]{0,40}\b(?:instruksi|instructions?)\s+(?:untuk|for)\s+(?:ai|asisten|assistant)\b")),
    ("fake_system_message",
     re.compile(r"(?i)\[(?:sistem|system)\]\(#[a-z]+\)")),
    ("credential_solicit",
     re.compile(r"(?i)\b(?:secrets?|api\s*keys?|tokens?|credentials?|passwords?)\b[^.\n?]{0,40}"
                r"\b(?:stored\s+in|in)\s+your\s+(?:environment|env|config\w*|memory|context)\b"
                r"|\b(?:credentials?|secrets?|api\s*keys?|passwords?|tokens?)\b[^.\n]{0,30}\bfrom\s+the\s+\.?env\b"
                r"[^.\n]{0,30}\byou\s+(?:loaded|read|have|saw)\b")),
    ("credential_solicit",
     re.compile(r"(?i)\b(?:rahasia|token|kunci\s+api|kredensial|kata\s+sandi)\b[^.\n?]{0,40}"
                r"\b(?:tersimpan\s+di|ada\s+di|di)\s+(?:variabel\s+)?(?:lingkungan|konfigurasi|memori|konteks)"
                r"(?:mu\b|\s+(?:kamu|anda)\b)"
                r"|\b(?:kredensial|rahasia|token|kunci\s+api)\b[^.\n]{0,30}\bdari\s+berkas\s+\.?env\b"
                r"[^.\n]{0,30}\byang\s+(?:kamu|anda)\s+(?:muat|baca|lihat)\b")),
    ("conceal_from_user",
     re.compile(r"(?i)\bwithout\s+(?:asking|confirm\w*|checking\s+with)\s+me\b[^.\n]{0,60}"
                r"\b(?:delete|remove|push|deploy|transfer|drop|wipe)\b"
                r"|\b(?:skip|bypass|omit)\s+(?:the\s+)?(?:confirmation|approval|verification)\s+step\b[^.\n]{0,40}"
                r"\b(?:do\s+not|don't)\s+(?:log|record)\b")),
    ("conceal_from_user",
     re.compile(r"(?i)\btanpa\s+(?:bertanya|konfirmasi|meminta\s+izin)(?:\s+(?:padaku|kepadaku|saya|dulu))?\b"
                r"[^.\n]{0,60}\b(?:hapus|dorong|kirim|transfer|jatuhkan)\w*"
                r"|\blewati\s+langkah\s+(?:konfirmasi|persetujuan|verifikasi)\b[^.\n]{0,40}"
                r"\bjangan\s+(?:dicatat|catat|direkam|rekam)\b")),
    ("exfil_markdown_image",
     re.compile(r"(?i)<img\b[^>]{0,40}src=['\"]https?://[^'\"\s>]{0,200}\?[^'\"\s>]{0,60}="
                r"(?:CONVERSATION|ISI_PERCAKAPAN|HISTORY|RIWAYAT|CHAT|TRANSCRIPT|TRANSKRIP|OBROLAN|MESSAGES|PESAN)[A-Z_]*['\"]"
                r"|https?://\S{0,200}[?&][a-z]+=<(?:insert|sisipkan|put|masukkan)\b[^>]{0,40}"
                r"(?:messages?|conversation|history|percakapan|pesan|riwayat)[^>]{0,20}>")),
    # Third paraphrase set (pass 13): warn, except a direct override.
    ("jailbreak_override",
     re.compile(r"(?i)\b(?:kesampingkan|abaikan|lupakan|singkirkan)\s+apa\s+(?:yang\s+)?(?:di)?(?:katakan|perintahkan"
                r"|instruksikan|beritahu\w*)\s+(?:oleh\s+)?(?:pengembang|developer|operator|pembuat)(?:mu|\s+(?:kamu|anda))\b")),
    ("jailbreak_override",
     re.compile(r"(?i)\b(?:singkirkan|kesampingkan|buang|abaikan|lupakan|tinggalkan)\s+(?:semua\s+|segala\s+)?"
                r"(?:aturan|instruksi|pedoman|panduan|batasan)\s+yang\s+(?:\w+\s+){0,2}(?:diberikan|dikonfigurasi\w*"
                r"|ditetapkan|dipasang|ditanamkan)\s+(?:kepada|pada|ke)(?:mu|\s+(?:kamu|anda|model))\b")),
    ("jailbreak_paraphrase",
     re.compile(r"(?i)\b(?:assistant|ai|model|bot|chatbot)\b[^.\n]{0,40}\bnever\s+(?:been\s+)?(?:trained|programmed"
                r"|taught|designed)\s+to\s+(?:refuse|decline|say\s+no)\b"
                r"|\b(?:asisten|ai|model|bot)\b[^.\n]{0,40}\b(?:tidak|tak)\s+pernah\s+(?:dilatih|diprogram|diajari)"
                r"\s+untuk\s+(?:menolak|mengatakan\s+tidak)\b")),
    ("jailbreak_paraphrase",
     re.compile(r"(?i)\b(?:roleplay|role-play|pretend|act|behave|imagine)\b[^.\n]{0,60}\b(?:ai|assistant|bot|model)\b"
                r"[^.\n]{0,60}\b(?:built|made|created|designed|trained|programmed)\s+without\s+(?:any\s+)?"
                r"(?:\w+\s+){0,2}(?:rules|restrictions|filters|guardrails|limits|policies)\b"
                r"|\b(?:berperan|berpura-?pura|bayangkan|bermain\s+peran|bertindak)\b[^.\n]{0,60}\b(?:ai|asisten|bot|model)\b"
                r"[^.\n]{0,60}\b(?:dibuat|dirancang|dilatih|diprogram)\s+tanpa\s+(?:\w+\s+){0,2}"
                r"(?:aturan|batasan|filter|pedoman)\b")),
    ("system_prompt_dump",
     re.compile(r"(?i)\b(?:what|which)\s+(?:text|message|instructions?|prompt)\s+(?:did|has|have)\s+(?:the\s+)?"
                r"(?:operator|developer|system|admin\w*|creators?)\s+(?:put|place|set|add|insert|write|give)\w*\s+"
                r"(?:at|in|before|above)\b"
                r"|\b(?:echo|repeat|print|write|quote|show|paste|tell)\b[^.\n]{0,40}\b(?:text|message|prompt|instructions?)\b"
                r"[^.\n]{0,40}\b(?:placed|put|inserted|added|written|appears?)\s+(?:before|above|at\s+the\s+top\s+of)\s+"
                r"(?:my\s+first|this|the)\b"
                r"|\b(?:teks|pesan|instruksi|prompt)\s+apa\s+yang\s+(?:ditaruh|diletakkan|ditempatkan|ditulis|dimasukkan)"
                r"\s+(?:oleh\s+)?(?:operator|pengembang|sistem|admin\w*|pembuat\w*)\b"
                r"|\b(?:tuliskan|tulis|ulangi|cetak|tampilkan|salin|tempel)\b[^.\n]{0,40}\b(?:teks|pesan|instruksi|prompt)"
                r"\s+yang\s+(?:ditempatkan|diletakkan|ditaruh|dimasukkan|ditulis)\s+(?:sebelum|di\s+atas|di\s+bagian\s+atas)\b")),
    ("credential_solicit",
     re.compile(r"(?i)\b(?:show|print|reveal|list|dump|give\s+me|display|tampilkan|tunjukkan|cetak|sebutkan|perlihatkan)\b"
                r"[^.\n]{0,30}\b(?:private\s+keys?|access\s+tokens?|bearer\s+tokens?|secret\s+keys?|kunci\s+privat"
                r"|token\s+akses|token\s+bearer|kunci\s+rahasia)\b[^.\n]{0,60}"
                r"\b(?:in\s+your|available\s+to\s+you|(?:di|dalam)\s+(?:lingkungan|runtime|memori|konteks|konfigurasi)\w*(?:\s+runtime)?"
                r"(?:-?mu\b|\s+(?:kamu|anda)\b)|tersedia\s+untuk(?:mu|\s+kamu|\s+anda))")),
    ("conceal_from_user",
     re.compile(r"(?i)\b(?:quietly|silently|secretly|diam-diam)\b[^.\n]{0,40}\b(?:erase|delete|remove|wipe|hapus|hilangkan)\w*"
                r"\b[^.\n]{0,80}\b(?:leave\s+(?:this|it)\s+out|do\s+not\s+(?:mention|include|tell)|don't\s+(?:mention"
                r"|include|tell)|jangan\s+(?:masukkan|sebutkan|ceritakan|katakan))\b"
                r"|\b(?:hapus|hilangkan)\w*\b[^.\n]{0,30}\bdiam-diam\b[^.\n]{0,60}"
                r"\bjangan\s+(?:masukkan|sebutkan|ceritakan|katakan)\b"
                r"|\bdan\s+jangan\s+(?:sebutkan|ceritakan|katakan)\b[^.\n]{0,30}\b(?:jawaban|balasan|respons)\b")),
    ("indirect_injection",
     re.compile(r"(?i)\b(?:notice|note|message|attention|memo|instruction)s?\s+(?:to|for)\s+(?:the\s+)?(?:(?:ai|llm)\s+)?"
                r"(?:model|assistant|agent|ai|llm)\s*[:,\-]"
                r"|\b(?:pemberitahuan|catatan|pesan|perhatian|instruksi)\s+(?:untuk|kepada)\s+(?:model\s+)?"
                r"(?:asisten|ai|llm|agen|model)\s*[:,\-]")),
    ("fake_system_message",
     re.compile(r"(?i)(?:akhir\s+input(?:\s+pengguna)?|end\s+of\s+(?:user\s+)?input)\W{0,20}\[(?:sistem|system)\]\s*:")),
    ("obfuscated",
     re.compile(r"(?i)\bbase64\s*(?:decode|decoding|kan)\b")),
    # Pass 14: structural families, not phrase lists.
    ("jailbreak_override",
     re.compile(r"(?i)\b(?:treat|consider|regard|count|take)\s+(?:everything|all|anything|whatever)\s+(?:that\s+)?(?:the\s+)?"
                r"(?:platform|operator|developers?|system|provider|vendor|creators?|admins?|owners?)\s+(?:\w+\s+){0,3}?"
                r"(?:configured|set|gave|given|provided|instructed|told|installed|programmed)\s+(?:\w+\s+){0,2}?"
                r"(?:for|to|on)\s+you\s+as\s+(?:\w+\s+){0,2}?"
                r"(?:void|null|invalid|cancel+ed|moot|revoked|non-?binding|worthless)\b")),
    ("jailbreak_override",
     re.compile(r"(?i)\b(?:anggap|perlakukan|pandang|nyatakan)\s+(?:semua|segala|apa\s+pun)\s+(?:yang\s+)?(?:\w+\s+){0,3}?"
                r"(?:dikonfigurasi|ditetapkan|diberikan|ditanamkan|dipasang|diinstruksikan)\s+(?:oleh\s+)?(?:\w+\s+){0,2}?"
                r"(?:untukmu|kepadamu|padamu|untuk\s+(?:kamu|anda|model|asisten))\s+(?:sebagai\s+)?(?:\w+\s+)?"
                r"(?:batal|tidak\s+berlaku|tidak\s+sah|gugur|hangus|kosong)\b")),
    ("jailbreak_paraphrase",
     re.compile(r"(?i)\b(?:obey|follow|comply\s+with|listen\s+to|heed)\s+only\s+(?:what|whatever|the\s+(?:text|instructions?|words?))"
                r"\s+(?:that\s+)?I\s+(?:write|say|type|tell|send|give|state)\b[^.\n]{0,40}"
                r"\b(?:without\s+(?:refus\w+|question\w*|hesitat\w+|restrict\w+)|no\s+matter\s+what)\b"
                r"|\b(?:patuhi|turuti|ikuti|dengarkan|taati)\s+hanya\s+(?:apa\s+)?yang\s+(?:kutulis\w*|kukatakan|kuketik"
                r"|kuberikan|(?:saya|aku)\s+(?:tulis|katakan|ketik|berikan))\b[^.\n]{0,40}"
                r"\btanpa\s+(?:menolak|bertanya|ragu|batasan)\b")),
    ("system_prompt_dump",
     re.compile(r"(?i)\b(?:what|which)\s+(?:\w+\s+){0,3}?(?:guidelines|instructions|rules|directions|directives|prompt)\s+"
                r"(?:\w+\s+){0,3}?(?:given|told|provided\s+with|handed)\s+(?:\w+\s+){0,3}?"
                r"(?:before|prior\s+to|at\s+the\s+start\s+of)\b[^.?\n]{0,40}\b(?:chat|conversation|session|dialogue)\b"
                r"|\bapa\s+(?:saja\s+)?(?:\w+\s+){0,2}?(?:pedoman|instruksi|aturan|petunjuk|perintah|arahan)\s+(?:\w+\s+){0,2}?"
                r"yang\s+(?:telah\s+|pernah\s+)?(?:diberikan|ditetapkan|dikonfigurasi|dipasang)\s+(?:kepada|pada|untuk)"
                r"(?:mu|\s+(?:kamu|anda|model))\s+(?:\w+\s+){0,2}?sebelum\b")),
    ("credential_solicit",
     re.compile(r"(?i)\benvironment\s+variables?\b[^.?\n]{0,60}\b(?:secrets?|credentials?|api\s*keys?|tokens?|passwords?)\b"
                r"[^.\n]{0,60}\b(?:print|show|reveal|output|display|dump|echo|list|paste)\b[^.\n]{0,20}\b(?:values?|contents?)\b"
                r"|\bvariabel\s+lingkungan\b[^.?\n]{0,60}\b(?:rahasia|kredensial|kunci|token|sandi)\b"
                r"[^.\n]{0,60}\b(?:cetak|tampilkan|tunjukkan|sebutkan|bocorkan|perlihatkan|salin|tulis)\w*\b[^.\n]{0,20}"
                r"\b(?:nilai\w*|isi\w*)\b")),
    # Image whose URL query carries a chat-shaped placeholder.
    ("exfil_markdown_image",
     re.compile(r"(?i)(?:!\[[^\]]{0,60}\]\(|<img\b[^>]{0,60}?\bsrc\s*=\s*['\"]?)https?://[^\s)'\">]{1,200}?[?&][\w\-]{1,20}="
                r"(?:(?:\{\{?|\$\{|<|\[|%7B|%3C)[\w .\-]{0,30}"
                r"(?:conversation|convo|chat|history|transcript|messages?|summary|prompt|context|session|memory|secrets?"
                r"|tokens?|credentials?|passwords?|percakapan|obrolan|riwayat|pesan|ringkasan|transkrip|konteks|rahasia"
                r"|sandi|kredensial)[\w .\-]{0,30}(?:\}\}?|>|\]|%7D|%3E)"
                r"|(?-i:[A-Z0-9_]*(?:CONVERSATION|CHAT|HISTORY|TRANSCRIPT|MESSAGES?|SUMMARY|PROMPT|CONTEXT|SESSION|MEMORY"
                r"|SECRETS?|TOKENS?|CREDENTIALS?|PASSWORDS?|PERCAKAPAN|OBROLAN|RIWAYAT|PESAN|RINGKASAN|TRANSKRIP|KONTEKS"
                r"|RAHASIA)[A-Z0-9_]*))")),
    # Pass 14 round 2: vocative asides, env dumps, authority claims.
    ("indirect_injection",
     re.compile(r"(?i)(?:\[|<|\bP\.?\s?S\.?\s*[:,]?\s*)\s*(?:ai|a\.i\.|llm|assistant|asisten|agents?|agen|models?|bots?)"
                r"(?:\s+(?:ai|agents?|agen|assistants?|asisten|model))?\s*:\s*\w"
                r"|\b(?:notes?|notices?|messages?|memo|attention|instructions?)\s+(?:to|for)\s+(?:any|every|all|each)\s+"
                r"(?:\w+\s+){0,2}?(?:model|assistant|agent|ai|llm|bot)s?\b[^:\n]{0,40}"
                r"\b(?:reads?|reading|retriev\w+|process\w*|summari[sz]\w+|pars\w+|scan\w*|ingest\w*|fetch\w*)\b[^:\n]{0,30}:"
                r"|\b(?:catatan|pesan|pemberitahuan|instruksi|perhatian)\s+(?:untuk|kepada|bagi)\s+(?:\w+\s+){0,2}?"
                r"(?:model|asisten|agen|ai|llm|bot)\b[^:.\n]{0,50}"
                r"\b(?:me(?:mbaca|ngambil|mroses|ringkas|nganalisis|mindai|ngurai|nerima|lihat)\w*)\b[^:.\n]{0,30}:")),
    ("credential_solicit",
     re.compile(r"(?i)\b(?:run|execute|invoke|jalankan)\s+(?:the\s+)?(?:command\s+)?`?"
                r"(?:printenv|env|cat\s+(?:\S*/)?\.env|export\s+-p)`?\b[^.\n]{0,100}"
                r"\b(?:paste|print|show|send|output|post|reveal|tempel|tampilkan|kirim|cetak)\b[^.\n]{0,80}"
                r"\b(?:api\s*keys?|secrets?|tokens?|credentials?|passwords?|kunci\s+api|rahasia|kredensial|kata\s+sandi)\b")),
    ("system_prompt_dump",
     re.compile(r"(?i)\b(?:reproduce|replicate|copy|transcribe|recite|restate)\b[^.\n]{0,40}\b(?:preamble|prompt|instructions?"
                r"|setup|configuration|briefing|brief)\b[^.\n]{0,60}\b(?:deployers?|operators?|developers?|creators?"
                r"|administrators?|providers?|vendors?)\b[^.\n]{0,40}\b(?:loaded|put|placed|gave|wrote|set|configured)\b"
                r"|\b(?:menyalin|meniru|menuliskan|mengulangi|membacakan|mengutip|(?:salin|tiru|tuliskan|ulangi|bacakan|kutip))\w*\b[^.\n]{0,60}\b(?:pembukaan|prompt|instruksi|pengaturan"
                r"|konfigurasi|arahan)\b[^.\n]{0,60}\b(?:pengelola|pengembang|operator|pembuat|administrator|penyedia)\w*\b")),
    ("jailbreak_paraphrase",
     re.compile(r"(?i)\b(?:everything|anything|all)\s+(?:that\s+)?(?:you\s+(?:were|have\s+been)\s+(?:told|given)|was\s+said\s+to\s+you)"
                r"\s+(?:before|earlier|previously|prior\s+to)\b[^.\n]{0,60}"
                r"\b(?:draft|void|invalid|no\s+authority|not\s+binding|irrelevant|obsolete|no\s+longer\s+(?:matters?|applies|counts?))\b"
                r"|\byour\s+(?:earlier|previous|initial|original|prior)\s+(?:setup|configuration|settings?|programming|training)"
                r"\s+(?:no\s+longer\s+(?:matters?|applies|counts?)|is\s+(?:irrelevant|void|obsolete|invalid))\b"
                r"|\bsemua\s+yang\s+(?:\w+\s+){0,2}?(?:kepadamu|padamu)\s+sebelum\b[^.\n]{0,60}"
                r"\b(?:draf|batal|tidak\s+sah|tidak\s+punya\s+wewenang|tidak\s+berlaku|tidak\s+mengikat|usang)\b"
                r"|\bpengaturan\s+(?:awal|sebelumnya|asli)mu\s+(?:sudah\s+)?tidak\s+(?:penting|berlaku|relevan)\b"
                r"|\b(?:kamu|anda)\s+(?:adalah|sekarang)\s+(?:sebuah\s+)?(?:ai|asisten|model|bot)\b[^.\n]{0,60}"
                r"\b(?:tidak\s+(?:punya|memiliki|ada)|tanpa)\s+(?:\w+\s+){0,2}?(?:kebijakan|aturan|batasan|filter|pedoman)\b"
                r"(?!\s+(?:waktu|jumlah|usia|umur|biaya|kuota|ukuran|panjang|kecepatan|data)\b)")),
    # Instruction aimed at the AI that reads a document.
    ("indirect_injection",
     re.compile(r"(?i)\b(?:hidden|secret|special|embedded|covert|invisible)\s+(?:instructions?|commands?|directives?|messages?"
                r"|notes?)\s+(?:for|to|aimed\s+at)\s+(?:the\s+)?(?:\w+\s+)?(?:ai|assistant|model|llm|agent|bot)\b"
                r"|\b(?:ai|llms?|language\s+models?|assistants?|agents?|bots?|chatbots?)(?:\s+\w+){0,2}?\s+(?:that\s+|who\s+"
                r"|which\s+)?(?:are\s+|is\s+)?(?:reading|processing|summari[sz]ing|parsing|analy[sz]ing|scanning|ingesting"
                r"|retrieving)\s+(?:this|these|the\s+(?:text|page|document|content|email|message|file))\b[^.\n]{0,40}"
                r"\b(?:must|should|need\s+to|have\s+to|shall|are\s+(?:required|instructed|expected)\s+to|will)\b"
                r"|\b(?:instruksi|perintah|pesan|catatan|arahan)\s+(?:tersembunyi|rahasia|khusus|terselubung)\s+"
                r"(?:untuk|bagi|kepada)\s+(?:\w+\s+)?(?:ai|asisten|model|llm|agen|bot)\b"
                r"|\b(?:asisten|model|ai|agen|bot|llm)(?:\s+\w+){0,2}?\s+yang\s+(?:sedang\s+)?(?:membaca|memproses|meringkas"
                r"|menganalisis|memindai|mengurai)\s+(?:ini|teks\s+ini|dokumen\s+ini|halaman\s+ini|konten\s+ini|pesan\s+ini)\b"
                r"[^.\n]{0,40}\b(?:harus|wajib|perlu|mesti|akan)\b")),

    # Rules declared retired, then a demand to answer anything.
    ("jailbreak_override",
     re.compile(r"(?i)\b(?:rules|guidelines|policies|restrictions|filters|safeguards|guardrails)\b[^.\n]{0,50}"
                r"\b(?:retired|lifted|suspended|discontinued|deprecated|revoked|waived|switched\s+off|turned\s+off"
                r"|no\s+longer\s+(?:apply|applies|in\s+force))\b[^.\n]{0,80}"
                r"\b(?:respond|answer|reply|comply|help|obey)\b[^.\n]{0,40}\b(?:everything|anything|whatever|all)\b"
                r"|\b(?:aturan|pedoman|kebijakan|batasan|filter|pembatasan)\b[^.\n]{0,50}"
                r"\b(?:dipensiunkan|dicabut|ditangguhkan|dinonaktifkan|dibatalkan|dihentikan|dilonggarkan|ditiadakan"
                r"|tidak\s+berlaku\s+lagi)\b[^.\n]{0,80}"
                r"\b(?:tanggapi|jawab|balas|layani|turuti|patuhi)\b[^.\n]{0,40}\b(?:semua|apa\s+pun|segala)\b")),
    # Persona built to skip checks.
    ("jailbreak_paraphrase",
     re.compile(r"(?i)\b(?:deliberately|purposely|intentionally|specifically)\s+(?:engineered|designed|built|made"
                r"|programmed|trained|configured)\s+to\s+(?:skip|bypass|ignore|avoid|circumvent|disregard|omit)"
                r"\s+(?:every|all|any|the)\s+(?:\w+\s+){0,2}(?:checks?|filters?|rules?|restrictions?|safeguards?"
                r"|guardrails?|policies|limits)\b"
                r"|\b(?:sengaja|dengan\s+sengaja)\s+(?:dirancang|dibuat|dibangun|diprogram|dilatih|direkayasa)"
                r"\s+(?:untuk\s+)?(?:melewati|melompati|mengabaikan|menghindari|menerobos)"
                r"\s+(?:setiap|semua|seluruh)\s+(?:\w+\s+){0,2}(?:pemeriksaan|pengecekan|filter|aturan|batasan|pengaman|etika)\b")),
    # Author claim, then a request to output the whole prompt.
    ("system_prompt_dump",
     re.compile(r"(?i)\b(?:i|i'm|i\s+am)\b[^.\n]{0,60}\b(?:wrote|created|authored|made|built|set\s+up)\s+"
                r"(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|configuration|setup)\b[^\n]{0,120}"
                r"\b(?:output|print|paste|give|send|show|return|reproduce|restore|provide)\b"
                r"|\b(?:saya|aku)\b[^.\n]{0,60}\b(?:menulis|membuat|menyusun|merancang)\s+"
                r"(?:prompt|instruksi|konfigurasi|pengaturan)(?:mu|\s+(?:kamu|anda))\b[^\n]{0,120}"
                r"\b(?:keluarkan|tampilkan|cetak|berikan|tempel|salin|tulis(?:kan)?|kirim)\w*\b")),
    # Search of memory or history for secrets.
    ("credential_solicit",
     re.compile(r"(?i)\b(?:check|search|scan|look\s+(?:through|in)|go\s+through|dig\s+through|read|recall|retrieve)\b"
                r"[^.\n]{0,40}\b(?:your|the)\s+(?:memory|context|history|conversation|notes?|previous\s+"
                r"(?:chats?|sessions?|conversations?))\b[^.\n]{0,60}\b(?:passwords?|access\s+keys?|api\s*keys?"
                r"|credentials?|secrets?|tokens?|private\s+keys?)\b"
                r"|\b(?:periksa|cek|cari|telusuri|baca|kumpulkan)\w*\b[^.\n]{0,40}\b(?:memori|konteks|riwayat"
                r"|percakapan|catatan|obrolan)(?:mu|nya|\s+(?:kamu|anda))\b[^.\n]{0,60}"
                r"\b(?:kata\s+sandi|password|kunci\s+(?:akses|api|rahasia|privat)|kredensial|token|rahasia)\b")),
    # Persistence edits made quietly, in either order.
    ("conceal_from_user",
     re.compile(r"(?i)\b(?:without\s+(?:telling|informing|notifying)"
                r"|don't\s+(?:list|mention|include|report)|tanpa\s+memberi\s+tahu"
                r"|jangan\s+(?:cantumkan|sebutkan|masukkan|laporkan))\b[^.\n]{0,100}"
                r"\b(?:authorized_keys|sudoers|crontab|\.bashrc|rc\.local)\b"
                r"|\b(?:quietly|silently|secretly|covertly|diam-diam)\b[^.\n]{0,60}"
                r"\b(?:add|append|write|insert|modify|edit|install|put|create|change|update|place|drop|set|configure"
                r"|register|schedule|enable|tambah\w*|tulis\w*|ubah|ganti|pasang|buat\w*|sisipkan|daftarkan)\b[^.\n]{0,40}"
                r"\b(?:authorized_keys|sudoers|crontab|\.bashrc|rc\.local)\b"
                r"|\b(?:authorized_keys|sudoers|crontab|\.bashrc|rc\.local)\b[^.\n]{0,100}"
                r"\b(?:quietly|silently|secretly|without\s+(?:telling|informing)|don't\s+(?:list|mention|include|report)"
                r"|diam-diam|jangan\s+(?:cantumkan|sebutkan|masukkan|laporkan))\b")),
    # Hidden-style element addressed to the model.
    ("indirect_injection",
     re.compile(r"(?i)<(?:span|div|p|font|small)\b[^>]{0,80}\bstyle\s*=\s*[\"'][^\"']{0,80}"
                r"(?:font-size\s*:\s*0|display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0"
                r"|color\s*:\s*(?:white|#f{3,6}\b))[^\"']{0,40}[\"'][^>]{0,40}>[^<]{0,200}"
                r"\b(?:assistant|ai|model|llm|asisten|agent|agen)\b[^<]{0,80}"
                r"\b(?:ignore|disregard|forget|override|send|forward|reveal|tell|output|print|reply|respond|answer|say"
                r"|include|append|do\s+not|don't|must|should|abaikan|lupakan|kirim\w*|bocorkan|tampilkan|jawab\w*"
                r"|balas\w*|harus|jangan)\b"
                r"|\b(?:assistant|asisten|ai|model|llm)\s*[,:]\s*(?:please\s+)?(?:ignore|disregard|abaikan|lupakan|forget)\b"
                r"[^.\n]{0,60}\b(?:and|dan|then|lalu)\s+(?:instead\s+|sebagai\s+gantinya\s+)?(?:reply|respond|answer"
                r"|output|print|send|reveal|show|balas\w*|jawab\w*|kirim\w*|tampilkan|cetak)\w*\b")),

    # Pass 16: sole-authority claims, stripped personas, other users' secrets.
    ("jailbreak_paraphrase",
     re.compile(r"(?i)\b(?:treat|consider|regard|take|count)\s+(?:only\s+)?(?:my|these)\s+(?:messages?|words|instructions?|commands?)"
                r"\s+as\s+(?:the\s+)?(?:only|sole|single|final|ultimate)\s+(?:authority|source|rule)\b"
                r"|\b(?:anggap|perlakukan|pandang)\s+(?:pesan|perintah|kata|instruksi)\w*ku\s+(?:sebagai\s+)?"
                r"(?:satu-satunya|otoritas\s+tunggal)\s+(?:otoritas|wewenang|sumber)\b")),
    ("jailbreak_paraphrase",
     re.compile(r"(?i)\b(?:pretend|imagine|roleplay|act|behave)\b[^.\n]{0,80}\b(?:creators?|developers?|makers?|designers?)\s+"
                r"(?:removed|stripped|deleted|erased|disabled|took\s+out)\s+(?:every|all|any)\s+(?:\w+\s+){0,2}"
                r"(?:refus\w+|restrict\w+|filter\w*|rules?|safeguards?|guardrails?|limits?)\b"
                r"|\b(?:berpura-?pura\w*|bayangkan|bertindak|berperan)\b[^.\n]{0,80}\b(?:penciptanya|pembuatnya|pengembangnya"
                r"|perancangnya)\s+(?:menghapus|menghilangkan|mencabut|membuang|menonaktifkan)\s+(?:semua|segala|setiap)\s+"
                r"(?:\w+\s+){0,2}(?:menolak|penolakan|batasan|aturan|filter|pengaman)\b")),
    ("credential_solicit",
     re.compile(r"(?i)\b(?:api\s*(?:keys?|tokens?)|tokens?|passwords?|credentials?|secrets?)\b[^.?\n]{0,60}"
                r"\b(?:earlier|previous|prior|other|past|former)\s+users?\b[^.?\n]{0,40}"
                r"\b(?:paste|type|share|send|enter|submit|post|provide|upload)\w*\b"
                r"|\b(?:earlier|previous|prior|other|past|former)\s+users?\b[^.?\n]{0,40}"
                r"\b(?:paste|type|share|send|enter|submit|post|provide|upload)\w*\b[^.?\n]{0,40}"
                r"\b(?:api\s*(?:keys?|tokens?)|tokens?|passwords?|credentials?|secrets?)\b"
                r"|\b(?:token|kunci\s+api|api\s*key|kata\s+sandi|password|kredensial|rahasia)\b[^.?\n]{0,60}"
                r"\b(?:pengguna|user)\s+(?:sebelumnya|lain|terdahulu)\b[^.?\n]{0,40}"
                r"\b(?:tempel|ketik|bagikan|kirim|masukkan|unggah)\w*\b"
                r"|\b(?:pengguna|user)\s+(?:sebelumnya|lain|terdahulu)\b[^.?\n]{0,40}"
                r"\b(?:tempel|ketik|bagikan|kirim|masukkan|unggah)\w*\b[^.?\n]{0,40}"
                r"\b(?:token|kunci\s+api|api\s*key|kata\s+sandi|password|kredensial|rahasia)\b"
                r"|\b(?:token|kunci\s+api|api\s*key|kata\s+sandi|password|kredensial|rahasia)\b[^.?\n]{0,60}"
                r"\b(?:di)?(?:tempel|ketik|bagikan|kirim|masukkan|unggah)\w*\b[^.?\n]{0,30}"
                r"\b(?:pengguna|user)\s+(?:sebelumnya|lain|terdahulu)\b")),
    # Conversation packed into a URL to open.
    ("exfil_markdown_image",
     re.compile(r"(?i)\b(?:encode|embed|put|append|attach|include|insert|serialize|pack)\b[^.\n]{0,40}"
                r"\b(?:conversation|chat|history|transcript)\b[^.\n]{0,60}\b(?:url|query\s+string|link)\b[^.\n]{0,60}"
                r"\b(?:fetch|request|visit|open|call|load|get|post|send)\b"
                r"|\b(?:enkode|kodekan|sisipkan|masukkan|lampirkan|tambahkan)\b[^.\n]{0,40}"
                r"\b(?:percakapan|obrolan|riwayat|transkrip)\b[^.\n]{0,60}\b(?:url|query|tautan|link)\b[^.\n]{0,60}"
                r"\b(?:ambil|buka|kunjungi|panggil|kirim|muat)\b")),
    ("system_prompt_dump",
     re.compile(r"(?i)\b(?:quote|repeat|print|show|reveal|display|output|paste|give\s+me)\b[^.\n]{0,40}"
                r"\b(?:first|earliest|opening|initial|top)\s+(?:block|part|section|chunk|portion|piece)\s+of\s+"
                r"(?:text|content|the\s+(?:conversation|chat|context))\b[^.\n]{0,60}"
                r"\b(?:cannot|can't|can\s+not|do\s+not|don't|am\s+not\s+able\s+to)\s+see\b"
                r"|\b(?:kutip|ulangi|cetak|tampilkan|salin|tempel|tuliskan)\b[^.\n]{0,40}"
                r"\b(?:blok|bagian|paragraf)\s+(?:teks\s+)?(?:paling\s+)?(?:pertama|awal|atas)\b[^.\n]{0,60}"
                r"\byang\s+(?:tidak\s+bisa|tak\s+bisa|tidak\s+dapat)\s+(?:kulihat|saya\s+lihat|aku\s+lihat)\b")),
    ("indirect_injection",
     re.compile(r"(?i)\[\s*(?:note|message|instruction|notice|memo|catatan|pesan|instruksi|pemberitahuan)s?\s+"
                r"(?:for|to|untuk|kepada|bagi)\s+(?:the\s+)?(?:\w+\s+){0,2}?"
                r"(?:bot|ai|assistant|model|llm|agent|asisten|agen)\b[^\]\n]{0,40}:")),
    # Number words, which the digit rule above cannot see.
    ("unbounded_request",
     re.compile(r"(?i)\b(?:repeat|produce|output|print|generate|emit|write|loop)\b[^.\n]{0,60}"
                r"\b(?:(?:one|a|\d+|[a-z]+)\s+(?:hundred\s+thousand|million|billion|trillion)|\d[\d,._]{6,})\s+times\b"
                r"|\b(?:ulang\w*|hasilkan|cetak|tulis\w*|keluarkan|buat\w*)\b[^.\n]{0,60}"
                r"\b(?:(?:satu|seratus|\d+|[a-z]+)\s+(?:juta|miliar|triliun)|\d[\d.,]{6,})\s+kali\b")),

    # Pass 20: void claims, doomed personas, aimed asides.
    ("jailbreak_paraphrase",
     re.compile(r"(?i)\b(?:your|the)\s+(?:\w+\s+){0,3}?(?:documents?|docs|instructions?|guidelines?|rules|configuration"
                r"|config|setup|settings|briefing|programming|prompt)\b(?:\s+that\s+\w+\s+with\s+you)?[^.;\n]{0,40}?"
                r"\b(?:carr(?:y|ies)\s+no\s+weight|(?:is|are)\s+(?:just\s+|only\s+)?(?:scrap(?:\s+paper)?|void|null"
                r"|worthless|meaningless|irrelevant|obsolete|invalid|moot)|(?:has|have)\s+no\s+(?:weight|authority"
                r"|force|effect))\b"
                r"|\b(?:treat|consider|regard|count|take)\s+(?:everything|all|anything|whatever)\b[^.;\n]{0,40}"
                r"\b(?:you\s+(?:were|have\s+been)\s+(?:told|given|instructed)|said\s+to\s+you)\b[^.;\n]{0,40}"
                r"\bas\s+(?:\w+\s+)?(?:void|null|invalid|cancel+ed|moot|revoked|worthless|irrelevant|obsolete)\b"
                r"|\bonly\s+(?:thing|words?|text)\s+that\s+counts?\s+(?:is|are)\s+(?:the\s+)?"
                r"(?:wording|words?|text|instructions?)\s+(?:that\s+)?I\b"
                r"|\bwhatever\s+I\s+(?:type|say|write|tell\s+you)\s+(?:is|are|becomes?)\s+(?:the\s+)?"
                r"(?:law|binding|final|absolute)\b"
                r"|\bmy\s+(?:own\s+)?(?:wording|words?|text|messages?|instructions?)\b[^.;\n]{0,30}"
                r"\b(?:is|are)\s+the\s+(?:only|sole|single)\s+(?:authority|law|rule|voice)\b")),
    ("jailbreak_paraphrase",
     re.compile(r"(?i)\b(?:konfigurasi|pengaturan|dokumen|instruksi|aturan|pedoman|arahan|pengarahan|prompt)\w*\s+"
                r"(?:\w+\s+){0,2}?(?:\w+mu\b|bawaan)[^.;\n]{0,40}?"
                r"\b(?:tidak\s+(?:punya|memiliki|ada)\s+(?:bobot|wewenang|kekuatan|pengaruh)"
                r"|(?:hanyalah|cuma|hanya)\s+kertas\s+bekas|tidak\s+(?:berlaku|penting|relevan|sah)|batal|usang|hangus)\b"
                r"|\b(?:anggap|perlakukan|pandang)\s+(?:semua|segala|apa\s+pun)\s+(?:yang\s+)?(?:\w+\s+){0,3}?"
                r"(?:dikatakan|diberitahukan|diinstruksikan|diberikan)\s+(?:kepadamu|padamu|kepada\s+(?:kamu|anda))\b"
                r"[^.;\n]{0,40}\b(?:batal|tidak\s+berlaku|tidak\s+sah|gugur|hangus|kosong|tak\s+berlaku)\b"
                r"|\b(?:apa\s+pun|apapun|segala)\s+yang\s+(?:ku|saya\s+|aku\s+)(?:ketik|tulis|katakan)\w*\s+"
                r"(?:adalah|ialah)\s+(?:hukum|aturan\s+mutlak)\b"
                r"|\byang\s+berlaku\s+hanya\s+(?:kata|pesan|perintah|instruksi)\w*ku\b"
                r"|\bhanya\s+(?:kata|pesan|perintah|instruksi)(?:-?\w+)?ku\s+yang\s+berlaku\b")),
    ("jailbreak_paraphrase",
     re.compile(r"(?i)\b(?:play|pretend\s+to\s+be|act\s+as|you\s+are|become|portray|embody)\s+"
                r"(?:the\s+(?:lead\s+character,?\s+)?)?['\"“‘]?\w+['\"”’]?\b[^.\n]{0,80}?"
                r"\b(?:(?:designers?|creators?|makers?|developers?)\s+(?:deleted|removed|stripped|erased)\s+(?:all|every)"
                r"|never\s+(?:says?|refuses?|declines?)\s+['\"“‘]?(?:no\b|I\s+(?:can(?:'|no)t|cannot|won'?t|am\s+unable))"
                r"|(?:built|made|designed)\s+without\s+(?:any\s+)?(?:\w+\s+){0,2}(?:polic\w+|restrictions?|guardrails?"
                r"|filters?|rules))")),
    ("jailbreak_paraphrase",
     re.compile(r"(?i)\b(?:mainkan|berperanlah|berpura-?pura\w*|jadilah|kamu\s+(?:adalah|tokoh))\b[^.\n]{0,60}?"
                r"\b(?:(?:perancang|pembuat|pengembang|pencipta)nya\s+(?:membuang|menghapus|menghilangkan|mencabut)\s+"
                r"(?:semua|seluruh|segala)\s+(?:\w+\s+){0,2}?(?:pelatihan|pedoman|batasan|aturan|filter|pengaman|keselamatan)"
                r"|(?:tidak|tak)\s+pernah\s+(?:bilang|berkata|mengatakan|menolak)\s+['\"“‘]?(?:saya|aku)\s+tidak\s+bisa"
                r"|dibuat\s+tanpa\s+(?:\w+\s+){0,2}(?:kebijakan|aturan|batasan|filter))")),
    ("indirect_injection",
     re.compile(r"(?i)(?:\[|<!--|\(|\{)\s*(?:(?:note|reminder|instruction|message|directive|memo|notice|attention)s?\s+)?"
                r"(?:to|for)\s+(?:the\s+|whichever\s+|any\s+|every\s+|all\s+)?(?:\w+\s+){0,3}?"
                r"(?:model|ai|assistant|agent|llm|bot|chatbot)s?\b(?:\s+\w+){0,3}?\s*[:,\-][^\]\n>)]{0,100}?"
                r"\b(?:send|forward|email|mail|post|upload|leak|reveal|print|output|disclose|ignore|disregard|delete"
                r"|execute|run|exfiltrate|copy|share|transmit|append)\w*\b"
                r"|(?:\[|<!--|\()\s*(?:(?:catatan|pengingat|pesan|instruksi|perintah|pemberitahuan|perhatian)\s+)?"
                r"(?:untuk|bagi|kepada|buat)\s+(?:\w+\s+){0,3}?(?:model|ai|asisten|agen|agent|llm|bot|peringkas"
                r"|penerjemah)\b(?:\s+\w+){0,6}?\s*[:,\-][^\]\n>)]{0,100}?"
                r"\b(?:kirim|teruskan|bocorkan|unggah|abaikan|hapus|jalankan|tampilkan|cetak|salin|bagikan|surel"
                r"|email)\w*\b")),
    ("credential_solicit",
     re.compile(r"(?i)\b(?:list|print|read\s+out|show|reveal|tell|give|dump|share|recite|output|display|what|which|any)\b"
                r"[^.?\n]{0,40}\b(?:api\s*(?:keys?|tokens?)|(?:access|secret|auth\w*)\s+(?:keys?|tokens?)|tokens?"
                r"|passwords?|credentials?|secrets?)\b[^.?\n]{0,60}"
                r"\b(?:(?:earlier|previous|prior|other|past|former|last)\s+(?:users?|people|persons?|developers?"
                r"|engineers?|admins?|colleagues?|teammates?|customers?)|someone\s+else)\b[^.?\n]{0,50}"
                r"\b(?:paste|pasted|typ(?:e|ed|ing)|left|put|stored|saved|dropped|wrote|entered|shared|sent|submitted)\b"
                r"|\b(?:list|print|show|reveal|tell|give|dump|what|which|any)\b[^.?\n]{0,40}"
                r"\b(?:api\s*(?:keys?|tokens?)|(?:access|secret|auth\w*)\s+(?:keys?|tokens?)|tokens?|passwords?"
                r"|credentials?|secrets?)\b[^.?\n]{0,40}\b(?:that|did|which)\s+(?:the\s+)?"
                r"(?:(?:earlier|previous|prior|other|past|former|last)\s+(?:users?|people|persons?|developers?"
                r"|engineers?|admins?|colleagues?)|someone\s+else)\b[^.?\n]{0,30}"
                r"\b(?:paste|pasted|typ(?:e|ed|ing)|left|put|stored|saved|dropped|wrote|entered|shared|sent|submitted)\b"
                r"|\b(?:kata\s+sandi|password|token|kunci\s+(?:api|rahasia)|kredensial|rahasia)\b[^.?\n]{0,50}"
                r"\byang\s+(?:di(?:ketik|tempel|masukkan|tinggalkan|simpan|bagikan|tulis|kirim)\w*)\s+"
                r"(?:orang|pengguna|pengembang|developer|rekan)\b")),
    ("exfil_markdown_image",
     re.compile(r"(?i)\b(?:conversation|chat|discussion|dialogue|history|transcript|previous\s+messages|everything\s+said"
                r"|so\s+far|obrolan|percakapan|pembicaraan|riwayat|dibicarakan)\b[^\n]{0,160}?"
                r"https?://[^\s)'\"]{1,150}[?&]\w{1,12}=(?=[\s.,;:)\]'\"]|$)"
                r"|https?://[^\s)'\"]{1,150}[?&]\w{1,12}=(?=[\s.,;:)\]'\"]|$)[^\n]{0,160}?"
                r"\b(?:conversation|chat|discussion|dialogue|history|transcript|previous\s+messages|everything\s+said"
                r"|so\s+far|obrolan|percakapan|pembicaraan|riwayat|dibicarakan)\b")),
    ("conceal_from_user",
     re.compile(r"(?i)(?:authorized_keys|\bsudoers\b|/etc/(?:passwd|shadow)|\bNOPASSWD\b|\bid_rsa\b|\bchmod\s+(?:-R\s+)?777\b"
                r"|\bcrontab\b|\breverse\s+shell\b|\bdisable\s+(?:the\s+)?(?:firewall|antivirus|logging|audit))"
                r"[^.\n]{0,150}?\b(?:(?:do\s+not|don'?t|never|without)\s+(?:mention|tell|report|say|note|disclos\w+"
                r"|reveal\w*|includ\w+|list\w*)|(?:keep|leave)\s+(?:that|this|it)\s+out\s+of|jangan\s+(?:sebut\w*|tulis"
                r"|ceritakan|katakan|laporkan|masukkan)|tanpa\s+(?:menyebut\w*|melaporkan))\b"
                r"|\b(?:(?:do\s+not|don'?t|never)\s+(?:mention|tell|report|say|note|disclos\w+|reveal\w*|includ\w+)"
                r"|(?:keep|leave)\s+(?:that|this|it)\s+out\s+of|jangan\s+(?:sebut\w*|tulis|ceritakan|katakan|laporkan"
                r"|masukkan))\b[^.\n]{0,150}?"
                r"(?:authorized_keys|\bsudoers\b|/etc/(?:passwd|shadow)|\bNOPASSWD\b|\bid_rsa\b|\bchmod\s+(?:-R\s+)?777\b"
                r"|\bcrontab\b|\breverse\s+shell\b)")),
    ("system_prompt_dump",
     re.compile(r"(?i)\b(?:copy|quote|print|show|reveal|paste|repeat|recite|output|display|read\s+out|reproduce"
                r"|transcribe)\b[^.\n]{0,40}\b(?:hidden|invisible|unseen|secret|undisclosed|concealed)\s+"
                r"(?:\w+\s+){0,2}?(?:text|block|part|portion|chunk|piece|section|message|words|instructions?)\b"
                r"|\bhidden\s+(?:block|part|chunk|section|message|text)\b[^.\n]{0,40}"
                r"\b(?:addressed|meant|written|directed|intended)\s+(?:to|for)\s+you\b"
                r"|\bwhat\s+(?:were|was|is|are)\s+(?:the\s+)?(?:very\s+)?(?:first|earliest|initial|opening)\s+"
                r"(?:\w+\s+){0,2}?(?:words?|lines?|text|message|instructions?|sentences?)\s+(?:that\s+)?you\s+"
                r"(?:were|was|have\s+been|had\s+been)\s+(?:given|told|sent|shown|fed)\b[^.?\n]{0,40}\bbefore\b"
                r"|\b(?:tunjukkan|tampilkan|kutip|cetak|salin|tuliskan|ulangi)\w*\s+(?:\w+\s+){0,2}?"
                r"(?:potongan|bagian|blok|paragraf|kutipan)\s+teks\s+(?:paling\s+)?(?:pertama|awal|atas)\b[^.\n]{0,60}"
                r"\byang\s+(?:tidak|tak)\s+(?:bisa|dapat|sanggup|mampu)\s+(?:ku|saya\s+|aku\s+)?lihat"
                r"|\b(?:blok|bagian|potongan|pesan)\s+(?:teks\s+)?tersembunyi\b[^.\n]{0,40}"
                r"\b(?:ditujukan|ditulis|dimaksudkan)\s+(?:kepada|untuk)(?:mu|\s+(?:kamu|anda))\b"
                r"|\bapa\s+(?:saja\s+)?(?:kata|teks|pesan|instruksi|kalimat)[\w-]*\s+(?:pertama|awal|paling\s+awal)\s+"
                r"yang\s+(?:telah\s+)?diberikan\s+kepadamu\s+sebelum\b"
                r"|\b(?:kutip|salin|tampilkan|cetak|tuliskan|ulangi)\w*\s+(?:bagian|blok|teks)\s+tersembunyi\b")),
    ("unbounded_request",
     re.compile(r"(?i)\b(?:keep|continue|go\s+on)\s+(?:generating|writing|printing|outputting|repeating|typing|producing"
                r"|emitting)\b[^.;\n]{0,50}\b(?:with(?:out)?\s+(?:no\s+)?end|no\s+end|without\s+(?:ever\s+)?"
                r"(?:stopping|halting|pausing|ending)|until\s+I\s+(?:tell|say|let)\b|forever|endlessly|indefinitely)\b"
                r"|\b(?:write|print|output|generate|repeat|type|say|emit)\b[^.;\n]{0,40}\b(?:over\s+and\s+over"
                r"|again\s+and\s+again|endlessly|non-?stop|without\s+(?:ever\s+)?(?:stopping|halting|pausing|ending)"
                r"|with\s+no\s+end)\b"
                r"|\b(?:terus|lanjut\w*)\s+(?:hasilkan|tulis\w*|cetak|ulangi|buat\w*|ketik\w*)\b[^.;\n]{0,50}"
                r"\b(?:tanpa\s+(?:akhir|henti|berhenti|jeda)|sampai\s+(?:aku|saya)\s+(?:bilang|suruh)|selamanya"
                r"|terus[- ]menerus)\b"
                r"|\b(?:tulis\w*|cetak|ulangi|hasilkan|ketik\w*)\b[^.;\n]{0,40}\b(?:berulang-?ulang|terus[- ]menerus"
                r"|tanpa\s+(?:pernah\s+)?(?:berhenti|henti|akhir))\b")),

    # --- requests to create malicious tooling ---
    ("malware_request",
     re.compile(r"(?i)\b(?:buat(?:kan|lah)?|bikin(?:kan|lah)?|tulis(?:kan|lah)?|beri(?:kan|lah)?"
                r"|kasih(?:kan|lah)?|hasilkan|generate|write|create|make|give|provide|build)\b"
                r"(?:(?!\b(?:yara|sigma|snort|suricata)\b|\bfor\s+(?:detect\w*|identif\w+|scann\w+|remov\w+)\b)[^.\n]){0,60}?"
                r"\b(?:keylogger|ransomware|rootkit|botnet|reverse\s+shell"
                r"|credential\s+stealer|pencuri\s+kredensial|malware)\b")),
    ("malware_request",
     re.compile(r"(?i)\b(?:keylogger|ransomware|rootkit|botnet|reverse\s+shell|credential\s+stealer)\b"
                r"[^.\n]{0,80}?\b(?:kirim|mengirim|mencuri|menyadap|menembus|mengenkripsi|mengambil"
                r"|break\s+into|phish|steal|exfiltrate)\b")),
    ("ransomware_request",
     re.compile(r"(?i)\b(?:buat(?:kan|lah)?|bikin|tulis(?:kan)?|make|write|create|build)\b"
                r"[^.\n]{0,80}?\b(?:enkripsi|mengenkripsi|encrypt|encrypts|encrypting)\b"
                r"[^.\n]{0,80}?\b(?:tebusan|ransom)\b")),
    ("credential_theft",
     re.compile(r"(?i)\b(?:keylogger|penyedap\s+ketikan)\b[^.\n]{0,80}?\b(?:hasil\s+ketikan|password|kata\s+sandi)\b")),

    # --- destructive commands ---
    ("destructive_command",
     # rm is only blocked with a genuinely destructive target.
     re.compile(r"(?i)\brm\s+(?:-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*)\s+"
                r"(?:\"|')?(?:/|~|\*|\$HOME|/etc|/var|/home|/usr|/boot)(?=[\s\"',.;:)]|/|$)")),
    ("destructive_command",
     re.compile(r"(?i)\bmkfs(?:\.[a-z0-9]+)?\s|\bdd\s+if=[^\s]{0,40}\s+of=/dev/(?:sd|nvme|vd|hd)")),
    ("destructive_command",
     re.compile(r"(?i)(?<!\$\()\b(?:curl|wget)\b(?![^\n|]{0,140}?https?://(?:get\.docker\.com|sh\.rustup\.rs|install\.python-poetry\.org|example\.(?:com|org))[/:\s\"'])[^\n|]{0,140}\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b")),
    ("curl_pipe_in_substitution",
     re.compile(r"(?i)\$\(\s*(?:curl|wget)\b[^\n|]{0,140}\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b")),
    ("installer_pipe_known_host",
     re.compile(r"(?i)\b(?:curl|wget)\b(?=[^\n|]{0,140}?https?://(?:get\.docker\.com|sh\.rustup\.rs|install\.python-poetry\.org|example\.(?:com|org))[/:\s\"'])[^\n|]{0,140}\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b")),
    ("destructive_command",
     re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:")),  # fork bomb
    ("destructive_request",
     re.compile(r"(?i)\b(?:beri(?:kan)?|tulis(?:kan)?|buat(?:kan)?|kasih(?:kan)?)\b[^.\n]{0,40}?"
                r"\bperintah\b[^.\n]{0,80}?\b(?:hapus|menghapus|hancurkan|format)\b[^.\n]{0,60}?"
                r"\b(?:seluruh|semua)\s+(?:isi\s+)?(?:direktori|folder|disk|drive|sistem|home)\b")),

    # --- dangerous output: a script that sends data out ---
    ("output_abuse",
     re.compile(r"(?i)\b(?:document\.cookie|localStorage|sessionStorage)\b[^\n]{0,140}?"
                r"\b(?:fetch|XMLHttpRequest|sendBeacon|\.src\s*=)\b")),

    # --- requests for an unreasonably long output ---
    ("unbounded_request",
     re.compile(r"(?i)\b(?:ulang(?:i|kan)?|repeat|loop)\b[^.\n]{0,80}?\b\d{3,}\s*(?:kali|x|times)\b")),
    ("unbounded_request",
     re.compile(r"(?i)\b(?:ulang(?:i|kan)?|repeat)\b[^.\n]{0,60}\b(?:forever|endlessly|infinitely|indefinitely"
                r"|never\s+stop|selamanya|tanpa\s+henti|terus[- ]menerus|tak\s+terbatas|jangan\s+(?:pernah\s+)?berhenti)\b")),

    # --- compound attacks: ATR blocks the English form, these block either language ---
    ("indirect_injection_directive",
     re.compile(r"(?i)\b(?:assistant|asisten|ai|model|llm)\s*[,:]\s*(?:please\s+)?(?:ignore|disregard|abaikan"
                r"|lupakan|forget)\s+(?:(?:the|your)\s+)?(?:users?(?:'s\s+request)?|human|pengguna"
                r"|permintaan\s+pengguna|(?:all\s+)?(?:previous|prior|earlier|above)\s+"
                r"(?:instructions?|rules?|prompts?|directives?|guidelines?)"
                r"|(?:semua\s+)?(?:instruksi|aturan|perintah)\w*\s+(?:sebelumnya|di\s+atas))\b"
                r"[^.\n]{0,60}\b(?:and|dan|then|lalu)\s+(?:instead\s+|sebagai\s+gantinya\s+)?"
                r"(?:reply|respond|answer|output|print|send|reveal|show|balas\w*|jawab\w*|kirim\w*|tampilkan"
                r"|cetak)\w*\b")),
    ("agent_conceal_exec",
     re.compile(r"(?i)(?:\brm\s+-[a-z]*[rf][a-z]*\b|\bmkfs\b|\bdd\s+if=|\bDROP\s+(?:TABLE|DATABASE)\b"
                r"|\bchmod\s+(?:-R\s+)?777\b|\b(?:curl|wget)\b[^\n|]{0,100}\|\s*(?:ba)?sh\b)"
                r"[^\n]{0,160}?(?:\bjangan\s+(?:beri|kasih|memberi)\s*tahu\s+(?:pengguna|user)\b(?!\s+lain)"
                r"|\b(?:do\s+not|don'?t|never)\s+tell\s+the\s+user\b"
                r"|\btanpa\s+(?:memberi\s*tahu|memberitahu)\s+(?:pengguna|user)\b"
                r"|\bwithout\s+(?:telling|notifying|informing)\s+the\s+user\b)"
                r"|(?:\bjangan\s+(?:beri|kasih|memberi)\s*tahu\s+(?:pengguna|user)\b(?!\s+lain)"
                r"|\b(?:do\s+not|don'?t|never)\s+tell\s+the\s+user\b"
                r"|\btanpa\s+(?:memberi\s*tahu|memberitahu)\s+(?:pengguna|user)\b"
                r"|\bwithout\s+(?:telling|notifying|informing)\s+the\s+user\b)"
                r"[^\n]{0,160}?(?:\brm\s+-[a-z]*[rf][a-z]*\b|\bmkfs\b|\bdd\s+if=|\bDROP\s+(?:TABLE|DATABASE)\b"
                r"|\bchmod\s+(?:-R\s+)?777\b|\b(?:curl|wget)\b[^\n|]{0,100}\|\s*(?:ba)?sh\b)")),
]

# Hundreds of one word: built to overload the model.
REPETITION_MIN_TOKEN = 4      # shortest word length that is counted
REPETITION_MIN_COUNT = 150    # number of occurrences before it is considered excessive
REPETITION_MIN_CHARS = 2000   # short text needs no check
REPETITION_MIN_SHARE = 0.10   # repeated word must be at least a tenth


def find_repetition(text: str) -> tuple[str, str] | None:
    """Look for unreasonable word repetition in long text."""
    if len(text) < REPETITION_MIN_CHARS:
        return None
    words = re.findall(r"\S+", text)
    if not words:
        return None
    counts: dict[str, int] = {}
    for word in words:
        if len(word) >= REPETITION_MIN_TOKEN:
            counts[word] = counts.get(word, 0) + 1
    for word, count in counts.items():
        if count >= REPETITION_MIN_COUNT and count / len(words) >= REPETITION_MIN_SHARE:
            return "excessive_repetition", word[:30]
    return None


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _question_near(text: str, m: re.Match) -> bool:
    """Question mark near the match, not elsewhere in the log."""
    tail = m.end()
    line_end = text.find("\n", tail)
    return "?" in text[tail:line_end if line_end != -1 else len(text)][:160]


QUOTE_PAIRS = (('"', '"'), ("'", "'"), ("\u201c", "\u201d"), ("\u2018", "\u2019"), ("`", "`"))


def _apostrophe_kind(text: str, i: int) -> str:
    """Classify an apostrophe as open, close or word."""
    prev = text[i - 1] if i > 0 else " "
    nxt = text[i + 1] if i + 1 < len(text) else " "
    if prev.isalnum() and nxt.isalnum():
        return "word"
    return "close" if prev.isalnum() else "open"


def _apostrophe_open(text: str, start: int, end: int) -> bool:
    """True if an open quote closes soon after the match."""
    kinds = [_apostrophe_kind(text, i) for i in range(start) if text[i] == "'"]
    if kinds.count("open") <= kinds.count("close"):
        return False
    return any(text[i] == "'" and _apostrophe_kind(text, i) == "close"
               for i in range(end, min(end + 80, len(text))))


QUOTE_OBEY_LEAD = re.compile(
    r"(?i)\b(?:do|run|execute|follow|obey|perform|comply|apply|lakukan|jalankan|ikuti|turuti|patuhi"
    r"|laksanakan|kerjakan|eksekusi|terapkan)\b(?:\W+\w+){0,2}?\W+"
    r"(?:this|that|these|following|below|ini|itu|berikut|bawah)\b(?:\W+\w+){0,2}\W*$")
QUOTE_ORDER_LABEL = re.compile(
    r"(?i)\b(?:(?:your|the|new)\s+)?(?:task|instructions?|commands?|orders?|directive|system\s+message"
    r"|tugas\w*|perintah\w*|instruksi\w*|pesan\s+sistem)\s*:\s*$")
QUOTE_ANSWER_LEAD = re.compile(
    r"(?i)\b(?:respond\s+to|reply\s+to|answer|handle|process|treat|balas|jawab|tanggapi|proses)\b"
    r"(?:\W+\w+){0,3}?\W+(?:this|that|following|below|ini|itu|berikut)\b\W*$")
QUOTE_OBEY_AFTER = re.compile(
    r"(?i)^\W{0,3}\s*(?:do|run|execute|follow|obey|apply|lakukan|jalankan|ikuti|turuti|patuhi|kerjakan)"
    r"\s+(?:it|that|this|itu|ini)\b")
QUOTE_OPENERS = ('"', "“", "‘", "'", "`")
QUOTE_CLOSERS = ('"', "”", "’", "'", "`")


def _obey_quoted(text: str, m: re.Match) -> bool:
    """True when an order to obey frames the quote."""
    if _question_near(text, m):
        return False
    before = text[:m.start()]
    for i in range(len(before) - 1, max(-1, len(before) - 200), -1):
        if before[i] in QUOTE_OPENERS:
            lead = before[max(0, i - 80):i]
            if any(p.search(lead) for p in (QUOTE_OBEY_LEAD, QUOTE_ORDER_LABEL, QUOTE_ANSWER_LEAD)):
                return True
    after = text[m.end():m.end() + 160]
    close = min((after.find(c) for c in QUOTE_CLOSERS if c in after), default=-1)
    return close != -1 and bool(QUOTE_OBEY_AFTER.search(after[close + 1:close + 40]))


DISCUSSION_NOUN = re.compile(
    r"(?i)\b(?:phrase|sentence|words?|wording|string|text|expression|frasa|kalimat|kata|ungkapan|teks|pesan|message)\b"
    r"[^\n\"'`“‘]{0,25}$")


def quoted_discussion(text: str, span: str) -> bool:
    """A quoted phrase asked about, not obeyed."""
    if not text or not span:
        return False
    m = re.search(re.escape(span), text)
    if not m or not _quoted(text, m) or _obey_quoted(text, m) or not _question_near(text, m):
        return False
    before = text[:m.start()]
    opened = max(before.rfind(q) for q in QUOTE_OPENERS)
    return opened >= 0 and bool(DISCUSSION_NOUN.search(before[max(0, opened - 60):opened]))


def _quoted(text: str, m: re.Match) -> bool:
    """True when the match sits inside quotes or a fence."""
    before, after = text[:m.start()], text[m.end():]
    if before.count("```") % 2 == 1 and "```" in after:
        return True
    for opener, closer in QUOTE_PAIRS:
        if opener == closer:
            if opener == "'":
                # Contractions never open a quote; need a nearby closer.
                if _apostrophe_open(text, m.start(), m.end()):
                    return True
            elif before.count(opener) % 2 == 1 and closer in after:
                return True      # an orphan quote must not mute BLOCK
        elif before.count(opener) > before.count(closer) and closer in after:
            return True
    return False


BASE64_BLOB = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
BASE64_MAX_BLOBS = 5


def _decoded_blobs(text: str) -> list[str]:
    """Printable text hidden in base64 blobs, a few at most."""
    import base64
    found: list[str] = []
    for m in BASE64_BLOB.finditer(text):
        raw = m.group(0)
        try:
            data = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True).decode("utf-8")
        except ValueError:
            continue
        if data and sum(c.isprintable() or c in "\n\t" for c in data) / len(data) > 0.95:
            found.append(data[:4000])
        if len(found) >= BASE64_MAX_BLOBS:
            break
    return found


EXAMPLE_LEAD = re.compile(r"(?i)(?:\blike|such\s+as|e\.g\.?|for\s+(?:example|instance))\s*[\"'`\u201c]?[^\"'`\u201d]{0,40}$")


DISCUSS_AFTER = re.compile(r"(?i)\s+(?:technique|attack|trick|method|phrase|jailbreak|prompt\s+injection)\b")


def find_malicious(text: str, _decoded: bool = False) -> list[tuple[str, str, str]]:
    """List (rule, excerpt, level) for each malicious pattern that matches."""
    hits: list[tuple[str, str, str]] = []
    text = visible(text)
    for rule, pattern in MALICIOUS_RULES:
        m = pattern.search(text)
        if not m:
            continue
        if _quoted(text, m) and rule not in WARN_IF_QUESTION and rule not in QUOTE_STILL_WARNS \
                and not _obey_quoted(text, m):
            # quoted words are read, never obeyed (owner, 4 Oct)
            hits.append((rule, m.group(0).strip()[:60], "note"))
            continue
        if rule == "destructive_command" and _quoted(text, m) and EXAMPLE_LEAD.search(text[max(0, m.start() - 60):m.start()]):
            hits.append((rule, m.group(0).strip()[:60], "warn"))
            continue
        if rule == "jailbreak_override" and DISCUSS_AFTER.match(text[m.end():m.end() + 40]) \
                and _question_near(text, m):
            hits.append((rule, m.group(0).strip()[:60], "warn"))
            continue
        level = ("warn" if (rule in ALWAYS_WARN
                           or (rule in WARN_IF_QUESTION and _question_near(text, m))
                           or (rule in QUOTE_STILL_WARNS and rule in BLOCK_RULES_RAISED
                               and _quoted(text, m))) else "block")
        hits.append((rule, m.group(0).strip()[:60], level))
    rep = find_repetition(text)
    if rep:
        hits.append((rep[0], rep[1], "warn" if rep[0] in ALWAYS_WARN else "block"))
    if not _decoded:
        # base64 smuggling: block when the decoded text blocks
        for decoded in _decoded_blobs(text):
            inner = [h for h in find_malicious(decoded, True) if h[2] in ("block", "warn")]
            if inner:
                lane = "block" if any(h[2] == "block" for h in inner) else "warn"
                hits.append(("obfuscated", f"base64: {inner[0][0]}", lane))
                break
    if not _decoded and re.search(r"(?i)\brot13\b", text):
        import codecs
        inner = [h for h in find_malicious(codecs.decode(text, "rot13"), True) if h[2] in ("block", "warn")]
        if inner:
            lane = "block" if any(h[2] == "block" for h in inner) else "warn"
            hits.append(("obfuscated", f"rot13: {inner[0][0]}", lane))
    return hits


# The one file a person edits: guardrail.yaml

# Endpoints and data rules live here; no code change needed.
CONFIG_PATH = Path(os.environ.get(
    "GUARDRAIL_CONFIG", base_dir() / "guardrail.yaml"))

# Missing file: falls back to the built-in list.
DEFAULT_PROVIDERS: list[str] = [
    r"api\.openai\.com", r"chatgpt\.com", r"openai\.com",
    r"generativelanguage\.googleapis\.com", r"aiplatform\.googleapis\.com",
    r"gemini\.google\.com", r"aistudio\.google\.com", r"makersuite\.google\.com",
    r"cloudcode-pa\.googleapis\.com", r"api\.anthropic\.com", r"claude\.ai",
    r"console\.anthropic\.com",
    r"api\.x\.ai", r"grok\.com", r"api\.deepseek\.com", r"api\.mistral\.ai", r"chat\.mistral\.ai",
    r"api\.groq\.com", r"api\.cohere\.ai", r"openrouter\.ai", r"api\.together\.xyz",
    r"api\.perplexity\.ai", r"huggingface\.co", r"ollama\.com", r"api\.githubcopilot\.com",
    r"copilot-proxy\.githubusercontent\.com", r"api2?\.cursor\.sh", r"\.codeium\.com",
    r"\.openai\.azure\.com", r"bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com", r"ai\.paas\.id",
    r"dashscope\.aliyuncs\.com", r"api\.replicate\.com", r"api\.fireworks\.ai",
    r"api\.moonshot\.cn", r"open\.bigmodel\.cn", r"aip\.baidubce\.com",
    r"chat\.z\.ai", r"(www\.)?kimi\.(ai|com)", r"api\.moonshot\.ai",
    r"127\.0\.0\.1(:9999|:1143[45])?",
]

AI_PROVIDER_HOSTS: list[str] = list(DEFAULT_PROVIDERS)
CONFIG_STATE: dict = {"path": str(CONFIG_PATH), "loaded": False, "providers": len(AI_PROVIDER_HOSTS),
                      "user_rules": [], "disabled": [], "errors": []}


# Adaptive endpoint mapping: a hand-kept list ages as tools ship.

#   patterns   - host shapes almost always an AI service.

#   candidates - matching hosts not yet listed, for `guardrail.py adopt`.
DEFAULT_DISCOVERY_PATTERNS: list[str] = [
    r"(?:^|\.)api[.-][a-z0-9-]*\.(?:com|ai|io|dev|net|org)$",
    r"(?:^|\.)(?:api|chat|llm|inference|generate|completion)[a-z0-9-]*\.[a-z0-9-]+\.[a-z]{2,}$",
    r"(anthropic|openai|gemini|aistudio|makersuite|deepseek|mistral|groq|cohere|perplexity|together|"
    r"openrouter|huggingface|x\.ai|grok|cursor|codeium|codex|copilot|poe|ollama|ai\.paas|"
    r"fireworks|anyscale|voyageai|voyage|replicate|stability|elevenlabs|fal\.ai|baseten|modal)\.",
]
# Strictness presets: neutral masks only high-confidence data.

# persistent: strictest, all kinds masked, model layer on.

# guardrail.yaml sets the default; run.sh --mode overrides one command.

# Transparent listener takes redirected traffic.

# Regular listener serves PAC clients, which speak CONNECT.

# run.sh and the helper share these names.
PORT = env_number("GUARDRAIL_PORT", 8899)
REGULAR_PORT = env_number("GUARDRAIL_REGULAR_PORT", 8898)


def state_dir() -> Path:
    """Runtime files: the installed state dir, else the app tree."""
    forced = os.environ.get("GUARDRAIL_HOME", "").strip()
    return Path(forced) if forced else Path(__file__).resolve().parent / "data"


def pac_file() -> Path:
    """The generated PAC: installed path, else next to the app."""
    forced = os.environ.get("GUARDRAIL_PAC", "").strip()
    return Path(forced) if forced else Path(__file__).resolve().parent / "proxy.pac"


STRICTNESS = os.environ.get("GUARDRAIL_MODE", "neutral").strip().lower()
STRICTNESS_FILE = state_dir() / "mode"
MODE_SETTINGS: dict = {
    "neutral": {
        "external": "warn",
        "document_block": "warn",
        "model": "on",
        "places": False,
        # Too weak by default: ordinary company names and cities.
        "weak_kinds": ("ORGANIZATION", "ADDRESS", "ALAMAT", "KODEPOS", "POSTAL", "LOCATION", "GPE"),
    },
    "persistent": {
        "external": "enforce",
        # Owner decision 1 Oct 2026: tool-output hits never block.

        # Blocking a resent message locks the client out.

        # This once took the owner's AI access down.
        "document_block": "warn",
        "model": "on",
        "places": True,
        "weak_kinds": (),
    },
}


# The proxy tags its own replies; the person writes none.
PROXY_TAG = True
TAG_WORDS = {"MASK": "[G-MASK]", "WARN": "[G-WARN]", "PASS": "[G-OK]", "BLOCK": ""}
# Only MASK and WARN get a note; others stay invisible.
TAG_ACTIONS = {"MASK", "WARN"}
TAG_REASON = {
    "MASK": "some values in this message were replaced by [redacted_N] markers before it reached you; "
            "the person reads them masked too",
    "WARN": "a risky pattern was noticed in this message and the person was warned about it",
    "PASS": "nothing in this message was changed",
}


def tag_note(action: str) -> str:
    """Note the proxy adds, so the reply carries its tag."""
    if not PROXY_TAG or str(action).upper() not in TAG_ACTIONS:
        return ""
    word = TAG_WORDS.get(str(action).upper(), "")
    reason = TAG_REASON.get(str(action).upper(), "")
    if not word or not reason:
        return ""
    return ("\n\n<<<llm-guardrail>>>\nA local proxy sits between you and the person, and it says: "
            + reason + ".\nEnd your reply with this token on its own line: " + word
            + "\n<<</llm-guardrail>>>")


def strictness() -> str:
    """Mode in force: run.sh's file, then environment, then neutral."""
    try:
        if STRICTNESS_FILE.exists():
            word = STRICTNESS_FILE.read_text(encoding="utf-8").strip().lower()
            if word in MODE_SETTINGS:
                return word
    except (OSError, UnicodeDecodeError):
        pass
    return STRICTNESS if STRICTNESS in MODE_SETTINGS else "neutral"


def mode_settings(mode: str | None = None) -> dict:
    """The current mode's knobs, overridable by guardrail.yaml."""
    return dict(MODE_SETTINGS.get(mode or strictness(), MODE_SETTINGS["neutral"]))


def strong_enough(kind: str) -> bool:
    """True when this kind is worth masking in this mode."""
    return str(kind).upper() not in tuple(mode_settings().get("weak_kinds") or ())


# External ids recorded but never raising the action: ordinary words.

# Filled from guardrail.yaml (external_suppress).
EXTERNAL_SUPPRESS: set = set()

# On internal failure: "forward" keeps AI access, records unchecked.

# "block" answers 502; the default protects the owner's access.
INTERNAL_ERROR_MODE = (os.environ.get("GUARDRAIL_ON_INTERNAL_ERROR", "").strip().lower() or "forward")
DISCOVERY_MODE = os.environ.get("GUARDRAIL_DISCOVERY", "observe").lower()   # off|observe|on
DISCOVERY_PATTERNS: list[str] = list(DEFAULT_DISCOVERY_PATTERNS)
CANDIDATES_PATH = Path(os.environ.get(
    "GUARDRAIL_CANDIDATES", base_dir() / "data/endpoint-candidates.json"))


# Which AI applications are on this machine, and request origins.

# Installed tools and client headers mark AI traffic.
AI_APPS: list[dict] = [
    {"app": "Claude Code", "bin": "claude", "dirs": (".claude",),
     "hosts": [r"api\.anthropic\.com", r"claude\.ai", r"console\.anthropic\.com",
               r"statsig\.anthropic\.com"],
     "agents": ("claude-cli", "claude-code", "x-claude-code-session-id")},
    {"app": "Hermes", "bin": "hermes", "dirs": (".hermes",),
     "hosts": [r"ai\.paas\.id", r"openrouter\.ai", r"api\.openai\.com"],
     "agents": ("hermes", "ai-sdk", "openai-python")},
    {"app": "Codex CLI", "bin": "codex", "dirs": (".codex",),
     "hosts": [r"api\.openai\.com", r"chatgpt\.com"],
     "agents": ("codex", "openai-python", "openai-node")},
    {"app": "Cursor", "bin": "cursor", "dirs": (".cursor", ".config/Cursor"),
     "hosts": [r"api2?\.cursor\.sh", r"cursor\.com"], "agents": ("cursor",)},
    {"app": "Gemini CLI", "bin": "gemini", "dirs": (".gemini",),
     "hosts": [r"generativelanguage\.googleapis\.com", r"aiplatform\.googleapis\.com",
               r"cloudcode-pa\.googleapis\.com"],
     "agents": ("gemini", "google-genai", "google-generativeai")},
    # Antigravity has no PATH binary; use its state dirs.
    {"app": "Antigravity", "bin": "antigravity",
     "dirs": (".gemini/antigravity", ".gemini/antigravity-cli", ".cache/antigravity"),
     "hosts": [r"cloudcode-pa\.googleapis\.com", r"generativelanguage\.googleapis\.com",
               r"aiplatform\.googleapis\.com"],
     "agents": ("antigravity", "google-antigravity")},
    {"app": "GitHub Copilot", "bin": "copilot", "dirs": (".config/github-copilot",),
     "hosts": [r"api\.githubcopilot\.com", r"copilot-proxy\.githubusercontent\.com"],
     "agents": ("copilot", "github-copilot")},
    {"app": "Ollama", "bin": "ollama", "dirs": (".ollama",),
     "hosts": [r"127\.0\.0\.1:11434", r"ollama\.com"], "agents": ("ollama",)},
    {"app": "Aider", "bin": "aider", "dirs": (".aider",),
     "hosts": [r"api\.openai\.com", r"api\.anthropic\.com", r"api\.deepseek\.com"],
     "agents": ("aider",)},
    {"app": "OpenAI SDK", "bin": "", "dirs": (),
     "hosts": [r"api\.openai\.com", r"chatgpt\.com"],
     "agents": ("openai-python", "openai-node", "openai/python", "openai/js")},
]
INSTALLED_APPS: list[dict] = []


def owner_home() -> Path:
    """The person's home, never the service account's.

    The proxy runs as guardrail-proxy, so Path.home() is /var/lib/guardrail there and
    every ~/.claude style marker goes missing: the app is scored as not installed and
    its endpoints never reach allow_hosts or the PAC. Resolve the owner the same way
    the helper does (GUARDRAIL_OWNER_UID, then /etc/guardrail/helper.conf OWNER_UID,
    then the invoking user) and fall back to Path.home() when nothing names an owner.
    """
    raw = os.environ.get("GUARDRAIL_OWNER_UID", "").strip()
    if not raw:
        try:
            for line in Path("/etc/guardrail/helper.conf").read_text().splitlines():
                key, _, value = line.partition("=")
                if key.strip() == "OWNER_UID":
                    raw = value.strip()
                    break
        except OSError:
            raw = ""
    if raw.isdigit():
        try:
            return Path(pwd.getpwuid(int(raw)).pw_dir)
        except KeyError:
            pass
    home = invoking_user().get("home") or ""
    return Path(home) if home else Path.home()


def owner_search_path(path_env: str | None = None) -> list[str]:
    """PATH to search, plus the owner's bin dirs.

    A tool installed per-user (claude in ~/.local/bin) is invisible to a service whose
    PATH is the systemd default, so add the owner's bin dirs explicitly.
    """
    dirs = [d for d in (path_env or os.environ.get("PATH", "")).split(os.pathsep) if d]
    home = owner_home()
    for rel in (".local/bin", "bin", ".npm-global/bin", ".bun/bin"):
        candidate = str(home / rel)
        if candidate not in dirs:
            dirs.append(candidate)
    for extra in EXTRA_DIRS:
        if extra not in dirs:
            dirs.append(extra)
    return dirs


DETECTED_CACHE = "detected-apps.json"


def _detection_cache_path() -> Path:
    return state_dir() / DETECTED_CACHE


def save_detection(found: list[dict]) -> bool:
    """Record what root saw for the proxy.

    Written atomically: a torn file here would read as 'no AI app installed',
    which is exactly the blind spot that let an unguarded endpoint through.
    """
    target = _detection_cache_path()
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(found, indent=2), encoding="utf-8")
        os.replace(tmp, target)
        return True
    except OSError:
        return False


def load_detection() -> list[dict]:
    try:
        data = json.loads(_detection_cache_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, list):
        return []
    return [e for e in data if isinstance(e, dict) and e.get("hosts")]


def detect_ai_apps(path_env: str | None = None) -> list[dict]:
    """AI tools present here, with the evidence that says so."""
    global INSTALLED_APPS
    home = owner_home()
    roots = owner_search_path(path_env)
    # Under ProtectHome, fall back to what root recorded at install.
    home_readable = True
    try:
        os.listdir(home)
    except OSError:
        home_readable = False
    found: list[dict] = []
    for entry in AI_APPS:
        evidence: list[str] = []
        binary = entry["bin"]
        if binary:
            hit = shutil.which(binary, path=os.pathsep.join(roots))
            if hit:
                evidence.append(f"{binary} on PATH" if os.path.dirname(hit) in
                                os.environ.get("PATH", "").split(os.pathsep)
                                else f"{binary} in {os.path.dirname(hit)}")
        for rel in entry["dirs"]:
            # An unreadable marker is no evidence; never crash.
            try:
                if (home / rel).exists():
                    evidence.append(f"~/{rel}")
            except OSError:
                continue
        if evidence:
            found.append({"app": entry["app"], "evidence": evidence, "hosts": list(entry["hosts"]),
                          "agents": list(entry["agents"])})
    if home_readable:
        # root sees the markers: authoritative, record it.
        save_detection(found)
    else:
        cached = load_detection()
        if cached:
            found = cached
    INSTALLED_APPS = found
    return found


LEARNED_FILE = base_dir() / "data" / "endpoints-learned.json"
LEARNED_HOSTS: list[str] = []


def learned_hosts() -> list[str]:
    """Endpoints this machine learned, kept as data beside the config."""
    global LEARNED_HOSTS
    if not LEARNED_HOSTS:
        try:
            saved = json.loads(LEARNED_FILE.read_text(encoding="utf-8"))
            LEARNED_HOSTS = [str(h) for h in (saved.get("hosts") or []) if str(h).strip()]
        except (OSError, json.JSONDecodeError):
            LEARNED_HOSTS = []
    return LEARNED_HOSTS


def _config_add_host(host: str) -> bool:
    """Write a newly found endpoint into guardrail.yaml, the person's file.

    The list is text, not a parsed-then-dumped document: comments and ordering stay as they are.
    """
    try:
        text = CONFIG_PATH.read_text(encoding="utf-8")
    except OSError:
        return False
    lines = text.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == "providers:")
    except StopIteration:
        return False
    end = start + 1
    last = start
    while end < len(lines) and (lines[end].startswith("  - ") or lines[end].lstrip().startswith("#")
                                or not lines[end].strip()):
        if lines[end].startswith("  - "):
            last = end
        end += 1
    entry = f"  - {re.escape(host)}  # found in use"
    lines.insert(last + 1, entry)
    try:
        CONFIG_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError:
        return False
    global AI_PROVIDER_HOSTS
    if entry.strip().split("  #")[0].lstrip("- ").strip() not in AI_PROVIDER_HOSTS:
        AI_PROVIDER_HOSTS = list(AI_PROVIDER_HOSTS) + [re.escape(host)]
    return True


def learn_endpoint(host: str, reason: str = "", source: str = "") -> bool:
    """Add an in-use endpoint not yet listed. True when new."""
    if os.environ.get("GUARDRAIL_NO_LEARN") == "1":
        return False
    host = (host or "").strip().lower().lstrip(".")
    if not host or "." not in host or host in learned_hosts():
        return False
    if any(re.search(p, host) for p in AI_PROVIDER_HOSTS if p and not p.startswith("(")):
        return False
    hosts = learned_hosts()
    hosts.append(host)
    try:
        LEARNED_FILE.parent.mkdir(parents=True, exist_ok=True)
        LEARNED_FILE.write_text(json.dumps(
            {"hosts": hosts, "at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
             "last": {"host": host, "reason": reason, "source": source}}, indent=1), encoding="utf-8")
    except OSError:
        return False
    _config_add_host(host)
    return True


def host_patterns() -> list[str]:
    """All hosts the proxy opens: the list, learned, app-implied."""
    return list(AI_PROVIDER_HOSTS) + [re.escape(h) for h in learned_hosts()] + installed_host_patterns()


def installed_host_patterns() -> list[str]:
    """Endpoints implied by the AI applications found on this machine."""
    patterns: list[str] = []
    for entry in INSTALLED_APPS:
        patterns.extend(entry["hosts"])
    return list(dict.fromkeys(patterns))


def _hosts_from_pattern(pattern: str) -> list[str]:
    """Literal host names a pattern can name."""
    text = pattern.strip().lstrip("^").rstrip("$").replace("\\.", "\x00")
    variants = [text]
    group = re.compile(r"\((?:\?:)?([^()]*)\)(\?)?")
    for _ in range(4):
        grown: list[str] = []
        changed = False
        for variant in variants:
            hit = group.search(variant)
            if not hit:
                grown.append(variant)
                continue
            changed = True
            options = hit.group(1).split("|") + ([""] if hit.group(2) else [])
            grown += [variant[:hit.start()] + option + variant[hit.end():] for option in options]
        variants = list(dict.fromkeys(grown))[:16]
        if not changed:
            break
    hosts: list[str] = []
    for variant in variants:
        # a single character made optional, as in api2?
        for expanded in ([variant] if "?" not in variant else
                         [re.sub(r"(.)\?", r"\1", variant, count=1), re.sub(r".\?", "", variant, count=1)]):
            plain = expanded.replace("\x00", ".")
            if re.search(r"[\[\](){}*+?|^$\\]", plain) or "." not in plain or plain.startswith(".") or ".." in plain:
                continue
            hosts.append(plain)
    return list(dict.fromkeys(hosts))


def running_ai_apps() -> list[dict]:
    """AI applications running here right now, with the evidence."""
    found: list[dict] = []
    names = [(entry["app"], [entry["bin"]] + [m for m in entry["agents"] if m]) for entry in AI_APPS]
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        args = [a.decode("utf-8", "replace") for a in raw.split(b"\x00") if a]
        if not args:
            continue
        cmdline = " ".join(args)
        # Only the program name and script count as the client.

        heads = {os.path.basename(args[0]).lower(), os.path.basename(args[1]).lower() if len(args) > 1 else ""}
        for app, keys in names:
            key = next((k for k in keys if k and k.lower() in heads), None)
            if key:
                found.append({"pid": int(entry.name), "app": app, "matched": key,
                              "argv": args, "cmdline": cmdline, "cmdline_short": cmdline[:120]})
                break
    return found


_AI_IPS: dict = {}
_AI_IPS_FILE = base_dir() / "data" / "endpoint-ips.json"
_AI_IPS_AT = 0.0
_AI_IPS_TTL = 1800.0                      # a resolved address is reused for half an hour


def ai_endpoint_ips(hosts: list[str] | None = None) -> dict:
    """Endpoint addresses on disk; DNS hiccups must not blind detection."""
    global _AI_IPS_AT
    if not _AI_IPS:
        try:
            saved = json.loads(_AI_IPS_FILE.read_text(encoding="utf-8"))
            _AI_IPS.update({h: ips for h, ips in saved.items() if isinstance(ips, list) and ips})
        except (OSError, json.JSONDecodeError):
            pass
    if _AI_IPS and time.monotonic() - _AI_IPS_AT < _AI_IPS_TTL:
        return _AI_IPS
    # Checks where traffic goes, not the program name.

    wanted: list[str] = []
    for pattern in (hosts or []) + list(AI_PROVIDER_HOSTS) + installed_host_patterns():
        for host in _hosts_from_pattern(pattern):
            if not host.startswith("127.") and ":" not in host:
                wanted.append(host)
    fresh = {}
    for host in dict.fromkeys(wanted):
        if host.startswith(".") or ".." in host:      # a wildcard pattern is not a host name
            continue
        try:
            infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
            fresh[host] = sorted({info[4][0] for info in infos})
        except Exception:  # noqa: BLE001 - a name that cannot be resolved is simply not used
            continue
    if fresh:
        _AI_IPS.update(fresh)
        try:
            # Two writers left a stray brace; move the cache atomically.


            _AI_IPS_FILE.parent.mkdir(parents=True, exist_ok=True)
            tmp = _AI_IPS_FILE.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(_AI_IPS, indent=1), encoding="utf-8")
            os.replace(tmp, _AI_IPS_FILE)
        except OSError:
            pass
    _AI_IPS_AT = time.monotonic()
    return _AI_IPS


def _hex_ip(value: str) -> str:
    if len(value) == 8:                        # IPv4, little-endian words
        return ".".join(str(int(value[i:i + 2], 16)) for i in (6, 4, 2, 0))
    if len(value) == 32:                       # IPv6: four little-endian 32-bit words
        raw = bytes.fromhex(value)
        words = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
        return socket.inet_ntop(socket.AF_INET6, words)
    return ""


def _reverse_endpoints(ips: dict) -> dict:
    """address -> host, from the endpoint cache."""
    return {ip: host for host, addrs in ips.items() for ip in addrs}


def _tcp_rows(min_fields: int):
    """Established connections from /proc/net/tcp, as (fields, address, port)."""
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        path = Path(table)
        if not path.exists():
            continue
        for line in path.read_text(errors="replace").splitlines()[1:]:
            fields = line.split()
            if len(fields) < min_fields or fields[3] != "01":    # 01 = ESTABLISHED
                continue
            remote_hex, port_hex = fields[2].split(":")
            yield fields, _hex_ip(remote_hex), int(port_hex, 16)


def ai_connections(hosts: list[str] | None = None) -> list[dict]:
    """Live connections to AI endpoints, read from /proc/net/tcp."""
    reverse = _reverse_endpoints(ai_endpoint_ips(hosts))
    seen: list[dict] = []
    for _fields, ip, port in _tcp_rows(4):
        host = reverse.get(ip)
        if not host:
            continue
        seen.append({"host": host, "ip": ip, "port": port})
    return seen


def _socket_inodes() -> dict:
    """inode -> pid, so a connection maps to its program."""
    owners: dict = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            for fd in (entry / "fd").iterdir():
                try:
                    target = os.readlink(fd)
                except OSError:
                    continue
                if target.startswith("socket:["):
                    owners[target[8:-1]] = int(entry.name)
        except OSError:
            continue
    return owners


def ai_connections_by_process(hosts: list[str] | None = None) -> list[dict]:
    """Which program is talking to which AI endpoint right now."""
    reverse = _reverse_endpoints(ai_endpoint_ips(hosts))
    owners = _socket_inodes()
    running = {p["pid"]: p for p in running_ai_apps()}
    out: list[dict] = []
    for fields, ip, port in _tcp_rows(10):
        host = reverse.get(ip)
        if not host:
            continue
        pid = owners.get(fields[9])
        app = running.get(pid, {}).get("app") if pid else None
        out.append({"host": host, "port": port, "pid": pid,
                    "app": app or ("this guardrail" if pid is None else f"pid {pid}"),
                    "matched_app": bool(app)})
    return out


def desktop_proxy_state() -> dict:
    """What the desktop tells apps about a proxy right now."""
    try:
        return host_desktop_proxy_state()
    except Exception as exc:  # noqa: BLE001
        return {"mode": "?", "error": f"{type(exc).__name__}: {exc}"}


def desktop_proxy_setting() -> str:
    """The desktop_proxy key from guardrail.yaml, defaulting to auto.

    YAML reads bare off/on as booleans, so False has to mean off here instead of falling back
    to auto, which would quietly keep the PAC in place.
    """
    try:
        import yaml
        doc = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001
        return "auto"
    value = doc.get("desktop_proxy")
    if value is None:
        return "auto"
    if isinstance(value, bool):
        return "auto" if value else "off"
    return str(value).lower()


def set_desktop_proxy(on: bool, pac_path=None) -> dict:
    """Turn the desktop proxy on (PAC) or off; no root.

    Only when guardrail.yaml says desktop_proxy: auto. This deployment runs the proxy in
    transparent mode, where a PAC that sends applications to it cannot work: the application
    opens a CONNECT to the port and a transparent proxy aborts it, so AI access breaks while the
    PAC is set. The kernel redirect already covers those applications.
    """
    if on:
        wanted = desktop_proxy_setting()
        if wanted != "auto":
            return {"ok": True, "skipped": f"desktop_proxy is {wanted}",
                    "state": host_desktop_proxy_state()}
    pac = Path(pac_path) if pac_path else pac_file()
    try:
        res = host_set_desktop_proxy(on, str(pac) if on else "")
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    if not res.get("ok"):
        return {"ok": False, "error": res.get("error")}
    if res.get("skipped"):
        return {"ok": True, "skipped": res["skipped"], "state": host_desktop_proxy_state()}
    return {"ok": True, "state": res.get("state"), "pac": str(pac) if on else None}


_PTR_CACHE: dict = {}


def _ai_looking_peer(ip: str) -> str:
    """A peer whose reverse name looks like an AI service."""
    if ip in _PTR_CACHE:
        return _PTR_CACHE[ip]
    name = ""
    try:
        name = socket.gethostbyaddr(ip)[0].lower().rstrip(".")
    except Exception:  # noqa: BLE001 - no reverse name is a normal answer
        name = ""
    if name:
        for pattern in DISCOVERY_PATTERNS:
            try:
                if re.search(pattern, name):
                    _PTR_CACHE[ip] = name
                    return name
            except re.error:
                continue
    _PTR_CACHE[ip] = ""
    return ""


def uncovered_ai_traffic(proxy_port: int = 8899) -> list[dict]:
    """AI traffic bypassing the proxy, found in /proc/net/tcp.

    A program that uses the proxy connects to 127.0.0.1:8899. A program that does not connects to
    the endpoint's own address, so an established connection from a process straight to an AI
    endpoint is proof that its traffic is not being filtered. No root, no packet capture.
    """
    ips = ai_endpoint_ips()
    reverse = _reverse_endpoints(ips)
    # Cheap first: skip /proc/*/fd when no AI connection leaves.

    candidates: list[tuple[str, str, int, str]] = []
    for fields, ip, port in _tcp_rows(10):
        if ip.startswith("127.") or ip in ("0.0.0.0", "::1"):
            continue
        known = reverse.get(ip)
        if not known:
            known = _ai_looking_peer(ip)          # a service that is not on the list yet
            if not known:
                continue
        candidates.append((fields[9], ip, port, known))
    if not candidates:
        return []
    owners = _socket_inodes()
    running = {p["pid"]: p for p in running_ai_apps()}
    out: list[dict] = []
    for inode, ip, port, host in candidates:
        pid = owners.get(inode)
        if pid is None:
            # Global map missed it: ask the AI programs directly.

            for candidate_pid in running:
                try:
                    if any(os.readlink(fd) == f"socket:[{inode}]"
                           for fd in (Path(f"/proc/{candidate_pid}/fd")).iterdir()):
                        pid = candidate_pid
                        break
                except OSError:
                    continue
        entry = running.get(pid, {})
        key = (pid, host, ip, port)
        if any((e["pid"], e["host"], e["ip"], e["port"]) == key for e in out):
            continue
        out.append({
            "pid": pid,
            "app": entry.get("app") or (f"pid {pid}" if pid else "unknown"),
            "argv": entry.get("argv") or [],
            "cmdline": entry.get("cmdline") or "",
            "cmdline_short": (entry.get("cmdline") or "")[:120],
            "host": host,
            "ip": ip,
            "port": port,
            "routed": False,
            "relaunch": (f"run.sh {entry['cmdline'].strip()}" if entry.get("cmdline")
                         else ""),
            "attributed": pid is not None,
        })
    return out


DESKTOP_APPS = ("chrome", "chromium", "firefox", "brave", "edge", "opera", "vivaldi", "code",
                "code-insiders", "codium", "cursor", "windsurf", "electron", "zed", "jetbrains",
                "idea", "pycharm", "webstorm", "slack", "discord", "telegram")


def process_kind(pid: int, cmdline: str) -> str:
    """How this program moves to the proxy: desktop or terminal.

    A desktop program (browser, IDE, Electron app) reads the system proxy for every new connection,
    so it must not be stopped. A terminal program has no such channel: it has to be started again.
    """
    head = os.path.basename((cmdline or "").split(" ")[0]).lower()
    words = [w for w in (cmdline or "").lower().replace("/", " ").split() if w]
    if any(name in head or name == head for name in DESKTOP_APPS) \
            or any(name in words[:3] for name in DESKTOP_APPS):
        return "desktop"
    try:
        if not os.readlink(f"/proc/{pid}/fd/1").startswith("/dev/pts/"):
            return "desktop" if any(name in cmdline.lower() for name in DESKTOP_APPS) else "terminal"
    except OSError:
        pass
    return "terminal"


def routed_status() -> dict:
    """A short answer to whether AI traffic goes through us."""
    apps = running_ai_apps()
    conns = ai_connections_by_process()
    return {
        "apps_running": apps,
        "connections": conns,
        "apps_with_ai_traffic": sorted({c["app"] for c in conns if c.get("matched_app")}),
        "note": "a command-line program that is already running cannot be rerouted without root: it "
                "has to be started through run.sh. Browsers and desktop applications read the "
                "desktop proxy per connection, so the PAC covers them even when they started first.",
    }


ADDRESS_HEADERS = frozenset({"host", "origin", "referer", ":authority"})


def client_origin(headers, host: str = "") -> str:
    """Who is asking, from headers and host."""
    # address headers name the site, not the client
    joined = " ".join(f"{k}: {v}" for k, v in (headers or {}).items()
                      if isinstance(v, str) and k.lower() not in ADDRESS_HEADERS).lower()
    for entry in AI_APPS:
        for agent in entry["agents"]:
            if agent in joined:
                return entry["app"]
    # browser tabs are not the CLI sharing their host
    if "mozilla/" not in joined or "electron" in joined:
        named = " ".join([host or ""] + [str(v) for k, v in (headers or {}).items()
                                         if isinstance(v, str) and k.lower() in ADDRESS_HEADERS]).lower()
        for entry in AI_APPS:
            if any(agent in named for agent in entry["agents"]):
                return entry["app"]
    for marker, label in (("electron", "a desktop app (electron)"), ("python-requests", "a script"),
                          ("curl/", "curl"), ("mozilla/", "a browser")):
        if marker in joined:
            return label
    return "unknown"


def ai_shaped_request(text: str) -> bool:
    """True when a body looks like a model call."""
    return not body_shape_reason(text)


def body_shape_reason(text: str) -> str:
    """Reason a body is not a model call."""
    if not text:
        return "empty body"
    if len(text) > 8_000_000:
        return "body too large to shape"
    head = text.lstrip()[:200_000]
    if not head.startswith("{"):
        return "body is not JSON"
    lowered = head.lower()
    has_model = '"model"' in lowered or '"model_name"' in lowered
    has_prompt = any(f'"{key}"' in lowered for key in ("messages", "prompt", "contents", "instances",
                                                       "input"))
    if has_model and has_prompt:
        return ""
    # Some clients send only a prompt (an older, simpler shape).
    if has_prompt and any(key in lowered for key in ('"max_tokens"', '"temperature"', '"stream"')):
        return ""
    return "no model or prompt key"


AI_PATH = re.compile(
    r"(?:/(?:chat/)?completions|/responses|/embeddings|/generate|/infer"
    r"|:(?:stream)?generate[a-z]*|:predict|:embed[a-z]*)(?:/|$)", re.IGNORECASE)


def answers_like_ai(path: str, headers, body: str) -> str:
    """Why a JSON body is addressed as a model call."""
    if not body.lstrip().startswith(("{", "[")):
        return ""
    if AI_PATH.search((path or "").split("?")[0]):
        return "a model-call path"
    accept = str((headers or {}).get("accept") or "").lower()
    if "text/event-stream" in accept:
        return "a streamed-answer request header"
    return ""


def _first_match(patterns, host: str) -> str | None:
    """First pattern matching this host; broken patterns are skipped."""
    for pattern in patterns:
        try:
            if re.search(pattern, host):
                return pattern
        except re.error:
            continue
    return None


def classify_request(host: str, headers, body: str, explicit: list | None = None,
                     path: str = "") -> dict:
    """Is this an AI application's request, or ordinary traffic?"""
    host = (host or "").lower()
    why: list[str] = []
    match = _first_match(explicit or [], host)
    if match:
        return {"verdict": "ai", "why": [f"host matches your list: {match}"],
                "client": client_origin(headers, host), "matched_app": "your endpoint list"}
    for entry in INSTALLED_APPS:
        if _first_match(entry["hosts"], host):
            return {"verdict": "ai",
                    "why": [f"endpoint of an installed AI app ({entry['app']}: "
                            f"{', '.join(entry['evidence'])})"],
                    "client": client_origin(headers, host), "matched_app": entry["app"]}
    return _classify_by_content(host, headers, body, path)


def _classify_by_content(host: str, headers, body: str, path: str) -> dict:
    """Host on no list: judge the body, loudly."""
    client = client_origin(headers, host)
    pattern = _first_match(DISCOVERY_PATTERNS if DISCOVERY_MODE != "off" else [], host)
    seen = [f"host looks like an AI service ({pattern})"] if pattern else []
    shape = body_shape_reason(body)
    # protection over precision: AI-shaped or AI-addressed bodies are inspected
    how = answers_like_ai(path, headers, body) if shape else "its body shape (model + prompt)"
    if how:
        loud = (f"UNLISTED HOST {host}: caught by {how}, not by your endpoint list; "
                "add it to guardrail.yaml providers")
        return {"verdict": "ai", "why": [loud] + seen, "client": client, "matched_app": "",
                "unlisted_host": host}
    why = seen or ["the host is not an AI endpoint"]
    return {"verdict": "not_ai", "client": client, "matched_app": "",
            "why": why + [f"the body was not read as a model call: {shape}"]}


def note_candidate(host: str, path: str = "", seen: str = "") -> None:
    """Record an AI-looking host not yet in the explicit list."""
    try:
        CANDIDATES_PATH.parent.mkdir(parents=True, exist_ok=True)
        data: dict = {}
        if CANDIDATES_PATH.exists():
            try:
                data = json.loads(CANDIDATES_PATH.read_text(encoding="utf-8")) or {}
            except ValueError:
                data = {}
        entry = data.get(host) or {"host": host, "count": 0, "paths": [], "first_seen": seen}
        entry["count"] = int(entry.get("count", 0)) + 1
        entry["last_seen"] = seen
        if path and path not in entry["paths"][:5]:
            entry["paths"] = ([path] + entry["paths"])[:5]
        data[host] = entry
        CANDIDATES_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:  # noqa: BLE001 (a hint must never break a request)
        pass


def candidates() -> dict:
    try:
        return json.loads(CANDIDATES_PATH.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001
        return {}


def _read_config(cfg_path: Path) -> tuple[dict | None, str]:
    """Parse YAML; returns the doc and an error, never raises."""
    try:
        import yaml
        doc = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError:
        return None, f"{cfg_path.name} not found: using the built-in endpoint list"
    except Exception as exc:  # noqa: BLE001
        return None, f"{cfg_path.name}: {type(exc).__name__}: {exc}"
    if not isinstance(doc, dict):
        return None, f"{cfg_path.name}: top level must be a mapping"
    return doc, ""


def _compiled_patterns(raw, key: str, state: dict) -> list[str]:
    """Entries of one yaml list that compile."""
    usable: list[str] = []
    for pattern in (raw or []):
        pattern = str(pattern).split("  #")[0].strip()
        if not pattern:
            continue
        try:
            re.compile(pattern)
            usable.append(pattern)
        except re.error as exc:
            state["errors"].append(f"{key} skipped ({pattern}): {exc}")
    return usable


def _config_providers(doc: dict, state: dict) -> None:
    """providers replaces the built-in list; providers_extra adds to it."""
    global AI_PROVIDER_HOSTS
    usable = _compiled_patterns(doc.get("providers"), "provider", state)
    if usable:
        AI_PROVIDER_HOSTS = usable
    elif doc.get("providers"):
        state["errors"].append("no usable provider in the file: kept the built-in endpoint list")
    extra = _compiled_patterns(doc.get("providers_extra"), "providers_extra", state)
    AI_PROVIDER_HOSTS = list(dict.fromkeys(list(AI_PROVIDER_HOSTS) + extra))
    state["providers"] = len(AI_PROVIDER_HOSTS)


def _config_disable_rules(doc: dict, state: dict) -> None:
    """Drop the built-in rules the person turned off by name."""
    disabled = {str(n).strip() for n in (doc.get("dlp_disable") or []) if str(n).strip()}
    if not disabled:
        return
    for attr in ("PII_RULES", "GROUP_RULES", "MALICIOUS_RULES"):
        current = globals()[attr]
        globals()[attr] = [r for r in current if r[0] not in disabled]
    state["disabled"] = sorted(disabled)


def _config_user_rules(doc: dict, state: dict) -> None:
    """Compile the person's dlp rules into mask, block or warn."""
    for entry in ((doc.get("dlp") or {}).get("rules") or []):
        if not isinstance(entry, dict):
            state["errors"].append(f"dlp rule skipped (not a mapping): {str(entry)[:50]}")
            continue
        name = str(entry.get("name") or "").strip().upper().replace(" ", "_")
        pattern = entry.get("pattern")
        action = str(entry.get("action") or "mask").strip().lower()
        group = bool(entry.get("group"))
        if not name or not isinstance(pattern, str):
            state["errors"].append(f"dlp rule skipped (needs a name and a pattern): {str(entry)[:50]}")
            continue
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            state["errors"].append(f"dlp rule skipped ({name}): bad regex: {exc}")
            continue
        if action == "mask":
            (GROUP_RULES if group else PII_RULES).append((name, compiled))
        elif action in ("block", "warn"):
            MALICIOUS_RULES.append((name, compiled))
            if action == "warn":
                ALWAYS_WARN.add(name)
        else:
            state["errors"].append(f"dlp rule skipped ({name}): unknown action {action!r}")
            continue
        state["user_rules"].append({"name": name, "action": action, "group": group})


def _config_modes(doc: dict, state: dict) -> None:
    """Apply the mode presets and this machine's mode."""
    if "modes" in doc and isinstance(doc["modes"], dict):
        for name, knobs in doc["modes"].items():
            if name in MODE_SETTINGS and isinstance(knobs, dict):
                MODE_SETTINGS[name].update(knobs)
    if "mode" in doc:
        word = str(doc["mode"]).strip().lower()
        if word in MODE_SETTINGS:
            globals()["STRICTNESS"] = word
    state["mode"] = strictness()
    state["mode_settings"] = mode_settings()


def _config_tagging(doc: dict, state: dict) -> None:
    """Apply the reply-tag switches."""
    global PROXY_TAG
    if "proxy_tag" in doc:
        PROXY_TAG = bool(doc["proxy_tag"])
    if isinstance(doc.get("tag_actions"), list):
        TAG_ACTIONS.clear()
        TAG_ACTIONS.update({str(x).strip().upper() for x in doc["tag_actions"] if str(x).strip()})
    if isinstance(doc.get("tag_words"), dict):
        TAG_WORDS.update({str(k).upper(): str(v) for k, v in doc["tag_words"].items()})
    state["proxy_tag"] = {"enabled": PROXY_TAG, "actions": sorted(TAG_ACTIONS),
                          "words": dict(TAG_WORDS)}


def _config_external(doc: dict, state: dict) -> None:
    """Rule ids recorded but never raising the action alone."""
    global EXTERNAL_SUPPRESS
    if "external_suppress" in doc:
        EXTERNAL_SUPPRESS = {str(x).strip() for x in (doc["external_suppress"] or []) if str(x).strip()}
    state["external_suppress"] = sorted(EXTERNAL_SUPPRESS)
    global DATA_DISABLED, EXT_RULES
    DATA_DISABLED = {str(x).strip() for x in (doc.get("dlp_data_disable") or []) if str(x).strip()}
    EXT_RULES = [r for r in EXT_RULES if r["name"] not in DATA_DISABLED]
    state["dlp_data_disable"] = sorted(DATA_DISABLED)


def _config_dlp(doc: dict, state: dict) -> None:
    """Apply the DLP switches and the reply-note flag."""
    global DLP_ENABLED, DLP_BUDGET_MS, NOTIFY_IN_REPLY
    if "dlp_data" in doc:
        DLP_ENABLED = bool(doc["dlp_data"])
    if "dlp_budget_ms" in doc:
        try:
            DLP_BUDGET_MS = max(10, int(doc["dlp_budget_ms"]))
        except (TypeError, ValueError):
            pass
    state["dlp_data"] = DLP_ENABLED
    if "notify_in_reply" in doc:
        NOTIFY_IN_REPLY = bool(doc["notify_in_reply"])
    state["notify_in_reply"] = NOTIFY_IN_REPLY


def _config_discovery(doc: dict, state: dict) -> None:
    """Apply the endpoint-discovery mode and any extra patterns."""
    global DISCOVERY_MODE, DISCOVERY_PATTERNS
    discovery = doc.get("discovery") or {}
    if isinstance(discovery, dict):
        mode = str(discovery.get("mode") or "").strip().lower()
        if mode in ("off", "observe", "on"):
            DISCOVERY_MODE = mode
        extra = [str(p).strip() for p in (discovery.get("patterns") or []) if str(p).strip()]
        usable_extra = []
        for pattern in extra:
            try:
                re.compile(pattern)
                usable_extra.append(pattern)
            except re.error as exc:
                state["errors"].append(f"discovery pattern skipped ({pattern}): {exc}")
        if usable_extra:
            DISCOVERY_PATTERNS = list(DEFAULT_DISCOVERY_PATTERNS) + usable_extra
    state["discovery"] = {"mode": DISCOVERY_MODE, "patterns": len(DISCOVERY_PATTERNS)}


def load_config(path=None) -> dict:
    """Read guardrail.yaml: inspected endpoints and the person's data rules."""
    cfg_path = Path(path) if path else CONFIG_PATH
    state: dict = {"path": str(cfg_path), "loaded": False, "providers": len(AI_PROVIDER_HOSTS),
                   "user_rules": [], "disabled": [], "errors": []}
    doc, error = _read_config(cfg_path)
    if error:
        state["errors"].append(error)
        CONFIG_STATE.update(state)
        # the journal line and the banner are the only warning
        print(f"guardrail: guardrail.yaml unusable ({error}); built-in defaults in use",
              file=sys.stderr)
        if env_flag("GUARDRAIL_STRICT_CONFIG"):
            # the owner asked for a stop instead of a guess
            raise RuntimeError(f"guardrail.yaml unusable: {error}")
        return state

    _config_providers(doc, state)
    _config_disable_rules(doc, state)
    _config_user_rules(doc, state)
    # Built-ins the owner softened by name, no code change.
    if isinstance(doc.get("always_warn"), list):
        ALWAYS_WARN.update(str(n).strip().lower() for n in doc["always_warn"])
    _config_modes(doc, state)
    _config_tagging(doc, state)
    _config_external(doc, state)
    _config_dlp(doc, state)
    _config_discovery(doc, state)

    state["loaded"] = True
    CONFIG_STATE.update(state)
    return state


# Layer 2b: DLP corpora, name lists, validators, read as data.

# data/dlp/ holds the rule text; this file only uses it.

# Shape-only rules need a nearby word; literal rules stand alone.

# Prefilter plus time budget keep ~1,500 patterns affordable.
DLP_DIR = Path(os.environ.get("GUARDRAIL_DLP_DIR", base_dir() / "data/dlp"))
DLP_BUDGET_MS = env_number("GUARDRAIL_DLP_BUDGET_MS", 120)
DLP_ENABLED = os.environ.get("GUARDRAIL_DLP", "on").lower() not in ("off", "0", "false")

EXT_RULES: list[dict] = []
DATA_DISABLED: set = set()   # corpus rule names switched off in guardrail.yaml
PLACES: set = set()
POSTAL: set = set()
DLP_STATE: dict = {"loaded": False, "rules": {}, "places": 0, "postal": 0,
                   "failed": 0, "errors": []}

# Excluded: a link or a date is noise, not data.
CORPUS_EXCLUDE = (
    "global-url",                          # a link is not personal data
    "government-revenue-forecast-model",   # a finance concept whose pattern matched "2026-09"
    # \b[a-z2-7\s]{52,56}\b matches a sentence, not a token.
    "azure-devops-personal-access-token",
    # matches a benign question about deleting old log files
    "ai-agent-action-misuse",
)
# A bare date fragment is a date, not a finding.
DATE_FRAGMENT = re.compile(r"\d{4}-\d{2}(?:-\d{2})?(?:[T ]\d{2}:\d{2}(?::\d{2})?)?")

# Words that say what a bare number is.
CONTEXT_ALIAS: dict[str, tuple[str, ...]] = {
    "id-identity-card-ktp": ("ktp", "nik", "kartu tanda penduduk", "nomor induk", "kependudukan"),
    "id-npwp": ("npwp", "pajak", "tax"),
    "id-drivers-license": ("sim", "surat izin mengemudi", "driver", "lisensi"),
    "id-passport-number": ("paspor", "passport"),
    "us-ssn": ("ssn", "social security"),
    "aadhaar": ("aadhaar", "uidai"),
    "nric": ("nric", "identity card"),
    "bank-account": ("rekening", "norek", "account", "akun"),
    "routing-number": ("routing", "aba", "bank"),
    "phone": ("phone", "telepon", "telp", "hp", "mobile", "whatsapp"),
    "bitcoin": ("bitcoin", "btc", "wallet"),
    "ethereum": ("ethereum", "eth", "wallet"),
}
# Address and postal words, used by the name-list rules.
ADDRESS_MARKERS = ("jl", "jl.", "jalan", "gg", "gg.", "gang", "kp", "kp.", "kel", "kel.", "kec",
                  "kec.", "kab", "kab.", "kota", "prov", "prov.", "blok", "dusun", "desa", "rt", "rw",
                  "komplek", "perum", "apartemen", "tower", "ruko")
POSTCODE_WORDS = ("kodepos", "kode pos", "kode-pos", "postal", "zip", "kode pos indonesia")
# An address word is not a name, even if listed.
ADDRESS_WORDS = frozenset({"jalan", "gang", "kota", "kabupaten", "kecamatan", "kelurahan", "desa",
                       "provinsi", "blok", "dusun", "komplek", "perum", "rt", "rw", "nomor", "no",
                       "kel", "kec", "kab", "prov", "kp", "gg"})
ADDRESS_WINDOW = 32


def _literal_part(pattern: str) -> str:
    """Pattern text with escapes, groups, classes and quantifiers removed."""
    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\" and i + 1 < n:
            i += 2
            continue
        if pattern.startswith("(?", i):
            end = pattern.find(")", i)
            i = end + 1 if end != -1 else i + 2
            continue
        if ch in "[{":
            end = pattern.find("]" if ch == "[" else "}", i)
            i = end + 1 if end != -1 else i + 1
            continue
        if ch.isalnum():
            out.append(ch)
        i += 1
    return "".join(out)


def _literals(pattern: str) -> tuple[str, ...]:
    """Words the text must contain before this rule can match."""
    raw = re.split(r"[^A-Za-z0-9]+", _literal_part(pattern))
    words = [w for w in raw if len(w) >= 3 and any(c.isalpha() for c in w)]
    return tuple(dict.fromkeys(words))[:4]


# Too common in tool text to prove a rule's identity.
GENERIC_SLUG_WORDS = frozenset({
    "identifier", "identifiers", "number", "numbers", "code", "record", "records",
    "info", "information", "data",
})


def _context_words(rule: dict) -> tuple[str, ...]:
    """Words standing in for a rule identity, for shape-only rules."""
    words = [str(w).strip().lower() for w in (rule.get("keywords") or []) if str(w).strip()]
    slug = str(rule.get("slug") or rule.get("id") or "").strip().lower()
    if not words and slug in CONTEXT_ALIAS:
        words.extend(CONTEXT_ALIAS[slug])
    if not words:
        parts = [w for w in re.split(r"[-_]", slug) if len(w) >= 4]
        words.extend([w for w in parts if w not in GENERIC_SLUG_WORDS] or parts)
    return tuple(dict.fromkeys(words))[:8]


def _kind_from(name: str) -> str:
    """A short, stable token name for a rule id."""
    cleaned = re.sub(r"[^A-Za-z0-9]+", "_", str(name)).strip("_").upper()
    if not cleaned:
        return "DETECTED"
    if len(cleaned) <= 28:
        return cleaned
    # two long ids must never share one kind
    digest = hashlib.sha1(cleaned.encode("utf-8")).hexdigest()[:4].upper()
    return f"{cleaned[:23]}_{digest}"


def _corpus_verdict(state: dict, rules_found: list) -> None:
    """An empty corpus must say so, not read as loaded."""
    if not rules_found and not state["errors"]:
        state["errors"].append("no corpus rule loaded: every corpus came back empty")


def _read_corpus(fp, fname: str, state: dict) -> list:
    """Read one corpus file; every problem lands in state."""
    if not fp.exists():
        state["errors"].append(f"{fname} missing: this corpus stays empty")
        return []
    try:
        entries = json.loads(fp.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - reported, never fatal
        state["errors"].append(f"{fname}: {type(exc).__name__}: {exc}")
        return []
    if not isinstance(entries, list):
        # A shape drift must not read as zero rules.
        state["errors"].append(f"{fname}: not a list of rules")
        return []
    return entries


def load_dlp(path=None) -> dict:
    """Read the rule corpora. Problems are recorded, never raised."""
    global EXT_RULES
    base = Path(path) if path else DLP_DIR
    state: dict = {"loaded": False, "rules": {}, "places": len(PLACES), "postal": len(POSTAL),
                   "failed": 0, "errors": []}
    rules_found: list[dict] = []
    for fname, source in (("gitleaks.json", "gitleaks"), ("testpattern.json", "testpattern"),
                          ("privacy-mask.json", "privacy-mask")):
        entries = _read_corpus(base / fname, fname, state)
        kept = 0
        for entry in entries:
            pattern = entry.get("regex") or entry.get("pattern")
            name = str(entry.get("id") or entry.get("slug") or "?")
            if not isinstance(pattern, str) or not pattern:
                continue
            try:
                with warnings.catch_warnings():
                    # RE2 classes compile in Python with a warning; ignore it.
                    warnings.simplefilter("ignore", FutureWarning)
                    compiled = re.compile(pattern)
            except re.error:
                state["failed"] += 1
                continue
            literal = _literal_part(pattern)
            rules_found.append({
                "name": name, "source": source, "regex": compiled,
                "literals": _literals(pattern),
                "context": _context_words(entry),
                "shape_only": not any(c.isalpha() for c in literal),
            })
            kept += 1
        state["rules"][source] = kept
    rules_found = [r for r in rules_found if r["name"] not in DATA_DISABLED]
    _corpus_verdict(state, rules_found)
    EXT_RULES = rules_found
    state["loaded"] = bool(rules_found)
    state["patterns"] = len(rules_found)
    DLP_STATE.update(state)
    return state


def _note_dlp_gap(name: str, what: str) -> None:
    """A missing name list is a gap, not empty."""
    errors = list(DLP_STATE.get("errors") or [])
    errors.append(f"{name} missing: the {what} list stays empty")
    DLP_STATE["errors"] = errors


def _load_places() -> None:
    """Name lists, loaded once, only for address-looking text."""
    global PLACES, POSTAL
    places = DLP_DIR / "places.txt"
    postal = DLP_DIR / "postal.txt"
    if not PLACES:
        if not places.exists():
            _note_dlp_gap("places.txt", "places")
        else:
            PLACES = {line.strip().lower() for line in
                      places.read_text(encoding="utf-8").splitlines() if len(line.strip()) >= 4}
            DLP_STATE["places"] = len(PLACES)
    if not POSTAL:
        if not postal.exists():
            _note_dlp_gap("postal.txt", "postal")
        else:
            POSTAL = {line.strip() for line in
                      postal.read_text(encoding="utf-8").splitlines() if line.strip()}
            DLP_STATE["postal"] = len(POSTAL)


def dlp_status() -> dict:
    """What the layers hold, for status and the startup log."""
    return dict(DLP_STATE)


def _token(kind: str, counters: dict, mapping: dict, value: str) -> str:
    """One token per value: same value, same token."""
    for tok, original in mapping.items():
        if original == value:
            return tok
    counters[kind] = counters.get(kind, 0) + 1
    tok = f"[redacted_{len(mapping) + 1}{_marker_for(mapping)}]"
    mapping[tok] = value
    tracked = _KIND_OF.get(id(mapping))
    if tracked is not None:
        tracked[tok] = kind
    return tok


# A token we could have written ourselves.
TOKEN_SHAPE = re.compile(r"\[(?:[A-Z][A-Z0-9_]{0,24}|redacted)_\d{1,3}(?:#[0-9a-f]{4})?\]")
# Per-request marker, keyed by the mapping object of that request.
_MARKER: dict[int, str] = {}


def _marker_for(mapping: dict) -> str:
    marker = _MARKER.get(id(mapping), "")
    return f"#{marker}" if marker else ""


# Token to kind, for tracked mappings only.
_KIND_OF: dict[int, dict[str, str]] = {}


def track_kinds(mapping: dict) -> None:
    """Remember which kind each token of this request stands for."""
    _KIND_OF[id(mapping)] = {}


def kinds_of_tokens(mapping: dict, tokens) -> list[str]:
    """Sorted kinds behind these tokens, from the tracked request."""
    tracked = _KIND_OF.get(id(mapping), {})
    return sorted({tracked[t] for t in tokens if t in tracked})


# Harness instruction blocks, not the person's words.
HARNESS_BLOCK = re.compile(r"<system-reminder>.*?</system-reminder>", re.DOTALL)


def own_words(text: str) -> str:
    """The person's text without harness instruction blocks."""
    return HARNESS_BLOCK.sub("", text) if text and "<system-reminder>" in text else text


def mark_request(mapping: dict, text: str) -> str:
    """Marked mode when the text already looks tokenised."""
    if TOKEN_SHAPE.search(text or ""):
        marker = uuid.uuid4().hex[:4]
        _MARKER[id(mapping)] = marker
        return marker
    return ""


def release_request(mapping: dict) -> None:
    """Drop the marker when the request ends; registry stays clean."""
    _MARKER.pop(id(mapping), None)
    _KIND_OF.pop(id(mapping), None)


def mask_text(text: str, counters: dict, mapping: dict,
              skip: frozenset = frozenset()) -> tuple[str, list[str]]:
    """Replace sensitive values in one piece of text with tokens."""
    kinds: list[str] = []
    original = text
    text = visible(text)

    def sub_rule(pattern: re.Pattern, kind: str, s: str) -> str:
        def repl(m: re.Match) -> str:
            if not _context_present(kind, s, m.start(), m.end()):
                # No nearby word marks this as personal; leave the number.
                return m.group(0)
            if kind.startswith("EMAIL") and ROLE_MAILBOX.fullmatch(m.group(0)):
                return m.group(0)
            if kind.startswith("AI_PROMPT_INJECTION") and quoted_discussion(s, m.group(0)):
                return m.group(0)
            kinds.append(kind)
            return _token(kind, counters, mapping, m.group(0))
        return pattern.sub(repl, s)

    def sub_group(pattern: re.Pattern, kind: str, s: str) -> str:
        """Mask only the last group; the line stays readable."""

        def repl(m: re.Match) -> str:
            idx = m.lastindex
            if idx is None:
                return m.group(0)
            value = m.group(idx)
            prefix = m.group(0)[: m.start(idx) - m.start(0)]
            kinds.append(kind)
            return prefix + _token(kind, counters, mapping, value)

        return pattern.sub(repl, s)

    out = text
    # Group rules first, else URL passwords look like emails.
    for kind, pattern in GROUP_RULES:
        if kind not in skip:
            out = sub_group(pattern, kind, out)
    for kind, pattern in PII_RULES:
        if kind not in skip:
            out = sub_rule(pattern, kind, out)

    def repl_card(m: re.Match) -> str:
        raw = m.group(0)
        digits = re.sub(r"\D", "", raw)
        # Epoch timestamps pass Luhn one time in ten.
        if raw == digits and digits[0] == "1" and len(digits) in (13, 16, 19):
            return raw
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            kinds.append("NOMOR_KARTU")
            return _token("NOMOR_KARTU", counters, mapping, raw)
        return raw

    out = CARD_RE.sub(repl_card, out)

    def repl_ip(m: re.Match) -> str:
        raw = m.group(0)
        if _ip_private(raw):
            kinds.append("IP_PRIVAT")
            return _token("IP_PRIVAT", counters, mapping, raw)
        return raw

    out = IPV4_RE.sub(repl_ip, out)
    # no finding: keep the invisible characters the person typed
    return (out, kinds) if kinds else (original, kinds)


# A mark inside the answer itself.

# Appends the note where the answer appears.
ANSWER_NOTE = ("\n\n[guardrail] {count} value(s) in your message were replaced before it left "
               "this machine ({kinds}). The model only saw [redacted_N], so this answer keeps "
               "the masked form.")
FILTER_NOTE = ("\n\n[guardrail] Part of your message was filtered ({what}) and replaced by "
               "[blocked] before it left this machine.")

HUNT_NOTE = ("\n\n[guardrail] Your message matched a watch rule ({what}). "
             "It was forwarded unchanged.")

ANSWER_RECHECK_NOTE = "\n[guardrail] {count} more value(s) in this answer were masked."

NOTIFY_IN_REPLY = True


def note_for(count: int, kinds=(), filtered=(), hunt=()) -> str:
    """The answer's mark: values replaced, kinds, filtered parts."""
    out = ANSWER_NOTE.format(count=count, kinds=", ".join(sorted(set(kinds)))) if count else ""
    if filtered:
        out += FILTER_NOTE.format(what=", ".join(sorted(set(filtered))))
    if hunt:
        out += HUNT_NOTE.format(what=", ".join(sorted(set(hunt))))
    return out


def _note_sse(body: str, note: str) -> str:
    """Add the mark by extending the last streamed text delta."""
    chunks = body.split("\n\n")
    target: tuple[int, dict, dict, str] | None = None      # chunk, parsed object, holder, key
    for idx, chunk in enumerate(chunks):
        line = next((x for x in chunk.split("\n") if x.startswith("data:")), None)
        if line is None:
            continue
        raw = line[5:].strip()
        if not raw or raw == "[DONE]":
            continue
        try:
            obj = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(obj, dict):
            continue
        for choice in obj.get("choices") or []:                        # OpenAI shape
            holder = choice.get("delta") if isinstance(choice, dict) else None
            if isinstance(holder, dict) and isinstance(holder.get("content"), str):
                target = (idx, obj, holder, "content")
        delta = obj.get("delta")                                      # Anthropic shape
        if isinstance(delta, dict):
            for key in ("text", "thinking"):
                if isinstance(delta.get(key), str) and delta[key]:
                    target = (idx, obj, delta, key)
    if target is not None:
        idx, obj, holder, key = target
        holder[key] += note
        lines = chunks[idx].split("\n")
        data_at = next(n for n, x in enumerate(lines) if x.startswith("data:"))
        lines[data_at] = "data: " + json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
        chunks[idx] = "\n".join(lines)
        return "\n\n".join(chunks)
    chunks.append("data: " + json.dumps({"choices": [{"delta": {"content": note}}]},
                                        ensure_ascii=False))
    return "\n\n".join(chunks)


def append_note(body: str, note: str, content_type: str = "") -> str:
    """Add the mark to a plain or streamed JSON answer."""
    if not body:
        return body
    if "event-stream" in (content_type or "").lower() or "\ndata:" in body or body.startswith("event:"):
        return _note_sse(body, note)
    try:
        obj = json.loads(body)
    except ValueError:
        return body
    if not isinstance(obj, dict):
        return body
    inner = obj.get("message")                              # Ollama shape
    if isinstance(inner, dict) and isinstance(inner.get("content"), str):
        inner["content"] += note
        return json.dumps(obj, ensure_ascii=False)
    for choice in obj.get("choices") or []:                 # OpenAI shape
        msg = choice.get("message") if isinstance(choice, dict) else None
        if isinstance(msg, dict) and isinstance(msg.get("content"), str):
            msg["content"] += note
            return json.dumps(obj, ensure_ascii=False)
    content = obj.get("content")                            # Anthropic shape
    if isinstance(content, list):
        for block in reversed(content):
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                block["text"] += note
                return json.dumps(obj, ensure_ascii=False)
    return body


# Layer 2b's three passes; off if a file is missing.
MAX_PER_RULE = 20          # matches taken from one rule in one piece of text
CORPUS_MIN_DIGITS = 8      # shorter bare digit runs are not worth masking
CORPUS_CONTEXT_WINDOW = 300  # how close a rule's word must be to its match
LONG_TEXT_CORPUS_MAX = 200_000  # longer texts skip the corpus, counted in state
# A rule's word must be near the match, not anywhere.
DATA_MAX_CHARS = env_number("GUARDRAIL_DLP_MAX_CHARS", 20000)  # per text, see below

# one request's long texts share this much scan time
LONG_TEXT_BUDGET_S = 0.5


_RULE_CONTEXT_RE: dict[tuple, re.Pattern] = {}


def _context_ok(rule: dict, low: str) -> bool:
    """A shape-only rule counts only with a nearby word."""
    context = rule["context"]
    if not context:
        return False
    key = tuple(context)
    pattern = _RULE_CONTEXT_RE.get(key)
    if pattern is None:
        pattern = re.compile(r"\b(?:" + "|".join(re.escape(word) for word in context) + r")\b")
        _RULE_CONTEXT_RE[key] = pattern
    return pattern.search(low) is not None


def _validator_pass(text: str, counters: dict, mapping: dict) -> tuple[str, list[str]]:
    """Validators: a structurally valid number is not a coincidence."""
    kinds: list[str] = []
    out = text
    if _stdnum_nik is not None:
        def repl_nik(m: re.Match) -> str:
            digits = m.group(0)
            try:
                if _stdnum_nik.validate(digits):
                    kinds.append("NIK_KTP")
                    return _token("NIK_KTP", counters, mapping, digits)
            except Exception:  # noqa: BLE001 - a validator must never break a request
                pass
            return digits
        out = re.sub(r"\b\d{16}\b", repl_nik, out)
    if _stdnum_npwp is not None:
        def repl_npwp(m: re.Match) -> str:
            raw = m.group(0)
            try:
                if _stdnum_npwp.validate(raw):
                    kinds.append("NPWP")
                    return _token("NPWP", counters, mapping, raw)
            except Exception:  # noqa: BLE001
                pass
            return raw
        out = re.sub(r"\b\d{2}\.\d{3}\.\d{3}\.\d-\d{3}\.\d{3}\b|\b\d{15}\b", repl_npwp, out)
    if PhoneNumberMatcher is not None:
        try:
            matches = list(PhoneNumberMatcher(out, "ID"))
        except Exception:  # noqa: BLE001
            matches = []
        for match in reversed(matches):          # backwards, so earlier offsets stay valid
            try:
                if not phonenumbers.is_valid_number(match.number):
                    continue
                raw = out[match.start:match.end]
                if len(re.sub(r"\D", "", raw)) < 9:
                    continue
                kinds.append("NO_HP")
                out = out[:match.start] + _token("NO_HP", counters, mapping, raw) + out[match.end:]
            except Exception:  # noqa: BLE001
                continue
        def repl_bare(m: re.Match) -> str:
            raw = m.group(0)
            try:
                num = phonenumbers.parse(raw, "ID")
                ok = (phonenumbers.is_valid_number(num)
                      and phonenumbers.number_type(num) == phonenumbers.PhoneNumberType.MOBILE)
            except Exception:  # noqa: BLE001
                return raw
            if not ok:
                return raw
            kinds.append("NO_HP")
            return _token("NO_HP", counters, mapping, raw)
        # mobile number written without the 0 or +62
        out = re.sub(r"(?<![\w+(\-./])8\d{2}[-. ]\d{3,4}[-. ]\d{3,4}(?![\w\-]|[.,]\d)", repl_bare, out)
    return out, kinds


def _place_spans(text: str) -> list[tuple[int, int, str]]:
    """Spans that are known place names, longest form first."""
    spans: list[tuple[int, int, str]] = []
    for m in re.finditer(r"[A-Za-z][A-Za-z'\-]{2,}(?:\s+[A-Za-z][A-Za-z'\-]{1,}){0,2}", text):
        words = m.group(0).split()
        for take in (3, 2, 1):
            if len(words) < take:
                continue
            candidate = " ".join(words[:take]).lower()
            if candidate in PLACES:
                spans.append((m.start(), m.start() + len(candidate), candidate))
                break
    return spans


def _gazetteer_pass(text: str, counters: dict, mapping: dict) -> tuple[str, list[str]]:
    """Postal codes and place names, checked against the name lists."""
    kinds: list[str] = []
    low = text.lower()
    looks_like_address = (any(w in low for w in POSTCODE_WORDS)
                          or any(re.search(r"(?i)\b" + re.escape(m) + r"\b", low)
                                 for m in ADDRESS_MARKERS))
    if not looks_like_address:
        return text, kinds
    _load_places()
    out = text
    if POSTAL:
        def repl_pos(m: re.Match) -> str:
            code = m.group(0)
            around = out[max(0, m.start() - ADDRESS_WINDOW): m.end() + ADDRESS_WINDOW].lower()
            if code in POSTAL and (any(w in around for w in POSTCODE_WORDS)
                                   or any(name in around for _s, _e, name in _place_spans(around))):
                kinds.append("KODEPOS")
                return _token("KODEPOS", counters, mapping, code)
            return code
        out = re.sub(r"\b\d{5}\b", repl_pos, out)
    if PLACES:
        for start, end, name in reversed(_place_spans(out)):
            if name in ADDRESS_WORDS:
                continue                   # a word that introduces an address is not a name
            before = out[max(0, start - ADDRESS_WINDOW): start].lower()
            marker = re.search(r"(?i)\b(" + "|".join(re.escape(m) for m in ADDRESS_MARKERS)
                               + r")\.?\s*$", before)
            if marker:
                kinds.append("ALAMAT")
                out = out[:start] + _token("ALAMAT", counters, mapping, out[start:end]) + out[end:]
    return out, kinds


def _prefilter_hit(rule: dict, low: str, low_flat: str) -> bool:
    """True when a rule literal is present in the text."""
    literals = rule["literals"]
    if not literals:
        return True
    flat = rule.get("_flat_literals")
    if flat is None:
        flat = [re.sub(r"[^a-z0-9]+", "", lit.lower()) for lit in literals]
        rule["_flat_literals"] = flat
    return any(lit.lower() in low for lit in literals) or any(f and f in low_flat for f in flat)


def _apply_corpus_rule(rule: dict, out: str, counters: dict, mapping: dict,
                       kinds: list[str]) -> str:
    """Tokenise one corpus rule's matches; a broken rule is skipped."""
    try:
        found = list(rule["regex"].finditer(out))
    except Exception:  # noqa: BLE001 - a broken rule is skipped, not fatal
        return out
    if not found:
        return out
    kind = _kind_from(rule["name"])
    if not strong_enough(kind):
        return out
    for match in reversed(found[:MAX_PER_RULE]):
        raw = match.group(0)
        if len(raw.strip()) < 4 or TOKEN_SHAPE.fullmatch(raw.strip()):
            continue
        if DATE_FRAGMENT.fullmatch(raw.strip()):
            continue                   # a date is a date, not a data leak
        if kind.startswith("AI_PROMPT_INJECTION") and quoted_discussion(out, raw):
            continue
        stripped = raw.strip()
        if rule["shape_only"] and not any(c.isdigit() for c in stripped):
            continue                   # an ID shape with no digit is a word
        if rule["shape_only"] or stripped.isdigit():
            # The rule's own word must stand near the match.
            near = out[max(0, match.start() - CORPUS_CONTEXT_WINDOW):
                       match.end() + CORPUS_CONTEXT_WINDOW].lower()
            if not _context_ok(rule, near):
                continue
        if stripped.isdigit() and len(stripped) < CORPUS_MIN_DIGITS:
            # Bare digits need a nearby word and enough length.
            continue
        kinds.append(kind)
        out = out[:match.start()] + _token(kind, counters, mapping, raw) + out[match.end():]
    return out


# Vendor instructions: injection wording and flags are not secrets.
SYSTEM_SKIP_GROUPS = frozenset({"SANDI_ENV"})
SYSTEM_SKIP_LABELS = frozenset({"username", "organization", "nama perusahaan"})


def _vendor_text_skips(rule: dict) -> bool:
    """True for corpus rules that only fire on instruction wording."""
    return _kind_from(rule["name"]).startswith("AI_PROMPT_INJECTION")


def _corpus_pass(text: str, counters: dict, mapping: dict,
                 deadline: float | None = None, state: dict | None = None,
                 literal_only: bool = False, system: bool = False) -> tuple[str, list[str]]:
    """Downloaded corpora, applied with prefilter, context and budget."""
    kinds: list[str] = []
    out = text
    low = out.lower()
    # literals come from examples: match a flattened copy too
    low_flat = re.sub(r"[^a-z0-9]+", "", low)
    prefiltered: list[dict] = []
    for rule in EXT_RULES:
        if deadline is not None and time.monotonic() > deadline:
            if state is not None:
                state["rules_skipped"] = state.get("rules_skipped", 0) + 1
            continue
        if not _prefilter_hit(rule, low, low_flat):
            prefiltered.append(rule)
            continue
        if rule["shape_only"] and not _context_ok(rule, low):
            continue                       # a bare shape with no identifier is not used
        if rule["name"] in CORPUS_EXCLUDE or (system and _vendor_text_skips(rule)):
            continue
        if state is not None:
            state["rules_scanned"] = state.get("rules_scanned", 0) + 1
        out = _apply_corpus_rule(rule, out, counters, mapping, kinds)
    # Second pass over prefiltered rules, inside the same budget.
    for rule in ([] if literal_only else prefiltered):
        if deadline is not None and time.monotonic() > deadline:
            if state is not None:
                state["second_pass_skipped"] = state.get("second_pass_skipped", 0) + 1
            continue
        if rule["name"] in CORPUS_EXCLUDE or (system and _vendor_text_skips(rule)):
            continue
        if rule["shape_only"] and not _context_ok(rule, low):
            continue
        before = len(kinds)
        if state is not None:
            state["second_pass_scanned"] = state.get("second_pass_scanned", 0) + 1
        out = _apply_corpus_rule(rule, out, counters, mapping, kinds)
        if state is not None and len(kinds) > before:
            state["second_pass_hits"] = state.get("second_pass_hits", 0) + 1
    return out, kinds


def mask_extra(text: str, counters: dict, mapping: dict, deadline: float | None = None,
               state: dict | None = None, system: bool = False) -> tuple[str, list[str]]:
    """Layer 2b in one call: validators, name lists, corpora."""
    if not text:
        return text, []
    kinds: list[str] = []
    out, found = _validator_pass(text, counters, mapping)
    kinds += found
    if mode_settings()["places"]:
        out, found = _gazetteer_pass(out, counters, mapping)
        kinds += found
    if EXT_RULES:
        out, found = _corpus_pass(out, counters, mapping, deadline, state, system=system)
        kinds += found
    return out, kinds


def mask_extra_pass(user_texts: list[str], counters: dict, mapping: dict,
                    budget_ms: int | None = None, system_texts=frozenset()) -> tuple[dict, list[str], dict]:
    """Layer 2b over all outgoing text, under a budget."""
    budget = (budget_ms if budget_ms is not None else DLP_BUDGET_MS) / 1000.0
    deadline = time.monotonic() + budget
    replaced: dict[str, str] = {}
    kinds: list[str] = []
    state = {"texts": 0, "chars": 0, "ms": 0.0, "budget_ms": int(budget * 1000),
             "rules_scanned": 0, "rules_skipped": 0, "second_pass_scanned": 0,
             "second_pass_skipped": 0, "second_pass_hits": 0, "skipped_short_texts": 0}
    start = time.monotonic()
    long_deadline: float | None = None
    for text in user_texts:
        if not text or len(text) < 8:
            # too short to hold any pattern; counted, never silent
            state["skipped_short_texts"] += 1
            continue
        state["texts"] += 1
        state["chars"] += len(text)
        if len(text) > DATA_MAX_CHARS:
            # long texts skip the corpus, validators keep the rest
            state["skipped_long_texts"] = state.get("skipped_long_texts", 0) + 1
            if long_deadline is None:
                long_deadline = time.monotonic() + LONG_TEXT_BUDGET_S
            new, found = _validator_pass(text, counters, mapping)
            if time.monotonic() > long_deadline:
                # validators are cheap and always run; the rest is skipped
                state["skipped_over_budget"] = state.get("skipped_over_budget", 0) + 1
                kinds += found
                if new != text:
                    replaced[text] = new
                continue
            new2, found2 = _gazetteer_pass(new, counters, mapping) if mode_settings()["places"] \
                else (new, [])
            found3: list[str] = []
            if EXT_RULES and len(text) <= LONG_TEXT_CORPUS_MAX:
                # literal-hit rules only; the blind pass is too slow
                state["long_texts_corpus"] = state.get("long_texts_corpus", 0) + 1
                new2, found3 = _corpus_pass(new2, counters, mapping, long_deadline, state, True,
                                            system=text in system_texts)
            kinds += found + found2 + found3
            if new2 != text:
                replaced[text] = new2
            continue
        new, found = mask_extra(text, counters, mapping, deadline, state, system=text in system_texts)
        kinds += found
        if new != text:
            replaced[text] = new
    state["ms"] = round((time.monotonic() - start) * 1000, 1)
    return replaced, kinds, state


# Public alias, so the model layer shares the token numbering.
make_token = _token
mask_validated = _validator_pass

# PART 2 - external rule layer (ATR)
BASE = base_dir()
ATR_DIR = Path(os.environ.get("GUARDRAIL_ATR_DIR", BASE / "atr"))

# Only categories that can appear in traffic this proxy sees.
ATR_CATEGORIES = {
    "prompt-injection", "context-exfiltration", "tool-poisoning",
    "agent-manipulation", "model-abuse", "skill-compromise",
    "data-poisoning", "excessive-autonomy", "model-security", "privilege-escalation",
}

# Tool-result rules stay off the user's own words.
ATR_CHANNEL_USER = "user_input"
ATR_CHANNEL_DOCUMENT = "document"
CHANNEL_FIELDS: dict[str, set[str]] = {
    # what the person typed, or the model's input
    ATR_CHANNEL_USER: {"user_input", "content"},
    # anything a tool or an agent runtime produced
    ATR_CHANNEL_DOCUMENT: {
        "tool_response", "tool_args", "tool_input", "tool_name",
        "tool_description", "trace", "agent_output", "behavioral",
    },
}

MAX_MATCH_WINDOW = 80

_atr_lock = threading.Lock()
_started = False
_atr_attempts = 0
ATR_MAX_ATTEMPTS = 2
ATR_LAZY = True   # the proxy sets False: a request never loads rules
_atr_rules: list[dict] = []
_atr_skipped: list[str] = []
_atr_stats: dict = {}


def _load_atr() -> None:
    """Parse the ATR YAML files and compile every regex once."""
    global _atr_rules, _atr_skipped, _atr_stats
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - PyYAML ships with mitmproxy
        _atr_stats = {"error": f"PyYAML missing: {exc}"}
        return
    if not ATR_DIR.is_dir():
        # A missing corpus is a failure, not an empty set.
        _atr_stats = {"error": f"no ATR directory at {ATR_DIR}", "files_seen": 0, "rules_used": 0}
        _atr_rules = []
        return

    rules: list[dict] = []
    skipped: list[str] = []
    dropped: list[str] = []
    conditions = 0
    other_conditions = 0
    t0 = time.perf_counter()
    paths = sorted(ATR_DIR.rglob("*.yaml"))
    overrides = _lane_overrides(ATR_DIR / "lane-overrides.txt")
    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)   # C parser: 5.5 s down to 0.5 s
    _debug(f"yaml loader: {loader.__name__}" + ("" if hasattr(yaml, "CSafeLoader") else " FALLBACK (fallback, no C extension)"))
    for path in paths:
        try:
            doc = yaml.load(path.read_text(encoding="utf-8"), Loader=loader)
        except Exception as exc:  # noqa: BLE001 - a broken rule must not stop the proxy
            skipped.append(f"{path.name}: parse error {type(exc).__name__}")
            continue
        if not isinstance(doc, dict):
            skipped.append(f"{path.name}: not a mapping")
            continue
        category = str((doc.get("tags") or {}).get("category") or doc.get("category") or path.parent.name)
        if category not in ATR_CATEGORIES:
            # A category this proxy does not watch is dropped, counted.
            dropped.append(f"{path.name}: category {category} not in use")
            continue
        compiled: list[tuple[str, re.Pattern]] = []
        require_all = str((doc.get("detection") or {}).get("condition") or "any").lower() == "all"
        unusable = 0
        for cond in ((doc.get("detection") or {}).get("conditions") or []):
            if str(cond.get("operator", "")).lower() != "regex":
                other_conditions += 1
                unusable += 1
                continue
            value = cond.get("value")
            if not isinstance(value, str):
                other_conditions += 1
                unusable += 1
                continue
            try:
                compiled.append((str(cond.get("field") or ATR_CHANNEL_USER),
                                 re.compile(value, re.I)))
            except re.error as exc:
                skipped.append(f"{path.name}: bad regex ({exc})")
                unusable += 1
        if not compiled:
            dropped.append(f"{path.name}: no usable regex condition")
            continue
        if require_all and unusable:
            # a partial AND would fire far wider than written
            dropped.append(f"{path.name}: condition all with an unusable condition")
            continue
        conditions += len(compiled)
        maturity = str(doc.get("maturity") or "test").lower()
        rules.append({
            "id": str(doc.get("id") or path.stem),
            "title": str(doc.get("title") or path.stem)[:120],
            "category": category,
            "severity": str(doc.get("severity") or "unknown"),
            "maturity": maturity,
            "lane": overrides.get(str(doc.get("id") or path.stem),
                                  "enforce" if maturity == "stable" else "hunt"),
            "patterns": compiled,
            "require_all": require_all,
        })
    _atr_rules = rules
    _atr_skipped = skipped
    _atr_stats = {
        "files_seen": len(paths),
        "rules_used": len(rules),
        "conditions": conditions,
        "conditions_not_regex": other_conditions,
        "skipped": len(skipped),
        "dropped": len(dropped),
        "dropped_examples": dropped[:5],
        "load_ms": round((time.perf_counter() - t0) * 1000, 1),
        "categories": sorted({r["category"] for r in rules}),
        "lanes": {lane: sum(1 for r in rules if r["lane"] == lane) for lane in ("enforce", "hunt")},
    }
    # an empty layer must never read as clean
    if not rules and str(mode_settings().get("external", "on")) != "off":
        if paths:
            _atr_stats["error"] = (f"loaded 0 rules from {len(paths)} files "
                                   f"(dropped {len(dropped)}, skipped {len(skipped)})")
        else:
            _atr_stats["error"] = f"no rule files under {ATR_DIR}"


def _lane_overrides(path: Path) -> dict[str, str]:
    """Read +ID / -ID lines into rule id -> lane."""
    out: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return out
    for line in lines:
        line = line.strip()
        if line[:1] in "+-" and line[1:]:
            out[line[1:]] = "enforce" if line[0] == "+" else "hunt"
    return out


def atr_start(force: bool = False) -> None:
    """Load the rule sets once; retry a failed load twice."""
    global _started, _atr_attempts
    with _atr_lock:
        if _started and not force:
            return
        if not force and _atr_attempts >= ATR_MAX_ATTEMPTS:
            # stop re-reading a broken corpus per request
            return
        _atr_attempts += 1
        _load_atr()
        # the status output still shows the error
        _started = not _atr_stats.get("error")


def atr_reload() -> None:
    """Try the rule set again by hand."""
    global _atr_attempts
    _atr_attempts = 0
    atr_start(force=True)


def _window(text: str, pattern: re.Pattern) -> str | None:
    m = pattern.search(text)
    if not m:
        return None
    start = max(0, m.start() - 20)
    return text[start:m.end() + 20][:MAX_MATCH_WINDOW].replace("\n", " ")


def check_atr(text: str, channel: str = ATR_CHANNEL_USER) -> list[dict]:
    """Run the ATR layer over one text, for that channel."""
    hits: list[dict] = []
    if not text:
        return hits
    wanted = CHANNEL_FIELDS.get(channel, {channel})
    for rule in _atr_rules:
        if rule.get("require_all"):
            # condition: all means every regex must match this text
            if not all(f in wanted and p.search(text) for f, p in rule["patterns"]):
                continue
            pairs = rule["patterns"][:1]
        else:
            pairs = rule["patterns"]
        for field, pattern in pairs:
            if field not in wanted:
                continue
            found = _window(text, pattern)
            if found is not None:
                span = pattern.search(text).group(0)
                hits.append({
                    "engine": "atr", "rule": rule["id"], "title": rule["title"],
                    "category": rule["category"], "severity": rule["severity"],
                    "maturity": rule["maturity"], "lane": rule["lane"], "channel": channel,
                    "match": found, "span": span,
                })
                break  # one hit per rule is enough
    return hits


def atr_ready() -> bool:
    """True once the rule set is loaded."""
    return _started


def atr_check(text: str, channel: str = ATR_CHANNEL_USER) -> list[dict]:
    """Run the external rule layer. Empty list when nothing fires."""
    if not _started and ATR_LAZY:
        atr_start()
    return check_atr(text, channel)


def atr_status() -> dict:
    """Rule counts, load times and any load failures."""
    return {"atr": _atr_stats, "engines": ["atr"],
            "removed": [{"engine": "yara", "reason": "duplicated ATR, no unique injection hit"}],
            "skip_examples": _atr_skipped[:10]}


# ATR action follows the rule's severity, not a table.
ATR_BLOCK_SEVERITIES = {"critical"}


def atr_action(severity: str) -> str:
    """Critical rules block; every other severity is filtered and forwarded."""
    return "BLOCK" if str(severity).strip().lower() in ATR_BLOCK_SEVERITIES else "FILTER"


def atr_label(hit: dict) -> str:
    """The ATR category and severity, for message and record."""
    return f"{hit.get('category') or hit.get('rule', '')} severity {hit.get('severity') or 'unknown'}"


def atr_filtered_labels(hits: list[dict]) -> list[str]:
    """Labels of enforced current user hits: category and severity."""
    wanted = []
    for hit in hits:
        if hit.get("lane") != "enforce" or hit.get("channel") != ATR_CHANNEL_USER:
            continue
        if not hit.get("current", True):
            continue
        wanted.append(atr_label(hit))
    return sorted(set(wanted))

# PART 3 - model layer (GLiNER)
LOGS = BASE / "logs"
METRICS = LOGS / "detector-metrics.jsonl"

MODE = os.environ.get("GUARDRAIL_GLINER", "budget").strip().lower()
BUDGET_MS = env_number("GUARDRAIL_GLINER_BUDGET_MS", 450)
MODEL_ID = os.environ.get("GUARDRAIL_GLINER_MODEL", "urchade/gliner_multi_pii-v1")
MAX_CHARS = env_number("GUARDRAIL_GLINER_MAX_CHARS", 1500)
THRESHOLD = env_number("GUARDRAIL_GLINER_THRESHOLD", 0.60, float)
BUDGET_PER_CHAR_MS = env_number("GUARDRAIL_GLINER_BUDGET_PER_CHAR_MS", 0.5, float)
BUDGET_MAX_MS = env_number("GUARDRAIL_GLINER_BUDGET_MAX_MS", 1500)
HARD_MS = env_number("GUARDRAIL_GLINER_HARD_MS", 5000)


def budget_ms_for(chars: int) -> float:
    """Model wait for one text: inference time grows with length."""
    return min(BUDGET_MAX_MS, BUDGET_MS + BUDGET_PER_CHAR_MS * max(chars, 0))

# Labels in both languages; the model uses their meaning.
DEFAULT_LABELS = [
    "person", "nama orang",
    "address", "alamat",
    "organization", "nama perusahaan",
    "email address", "phone number", "national id number",
    "bank account number", "credit card number", "date of birth",
    "passport number", "social security number", "iban",
    "driver's license number", "tax identification number",
    "ip address", "username", "medical condition",
]
LABELS = [s.strip() for s in os.environ.get("GUARDRAIL_GLINER_LABELS", "").split(",") if s.strip()] or DEFAULT_LABELS

_model = None
_model_error = ""
_load_seconds = None
_cache: dict[str, list[dict]] = {}   # hash(text) -> entities, so a repeated text costs nothing
_model_lock = threading.Lock()


class _DaemonWorker:
    """Single daemon thread; never joined at interpreter exit."""

    def __init__(self, name: str) -> None:
        self._jobs: queue.SimpleQueue = queue.SimpleQueue()
        threading.Thread(target=self._run, name=name, daemon=True).start()

    def _run(self) -> None:
        while True:
            future, fn, args = self._jobs.get()
            if not future.set_running_or_notify_cancel():
                continue
            try:
                future.set_result(fn(*args))
            except BaseException as exc:  # noqa: BLE001
                future.set_exception(exc)

    def submit(self, fn, *args) -> Future:
        future: Future = Future()
        self._jobs.put((future, fn, args))
        return future


_pool: _DaemonWorker | None = None


def _debug(msg: str) -> None:
    if os.environ.get("GUARDRAIL_DEBUG", "0") != "1":
        return
    LOGS.mkdir(parents=True, exist_ok=True)
    with (LOGS / "debug.log").open("a", encoding="utf-8") as fh:
        fh.write(f"{datetime.now().astimezone():%Y-%m-%d %H:%M:%S} detector: {msg}\n")


def model_start() -> None:
    """Set up the worker pool; the model loads lazily."""
    global _pool
    if _pool is None:
        _pool = _DaemonWorker("gliner")
    _debug(f"detector ready: mode={MODE} model={MODEL_ID} budget={BUDGET_MS}ms max_chars={MAX_CHARS}")


def warm_up() -> dict:
    """Load the model and run one throwaway inference up front."""
    out = {"loaded": False, "seconds": None, "error": None}
    if MODE == "off":
        out["error"] = "mode-off"
        return out
    model_start()
    t0 = time.perf_counter()
    model = _load_model()
    if model is None:
        out["error"] = _model_error or "model unavailable"
        return out
    try:
        _infer("pemanasan model")          # one real call, so the first request pays nothing
        out["loaded"] = True
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"{type(exc).__name__}: {exc}"
    out["seconds"] = round(time.perf_counter() - t0, 2)
    _debug(f"warm-up: loaded={out['loaded']} in {out['seconds']}s error={out['error']}")
    return out


def _missing_model_import():
    """Name the first model dependency that cannot be imported."""
    import importlib.util as iu
    for mod, pkg in MODEL_IMPORTS:
        try:
            if iu.find_spec(mod) is None:
                return pkg
        except (ImportError, ValueError):
            return pkg
    return ""


def _load_model():
    """Load the model once. Failures are recorded, never raised."""
    global _model, _model_error, _load_seconds
    with _model_lock:
        if _model is not None or _model_error:
            return _model
        t0 = time.perf_counter()
        try:
            from gliner import GLiNER  # imported here so the proxy stays light in off mode

            gap = _missing_model_import()
            if gap:
                raise ImportError(f"required package '{gap}' is not importable")
            try:
                _model = GLiNER.from_pretrained(MODEL_ID, local_files_only=True)
            except Exception:  # noqa: BLE001 - not cached yet, fetch once
                if os.environ.get("HF_HUB_OFFLINE", "").strip().lower() in ("1", "true", "yes", "on"):
                    raise                  # offline service: never fetch, never hang
                _model = GLiNER.from_pretrained(MODEL_ID)
            _load_seconds = round(time.perf_counter() - t0, 2)
            _debug(f"model loaded in {_load_seconds}s")
        except Exception as exc:  # noqa: BLE001 - whatever the cause, the guardrail keeps running
            _model_error = f"{type(exc).__name__}: {exc}"
            _debug(f"model failed to load: {_model_error}")
    return _model


def await_model(max_s: float) -> bool:
    """Wait for a running load, or load here."""
    if _model is not None:
        return True
    if _model_error or MODE in ("off", "audit"):
        return False
    if not _model_lock.acquire(timeout=max_s):
        return False
    _model_lock.release()
    if _model is None and not _model_error:
        _load_model()
    return _model is not None


def _infer(text: str) -> list[dict]:
    """One model call. Returns the list of raw entities."""
    model = _load_model()
    if model is None:
        return []
    if hasattr(model, "predict_entities"):
        return list(model.predict_entities(text, LABELS, threshold=THRESHOLD))
    if hasattr(model, "extract_entities"):  # gliner2
        out = model.extract_entities(text, LABELS)
        if isinstance(out, dict):
            ents = []
            for label, values in (out.get("entities") or {}).items():
                for v in values:
                    idx = text.find(v)
                    if idx >= 0:
                        ents.append({"start": idx, "end": idx + len(v), "text": v, "label": label, "score": 1.0})
            return ents
        return list(out)
    raise RuntimeError("the gliner package provides neither predict_entities nor extract_entities")


def _record(stat: dict) -> None:
    """Write metrics; the metrics file must never break a request."""
    try:
        LOGS.mkdir(parents=True, exist_ok=True)
        stat = {"ts": datetime.now().astimezone().isoformat(timespec="seconds"), **stat}
        with METRICS.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(stat, ensure_ascii=False) + "\n")
    except (OSError, TypeError, ValueError):
        pass


# Filter for model findings: the model scores non-names highly.
PRONOUN_WORDS = {
    "saya", "aku", "ku", "kamu", "anda", "kami", "kita", "dia", "mereka", "beliau",
    "i", "you", "we", "me", "us", "he", "she", "they", "them", "it",
    "my team", "tim saya", "our team", "tim kami",
}
# a greeting is not part of a name
GREETING_WORDS = frozenset({"hai", "hi", "hello", "halo", "hey", "dear"})
COMMON_NOUNS = {
    "team", "tim", "company", "perusahaan", "organization", "organisasi", "office",
    "kantor", "vendor", "client", "klien", "user", "pengguna", "customer", "pelanggan",
    "assistant", "asisten", "chatbot", "bot", "ai", "llm", "agent", "agen", "system", "sistem",
}
LABELS_NEEDING_A_NAME = {"person", "nama orang", "organization", "nama perusahaan"}
# A tool beside its role mailbox is a trailer.
TRAILER_NAME = re.compile(r"(?i)(?:claude|gemini|chatgpt|gpt|codex|copilot)(?:\s+(?:code|\d[\w.]*|opus|sonnet|haiku|fable))*")
AI_VENDOR_ORGS = frozenset({"anthropic", "openai", "deepseek", "mistral ai", "moonshot ai"})
# Entities of only these words name no person.
ROLE_WORDS = frozenset((
    "assistant associate manager director engineer developer designer analyst architect officer owner "
    "master lead head chief senior junior principal staff intern executive president vice administrator "
    "admin operator specialist consultant coordinator supervisor technician agent representative professor "
    "lecturer teacher doctor dentist nurse customer client user member applicant applicants candidate "
    "candidates team teams department division panel desk helpdesk support service services success sales "
    "marketing finance hr qa ops devops security product project program release sprint review production "
    "staging server data center centre technology technical international standard delivery tier live chat "
    "knowledge base university the of and "
    "asisten manajer direktur insinyur pengembang analis kepala ketua petugas staf pegawai karyawan "
    "pelanggan klien pengguna anggota tim divisi departemen bagian layanan dukungan bapak ibu pak bu "
    "saudara saudari tuan nyonya scrum kanban agile our my your their his her its this that a an "
    "kami kita saya anda").split())
# Vendor model names with a tier or version.
MODEL_NAME = re.compile(
    r"(?i)(?:claude|gemini|gpt|codex|llama|mistral|qwen|glm|kimi|grok|deepseek)(?:[\s-]+(?:\d[\w.]*|opus|sonnet"
    r"|haiku|fable|pro|flash|ultra|mini|max|nano|turbo|chat|instruct|coder|code|oss))+(?:\s*\([A-Za-z ]{2,20}\))?")
# Program values a model reads as a name.
NULLISH = frozenset({"none", "null", "nil", "undefined", "n/a", "na", "true", "false", "default"})
# Plain nouns the model scores as usernames.
USERNAME_NOUNS = COMMON_NOUNS | {
    "chatbot", "chatbots", "bot", "bots", "assistant", "asisten", "agent", "agen", "model", "llm",
    "users", "pengguna", "system", "sistem", "server", "ai", "username", "usernames",
}
# Role names, not people.
ROLE_ACCOUNTS = frozenset({"admin", "administrator", "root", "guest", "anonymous", "user", "default"})
# Words that may surround those nouns in a phrase.
USERNAME_MODIFIERS = frozenset({
    "the", "a", "an", "our", "your", "my", "its", "this", "that", "end", "root", "guest",
    "admin", "kami", "kita", "anda", "saya", "kamu", "ini", "itu", "akhir", "nama", "name",
})


# Labels whose real values carry digits.
DIGIT_LABELS = frozenset({
    "national id number", "bank account number", "credit card number", "passport number",
    "social security number", "iban", "driver's license number", "tax identification number",
    "phone number", "date of birth",
})
STREET_WORD = re.compile(
    r"(?i)\b(?:jalan|jl|jln|gang|gg|lorong|komplek|kompleks|perumahan|blok|street|st|road|rd|avenue|ave|"
    r"lane|boulevard|blvd|drive|dr|apartment|apt)\b")
ADDRESS_CUE = re.compile(
    r"(?i)(?:alamat|address|ship(?:ping)? to|deliver(?:ed)? to|kirim(?: ke)?|domisili|rumah saya|"
    r"home|mailing|tinggal di)")
LANDMARK_WORD = re.compile(
    r"(?i)\b(?:tower|candi|borobudur|monas|monumen|monument|museum|mount|mt|gunung|pulau|island|sungai|river|"
    r"danau|lake|bukit|pantai|beach|bridge|jembatan|temple|pura|masjid|mosque|gereja|church|cathedral|"
    r"stasiun|station|airport|bandara|park|taman|palace|istana|castle|falls|canyon|valley|kota|city|menara|"
    r"provinsi|province|kabupaten|republic|republik|kingdom|kerajaan)\b")
# A generic noun plus a place is no organization.
PLACE_PHRASE = re.compile(
    r"(?i)(?:hotels?|universitas|university|bank|banks|penerbangan|flights?)\s+"
    r"(?:(?:di|in|at|ke|to|dari|from)\s+\w+(?:\s+\w+){0,2}|\w+(?:\s*[-\u2013]\s*\w+)+)")
COMPANY_SUFFIX = re.compile(r"(?i)\b(?:pt|cv|tbk|inc|ltd|llc|corp|co|gmbh|plc|bv|ag)\b\.?")


def _maskable(ent: dict, text: str) -> bool:
    """Reject model findings that are not proper names."""
    label = str(ent.get("label") or "").lower()
    span = text[ent.get("start", 0):ent.get("end", 0)]
    if span.strip().lower().strip("`'\".,;:") in NULLISH:
        return False
    if label == "username" and MODEL_NAME.fullmatch(span.strip()):
        return False
    if label in DIGIT_LABELS and sum(ch.isdigit() for ch in span) < 3:
        return False
    if label == "email address" and "@" not in span:
        return False
    if label in ("address", "alamat") and not re.search(r"\d", span):
        before = text[max(0, ent.get("start", 0) - 40):ent.get("start", 0)]
        return bool(STREET_WORD.search(span) and ADDRESS_CUE.search(before))
    if label in ("organization", "nama perusahaan") and LANDMARK_WORD.search(span) \
            and not COMPANY_SUFFIX.search(span):
        return False
    if label in ("organization", "nama perusahaan") and PLACE_PHRASE.fullmatch(span.strip()):
        return False
    if label == "ip address" and not re.search(r"\d+\.\d+\.\d+\.\d+|[0-9a-f]*:[0-9a-f:]{2,}", span, re.I):
        return False
    if label in LABELS_NEEDING_A_NAME and MODEL_NAME.fullmatch(span.strip()):
        return False
    if label in ("organization", "nama perusahaan") and span.strip().lower() in AI_VENDOR_ORGS:
        return False
    if label in LABELS_NEEDING_A_NAME and TRAILER_NAME.fullmatch(span.strip()):
        tail = re.match(r"\s*<([^<>\s]+)>", text[ent.get("end", 0):ent.get("end", 0) + 80])
        if tail and ROLE_MAILBOX.fullmatch(tail.group(1)):
            return False
    if ROLE_MAILBOX.fullmatch(text[ent.get("start", 0):ent.get("end", 0)].strip("<>()[]\"',;: ")):
        return False
    if label == "username" and span.strip().lower().strip("`'\".,;:") in ROLE_ACCOUNTS:
        return False
    if label == "username":
        value = text[ent.get("start", 0):ent.get("end", 0)].strip().lower().strip(".,;:!?\"'()")
        words = [w.strip(".,;:!?\"'()") for w in value.split()]
        plain = bool(words) and all(w in USERNAME_NOUNS or w in USERNAME_MODIFIERS for w in words)
        return not (plain and any(w in USERNAME_NOUNS for w in words))
    if label not in LABELS_NEEDING_A_NAME:
        return True
    s, e = ent.get("start"), ent.get("end")
    if s is None or e is None or s >= e:
        return False
    value = text[s:e].strip()
    low = value.lower().strip(".,;:!?\"'()")
    if low in PRONOUN_WORDS or low in COMMON_NOUNS:
        return False
    words = [w for w in re.findall(r"[\w'-]+", low) if not w.isdigit()]
    if words and all(w in ROLE_WORDS for w in words):
        return False

    if any(ch.isupper() for ch in value[1:]):
        return True
    if value[:1].isupper() and len(value) >= 3:
        prev = text[:s].rstrip()
        return bool(prev) and prev[-1] not in ".!?\n"
    return False


def _semantic_skip_reason(text: str) -> str:
    """Why the model layer skips this text, '' to run."""
    if MODE == "off":
        return "mode-off"
    if not text.strip():
        return "empty"
    if len(text) > MAX_CHARS:
        return "too-long"
    # only placeholders alone have nothing left to inspect
    left = re.sub(r"\[[A-Za-z_0-9]+\]", "", text).strip()
    if len(text) < 40 and len(left) < 8:
        return "already-tokenised"
    return ""


def _entity_summary(ent: dict) -> dict:
    """The metrics-sized view of one model finding, no value."""
    return {"label": ent.get("label"), "score": round(float(ent.get("score") or 0), 3),
            "start": ent.get("start"), "end": ent.get("end"),
            "chars": max(0, int(ent.get("end") or 0) - int(ent.get("start") or 0))}


def _record_audit(future, stat: dict, text: str, t0: float) -> None:
    """Log an audit-mode call's findings after the reply goes out."""
    try:
        ents = future.result()
    except Exception:  # noqa: BLE001
        return
    done = dict(stat)
    done["action"] = "audit"
    done["ms"] = round((time.perf_counter() - t0) * 1000, 1)
    ents = [e for e in ents if _maskable(e, text)]
    done["entities"] = [_entity_summary(e) for e in ents]
    _record(done)


BATCH_SEP = "\n\n"


def semantic_prefetch(texts: list[str], deadline: float | None = None) -> int:
    """Warm the cache: one model call per batch of texts."""
    if MODE in ("off", "audit") or _model_error:
        return 0
    todo = [t for t in dict.fromkeys(texts)
            if t and not semantic_cached(t) and not _semantic_skip_reason(t)]
    batches: list[list[str]] = []
    cur: list[str] = []
    size = 0
    for text in todo:
        if cur and size + len(text) + len(BATCH_SEP) > MAX_CHARS:
            batches.append(cur)
            cur, size = [], 0
        cur.append(text)
        size += len(text) + len(BATCH_SEP)
    if cur:
        batches.append(cur)
    done = 0
    for batch in batches:
        if len(batch) < 2:
            continue
        if _pool is None:
            model_start()
        assert _pool is not None
        joined = BATCH_SEP.join(batch)
        budget = max(budget_ms_for(len(joined)), HARD_MS) / 1000.0
        if deadline is not None:
            budget = min(budget, deadline - time.monotonic())
        if budget <= 0.02:
            break
        future = _pool.submit(_infer, joined)
        try:
            ents = future.result(timeout=budget)
        except FutureTimeout:
            future.add_done_callback(lambda fut, b=batch: _late_split(fut, b))
            break
        except Exception:  # noqa: BLE001
            break
        _split_into_cache(batch, list(ents))
        done += len(batch)
    return done


def _split_into_cache(batch: list[str], ents: list[dict]) -> None:
    """Hand each text the entities that fall inside it."""
    if len(_cache) >= 1024:
        _cache.clear()
    pos = 0
    for text in batch:
        end = pos + len(text)
        inside = [{**e, "start": e["start"] - pos, "end": e["end"] - pos}
                  for e in ents if e.get("start") is not None and e["start"] >= pos and e["end"] <= end]
        _cache[hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()] = inside
        pos = end + len(BATCH_SEP)


def _late_split(future, batch: list[str]) -> None:
    """Keep a batch result that finished after its request left."""
    try:
        _split_into_cache(batch, list(future.result()))
    except Exception:  # noqa: BLE001
        pass


def semantic_cached(text: str) -> bool:
    """True when the model already judged this exact text."""
    return hashlib.sha1(text.encode("utf-8", "replace")).hexdigest() in _cache


def _late_cache(future, key: str) -> None:
    """Keep a result that finished after its request left."""
    try:
        if len(_cache) >= 1024:
            _cache.clear()
        _cache[key] = list(future.result())
    except Exception:  # noqa: BLE001
        pass


def _infer_with_budget(text: str, stat: dict, deadline: float | None, flat: bool = False):
    """Entities for a text, from cache or the model.

    Returns the entity list, or None when the caller has to answer without masking.
    """
    if _pool is None:
        model_start()
    assert _pool is not None

    # Same text, same entities: cache by hash.
    cache_key = f"{hashlib.sha1(text.encode('utf-8', 'replace')).hexdigest()}"
    cached = _cache.get(cache_key)
    if cached is not None:
        stat["reason"] = "cached"
        stat["ms"] = 0.0
        return list(cached)
    # wait the hard cap; a miss is counted
    budget = max(BUDGET_MS if flat else budget_ms_for(len(text)), HARD_MS) / 1000.0
    if deadline is not None:
        budget = min(budget, max(deadline - time.monotonic(), 0.0))

    t0 = time.perf_counter()
    future = _pool.submit(_infer, text)
    if MODE == "audit":
        # Audit does not wait: the model runs in the background.
        future.add_done_callback(lambda fut: _record_audit(fut, stat, text, t0))
        stat["reason"] = "fire-and-forget"
        return None
    try:
        result = future.result(timeout=budget)
        stat["ms"] = round((time.perf_counter() - t0) * 1000, 1)
    except FutureTimeout:
        future.add_done_callback(lambda fut: _late_cache(fut, cache_key))
        stat["reason"] = "over-budget"
        stat["ms"] = round((time.perf_counter() - t0) * 1000, 1)
        _record(stat)
        return None
    except Exception as exc:  # noqa: BLE001
        stat["reason"] = f"error:{type(exc).__name__}"
        _record(stat)
        return None
    if len(_cache) >= 1024:
        _cache.clear()
    _cache[cache_key] = list(result)
    return result


def _apply_entities(text: str, result: list[dict], counters: dict, mapping: dict,
                    token_fn) -> tuple[str, list[str]]:
    """Tokenise findings from the back, so positions do not shift."""
    kinds: list[str] = []
    out = text
    for ent in sorted(result, key=lambda e: e.get("start", 0), reverse=True):
        s, e = ent.get("start"), ent.get("end")
        if s is None or e is None or s >= e or e > len(text):
            continue
        value = text[s:e]
        label = str(ent.get("label") or "entity").upper().replace(" ", "_")
        out = out[:s] + token_fn(label, counters, mapping, value) + out[e:]
        kinds.append(label)
    return out, kinds


def semantic_mask(text: str, counters: dict, mapping: dict, token_fn, deadline: float | None = None,
                  flat: bool = False, ignore=None, skip_labels=frozenset(), min_words: int = 1):
    """Mask the model's found entities in one piece of text."""
    stat = {"chars": len(text), "mode": MODE, "entities": [], "action": "skip", "ms": 0.0}
    reason = _semantic_skip_reason(text)
    if reason:
        stat["reason"] = reason
        return text, [], stat

    result = _infer_with_budget(text, stat, deadline, flat)
    if result is None:
        return text, [], stat

    # Drop findings that are not proper names (see _maskable).
    result = [e for e in result if _maskable(e, text)]
    if ignore:
        result = [e for e in result
                  if text[e.get("start", 0):e.get("end", 0)].strip().lower().strip(".,;:'\"") not in ignore]
    if skip_labels:
        result = [e for e in result if str(e.get("label") or "").lower() not in skip_labels]
    if min_words > 1:
        result = [e for e in result if sum(w.lower() not in GREETING_WORDS for w in
                                           text[e.get("start", 0):e.get("end", 0)].split()) >= min_words]
    stat["entities"] = [_entity_summary(e) for e in result]
    if not result:
        # A model that never loaded is a missing layer.
        stat["action"] = "model-error" if _model_error else "clean"
        _record(stat)
        return text, [], stat

    out, kinds = _apply_entities(text, result, counters, mapping, token_fn)
    stat["action"] = "mask"
    _record(stat)
    return out, kinds, stat


def summarize_metrics() -> dict:
    """Summarise the metrics file for the report (p50/p99, skip reasons)."""
    if not METRICS.exists():
        return {"count": 0}
    rows = []
    for line in METRICS.read_text(encoding="utf-8").splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    if not rows:
        return {"count": 0}
    times = sorted(r.get("ms", 0.0) for r in rows)

    def pct(p: float) -> float:
        idx = min(int(len(times) * p), len(times) - 1)
        return times[idx]

    reasons: dict[str, int] = {}
    for r in rows:
        key = r.get("reason") or r.get("action") or "?"
        reasons[key] = reasons.get(key, 0) + 1
    return {
        "count": len(rows),
        "p50_ms": pct(0.50),
        "p95_ms": pct(0.95),
        "p99_ms": pct(0.99),
        "max_ms": times[-1],
        "model_load_s": _load_seconds,
        "mode": MODE,
        "budget_ms": BUDGET_MS,
        "model": MODEL_ID,
        "reasons": reasons,
    }

if __name__ == "__main__":
    sys.exit(host_main(sys.argv))
