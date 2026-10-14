#!/usr/bin/env bash
# usage: run.sh install|requirements|route|rollback|panic|verify|watch [opts]
set -u

# ---- route: the worker (was router.sh) --------------------------------------------------------
# worker: reports only, never stops or restarts a program

# needs /proc and ss; say so on non-Linux hosts
route_require_linux() {
  case "$(uname -s)" in
    Linux) ;;
    *) echo "run.sh route: Linux only (needs /proc and ss); $(uname -s) is not supported" >&2; exit 3 ;;
  esac
  if ! command -v ss >/dev/null 2>&1; then
    echo "run.sh route: 'ss' is missing (install iproute2): without it no program can be found" >&2
    exit 3
  fi
}

# 1 when the installed layout owns 8899; ours would loop
route_system_proxy() {
  case "${GUARDRAIL_SYSTEM:-}" in
    0) echo 0 ;;
    1) echo 1 ;;
    *) if [ -x /usr/local/lib/guardrail/venv/bin/mitmdump ] && id guardrail-proxy >/dev/null 2>&1; then
         echo 1
       else
         echo 0
       fi ;;
  esac
}

cmd_route() {
route_require_linux

APP="${GUARDRAIL_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)}"
PORT="${GUARDRAIL_PORT:-8899}"
ONCE=0
SHOW=0
for arg in "$@"; do
  case "$arg" in
    --once) ONCE=1 ;;
    --show) SHOW=1 ;;
    *) echo "run.sh route: unknown option '$arg'" >&2; exit 2 ;;
  esac
done

export GUARDRAIL_APP="$APP" GUARDRAIL_PORT="$PORT" GUARDRAIL_ONCE="$ONCE" GUARDRAIL_SHOW="$SHOW"
export GUARDRAIL_SYSTEM="$(route_system_proxy)"
exec "$APP/.venv/bin/python" -u "$APP/router.py" "$APP"
}


# ---- rollback (was rollback.sh) ---------------------------------------------------------------
rollback_help() {
  cat <<'RBHELP'
# Restore this machine to how it was before the guardrail was installed, and remove what the
# test rounds left behind.
#
# Run it without arguments first: it only prints the plan, one line per action, and changes
# nothing. Add --yes when you have read the plan and want it carried out.
#
#   bash run.sh rollback                  # the plan only
#   bash run.sh rollback --yes            # carry it out
#   bash run.sh rollback --yes --purge-project   # also delete the app folder and ~/.mitmproxy
#
# Nothing here deletes the report, the evidence folders, or the Hermes profile.
set -u

RBHELP
}
# step(), act(), note(): top level so the steps share them
step() { printf '%s) %s\n' "$1" "$2"; }
act() { if [ "$EXEC" = 1 ]; then "$@"; else echo "   will run: $*"; fi; }
note() { echo "   $*"; }

# paths rollback needs: app, interpreter, helper
rollback_setup() {
  APP="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
  PY3="$(command -v python3 || true)"
  [ -x "$APP/.venv/bin/python" ] && PY3="$APP/.venv/bin/python"
  HELPER=/usr/local/sbin/guardrail-adm
  GR_CA_ANCHOR=""
  GR_CA_UPDATE=()
}

# router first: it restarts the proxy; pid checked before kill
rollback_stop_services() {
step 1 "stopping the proxy, the timer and the network rule"
if [ -d /usr/local/lib/guardrail ] || [ -d /var/lib/guardrail ] || id guardrail-proxy >/dev/null 2>&1; then
  if [ -x "$HELPER" ]; then
    if [ "$EXEC" = 1 ]; then
      sudo "$HELPER" uninstall 2>&1 | sed 's/^/   /'
      rc="${PIPESTATUS[0]}"
      [ "$rc" = 0 ] && note "the installed layout was reversed by guardrail-adm uninstall" \
                    || note "uninstall did not finish; run it again: sudo $HELPER uninstall"
    else
      note "will run: sudo $HELPER uninstall  (reverses units, trust, files and the proxy user)"
    fi
  else
    note "helper missing; the installed layout is still present:"
    for d in /usr/local/lib/guardrail /var/lib/guardrail /var/log/guardrail /etc/guardrail; do
      [ -e "$d" ] && note "  $d"
    done
    note "  remove with: sudo rm -rf /usr/local/lib/guardrail /var/lib/guardrail /var/log/guardrail /etc/guardrail"
    id guardrail-proxy >/dev/null 2>&1 && note "  remove the user with: sudo userdel guardrail-proxy"
  fi
else
  note "no installed layout"
fi
for name in router panel; do
  pidfile="$APP/data/$name.pid"
  [ -f "$pidfile" ] || continue
  pid="$(cat "$pidfile" 2>/dev/null)"
  if [ -n "$pid" ] && [ -d "/proc/$pid" ] \
     && grep -qa "run.sh\|$APP" "/proc/$pid/cmdline" 2>/dev/null; then
    act kill "$pid" 2>/dev/null
    [ "$EXEC" = 1 ] && note "$name (pid $pid) stopped"
  fi
  act rm -f "$pidfile"
done
if pgrep -u "$(id -u)" -f mitmdump >/dev/null 2>&1; then
  act pkill -u "$(id -u)" -f mitmdump
  [ "$EXEC" = 1 ] && note "mitmdump of this account was stopped"
else
  note "no mitmdump of this account is running"
fi
}

# 2) restore via the helper, which owns the setting
desktop_proxy_restore() {
  local out
  if [ -x "$HELPER" ] && sudo -n "$HELPER" status >/dev/null 2>&1; then
    out="$(sudo -n "$HELPER" proxy-stop 2>/dev/null)"
    if grep -qi "restored" <<<"$out"; then
      echo "   desktop proxy: the owner's saved setting is back (helper)"
      return 0
    fi
    if grep -qi "never changed the desktop proxy" <<<"$out"; then
      echo "   desktop proxy: the guardrail never changed it; left as it is"
      return 0
    fi
  fi
  if [ -n "$PY3" ] && [ -f "$APP/rules.py" ]; then
    "$PY3" -I "$APP/rules.py" desktop-proxy off | sed 's/^/   /'
    echo "   note: no saved setting was found, so this resets the setting to none"
  fi
}

rollback_restore_desktop_proxy() {
step 2 "restoring the desktop proxy setting"
if [ "$EXEC" = 1 ]; then
  desktop_proxy_restore
else
  note "will run: the helper puts the saved setting back; without it, rules.py desktop-proxy off"
fi
}

# 3) remove the guardrail CA entries from the browser stores.
rollback_remove_browser_ca() {
step 3 "removing the CA entries from the browser stores"
if command -v certutil >/dev/null 2>&1; then
  # same stores rules.py nss_dbs() writes
  nssdirs=("$HOME/.pki/nssdb" "$HOME/.local/share/pki/nssdb")
  for ffroot in "$HOME/.mozilla/firefox" "$HOME/.config/mozilla/firefox" \
                "$HOME/snap/firefox/common/.mozilla/firefox" \
                "$HOME/.var/app/org.mozilla.firefox/.mozilla/firefox"; do
    for d in "$ffroot"/*/; do
      [ -f "${d}cert9.db" ] && nssdirs+=("${d%/}")
    done
  done
  for dir in "${nssdirs[@]}"; do
    [ -d "$dir" ] || continue
    for nick in mitmproxy guardrail; do
      if certutil -d "sql:$dir" -L 2>/dev/null | grep -qx "$nick"; then
        act certutil -d "sql:$dir" -D -n "$nick"
        [ "$EXEC" = 1 ] && note "entry '$nick' removed from $dir"
      else
        note "$dir: no entry '$nick'"
      fi
    done
  done
else
  note "certutil missing, this step is skipped"
fi
}

# 4) remove the guardrail CA from the system trust store.
rollback_remove_trust_ca() {
step 4 "the CA in the system trust store"
found=0
if [ -n "$GR_CA_ANCHOR" ]; then
  for f in "$(dirname "$GR_CA_ANCHOR")/mitmproxy-ca-cert.pem" "$GR_CA_ANCHOR"; do
    if [ -e "$f" ]; then
      found=1
      act sudo rm -f "$f"
      [ "$EXEC" = 1 ] && note "$f removed"
      if [ "${#GR_CA_UPDATE[@]}" -gt 0 ]; then
        act sudo "${GR_CA_UPDATE[@]}"
        [ "$EXEC" = 1 ] && note "${GR_CA_UPDATE[*]} ran"
      fi
    fi
  done
fi
[ "$found" = 0 ] && note "no guardrail CA in the system trust store${GR_CA_ANCHOR:+ ($(dirname "$GR_CA_ANCHOR"))}"
}

# 5) remove CA env files and the files guardrail wrote
rollback_remove_leftover_files() {
step 5 "CA variables and the files the guardrail wrote"
for f in "$HOME/.config/environment.d/guardrail.conf" /etc/environment.d/90-guardrail-ca.conf \
         /etc/profile.d/guardrail-ca.sh; do
  [ -e "$f" ] || continue
  if grep -qiE 'mitmproxy-ca|guardrail-ca' "$f" 2>/dev/null; then
    if [ -w "$f" ]; then
      act rm -f "$f"
      [ "$EXEC" = 1 ] && note "$f removed"
    else
      note "will run: sudo rm -f $f   (owned by root)"
      act sudo rm -f "$f"
    fi
  else
    note "$f exists but does not point at the guardrail CA, left alone"
  fi
done
# Files the guardrail wrote, not files the install created.
tmpfiles=(/tmp/guardrail-run.log /tmp/guardrail-router.log /tmp/guardrail-watch.md
          /tmp/guardrail-ca-bundle.pem)
for f in "${tmpfiles[@]}"; do
  [ -e "$f" ] && act rm -f "$f"
done
}

# 6) check what is left; the redirect rule matters most
rollback_check_leftovers() {
step 6 "checking what is left"
LEFT=0
RULE_UNCONFIRMED=0
# failed uninstall can leave the rule; disarm needs no password
if [ "$EXEC" = 1 ] && [ -x "$HELPER" ] && nft list table inet guardrail >/dev/null 2>&1; then
  if sudo -n "$HELPER" disarm >/dev/null 2>&1; then
    note "the redirect rule was still installed; released it with: guardrail-adm disarm"
  else
    note "CHECK: the redirect rule is still installed and could not be released: sudo $HELPER disarm"
  fi
fi
if [ "$EXEC" = 1 ]; then
  # verify lives here; a subshell keeps its helpers local
  ( cmd_verify ) | sed 's/^/   /'
  ss -ltnH "sport = :8899" 2>/dev/null | grep -q . \
    && note "CHECK: something is still listening on port 8899" || note "OK: port 8899 is free"
  if command -v nft >/dev/null 2>&1; then
    NFT_OUT="$(nft list table inet guardrail 2>&1)"; NFT_RC=$?
    case "$NFT_OUT" in
      *"permitted"*|*"Permission denied"*|*"must be root"*)
        note "cannot be checked without root: nft refuses here (re-run with sudo)"
        RULE_UNCONFIRMED=1 ;;
      *) if [ "$NFT_RC" = 0 ]; then note "CHECK: the guardrail nft table is still there"
         else note "OK: no guardrail nft table"
         fi ;;
    esac
  else
    note "cannot be checked: nft is not on PATH"
    RULE_UNCONFIRMED=1
  fi
  id guardrail-proxy >/dev/null 2>&1 \
    && note "CHECK: the guardrail-proxy user is still there" || note "OK: no guardrail-proxy user"
  if [ -e /etc/sudoers.d/guardrail ] || [ -e /etc/sudoers.d/guardrail-test ]; then
    note "CHECK: the sudoers entry is still there"
  elif [ "$(id -u)" != 0 ] && ! ls /etc/sudoers.d >/dev/null 2>&1; then
    note "cannot be checked without root: /etc/sudoers.d is not readable"
  else
    note "OK: no sudoers entry"
  fi
  [ -e "$HELPER" ] && note "CHECK: the helper is still there" || note "OK: no helper"
  if nft list table inet guardrail >/dev/null 2>&1 \
     || ss -ltnH "sport = :8899" 2>/dev/null | grep -q .; then
    note "CHECK FAILED: the rule or the listener is still here, so this rollback is incomplete"
    LEFT=1
  elif [ "$RULE_UNCONFIRMED" = 1 ]; then
    note "NOT CONFIRMED: the nft rule could not be read here, so its state is unknown"
  fi
else
  note "will check: port 8899, the nft table, the proxy user, the sudoers entry, the helper, and run"
  note "  run.sh verify"
fi
}

# 7) the project files themselves.
rollback_project_files() {
step 7 "project files"
if [ -f "$APP/guardrail.py" ] && [ -f "$APP/run.sh" ]; then
  if [ "$PURGE" = 1 ]; then
    act rm -rf "$APP" "$HOME/.mitmproxy"
  else
    note "$APP is left alone (use --purge-project to delete it)"
  fi
else
  note "$APP does not look like the guardrail app, left untouched"
fi
}

cmd_rollback() {
EXEC=0
PURGE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --yes) EXEC=1 ;;
    --purge-project) PURGE=1 ;;
    --dry-run) EXEC=0 ;;
    -h|--help) rollback_help; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

rollback_setup

if [ "$EXEC" = 1 ]; then
  echo "MODE: running for real (--yes). What is printed below actually happens."
else
  echo "MODE: plan only. Nothing is changed. Add --yes to carry it out."
fi
echo

if [ -n "$PY3" ] && [ -f "$APP/rules.py" ] && detected="$("$PY3" -I "$APP/rules.py" shell)"; then
  eval "$detected"
else
  echo "note: python3 or rules.py missing, steps that need detection are skipped"
fi

rollback_stop_services
rollback_restore_desktop_proxy
rollback_remove_browser_ca
rollback_remove_trust_ca
rollback_remove_leftover_files
rollback_check_leftovers
rollback_project_files

echo
if [ "$EXEC" = 1 ]; then
  if [ "${LEFT:-0}" = 1 ]; then
    echo "rollback INCOMPLETE: see the CHECK FAILED line in step 6. The machine is not back to normal."
    exit 1
  fi
  if [ "${RULE_UNCONFIRMED:-0}" = 1 ]; then
    echo "rollback NOT CONFIRMED: the redirect rule could not be inspected here, so its state is unknown."
    echo "Confirm it with: sudo bash $0 rollback"
    exit 1
  fi
  echo "rollback finished. Read step 6 for anything still left behind."
else
  echo "plan finished. Nothing was changed."
  echo "to carry it out: bash $0 rollback --yes"
fi
}


# ---- panic: the emergency switch (was panic.sh) -----------------------------------------------
# root only: drop the nft redirect, QUIC reject and proxy

# root needed: the proxy runs as guardrail-proxy
panic_require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "needs root: the proxy runs as guardrail-proxy (or an older one as root), so stopping it needs root." >&2
    echo "  sudo bash $0 panic" >&2
    exit 1
  fi
}

# 1) the nft redirect and its own QUIC chain
panic_clear_rules() {
  echo "1) redirect rule"
  if [ -z "$NFT" ]; then
    echo "   nft not found: no nftables rule can exist here, nothing to flush"
  elif $NFT list chain inet guardrail divert >/dev/null 2>&1; then
    $NFT flush chain inet guardrail divert
    echo "   divert chain flushed. table inet guardrail and set ai4 are kept,"
    echo "   so phase2 can be run again without redoing phase1."
  else
    echo "   no divert chain here, nothing to flush"
  fi
  # left behind, the quic chain keeps rejecting UDP 443
  if [ -n "$NFT" ] && $NFT list chain inet guardrail quic >/dev/null 2>&1; then
    $NFT flush chain inet guardrail quic
    echo "   quic chain flushed too, so UDP 443 is no longer rejected"
  fi
}

# router first: it restarts the proxy; check pid before kill
panic_stop_router() {
  RPID="$(cat "$APPDIR/data/router.pid" 2>/dev/null || true)"
  if [ -n "$RPID" ] && [ -d "/proc/$RPID" ] \
     && grep -qa "run.sh\|$APPDIR" "/proc/$RPID/cmdline" 2>/dev/null \
     && [ "$(stat -c %u "/proc/$RPID" 2>/dev/null)" = "$UID_TARGET" ]; then
    kill "$RPID" 2>/dev/null && echo "   router stopped (pid $RPID): it would have restarted the proxy"
    sleep 1
    [ -d "/proc/$RPID" ] && kill -9 "$RPID" 2>/dev/null
    rm -f "$APPDIR/data/router.pid"
  else
    rm -f "$APPDIR/data/router.pid"
    echo "   no router running"
  fi
  # systemd Restart=on-failure would bring a killed proxy back
  if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1 \
     && systemctl is-active --quiet guardrail-proxy.service 2>/dev/null; then
    systemctl stop guardrail-proxy.service && echo "   guardrail-proxy.service stopped (still enabled; it returns at boot)"
  fi
  # an enabled net unit re-adds the rule at next boot
  if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1 \
     && systemctl is-enabled --quiet guardrail-net.service 2>/dev/null; then
    systemctl disable --now guardrail-net.service \
      && echo "   guardrail-net.service disabled: the rule will not come back at boot"
  fi
}

# owner's mitmdump only if ours: guardrail.py or port
panic_stop_proxy() {
  local p held pids
  held="$(ss -ltnpH "sport = :$PORT" 2>/dev/null || true)"
  pids=""
  for p in $(pgrep -u "$UID_TARGET" -f mitmdump 2>/dev/null || true); do
    if grep -qa 'guardrail\.py\|--mode transparent' "/proc/$p/cmdline" 2>/dev/null \
       || grep -q "pid=$p," <<<"$held"; then
      pids="$pids $p"
    else
      echo "   left alone: mitmdump pid $p is not the guardrail's"
    fi
  done
  pids="$( { printf '%s\n' $pids; pgrep -f 'mitmdump --mode transparent' 2>/dev/null || true; } \
           | sort -u | tr '\n' ' ')"
  if [ -n "${pids// /}" ]; then
    kill $pids 2>/dev/null
    sleep 1
    left="$(pgrep -f 'mitmdump --mode transparent' || true)"
    if [ -n "$left" ]; then
      kill -9 $left 2>/dev/null
      echo "   sigterm was not enough, force killed: $left"
    else
      echo "   stopped: $pids"
    fi
  else
    echo "   none running"
  fi
}

# watchdog first, or it reverts a gone proxy
panic_stop_watchdog() {
  local d pid i
  for d in "/run/user/$UID_TARGET/guardrail-watchdog" "/tmp/guardrail-watchdog-$UID_TARGET"; do
    pid="$(cat "$d/watchdog.pid" 2>/dev/null || true)"
    case "$pid" in ''|*[!0-9]*) continue ;; esac
    if [ -d "/proc/$pid" ] && grep -qa "watchdog.py" "/proc/$pid/cmdline" 2>/dev/null \
       && [ "$(stat -c %u "/proc/$pid" 2>/dev/null)" = "$UID_TARGET" ]; then
      if [ -e "$d/reverting" ]; then
        echo "   watchdog (pid $pid) is reverting; it ends by itself"
        return 0
      fi
      kill "$pid" 2>/dev/null
      for i in 1 2 3 4 5; do [ -d "/proc/$pid" ] || break; sleep 1; done
      [ -d "/proc/$pid" ] && kill -9 "$pid" 2>/dev/null
      echo "   watchdog stopped (pid $pid): it would have reverted a proxy that is gone"
      return 0
    fi
  done
  echo "   no watchdog running"
}

# reset via the owner's tool; runs as owner, never root
panic_reset_desktop_proxy() {
  # the helper restored it; a direct reset cannot
  if [ -x "$HELPER" ] && sudo -n "$HELPER" status >/dev/null 2>&1 \
     && sudo -n "$HELPER" proxy-stop 2>/dev/null | grep -qi "restored"; then
    echo "   desktop proxy: the owner's saved setting is back (helper)"
    return 0
  fi
  if [ "$UID_TARGET" = 0 ]; then
    echo "   skipped: run through sudo or pkexec from the owner's account to reset their desktop proxy"
  elif ! command -v python3 >/dev/null 2>&1 || [ ! -f "$HOSTMOD" ]; then
    echo "   skipped: python3 or $HOSTMOD is missing"
    echo "     as $OWNER: python3 $HOSTMOD desktop-proxy off"
  elif command -v runuser >/dev/null 2>&1; then
    runuser -u "$OWNER" -- python3 -I "$HOSTMOD" desktop-proxy off 2>&1 | sed 's/^/   /'
  elif command -v setpriv >/dev/null 2>&1; then
    setpriv --reuid="$UID_TARGET" --regid="$(id -g "$UID_TARGET")" --init-groups -- \
      python3 -I "$HOSTMOD" desktop-proxy off 2>&1 | sed 's/^/   /'
  else
    echo "   skipped: no runuser or setpriv to drop to $OWNER"
    echo "     as $OWNER: python3 $HOSTMOD desktop-proxy off"
  fi
}

# 4) check the port and one real network call
panic_check() {
  if ! command -v ss >/dev/null 2>&1; then
    echo "   ss not found, port $PORT not checked"
  elif ss -ltnH "sport = :$PORT" | grep -q .; then
    echo "   port $PORT is still busy. who holds it:  sudo ss -ltnp | grep $PORT"
  else
    echo "   port $PORT is free"
  fi
  if command -v curl >/dev/null 2>&1; then
    code="$(env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
      curl -m 8 -s -o /dev/null -w '%{http_code}' https://api.anthropic.com/ || true)"
    echo "   test call to api.anthropic.com: HTTP ${code:-no answer}"
  else
    echo "   curl not found, test call skipped"
  fi
}

cmd_panic() {
export PATH="$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PORT=8899
APPDIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
HOSTMOD="$APPDIR/rules.py"
# The owner is whoever called sudo or pkexec.
UID_TARGET="${SUDO_UID:-${PKEXEC_UID:-$(id -u)}}"
OWNER="$(id -nu "$UID_TARGET" 2>/dev/null || echo "$UID_TARGET")"
NFT="$(command -v nft || true)"

panic_require_root
panic_clear_rules

echo "2) watchdog, router and transparent proxy"
panic_stop_watchdog
panic_stop_router
panic_stop_proxy

echo "3) desktop proxy"
panic_reset_desktop_proxy

echo "4) check"
panic_check

echo
echo "done. AI clients can be started again."
}

# ---- verify and watch -------------------------------------------------------------
# verify is read-only; watch only reverses the proxy path
verify_help() {
  cat <<'HELP'
run.sh verify - check a guardrail installation on any Linux host.

Purpose: prove, on a machine that is not the development machine, that the
guardrail is installed and running without the owner having configured
anything by hand. Read-only: it changes nothing.

Usage:  bash run.sh verify [--proxy-user NAME] [--port PORT]
Exit:   0 all critical checks passed, 1 something critical failed.
HELP
}

# ---- verify (from tools/verify-install.sh) ----
cmd_verify() {
  local PROXY_USER="guardrail-proxy"
  local PORT="8899"
  local LIB="/usr/local/lib/guardrail"
  local STATE="/var/lib/guardrail"
  local CONF="$STATE/conf"
  local UNIT="/etc/systemd/system/guardrail-proxy.service"
  local HELPER="/usr/local/sbin/guardrail-adm"

  while [ $# -gt 0 ]; do
    case "$1" in
      --proxy-user) PROXY_USER="${2:-}"; shift 2 ;;
      --port) PORT="${2:-}"; shift 2 ;;
      -h|--help) verify_help; exit 0 ;;
      *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
  done

  local fail=0
  local skip=0

  say() { printf '%-46s %s\n' "$1" "$2"; }
  ok() { say "$1" "OK   $2"; }
  bad() { say "$1" "FAIL $2"; fail=$((fail + 1)); }
  note() { say "$1" "skipped: $2"; skip=$((skip + 1)); }

  have() { command -v "$1" >/dev/null 2>&1; }

  echo "== guardrail installation check =="
  echo "host: $(hostname 2>/dev/null) | kernel: $(uname -r) | time: $(date '+%Y-%m-%d %H:%M:%S %Z')"
  echo

  echo "-- install and permissions --"
  if id "$PROXY_USER" >/dev/null 2>&1; then
    shell_of="$(getent passwd "$PROXY_USER" | cut -d: -f7)"
    case "$shell_of" in
      */nologin|*/false) ok "user $PROXY_USER" "no login shell ($shell_of)" ;;
      *) bad "user $PROXY_USER" "has a login shell ($shell_of); should be nologin" ;;
    esac
  else
    bad "user $PROXY_USER" "not present"
  fi

  if [ -d "$LIB/venv" ]; then
    owner="$(stat -c %U "$LIB/venv" 2>/dev/null)"
    [ "$owner" = root ] && ok "proxy venv" "owned by root ($LIB/venv)" || bad "proxy venv" "owned by $owner, should be root"
    if [ -x "$LIB/venv/bin/mitmdump" ]; then
      perm="$(stat -c %A "$LIB/venv/bin/mitmdump")"
      case "$perm" in
        *w*w*) bad "mitmdump binary" "mode $perm writable by someone else" ;;
        *) ok "mitmdump binary" "mode $perm" ;;
      esac
    else
      bad "mitmdump binary" "missing or not executable"
    fi
  else
    note "proxy venv" "$LIB/venv is not there yet"
  fi

  if [ -d "$LIB/app" ]; then
    owner="$(stat -c %U "$LIB/app" 2>/dev/null)"
    writable_other="$(find "$LIB/app" -perm -o+w -o -perm -g+w 2>/dev/null | head -3)"
    [ "$owner" = root ] && ok "app copy" "owned by root ($LIB/app)" || bad "app copy" "owned by $owner, should be root"
    [ -z "$writable_other" ] && ok "app files" "not writable by anyone else" \
      || bad "app files" "writable by someone else: $(echo "$writable_other" | tr '\n' ' ')"
  else
    note "app copy" "$LIB/app is not there yet"
  fi

  if [ -d "$CONF" ]; then
    owner="$(stat -c %U "$CONF" 2>/dev/null)"
    perm="$(stat -c %a "$CONF" 2>/dev/null)"
    [ "$owner" = "$PROXY_USER" ] && ok "config dir" "owned by $PROXY_USER, mode $perm" \
      || bad "config dir" "owned by $owner, should be $PROXY_USER"
    [ "$perm" = "700" ] || say "  note" "mode $perm, should be 700"
  else
    note "config dir" "$CONF is not there yet"
  fi

  echo
  echo "-- CA identity (must be the same everywhere) --"
  fp() { openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2; }
  conf_ca=""
  if [ ! -d "$CONF" ]; then
    note "CA in config dir" "$CONF is not there yet"
  elif [ ! -r "$CONF" ]; then
    note "CA in config dir" "cannot be read without root (mode 700, owned by the proxy user); check with: sudo guardrail-adm verify"
  else
    for c in "$CONF/mitmproxy-ca-cert.pem" "$CONF/mitmproxy-ca.pem" "$CONF/guardrail-ca.pem"; do
      [ -f "$c" ] && conf_ca="$(fp "$c")" && break
    done
    if [ -n "$conf_ca" ]; then
      ok "CA in config dir" "${conf_ca:0:24}..."
    else
      bad "CA in config dir" "the directory is readable but holds no certificate"
    fi
  fi

  anchor=""
  for a in /etc/pki/trust/anchors/guardrail-ca.pem /etc/pki/ca-trust/source/anchors/guardrail-ca.pem \
           /usr/local/share/ca-certificates/guardrail-ca.crt /etc/ca-certificates/trust-source/anchors/guardrail-ca.pem; do
    [ -f "$a" ] && anchor="$a" && break
  done
  if [ -n "$anchor" ]; then
    if [ -z "$conf_ca" ]; then
      note "CA in the trust store" "an anchor exists at $anchor, but the proxy CA is not there yet, so they cannot be compared"
    else
      a_fp="$(fp "$anchor")"
      [ "$a_fp" = "$conf_ca" ] && ok "CA in the trust store" "same as the proxy's" \
        || bad "CA in the trust store" "differs from the proxy's ($anchor)"
    fi
  else
    note "CA in the trust store" "no anchor; skipped if this distro uses another path"
  fi

  env_out=""
  for e in "$HOME/.config/environment.d/guardrail.conf" /etc/environment.d/90-guardrail-ca.conf /etc/profile.d/guardrail-ca.sh; do
    [ -f "$e" ] && env_out="$e" && break
  done
  if [ -n "$env_out" ]; then
    if grep -q "mitmproxy-ca-cert.pem\|guardrail-ca" "$env_out" 2>/dev/null; then
      ok "CA variables for clients" "$env_out"
    else
      bad "CA variables for clients" "$env_out exists but does not point at the CA"
    fi
  else
    note "CA variables for clients" "environment.d and profile.d are not present"
  fi

  echo
  echo "-- services and rule --"
  if [ -f "$UNIT" ]; then
    if grep -qE "^User=$PROXY_USER$" "$UNIT"; then
      ok "systemd unit" "User=$PROXY_USER, does not run as root"
    else
      bad "systemd unit" "does not use User=$PROXY_USER"
    fi
  else
    note "systemd unit" "$UNIT is not there yet"
  fi

  if have systemctl; then
    st="$(systemctl is-active guardrail-proxy 2>/dev/null)"
    [ "$st" = active ] && ok "proxy service" "active" || say "proxy service" "state $st"
  fi

  NFT_BIN="$(command -v nft || echo /usr/sbin/nft)"
  if [ -x "$NFT_BIN" ]; then
    nft_out="$("$NFT_BIN" list table inet guardrail 2>&1)"
    case "$nft_out" in
      *[Pp]ermission*|*"must be root"*|*"not permitted"*)
        # a chain that exists is invisible to a plain user
        note "nft table" "cannot be read without root (check with: sudo $HELPER verify)" ;;
      *)
        if [ -n "$nft_out" ]; then
          ok "nft table" "inet guardrail is there"
          "$NFT_BIN" list chain inet guardrail quic >/dev/null 2>&1 \
            && ok "QUIC closure" "the quic chain is there" || bad "QUIC closure" "the quic chain is missing"
        else
          say "nft table" "not installed yet (normal while the proxy is not in use)"
        fi ;;
    esac
  else
    note "nft table" "nft is not present"
  fi

  listeners=""
  for fam in 127.0.0.1 ::1; do
    if have ss; then
      ss -ltnH "sport = :$PORT" 2>/dev/null | grep -q "$fam" && listeners="$listeners $fam"
    fi
  done
  if [ -n "$listeners" ]; then
    ok "proxy listener" "port $PORT on$listeners"
  else
    say "proxy listener" "port $PORT nothing is listening (normal while the proxy is stopped)"
  fi

  echo
  echo "-- the proxy must not run as root --"
  root_proxy=""
  if have ss && have ps; then
    pids="$(ss -ltnpH "sport = :$PORT" 2>/dev/null | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u)"
    if [ -z "$pids" ]; then
      if have pgrep; then
        other="$(pgrep -u "$(id -u "$PROXY_USER" 2>/dev/null || echo nobody)" -f mitmdump 2>/dev/null | head -3)"
        if [ -n "$other" ]; then
          ok "proxy process owner" "started by $PROXY_USER (pid $(echo "$other" | tr '\n' ' ')); ss without root does not show other users' pids"
        else
          note "proxy process owner" "no process on port $PORT"
        fi
      fi
    else
      for p in $pids; do
        u="$(ps -o user= -p "$p" 2>/dev/null | tr -d ' ')"
        case "$u" in
          ""|root) root_proxy="$root_proxy $p" ;;
          *) ok "proxy process owner" "pid $p is started by $u" ;;
        esac
      done
      [ -n "$root_proxy" ] && bad "proxy process owner" "still running as root: pid$root_proxy"
    fi
    for p in $(ps -eo user=,args= | awk '/mitmdump --mode [t]ransparent/ {print $1}' | sort -u); do
      [ "$p" = root ] && bad "no proxy running as root" "a mitmdump process is owned by root"
    done
    ps -eo user=,args= | grep -q "^root .*mitmdump --mode [t]ransparent" || ok "no proxy running as root" "not one of them runs as root"
  fi

  echo
  echo "-- summary --"
  if [ "$fail" -eq 0 ]; then
    echo "PASS: no important check failed. ($skip skipped because that part is not on this host)"
    exit 0
  fi
  echo "FAIL: $fail important checks failed. ($skip skipped)"
  exit 1
}

# ---- watch (from tools/watchdog-api.sh) ----
cmd_watch() {
  export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

  local HELPER=/usr/local/sbin/guardrail-adm
  # the router pidfile is read here too
  local APP="${GUARDRAIL_HOME:-$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]:-$0}")")" && pwd)}"
  local PORT="${GUARDRAIL_PORT:-8899}"
  local INTERVAL="${WATCHDOG_INTERVAL:-20}"
  local FAILS="${WATCHDOG_FAILS:-5}"
  local PIDFILE="${TMPDIR:-/tmp}/guardrail-watchdog.pid"
  local LOGFILE="${TMPDIR:-/tmp}/guardrail-watchdog.log"
  local STREAK="${TMPDIR:-/tmp}/guardrail-watchdog.streak"
  local HOSTMOD
  HOSTMOD="$(cd "$(dirname "$(readlink -f "$0")")" 2>/dev/null && pwd)/rules.py"

  # owner's endpoints: DeepSeek, ai.paas.id, Claude, Gemini
  local ENDPOINTS="https://api.deepseek.com/v1/chat/completions
https://ai.paas.id/v1/chat/completions
https://api.anthropic.com/v1/messages
https://generativelanguage.googleapis.com/v1beta/models"

  local PROMPT='{"model":"health","messages":[{"role":"user","content":"ping"}],"max_tokens":1}'

  log() { printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >>"$LOGFILE"; }

  notify_owner() {
    [ "${WATCHDOG_NO_NOTIFY:-0}" = 1 ] && return 0
    local uid secs ms id; uid="$(id -u)"
    [ -S "/run/user/$uid/bus" ] || return 0
    # the banner must leave the screen on its own
    secs="$(awk -v s="${GUARDRAIL_NOTIFY_CLOSE_S:-6}" 'BEGIN { printf "%d", s }')" || secs=""
    [ -n "$secs" ] || secs=6
    ms="$(( secs * 1000 ))"
    export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus"
    if command -v gdbus >/dev/null 2>&1; then
      id="$(gdbus call --session --dest org.freedesktop.Notifications \
        --object-path /org/freedesktop/Notifications \
        --method org.freedesktop.Notifications.Notify \
        "Guardrail" 0 "dialog-warning" "Guardrail" "$1" "[]" \
        "{'urgency': <byte 2>, 'transient': <true>}" "$ms" 2>/dev/null \
        | sed -n 's/.*uint32 \([0-9]\{1,\}\).*/\1/p')"
      if [ -n "$id" ]; then
        # close it by id; critical banners outlive timeouts
        ( sleep "$secs"; gdbus call --session --dest org.freedesktop.Notifications \
            --object-path /org/freedesktop/Notifications \
            --method org.freedesktop.Notifications.CloseNotification "$id" \
            >/dev/null 2>&1 ) &
        return 0
      fi
    fi
    command -v notify-send >/dev/null 2>&1 || return 0
    notify-send -t "$ms" -u critical "Guardrail" "$1" 2>/dev/null || true
  }

  # 0 if any answers; a guardrail refusal counts as dead
  call_endpoints() {
    local url host code alive=1 body head
    for url in $ENDPOINTS; do
      host="${url#https://}"; host="${host%%/*}"
      body="$(mktemp)"; head="$(mktemp)"
      code="$(env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
        curl -m 10 -s -o "$body" -D "$head" -w '%{http_code}' -H 'Content-Type: application/json' \
        -d "$PROMPT" "$url" 2>/dev/null)"
      # only 'blocked' counts; a warn header is not an outage
      if grep -q 'guardrail_block' "$body" 2>/dev/null \
         || grep -qiE '^x-llm-guardrail: *blocked' "$head" 2>/dev/null; then
        printf '   %-38s HTTP %s  (refused by the guardrail)\n' "$host" "${code:-000}"
        rm -f "$body" "$head"
        continue
      fi
      printf '   %-38s HTTP %s\n' "$host" "${code:-000}"
      case "${code:-000}" in
        000|502|503|504) : ;;                  # dead, or something answered that is not the provider
        *) alive=0 ;;
      esac
      rm -f "$body" "$head"
    done
    return $alive
  }

  # no proxy, non-AI page: dead network or our block
  probe_neutral() {
    local url
    for url in ${GUARDRAIL_NEUTRAL_URLS:-https://example.com https://www.wikipedia.org}; do
      env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
        curl -m 8 -s -o /dev/null "$url" && return 0
    done
    return 1
  }

  rules_installed() {
    [ "${WATCHDOG_FORCE_RULES:-0}" = 1 ] && return 0
    [ -x "$HELPER" ] || return 1
    sudo -n "$HELPER" status 2>/dev/null | grep -qE "redirect to|udp dport 443 .* (drop|reject)"
  }

  proxy_listening() {
    command -v ss >/dev/null 2>&1 || return 0
    ss -ltnH "sport = :$PORT" 2>/dev/null | grep -q .
  }

  # stay quiet while a known suite is running
  round_running() { pgrep -f "rerun_round.sh|run_suites.sh" >/dev/null 2>&1; }

  restore_access() {
    log "PANIC: restoring AI access (threshold of $FAILS failures reached)"
    # the router restarts the proxy: kill it first
    local rpid
    rpid="$(cat "$APP/data/router.pid" 2>/dev/null || true)"
    if [ -n "$rpid" ] && [ -d "/proc/$rpid" ] \
       && grep -qa "run.sh\|$APP" "/proc/$rpid/cmdline" 2>/dev/null \
       && [ "$(stat -c %u "/proc/$rpid" 2>/dev/null)" = "$(id -u)" ]; then
      kill "$rpid" 2>/dev/null && log "  router stopped (pid $rpid)"
      sleep 1
      [ -d "/proc/$rpid" ] && kill -9 "$rpid" 2>/dev/null
    else
      log "  no router of ours is running"
    fi
    rm -f "$APP/data/router.pid" "$APP/data/panel.pid"
    if [ -x "$HELPER" ] && sudo -n "$HELPER" status >/dev/null 2>&1; then
      sudo -n "$HELPER" disarm     >>"$LOGFILE" 2>&1 || log "  disarm failed"
      sudo -n "$HELPER" proxy-stop >>"$LOGFILE" 2>&1 || log "  proxy-stop failed"
      # the helper already restored the owner's setting
    else
      log "  helper not available; run it yourself: sudo bash $(dirname "$0")/run.sh panic"
      [ -f "$HOSTMOD" ] && python3 -I "$HOSTMOD" desktop-proxy off >>"$LOGFILE" 2>&1
    fi
    [ -f "$STREAK" ] && rm -f "$STREAK"
    # say what actually happened instead of assuming it worked
    if call_endpoints >/dev/null 2>&1; then
      log "PANIC: done, access is back"
      notify_owner "AI access restored: the redirect rule was released and the proxy stopped."
    elif ! probe_neutral; then
      log "PANIC: done, but this machine still has no network; the guardrail was not the cause"
      notify_owner "This machine has no network at all; the guardrail was not the cause."
    else
      log "PANIC: access is still not back; something else is in the path"
      notify_owner "AI access is still blocked; the guardrail was not the only cause."
    fi
  }

  # our own block is the outage; judge the newest once
  GR_SEEN="${STREAK%.streak}.seen"
  blocked_by_us() {
    [ -x "$HELPER" ] || return 1
    local newest marker
    newest="$(sudo -n "$HELPER" status 2>/dev/null | grep -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}T' | tail -1)"
    [ -n "$newest" ] || return 1
    marker="$(printf '%s' "$newest" | cut -c1-60)"
    [ "$(cat "$GR_SEEN" 2>/dev/null)" = "$marker" ] && return 1
    printf '%s' "$marker" >"$GR_SEEN" 2>/dev/null
    printf '%s\n' "$newest" | grep -qE '[[:space:]]BLOCK[[:space:]]'
  }

  check_once() {
    local rules=no listening=no answer=no blocked=no neutral=no
    rules_installed && rules=yes
    proxy_listening && listening=yes
    blocked_by_us && blocked=yes
    probe_neutral && neutral=yes
    echo "redirect rule   : $rules"
    echo "proxy :$PORT     : $listening"
    echo "neutral site    : $neutral"
    echo "last blocked     : $blocked"
    echo "prompt calls    :"
    if call_endpoints >/dev/null 2>&1; then answer=yes; fi
    # our outage only: AI silent, network alive
    [ "$answer" = yes ] && return 0
    [ "$rules" = no ] && return 0
    [ "$neutral" = yes ] || return 0
    [ "$blocked" = yes ] && return 1
    return 1
  }

  case "${1:---check}" in
    --check)
      if round_running; then
        echo "a test round is running: the watchdog stays quiet (the rule was installed on purpose)"
        exit 0
      fi
      call_endpoints
      if check_once; then
        rm -f "$STREAK"
        echo "healthy"
        exit 0
      fi
      n=0; [ -f "$STREAK" ] && n="$(cat "$STREAK" 2>/dev/null || echo 0)"
      n=$((n + 1)); echo "$n" >"$STREAK"
      echo "unhealthy: failure $n of $FAILS"
      if [ "$n" -ge "$FAILS" ]; then restore_access; else echo "not restoring yet: threshold $FAILS"; fi
      ;;
    --probe)
      rounds="${PROBE_ROUNDS:-2}"; calls="${PROBE_CALLS:-5}"; bad_rounds=0; r=1
      while [ "$r" -le "$rounds" ]; do
        echo "== round $r of $rounds =="
        i=1; bad=0
        while [ "$i" -le "$calls" ]; do
          printf 'call %s/%s:\n' "$i" "$calls"
          call_endpoints || bad=$((bad + 1))
          i=$((i + 1))
        done
        echo "   round $r summary: $bad failed of $calls"
        [ "$bad" -gt 0 ] && bad_rounds=$((bad_rounds + 1))
        echo "   session closed, 5 second pause"
        sleep 5
        r=$((r + 1))
      done
      echo
      if [ "$bad_rounds" -eq 0 ]; then
        echo "VERDICT: $((rounds * calls)) prompt calls all answered."
      else
        echo "VERDICT: $bad_rounds of $rounds rounds had failures."
      fi
      ;;
    --start)
      if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; then
        echo "watchdog is already running (pid $(cat "$PIDFILE"))"; exit 0
      fi
      setsid nohup bash "$0" watch --run >>"$LOGFILE" 2>&1 &
      echo $! >"$PIDFILE"; echo "watchdog running (pid $(cat "$PIDFILE")); log $LOGFILE"
      ;;
    --run)
      log "watchdog started: interval ${INTERVAL}s, threshold ${FAILS}x"
      while :; do
        if round_running || check_once >/dev/null 2>&1; then
          rm -f "$STREAK"
        else
          n=0; [ -f "$STREAK" ] && n="$(cat "$STREAK" 2>/dev/null || echo 0)"
          n=$((n + 1)); echo "$n" >"$STREAK"; log "unhealthy, $n of $FAILS"
          [ "$n" -ge "$FAILS" ] && restore_access
        fi
        sleep "$INTERVAL"
      done
      ;;
    --stop)  [ -f "$PIDFILE" ] && { kill "$(cat "$PIDFILE")" 2>/dev/null; rm -f "$PIDFILE"; echo "watchdog stopped"; } || echo "watchdog is not running" ;;
    --status)
      if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; then
        echo "watchdog: running (pid $(cat "$PIDFILE"))"; else echo "watchdog: not running"; fi
      call_endpoints
      echo "last log lines:"; tail -2 "$LOGFILE" 2>/dev/null | sed 's/^/  /'
      ;;
    *) echo "usage: $0 watch [--check|--probe|--start|--stop|--status]" >&2; exit 2 ;;
  esac
}


# first run: hand the privileged work to the root tool
cmd_install() {
  local helper; helper="$(root_tool install)" || return 3
  # --dry-run only prints the plan, so no root needed
  case " $* " in *" --dry-run "*) bash "$helper" install "$@" ; return $? ;; esac
  if [ "$(id -u)" = 0 ]; then bash "$helper" install "$@"; else
    echo "run.sh install: needs root, running: sudo bash $helper install"
    sudo bash "$helper" install "$@"
  fi
}
# the root tool, installed first, then beside this script
root_tool() {
  local here h=/usr/local/sbin/guardrail-adm
  here="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
  # install uses the helper beside this script
  case "${1:-}" in
    install|uninstall|requirements)
      [ -f "$here/guardrail-adm" ] && { echo "$here/guardrail-adm"; return 0; } ;;
  esac
  [ -f "$h" ] || h="$here/guardrail-adm"
  [ -f "$h" ] || { echo "run.sh: guardrail-adm not found; run this from the project folder" >&2; return 3; }
  echo "$h"
}
# read-only prerequisite check; changes nothing
cmd_requirements() {
  local helper; helper="$(root_tool requirements)" || return 3
  bash "$helper" requirements "$@"
}

# subcommands first, so panic works with a broken venv
case "${1:-}" in
  route)    shift; cmd_route "$@"    ; exit $? ;;
  rollback) shift; cmd_rollback "$@" ; exit $? ;;
  panic)    shift; cmd_panic "$@"    ; exit $? ;;
  install)  shift; cmd_install "$@"      ; exit $? ;;
  requirements) shift; cmd_requirements "$@" ; exit $? ;;
  verify|v) shift; ( cmd_verify "$@" ) ; exit $? ;;
  watch|w)  shift; ( cmd_watch  "$@" ) ; exit $? ;;
esac


MODE="${GUARDRAIL_MODE:-}"
STOP=0
CMD=()
while [ $# -gt 0 ]; do
  case "$1" in
    --stop) STOP=1; shift ;;
    --mode) MODE="${2:-}"; shift 2 ;;
    --) shift; CMD=("$@"); break ;;
    *) echo "run.sh: unknown option '$1'" >&2; exit 2 ;;
  esac
done
case "$MODE" in
  persistent|neutral|"") ;;
  *) echo "run.sh: unknown mode '$MODE' (use persistent or neutral)" >&2; exit 2 ;;
esac

# not installed: show one command, then stop

# never for --stop, a wrapped command, or GUARDRAIL_SYSTEM=0
if [ ! -d /usr/local/lib/guardrail/app ] && [ "$STOP" != 1 ] && [ "${#CMD[@]}" = 0 ] \
   && [ "${GUARDRAIL_SYSTEM:-}" != 0 ]; then
  cat <<'FIRST'
Guardrail is not installed on this machine yet.
  bash run.sh requirements    check the prerequisite tools, changes nothing
  bash run.sh install         installs it from scratch (asks for your password)
FIRST
  exit 2
fi

# Linux only: needs /proc and ss; say so elsewhere
case "$(uname -s)" in
  Linux) ;;
  *) echo "run.sh: Linux only (needs /proc and ss); $(uname -s) is not supported" >&2; exit 3 ;;
esac
if ! command -v ss >/dev/null 2>&1; then
  echo "run.sh: 'ss' is missing (install iproute2): without it no program can be found" >&2
  exit 3
fi

# the app is where this script lives
APP="${GUARDRAIL_HOME:-$(cd "$(dirname "$(readlink -f "$0")")" && pwd)}"
PY3="$APP/.venv/bin/python"
[ -x "$PY3" ] || PY3="$(command -v python3 || true)"
if [ -z "$PY3" ] || [ ! -f "$APP/rules.py" ]; then
  echo "run.sh: no python3 and no $APP/.venv: create the venv first (python3 -m venv .venv)" >&2
  exit 3
fi
detected="$("$PY3" -I "$APP/rules.py" shell)" || { echo "run.sh: host detection failed" >&2; exit 3; }
eval "$detected"
# installed layout owns 8899; force with GUARDRAIL_SYSTEM=0 or 1
SYS_LIB="${GUARDRAIL_SYS_LIB:-/usr/local/lib/guardrail}"
case "${GUARDRAIL_SYSTEM:-}" in
  0) SYSTEM=0 ;;
  1) SYSTEM=1 ;;
  *) SYSTEM=0
     if [ -x "$SYS_LIB/venv/bin/mitmdump" ] && id guardrail-proxy >/dev/null 2>&1; then SYSTEM=1; fi ;;
esac
# installed PAC lives outside the project; point tools at it
if [ "$SYSTEM" = 1 ]; then
  export GUARDRAIL_PAC="${GUARDRAIL_PAC:-/var/lib/guardrail/pac/guardrail.pac}"
fi
if [ "$SYSTEM" = 0 ] && { [ "$GR_VENV_OK" != 1 ] || [ ! -x "$APP/.venv/bin/mitmdump" ]; }; then
  echo "run.sh: $APP/.venv is missing, has no mitmdump, or is older than Python 3.11" >&2
  exit 3
fi
PORT="${GUARDRAIL_PORT:-8899}"
LOG="${GUARDRAIL_WRAP_LOG:-/tmp/guardrail-run.log}"
ROUTER_LOG="${GUARDRAIL_ROUTER_LOG:-/tmp/guardrail-router.log}"
if [ "$SYSTEM" = 1 ] && [ -r "$SYS_LIB/guardrail-ca.pem" ]; then
  CA="${GUARDRAIL_CA:-$SYS_LIB/guardrail-ca.pem}"
else
  CA="${GUARDRAIL_CA:-$HOME/.mitmproxy/mitmproxy-ca-cert.pem}"
fi
# CA bundle needs public roots too, and a non-empty marker
CA_MARKER=""
[ -r "$CA" ] && CA_MARKER="$(sed -n '2p' "$CA")"
CA_BUNDLE=""
# GR_CA_BUNDLE is the distro bundle; phase 3 builds its own
for f in "${GUARDRAIL_CA_BUNDLE:-}" "$GR_CA_BUNDLE" /etc/guardrail/ca-bundle.pem "$APP/ca-bundle.pem"; do
  if [ -n "$f" ] && [ -f "$f" ] && [ -n "$CA_MARKER" ] && grep -qF "$CA_MARKER" "$f"; then
    CA_BUNDLE="$f"
    break
  fi
done
CA_BUNDLE="${CA_BUNDLE:-$CA}"

listening() { (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; }

# someone else on the port: clients go uninspected
holder_ok() {
  if [ "$SYSTEM" = 1 ]; then
    sudo -n /usr/local/sbin/guardrail-adm status 2>/dev/null | grep -q "running as: guardrail-proxy"
  else
    ss -ltnpH "sport = :$PORT" 2>/dev/null | grep -q "mitmdump"
  fi
}

# in transparent mode the kernel rule carries the client
armed_rule_present() {
  sudo -n /usr/local/sbin/guardrail-adm status 2>/dev/null | grep -q "redirect to"
}

# our processes from an earlier call, minus this session
sweep() {
  "$PY3" "$APP/sweep.py" "$APP"
}
# router execs into python; its pid file is the check
router_running() {
  local pidfile="$APP/data/router.pid" pid
  [ -f "$pidfile" ] || return 1
  pid="$(cat "$pidfile" 2>/dev/null)"
  [ -n "$pid" ] && [ -d "/proc/$pid" ]
}

if [ "$STOP" = "1" ]; then
  sweep
  # stop the two pids this project wrote down
  for name in router guardrail; do
    pidfile="$APP/data/$name.pid"
    [ -f "$pidfile" ] || continue
    pid="$(cat "$pidfile" 2>/dev/null)"
    if [ -n "$pid" ] && [ -d "/proc/$pid" ] && grep -qa "llm-guardrail\|mitmdump" "/proc/$pid/cmdline"; then
      kill "$pid" 2>/dev/null && echo "$name (pid $pid) stopped"
    fi
    rm -f "$pidfile"
  done
  rm -f "$APP/data/mode" "$APP/data/tag" "$APP/data/panel.pid" 2>/dev/null
  if [ "$SYSTEM" = 1 ]; then
    # the system proxy still runs, so its setting stays
    echo "guardrail and router stopped"
    echo "the system proxy (guardrail-proxy) keeps running; stop it with: sudo /usr/local/sbin/guardrail-adm proxy-stop"
    exit 0
  fi
  # no proxy tool: says skipped, not failed
  "$PY3" -I "$APP/rules.py" desktop-proxy off
  echo "guardrail and router stopped"
  exit 0
fi

# 1) the guardrail itself
if [ -n "$MODE" ]; then
  if [ "$SYSTEM" = 1 ]; then
    # the system proxy reads its own state file
    sudo -n /usr/local/sbin/guardrail-adm mode "$MODE" 2>/dev/null \
      || echo "run.sh: mode not set for the installed proxy; run: sudo /usr/local/sbin/guardrail-adm mode $MODE" >&2
  else
    mkdir -p "$APP/data" 2>/dev/null
    printf '%s\n' "$MODE" > "$APP/data/mode" 2>/dev/null
  fi
fi
if [ "$SYSTEM" = 1 ]; then
  listening || echo "run.sh: the system proxy is not listening on $PORT; start it with: sudo /usr/local/sbin/guardrail-adm proxy-start" >&2
elif ! listening; then
  [ -f "$LOG" ] && chmod 600 "$LOG" 2>/dev/null
  # the log holds headers, so it must never be world-readable
  ( umask 077; cd "$APP" && setsid nohup .venv/bin/mitmdump --set flow_detail=1 >>"$LOG" 2>&1 < /dev/null & ) >/dev/null 2>&1
  for _ in $(seq 1 120); do
    listening && break
    sleep 0.5
  done
  # saying nothing here execs the client against a dead port
  if ! listening; then
    echo "run.sh: the guardrail did not listen on $PORT within 60s; see $LOG" >&2
    exit 3
  fi
elif ! holder_ok; then
  echo "run.sh: port $PORT is held by something that is not this guardrail; clients started from here would go uninspected" >&2
fi

# 2) the router, silent, in the background
if ! router_running; then
  ( cd "$APP" && GUARDRAIL_HOME="$APP" setsid nohup "$APP/run.sh" route >>"$ROUTER_LOG" 2>&1 < /dev/null & ) >/dev/null 2>&1
  sleep 1
fi

# 3) -- cmd runs through the guardrail with the CA
if [ "${#CMD[@]}" -gt 0 ]; then
  if [ -z "$CA_MARKER" ]; then
    echo "run.sh: guardrail CA not found or unreadable ($CA): cannot pick a trusted bundle" >&2
    exit 3
  fi
  if ! command -v "${CMD[0]}" >/dev/null 2>&1; then
    echo "run.sh: '${CMD[0]}' is not installed or not on PATH" >&2
    exit 127
  fi
  if ! holder_ok; then
    echo "run.sh: port $PORT is held by something that is not this guardrail; not starting '${CMD[0]}' uninspected" >&2
    exit 3
  fi
  if [ "$SYSTEM" = 1 ]; then
    # transparent mode needs no proxy vars; the kernel rule sends
    if ! listening; then
      echo "run.sh: the system proxy is down; not starting '${CMD[0]}' uninspected" >&2
      exit 3
    fi
    # without the rule this client leaves uninspected
    if ! armed_rule_present; then
      if [ "${GUARDRAIL_ALLOW_UNARMED:-0}" != "1" ]; then
        echo "run.sh: the kernel rule is not armed, so '${CMD[0]}' would bypass the guardrail" >&2
        echo "         arm it first:  sudo /usr/local/sbin/guardrail-adm arm 30m" >&2
        echo "         or accept the risk:  GUARDRAIL_ALLOW_UNARMED=1 run.sh ${CMD[*]}" >&2
        exit 3
      fi
      echo "run.sh: warning, the kernel rule is not armed and GUARDRAIL_ALLOW_UNARMED=1 was set" >&2
    fi
    export SSL_CERT_FILE="$CA_BUNDLE" REQUESTS_CA_BUNDLE="$CA_BUNDLE" CURL_CA_BUNDLE="$CA_BUNDLE" NODE_EXTRA_CA_CERTS="$CA"
    echo "run.sh: system proxy as guardrail-proxy; traffic goes in through the kernel rule: ${CMD[*]}"
    echo "run.sh: check the rule is armed with: sudo /usr/local/sbin/guardrail-adm status"
    exec "${CMD[@]}"
  fi
  export https_proxy="http://127.0.0.1:$PORT" http_proxy="http://127.0.0.1:$PORT"
  export HTTPS_PROXY="$https_proxy" HTTP_PROXY="$http_proxy"
  export no_proxy="localhost,127.0.0.1,::1"
  export NO_PROXY="$no_proxy"
  export SSL_CERT_FILE="$CA_BUNDLE" REQUESTS_CA_BUNDLE="$CA_BUNDLE" CURL_CA_BUNDLE="$CA_BUNDLE" NODE_EXTRA_CA_CERTS="$CA"
  echo "run.sh: through the guardrail on 127.0.0.1:$PORT: ${CMD[*]}"
  exec "${CMD[@]}"
fi

# 4) panel prints only on change; this pid is protected
mkdir -p "$APP/data" 2>/dev/null
printf '%s\n' "$$" > "$APP/data/panel.pid" 2>/dev/null
[ "$SYSTEM" = 1 ] && echo "run.sh: the guardrail on $PORT is the system proxy (guardrail-proxy); its records are in /var/lib/guardrail/state"
exec "$PY3" -u "$APP/panel.py" "$APP" "$PORT"
