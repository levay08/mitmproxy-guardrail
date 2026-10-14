#!/usr/bin/python3 -I
"""Raise a desktop banner for each new BLOCK line in the audit file."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import queue
import threading
import time

APP_NAME = "LLM Guardrail"
CLOSE_S = 8
POLL_S = 0.5
MAX_BACKLOG = 5
QUEUE: "queue.Queue[dict]" = queue.Queue()
SEEN: dict = {}


def notify(summary: str, body: str) -> int | None:
    cmd = ["gdbus", "call", "--session",
           "--dest", "org.freedesktop.Notifications",
           "--object-path", "/org/freedesktop/Notifications",
           "--method", "org.freedesktop.Notifications.Notify",
           APP_NAME, "0", "security-high", summary, body,
           "[]", "{'urgency': <byte 2>, 'transient': <true>}", str(CLOSE_S * 1000)]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except Exception as exc:  # the watcher must keep running
        print(f"notify error: {exc}", file=sys.stderr, flush=True)
        return None
    if res.returncode != 0:
        print(f"notify failed: {res.stderr.strip()[:200]}", file=sys.stderr, flush=True)
        return None
    found = re.search(r"uint32\s+(\d+)", res.stdout or "")
    return int(found.group(1)) if found else None


def close(note_id: int) -> None:
    cmd = ["gdbus", "call", "--session",
           "--dest", "org.freedesktop.Notifications",
           "--object-path", "/org/freedesktop/Notifications",
           "--method", "org.freedesktop.Notifications.CloseNotification", str(note_id)]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except Exception as exc:  # a stuck banner is not worth a crash
        print(f"close error: {exc}", file=sys.stderr, flush=True)


def show(summary: str, body: str) -> None:
    # critical banners ignore expiry and queue, so show one, then close it
    note_id = notify(summary, body)
    time.sleep(CLOSE_S)
    if note_id is not None:
        close(note_id)


def banner(rec: dict) -> None:
    host = str(rec.get("host") or "unknown host")[:80]
    rule = str(rec.get("rule") or "-")[:60]
    rid = str(rec.get("request_id") or "-")[:16]
    show("Prompt blocked", f"to {host} - rule: {rule}. Nothing was sent. ID: {rid}")


def worker() -> None:
    while True:
        rec = QUEUE.get()
        extra = []
        # a burst past MAX_BACKLOG is summarised, never dropped silently
        while QUEUE.qsize() >= MAX_BACKLOG:
            extra.append(QUEUE.get())
        if extra:
            ids = ", ".join(str(r.get("request_id") or "-")[:8] for r in [rec] + extra[:5])
            show("Prompts blocked", f"{len(extra) + 1} requests blocked in a burst. "
                 f"Nothing was sent. IDs: {ids}. See the audit log.")
        else:
            banner(rec)


def handle(line: str) -> None:
    try:
        rec = json.loads(line)
    except ValueError:
        return
    if not isinstance(rec, dict) or rec.get("action") != "BLOCK":
        return
    rid = rec.get("request_id")
    # the only dedupe: the same request_id written twice is one banner
    if rid is not None:
        if rid in SEEN:
            return
        SEEN[rid] = None
        while len(SEEN) > 512:
            SEEN.pop(next(iter(SEEN)))
    QUEUE.put(rec)


def watch(path: str) -> None:
    fh, ino, pos = None, None, 0
    first = True
    while True:
        try:
            st = os.stat(path)
        except OSError:
            fh, ino = None, None
            time.sleep(POLL_S)
            continue
        if fh is None or st.st_ino != ino or st.st_size < pos:
            if fh:
                fh.close()
            try:
                fh = open(path, "r", encoding="utf-8", errors="replace")
            except OSError:
                fh = None
                time.sleep(POLL_S)
                continue
            ino = st.st_ino
            # history is not replayed; a rotated file is read from the start
            pos = fh.seek(0, os.SEEK_END) if first else 0
            fh.seek(pos)
            first = False
        line = fh.readline()
        if line.endswith("\n"):
            pos = fh.tell()
            handle(line)
        else:
            if line:
                fh.seek(pos)
            time.sleep(POLL_S)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: notify_user.py <audit.jsonl>")
    threading.Thread(target=worker, daemon=True).start()
    watch(sys.argv[1])
