#!/usr/bin/env python3
"""Stop our own leftover instances of this project."""
import os
import signal
import sys
from pathlib import Path
app = sys.argv[1]
mine, pid = set(), os.getpid()
while pid and pid not in mine:
    mine.add(pid)
    try:
        pid = int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[1])
    except (OSError, IndexError, ValueError):
        break


def is_ours(tokens):
    """Only the program being run counts, not its arguments."""
    if tokens and os.path.basename(tokens[0]) == "mitmdump":
        return True
    # runtime modules as a script arg, not a grep pattern
    ours = ("guardrail.py", "router.sh", "panel.sh", "router.py", "panel.py", "sweep.py")
    if len(tokens) > 1 and os.path.basename(tokens[1]) in ours \
            and tokens[1].startswith(app + "/"):
        return True
    for i, token in enumerate(tokens):
        if os.path.basename(token) == "run.sh" and token.startswith(app + "/") \
                and i + 1 < len(tokens) and tokens[i + 1] == "route":
            return True
    return f"-u - {app}" in " ".join(tokens)


def mine_only(entry):
    """Someone else's process is not ours to signal."""
    try:
        return entry.stat().st_uid == os.getuid()
    except OSError:
        return False


for entry in Path("/proc").iterdir():
    if not entry.name.isdigit() or int(entry.name) in mine or not mine_only(entry):
        continue
    try:
        # NUL-separated /proc cmdline: read tokens, not one string
        tokens = (entry / "cmdline").read_bytes().decode("utf-8", "replace").split("\0")
    except OSError:
        continue
    tokens = [t for t in tokens if t]
    if app in " ".join(tokens) and is_ours(tokens):
        try:
            os.kill(int(entry.name), signal.SIGTERM)
            print(f"  stopped a leftover instance: pid {entry.name}")
        except OSError:
            continue          # one process we may not signal cannot stop the sweep
