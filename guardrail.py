"""LLM guardrail: mitmproxy addon, config loader and CLI."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import re
import threading
import time
import uuid

from mitmproxy import ctx, http
from mitmproxy.proxy.mode_specs import ProxyMode
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timedelta

import rules


def _rules_stamp() -> tuple[int, int] | None:
    try:
        st = os.stat(getattr(rules, "__file__", ""))
        return st.st_mtime_ns, st.st_size
    except OSError:
        return None


# kept on the module so a reload keeps it
_RULES_LOADED = vars(rules).setdefault("_GR_STAMP", _rules_stamp())

# model budget per request (ms); rules.py sets the default
SEM_BUDGET_MS = rules.env_number("GUARDRAIL_SEMANTIC_BUDGET_MS", rules.BUDGET_MS)
SEM_MIN_CHARS = rules.env_number("GUARDRAIL_SEMANTIC_MIN_CHARS", 25)
# short texts: only multi-word person names count
SEM_SHORT_MIN_CHARS = rules.env_number("GUARDRAIL_SEMANTIC_SHORT_MIN_CHARS", 8)
SHORT_ONLY_PERSON = frozenset(label.lower() for label in rules.LABELS) - {"person", "nama orang"}
SEM_HARD_MS = rules.env_number("GUARDRAIL_SEMANTIC_HARD_MS", 6000)
SEM_LOAD_WAIT_MS = rules.env_number("GUARDRAIL_SEMANTIC_LOAD_WAIT_MS", 45000)

# external modes: off, audit (record), warn, enforce (may block)
EXTERNAL_MODE = os.environ.get("GUARDRAIL_EXTERNAL", "").lower()
EXTERNAL_BUDGET_MS = rules.env_number("GUARDRAIL_EXTERNAL_BUDGET_MS", 60)
EXTERNAL_MAX_TEXTS = rules.env_number("GUARDRAIL_EXTERNAL_MAX_TEXTS", 3)
EXTERNAL_MAX_CHARS = rules.env_number("GUARDRAIL_EXTERNAL_MAX_CHARS", 6000)
EXTERNAL_MAX_DOC_TEXTS = rules.env_number("GUARDRAIL_EXTERNAL_MAX_DOC_TEXTS", 2)
EXTERNAL_MAX_DOC_CHARS = rules.env_number("GUARDRAIL_EXTERNAL_MAX_DOC_CHARS", 4000)

# clients read 403 as a key error; say otherwise
BLOCK_NOT_KEY = "This is a guardrail block, not an API key or provider error."

# telemetry paths: recorded, but never read as prompts
TELEMETRY_PATHS = ("/api/eval/", "/api/event_logging/")


def _is_telemetry(path: str) -> bool:
    return path.split("?", 1)[0].startswith(TELEMETRY_PATHS)


def _tool_result_texts(block: dict) -> list[str]:
    """Text inside a tool_result block: a string or list."""
    inner = block.get("content")
    if isinstance(inner, str):
        return [inner]
    if isinstance(inner, list):
        return [b["text"] for b in inner if isinstance(b, dict) and isinstance(b.get("text"), str)]
    return []


def _message_texts(message: dict, tool_results: bool) -> tuple[list[str], list[str]]:
    """One chat message split into person text and tool output."""
    content = message.get("content")
    if isinstance(content, str):
        return [content], []
    # ChatGPT web wraps the prompt in content.parts (seen 4 Oct).
    if isinstance(content, dict):
        parts = content.get("parts")
        if isinstance(parts, list):
            return [p for p in parts if isinstance(p, str)], []
        if isinstance(content.get("text"), str):
            return [content["text"]], []
        return [], []
    if not isinstance(content, list):
        return [], []
    pieces: list[str] = []
    docs: list[str] = []
    for part in content:
        if not isinstance(part, dict):
            continue
        if part.get("type") == "tool_result":
            # Anthropic puts tool output in the user turn; keep separate
            if tool_results:
                docs.extend(_tool_result_texts(part))
        elif isinstance(part.get("text"), str):
            pieces.append(part["text"])
    return pieces, docs


def _texts_by_channel(payload, tool_results: bool = True) -> tuple[list[str], list[str]]:
    """Split person text from tool output; rules differ."""
    if isinstance(payload, list):
        # a top-level array: every string counts as person text
        array_texts: list[str] = []
        _collect_strings(payload, array_texts)
        return array_texts, []
    payload = _core(payload)
    messages = payload.get("messages") if isinstance(payload, dict) else None
    if not isinstance(messages, list):
        return _texts_other_shapes(payload)
    user_texts: list[str] = []
    doc_texts: list[str] = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        role = str(message.get("role") or "").lower()
        if not role:
            # ChatGPT web nests it as author.role
            author = message.get("author")
            if isinstance(author, dict):
                role = str(author.get("role") or "").lower()
        pieces, docs = _message_texts(message, tool_results)
        doc_texts.extend(docs)
        if role == "user":
            user_texts.extend(pieces)
        elif role in ("tool", "function"):
            doc_texts.extend(pieces)
    if not user_texts and not doc_texts:
        return _texts_other_shapes(payload)
    return user_texts, doc_texts


MODEL_ROLES = {"assistant", "model", "system", "developer"}
TURN_KEYS = ("messages", "input", "contents")


def _keyed_messages(node, depth: int = 0) -> list | None:
    """Messages keyed by id (chat.z.ai chats/new), as a list."""
    if depth > 5 or not isinstance(node, dict):
        return None
    found = node.get("messages")
    if isinstance(found, dict):
        items = [m for m in found.values() if isinstance(m, dict) and isinstance(m.get("role"), str)]
        if items:
            return items
    for value in node.values():
        items = _keyed_messages(value, depth + 1)
        if items:
            return items
    return None


def _core(payload):
    """The turn list; Cloud Code nests it in request."""
    if isinstance(payload, dict) and not any(isinstance(payload.get(k), list) for k in TURN_KEYS):
        inner = payload.get("request")
        if isinstance(inner, dict) and any(isinstance(inner.get(k), list) for k in TURN_KEYS):
            return inner
        keyed = _keyed_messages(payload)
        if keyed:
            return {"messages": keyed}
    return payload


def _turn_items(payload) -> list:
    """Turns in order: messages, Responses input or Gemini contents."""
    payload = _core(payload)
    if not isinstance(payload, dict):
        return []
    for key in TURN_KEYS:
        if isinstance(payload.get(key), list):
            return payload[key]
    return []


def _is_model_item(item: dict) -> bool:
    """A turn the model wrote, not a person."""
    role = str(item.get("role") or "").lower()
    itype = str(item.get("type") or "").lower()
    return role in MODEL_ROLES or itype == "reasoning" or itype.endswith("_call")


MODEL_SKIP_KEYS = {"role", "type", "id", "name", "call_id", "model", "signature", "tool_use_id",
                   "status", "stop_reason", "mime_type", "mimeType"}
SYSTEM_KEYS = ("system", "instructions", "systemInstruction", "system_instruction")


def _model_strings(node, out: list[str], depth: int = 0) -> None:
    """Text leaves of a model or system turn."""
    if depth > 12:
        return
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, list):
        for item in node:
            _model_strings(item, out, depth + 1)
    elif isinstance(node, dict):
        for key, value in node.items():
            if key not in MODEL_SKIP_KEYS:
                _model_strings(value, out, depth + 1)


def _model_texts(payload) -> list[str]:
    """Assistant and system text: history the client resends."""
    payload = _core(payload)
    found: list[str] = []
    if isinstance(payload, dict):
        for key in SYSTEM_KEYS:
            if key in payload:
                _model_strings(payload[key], found)
    for item in _turn_items(payload):
        if isinstance(item, dict) and _is_model_item(item):
            _model_strings(item, found)
    return [t for t in dict.fromkeys(found) if t.strip()]


IDENTITY_WORDS = frozenset({"claude", "anthropic", "openai", "gemini", "chatgpt", "codex", "copilot", "claude code"})


def _system_texts(payload) -> list[str]:
    """Text the client wrote as instructions, not history."""
    payload = _core(payload)
    found: list[str] = []
    if isinstance(payload, dict):
        for key in SYSTEM_KEYS:
            if key in payload:
                _model_strings(payload[key], found)
    for item in _turn_items(payload):
        if isinstance(item, dict) and str(item.get("role") or "").lower() in ("system", "developer"):
            _model_strings(item, found)
    return list(dict.fromkeys(found))


def _is_tool_item(item: dict) -> bool:
    """True when the turn is only tool output."""
    if str(item.get("role") or "").lower() in ("tool", "function"):
        return True
    if str(item.get("type") or "").lower().endswith("_output"):
        return True
    has_text = isinstance(item.get("content"), str) and bool(item["content"].strip())
    has_result = False
    for key in ("content", "parts"):
        for part in item.get(key) if isinstance(item.get(key), list) else []:
            if not isinstance(part, dict):
                continue
            if part.get("type") == "tool_result" or "functionResponse" in part:
                has_result = True
            elif isinstance(part.get("text"), str) and part["text"].strip():
                has_text = True
    return has_result and not has_text


def _newest_turn_is_tool_output(payload) -> bool:
    """True when the newest non-model turn is only tool output."""
    for item in reversed(_turn_items(payload)):
        if not isinstance(item, dict) or _is_model_item(item):
            continue
        return _is_tool_item(item)
    return False


def _newest_run(items: list) -> tuple[int, int]:
    """Bounds of the newest turns not written by the model."""
    def by_model(idx: int) -> bool:
        return isinstance(items[idx], dict) and _is_model_item(items[idx])
    end = len(items)
    while end and by_model(end - 1):
        end -= 1
    start = end
    while start and not by_model(start - 1):
        start -= 1
    return start, end


def _split_turns(payload) -> tuple[dict, dict, dict]:
    """Earlier turns, newest tool output, and the person's newest turn."""
    payload = _core(payload)
    if not isinstance(payload, dict):
        return {}, {}, {}
    for key in TURN_KEYS:
        items = payload.get(key)
        if isinstance(items, list):
            start, end = _newest_run(items)
            # text before the newest tool output is not new
            cut = max([i + 1 for i in range(start, end)
                       if isinstance(items[i], dict) and _is_tool_item(items[i])], default=start)
            # a trailing prefill is the model's, not the person's
            return ({key: items[:start] + items[end:]}, {key: items[start:cut]},
                    {**payload, key: items[cut:end]})
    return {}, {}, payload


def _turn_parts(said: list, docs: list, old_said: list, old_docs: list) -> dict:
    """Sort texts into the person's words and everything else."""
    said = [t for t in said if t]
    # owner question Q1 open: only the last block blocks
    last = rules.own_words(said[-1]) if said else ""
    blocking = last if last.strip() else ""
    context = [t for t in map(rules.own_words, said[:-1]) if t.strip()]
    return {
        "words": "\n".join(context + ([blocking] if blocking else [])),
        "blocking": blocking,
        "context": context,
        "docs": [t for t in docs if t],
        "earlier": [t for t in old_said if t]
                   + [b for t in said for b in rules.HARNESS_BLOCK.findall(t)],
        "earlier_docs": [t for t in old_docs if t],
    }


def _gemini_web_prompt(payload) -> str | None:
    """The typed prompt in Gemini web's f.req body, else None."""
    if not (isinstance(payload, list) and len(payload) >= 2 and payload[0] is None
            and isinstance(payload[1], str) and payload[1][:2] == "[["):
        return None
    try:
        inner = json.loads(payload[1])
    except ValueError:
        return None
    head = inner[0] if isinstance(inner, list) and inner else None
    langs = inner[1] if len(inner) > 1 else None
    if not (isinstance(head, list) and head and isinstance(head[0], str) and head[0].strip()
            and isinstance(langs, list) and all(isinstance(x, str) for x in langs)):
        return None
    return head[0]


def _person_turn(payload) -> dict:
    """What the person said last, and everything else."""
    typed = _gemini_web_prompt(payload)
    if typed is not None:
        # nested JSON string hides the prompt from the quote rule
        return _turn_parts([typed], [], [], [])
    earlier, tools, newest = _split_turns(payload)
    said, docs = _texts_by_channel(newest)
    tool_said, tool_docs = _texts_by_channel(tools)
    old_said, old_docs = _texts_by_channel(earlier)
    turn = _turn_parts(said, tool_docs + docs, old_said + tool_said, old_docs)
    if not any(turn.values()) and not _turn_items(payload):
        # unknown shape: all of it warns, none blocks
        strings: list[str] = []
        _collect_strings(payload, strings)
        turn["context"] = ["\n".join(strings)] if strings else []
    return turn


def _turn_shape(payload) -> dict:
    """Structure of the newest turns, never their text."""
    items = _turn_items(payload)
    tail = [str(i.get("role") or i.get("type") or "?")[:16] if isinstance(i, dict) else "str"
            for i in items[-4:]]
    return {"turns": len(items), "tail": tail}


_TAG = {"value": "", "mtime": 0.0}


def request_tag() -> str:
    """The label run.sh left for the current command."""
    path = rules.state_dir() / "tag"
    try:
        stamp = path.stat().st_mtime
        if stamp != _TAG["mtime"]:
            _TAG["value"] = path.read_text(encoding="utf-8").strip()[:60]
            _TAG["mtime"] = stamp
    except OSError:
        _TAG["value"] = ""
    return _TAG["value"]


def _audit_rows_last_day(needles: tuple[str, ...]) -> int:
    """Audit lines carrying any needle, inside the last 24h."""
    if not AUDIT.exists():
        return 0
    cutoff = datetime.now().astimezone() - timedelta(hours=24)
    total = 0
    try:
        for line in AUDIT.read_text(encoding="utf-8").splitlines():
            if not any(needle in line for needle in needles):
                continue
            stamp = re.search(r'"ts": "([^"]+)"', line)
            if not stamp:
                total += 1
                continue
            try:
                if datetime.fromisoformat(stamp.group(1)) >= cutoff:
                    total += 1
            except ValueError:
                total += 1
    except OSError:
        return 0
    return total


def _unchecked_last_day() -> int:
    """Unchecked in the last 24h: failed, unparseable, ATR not ready."""
    # UNPARSED is forwarded uninspected too, so it counts
    return _audit_rows_last_day(('"action": "ERROR"', '"action": "UNPARSED"',
                                 "unchecked, forwarded",
                                 '"skipped": "atr-not-ready"'))


def _degraded_last_day() -> int:
    """Requests forwarded with text the model never scanned."""
    return _audit_rows_last_day(('"semantic_degraded": true',))


def _stale_module_last_day() -> int:
    """Requests failed by a stale rules module in 24h."""
    return _audit_rows_last_day(("STALE-MODULE",))


def _inject_note(payload: dict, note: str) -> bool:
    """Put the proxy's note where the model reads it."""
    if not isinstance(payload, dict):
        return False
    if isinstance(payload.get("system"), str):                 # Anthropic
        payload["system"] = payload["system"] + note
        return True
    messages = payload.get("messages")
    if isinstance(messages, list):
        for message in reversed(messages):                     # OpenAI: the system turn
            if isinstance(message, dict) and str(message.get("role")).lower() == "system" \
                    and isinstance(message.get("content"), str):
                message["content"] = message["content"] + note
                return True
    if isinstance(messages, list):
        for message in reversed(messages):
            if not isinstance(message, dict) or str(message.get("role")).lower() not in ("user", "human"):
                continue
            content = message.get("content")
            if isinstance(content, str):
                message["content"] = content + note
                return True
            if isinstance(content, list):
                for block in reversed(content):
                    if isinstance(block, dict) and isinstance(block.get("text"), str):
                        block["text"] = block["text"] + note
                        return True
            return False
    for key in ("prompt", "input"):
        if isinstance(payload.get(key), str):
            payload[key] = payload[key] + note
            return True
    return False


def external_mode() -> str:
    """External-rule mode: environment wins, then the preset."""
    if EXTERNAL_MODE in ("off", "audit", "warn", "enforce"):
        return EXTERNAL_MODE
    return str(rules.mode_settings()["external"])


class AtrNotReady(RuntimeError):
    """Block mode refuses this like any internal error."""


def _external_hits(joined: str, user_texts: list[str], doc_texts: list[str] | None = None,
                   turn: dict | None = None) -> tuple[list[dict], dict]:
    """Run the external rule sets; raises only in block mode."""
    if external_mode() == "off":
        return [], {"mode": "off", "skipped": "mode-off"}
    if turn is None:
        # no payload given: the last text is the newest message
        turn = _turn_parts(user_texts[-1:], doc_texts or [], user_texts[:-1], [])
    # (text, may block, newest turn), newest first under the cap
    texts = ([(turn["blocking"], True, True)]
             + [(t, False, True) for t in reversed(turn["context"])]
             + [(t, False, False) for t in reversed(turn["earlier"])])
    texts = [entry for entry in texts if entry[0]]
    if not texts and joined:
        # no person text: inspect and record, never act
        texts = [(joined, False, False)]
    texts = texts[:EXTERNAL_MAX_TEXTS]
    # truncate long text, never drop it; state reports it
    truncated = sum(1 for t, _, _ in texts if len(t) > EXTERNAL_MAX_CHARS)
    docs = ([(t, True) for t in turn["docs"]]
            + [(t, False) for t in reversed(turn["earlier_docs"])])[:EXTERNAL_MAX_DOC_TEXTS]
    # same deal for tool output: truncate, never drop
    docs_truncated = sum(1 for t, _ in docs if len(t) > EXTERNAL_MAX_DOC_CHARS)
    docs = [(t[:EXTERNAL_MAX_DOC_CHARS], newest) for t, newest in docs]
    if not texts and not docs:
        return [], {"mode": external_mode(), "skipped": "no-suitable-text"}
    if not rules.ATR_LAZY and not rules.atr_ready():
        detail = str(rules.atr_status()["atr"].get("error") or "loading")[:140]
        if rules.INTERNAL_ERROR_MODE == "block":
            # same 502 as every internal error
            raise AtrNotReady(f"atr-not-ready: {detail}")
        # forwarded unchecked, and the record says why
        return [], {"mode": external_mode(), "skipped": "atr-not-ready", "detail": detail}
    t0 = time.monotonic()
    try:
        found: list[dict] = []
        discussed: set[str] = set()
        for text, current, newest in texts:
            for hit in rules.atr_check(text[:EXTERNAL_MAX_CHARS], channel=rules.ATR_CHANNEL_USER):
                if rules.quoted_discussion(text, hit.get("span", "")):
                    discussed.add(hit["rule"])
                    continue
                hit["current"] = current
                hit["newest"] = newest
                found.append(hit)
        for text, newest in docs:
            for hit in rules.atr_check(text, channel=rules.ATR_CHANNEL_DOCUMENT):
                # an older turn's tool output is recorded only
                hit["newest"] = newest
                found.append(hit)
        elapsed = round((time.monotonic() - t0) * 1000, 1)
        state = {"mode": external_mode(), "user_texts": len(texts), "document_texts": len(docs),
                 "hits": len(found), "ms": elapsed,
                 "engines": sorted({h["engine"] for h in found}),
                 "lanes": sorted({h["lane"] for h in found}),
                 "channels": sorted({h.get("channel", "any") for h in found})}
        if discussed:
            state["quoted_discussion"] = sorted(discussed)
        if truncated:
            state["user_texts_truncated"] = truncated
            state["max_chars"] = EXTERNAL_MAX_CHARS
        if docs_truncated:
            state["document_texts_truncated"] = docs_truncated
            state["max_doc_chars"] = EXTERNAL_MAX_DOC_CHARS
        if elapsed > EXTERNAL_BUDGET_MS:
            state["over_budget"] = True
        return found, state
    except Exception as exc:  # noqa: BLE001 (a broken rule set must not break the proxy)
        return [], {"mode": external_mode(), "error": f"{type(exc).__name__}: {exc}"[:140]}


def _filter_external(masked, ext: list[dict], action: str, counters: dict | None = None,
                     mapping: dict | None = None):
    """Replace the matched part of enforcing ATR hits with [blocked]."""
    if action != "FILTER":
        return masked, []
    hits = [h for h in ext if h.get("lane") == "enforce" and h.get("current", True)
            and h.get("channel") == rules.ATR_CHANNEL_USER
            and h["rule"] not in rules.EXTERNAL_SUPPRESS and h.get("span")]
    spans = sorted({h["span"] for h in hits}, key=len, reverse=True)
    out = _map_strings(masked, lambda t: _blank(t, spans))
    # span may be masked: try its masked form
    for span in spans:
        if span in _blob(out):
            continue
        try:
            token_form, _ = rules.mask_text(span, counters or {}, mapping or {})
        except Exception:  # noqa: BLE001 - a filter that cannot run must not break the request
            continue
        if token_form and token_form != span:
            out = _map_strings(out, lambda t: _blank(t, [token_form]))
    # only what left the body counts as filtered
    landed = rules.atr_filtered_labels([h for h in hits if h["span"] not in _blob(out)])
    return out, landed


def _long_strings(node) -> list[str]:
    """Every string in the payload that can hold a value."""
    found: list[str] = []
    _collect_strings(node, found)
    return [t for t in found if len(t) >= 8]


def _blob(payload) -> str:
    """The payload as text, to look for a span."""
    return json.dumps(payload, ensure_ascii=False)


def _person_hunt(ext: list[dict], current: str) -> list[dict]:
    """Hunt hits that matched inside the person's own words."""
    spoken = rules.own_words(current)
    return [h for h in ext if h.get("lane") != "enforce" and h.get("newest", True)
            and h.get("channel") == rules.ATR_CHANNEL_USER
            and h["rule"] not in rules.EXTERNAL_SUPPRESS and h.get("span") and h["span"] in spoken]


def _scope_values(masked, mapping: dict) -> list[str]:
    """Masked values of the person's turn, as banner keys."""
    own = _person_turn(masked)["words"]
    return sorted({f"mask\0{mapping[t]}" for t in rules.TOKEN_SHAPE.findall(own) if t in mapping})


def _person_scope(masked, mapping: dict, ext: list[dict], current: str,
                  landed: list[str] | None = None) -> dict:
    """Person-scope counts shared by banner, note and audit."""
    own = _person_turn(masked)["words"]
    tokens = {t for t in rules.TOKEN_SHAPE.findall(own) if t in mapping}
    spoken = rules.own_words(current)
    filtered = rules.atr_filtered_labels([h for h in ext if h.get("span") and h["span"] in spoken])
    if landed is not None:
        # claim only what was actually removed
        keep = set(landed)
        filtered = [label for label in filtered if label in keep]
    return {"values": len(tokens), "kinds": rules.kinds_of_tokens(mapping, tokens),
            "filtered": filtered, "hunt": _rule_names(_person_hunt(ext, current))}


BLOCK_RETRY_WINDOW_S = rules.env_number("GUARDRAIL_BLOCK_RETRY_S", 180, float)
_BLOCKS_SEEN: dict[str, list] = {}
_BLOCKS_LOCK = threading.Lock()
_AUDIT_LOCK = threading.Lock()


def _block_repeat(rule: str, matched: str, client: str = "", request_id: str = "",
                  host: str = "", prompt_sha: str = "") -> tuple[int, str]:
    """(0, "") if new, else (attempts, first id)."""
    # retry = same rule, text, client, host, prompt
    key = hashlib.sha256(
        f"{rule}\0{matched}\0{client}\0{host}\0{prompt_sha}".encode("utf-8", "replace")).hexdigest()
    now = time.monotonic()
    with _BLOCKS_LOCK:
        for old in [k for k, v in _BLOCKS_SEEN.items() if now - v[0] > BLOCK_RETRY_WINDOW_S]:
            del _BLOCKS_SEEN[old]
        seen = _BLOCKS_SEEN.get(key)
        if seen is None:
            _BLOCKS_SEEN[key] = [now, 1, request_id]
            return 0, ""
        seen[0] = now
        seen[1] += 1
        return seen[1], seen[2]


BLOCKED_PLACEHOLDER = "[an earlier prompt was blocked by the guardrail and removed]"
BLOCKED_TEXTS_KEPT = 32
BLOCKED_HASHES_KEPT = 128
BLOCKED_MIN_CHARS = 12
_BLOCKED_TEXTS: dict[str, str] = {}
_BLOCKED_HASHES: list[str] | None = None


def _blocked_hashes_path() -> Path:
    return DATA / "blocked-hashes.json"


def _load_blocked_hashes() -> list[str]:
    """Blocked-prompt hashes kept across restarts; lock held."""
    global _BLOCKED_HASHES
    if _BLOCKED_HASHES is None:
        try:
            raw = json.loads(_blocked_hashes_path().read_text(encoding="utf-8"))
            _BLOCKED_HASHES = [h for h in raw if isinstance(h, str) and len(h) == 64][-BLOCKED_HASHES_KEPT:]
        except (OSError, ValueError, TypeError):
            _BLOCKED_HASHES = []
    return _BLOCKED_HASHES


def _save_blocked_hashes(hashes: list[str]) -> None:
    """Write hashes only, mode 0600; failure is silent."""
    path = _blocked_hashes_path()
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(hashes, fh)
        os.replace(tmp, path)
    except OSError:
        pass


def _newest_said(payload) -> str:
    """The person's newest typed block, raw."""
    typed = _gemini_web_prompt(payload)
    if typed is not None:
        return typed
    _, _, newest = _split_turns(payload)
    said = [t for t in _texts_by_channel(newest)[0] if t]
    return said[-1] if said else ""


def _remember_blocked(text: str) -> None:
    """Remember blocked prompt text to clean resent history."""
    text = text.strip()
    if len(text) < BLOCKED_MIN_CHARS:
        return
    key = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
    with _BLOCKS_LOCK:
        _BLOCKED_TEXTS.pop(key[:16], None)
        _BLOCKED_TEXTS[key[:16]] = text
        while len(_BLOCKED_TEXTS) > BLOCKED_TEXTS_KEPT:
            del _BLOCKED_TEXTS[next(iter(_BLOCKED_TEXTS))]
        hashes = _load_blocked_hashes()
        if key in hashes:
            hashes.remove(key)
        hashes.append(key)
        del hashes[:-BLOCKED_HASHES_KEPT]
        _save_blocked_hashes(hashes)


def _strip_blocked(payload, newest: str):
    """Replace earlier blocked prompts; the newest turn stays."""
    with _BLOCKS_LOCK:
        kept = list(_BLOCKED_TEXTS.values())
        known = set(_load_blocked_hashes())
    if not kept and not known:
        return payload, 0
    count = [0]

    def clean(text: str) -> str:
        if len(text) < BLOCKED_MIN_CHARS or (newest and newest in text):
            return text
        if known and hashlib.sha256(text.strip().encode("utf-8", "replace")).hexdigest() in known:
            count[0] += 1
            return BLOCKED_PLACEHOLDER
        out = text
        for old in kept:
            if old in out:
                out = out.replace(old, BLOCKED_PLACEHOLDER)
        if out != text:
            count[0] += 1
        return out
    return _map_strings(payload, clean), count[0]


_BANNERS_SEEN: dict[str, float] = {}


def _banner_repeat(host: str, client: str, items: list[str]) -> bool:
    """True if every item was already announced inside the window."""
    now = time.monotonic()
    keys = [hashlib.sha256(f"{host}\0{client}\0{i}".encode("utf-8", "replace")).hexdigest()
            for i in items]
    with _BLOCKS_LOCK:
        for old in [k for k, t in _BANNERS_SEEN.items() if now - t > BLOCK_RETRY_WINDOW_S]:
            del _BANNERS_SEEN[old]
        fresh = [k for k in keys if k not in _BANNERS_SEEN]
        for k in keys:
            _BANNERS_SEEN[k] = now
    return bool(keys) and not fresh


def _notify_changed(host, scope, request_id, model, endpoint, repeat: bool = False) -> None:
    if repeat:
        return
    if scope["filtered"]:
        notify_filter(host, scope["filtered"], request_id, model, endpoint)
    elif scope["values"]:
        notify_mask(host, scope["kinds"], scope["values"], request_id, model, endpoint)


def _blank(text: str, spans: list[str]) -> str:
    for span in spans:
        text = text.replace(span, "[blocked]")
    return text


def _rule_names(hits: list[dict]) -> list[str]:
    """Sorted rule names of one bucket of hits."""
    return sorted({h["rule"] for h in hits})


def _external_buckets(external: list[dict]) -> dict:
    """Enforcing hits, split by channel and by turn."""
    buckets: dict = {"enforce": [], "enforce_context": [], "enforce_stale": [], "document": []}
    user_field = rules.ATR_CHANNEL_USER
    for hit in external:
        if hit.get("lane") != "enforce":
            continue
        channel = hit.get("channel", user_field)
        if channel == rules.ATR_CHANNEL_DOCUMENT:
            buckets["document"].append(hit)
        elif channel == user_field:
            # rest of the newest message warns; older turns are recorded
            if hit.get("current", True):
                buckets["enforce"].append(hit)
            else:
                buckets["enforce_context" if hit.get("newest", True) else "enforce_stale"].append(hit)
    return buckets


def _external_notes(external: list[dict], buckets: dict, mode: str, own_mask: bool) -> dict:
    """What the record says about the external layers."""
    return {
        "external_mode": mode,
        "external_suppressed": [r for r in _rule_names(external) if r in rules.EXTERNAL_SUPPRESS],
        "external_rules": _rule_names(external),
        "external_hunt_rules": _rule_names([h for h in external if h.get("lane") != "enforce"]),
        "external_engines": sorted({h["engine"] for h in external}),
        "external_channels": sorted({h.get("channel", "any") for h in external}),
        "external_enforce_rules": _rule_names(buckets["enforce"]),
        "external_document_enforce_downgraded": _rule_names(buckets["document"]),
        "external_enforce_context": _rule_names(buckets["enforce_context"]),
        "external_enforce_stale": _rule_names(buckets["enforce_stale"]),
        "masked": own_mask,
    }


def _raising(external: list[dict]) -> list[dict]:
    """Hits that may change the action: enforce lane, never hunt."""
    # an older turn or its tool output never warns again
    return [h for h in external if h.get("lane") == "enforce" and h.get("newest", True)
            and h["rule"] not in rules.EXTERNAL_SUPPRESS]


def _warn_reasons(own_warn: bool, mode: str, raised: list[dict]) -> list[str]:
    """Which layer raised the warning: ours, external, or both."""
    reasons = ["own"] if own_warn else []
    if mode in ("warn", "enforce") and raised:
        # suppressed rules are recorded, never raise the action
        reasons.append("external")
    return reasons


def arbitrate(own_block: bool, own_warn: bool, own_mask: bool,
              external: list[dict], mode: str | None = None,
              person_hunt: list[dict] | None = None) -> tuple[str, dict, list[str], dict]:
    """Layers combined: BLOCK, FILTER, WARN, MASK, PASS."""
    mode = mode or external_mode()
    buckets = _external_buckets(external)
    enforcing = [h for h in buckets["enforce"] if h["rule"] not in rules.EXTERNAL_SUPPRESS]
    if person_hunt is None:
        # no text given: user-channel hunt hits count
        person_hunt = [h for h in external if h.get("lane") != "enforce"
                       and h.get("channel", rules.ATR_CHANNEL_USER) == rules.ATR_CHANNEL_USER
                       and h.get("newest", True) and h["rule"] not in rules.EXTERNAL_SUPPRESS]
    # hunt hits in the person's own words warn
    raised = _raising(external) + person_hunt
    notes = _external_notes(external, buckets, mode, own_mask)
    notes["external_person_hunt_rules"] = _rule_names(person_hunt)
    if own_block:
        # our rule wins the reason; external findings are still recorded
        return "BLOCK", {"source": "own"}, [], notes
    if mode == "enforce" and enforcing:
        # severity picks the rule's action: critical blocks, else filter
        blockers = [h for h in enforcing if rules.atr_action(h.get("severity")) == "BLOCK"]
        first = (blockers or enforcing)[0]
        return ("BLOCK" if blockers else "FILTER"), {
            "source": "external", "rule": first["rule"], "match": first.get("match", ""),
            "category": first.get("category", ""), "severity": first.get("severity", "")}, [], notes
    warn_rules = _warn_reasons(own_warn, mode, raised)
    if warn_rules:
        return "WARN", {}, warn_rules, notes
    if own_mask:
        return "MASK", {}, [], notes
    return "PASS", {}, [], notes


MAX_JSON_DEPTH = 200      # walkers recurse; 200 stays far below the stack limit
FORM_PROMPT_KEYS = ("prompt", "message")      # ChatGPT web posts prompt= as a form field


def _form_prompt(flow, host: str, raw: str) -> str:
    """Chat-shaped JSON for a listed host's form prompt, else empty."""
    if not rules._first_match(rules.AI_PROVIDER_HOSTS, host):
        return ""
    from urllib.parse import parse_qsl
    pairs = parse_qsl(raw, keep_blank_values=True)
    keys = [k for k, v in pairs if k in FORM_PROMPT_KEYS and v.strip()]
    if len(keys) != 1:
        return ""
    flow.metadata["guardrail_form_prompt"] = (keys[0], pairs)
    value = next(v for k, v in pairs if k == keys[0])
    return json.dumps({"messages": [{"role": "user", "content": value}]}, ensure_ascii=False)


def _too_deep(root, limit: int = MAX_JSON_DEPTH) -> bool:
    """True when nesting passes the limit; no recursion."""
    stack = [(root, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            node = list(node.values())
        elif not isinstance(node, list):
            continue
        if depth > limit:
            return True
        stack.extend((child, depth + 1) for child in node)
    return False


def _collect_strings(node, out: list[str]) -> None:
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, list):
        for item in node:
            _collect_strings(item, out)
    elif isinstance(node, dict):
        for value in node.values():
            _collect_strings(value, out)


GEMINI_MODEL_ROLES = {"model", "assistant"}
RESPONSES_SKIP_ROLES = {"assistant", "system", "developer", "model"}
RESPONSES_SKIP_TYPES = {"reasoning"}
RESPONSES_DOC_ROLES = {"tool", "function"}
RESPONSES_USER_TYPES = {"", "message", "input_text"}


def _gemini_texts(payload: dict, user_texts: list[str], doc_texts: list[str]) -> None:
    """Contents blocks: the person's parts in, the model's dropped."""
    contents = payload.get("contents")
    if not isinstance(contents, list):
        return
    for item in contents:
        if not isinstance(item, dict):
            continue
        pieces = [p["text"] for p in (item.get("parts") or [])
                  if isinstance(p, dict) and isinstance(p.get("text"), str)]
        role = str(item.get("role") or "user").lower()
        if role in GEMINI_MODEL_ROLES:
            continue                      # the model's own words, as in chat
        if role == "user":
            user_texts.extend(pieces)
        else:
            doc_texts.extend(pieces)


def _responses_user_texts(item: dict, user_texts: list[str], doc_texts: list[str]) -> None:
    """A user turn: tool output counts as a document."""
    holder = item.get("content")
    if isinstance(holder, list):
        for part in holder:
            if isinstance(part, dict) and str(part.get("type") or "") == "tool_result":
                doc_texts.extend(_as_texts(part))
        keep = [p for p in holder if not (isinstance(p, dict)
                                         and str(p.get("type") or "") == "tool_result")]
    else:
        keep = holder
    pieces = _as_texts(keep) + _as_texts(item.get("parts"))
    if isinstance(item.get("text"), str):
        pieces.append(item["text"])
    user_texts.extend(pieces)


def _responses_item_texts(item, user_texts: list[str], doc_texts: list[str]) -> None:
    """One Responses item: person text, tool output, or model words."""
    if isinstance(item, str):
        user_texts.append(item)
        return
    if not isinstance(item, dict):
        return
    role = str(item.get("role") or "").lower()
    itype = str(item.get("type") or "").lower()
    if role in RESPONSES_SKIP_ROLES or itype in RESPONSES_SKIP_TYPES:
        return                            # the model's own words are not a request
    if role in RESPONSES_DOC_ROLES:
        doc_texts.extend(_as_texts(item.get("content")))
        doc_texts.extend(_as_texts(item.get("parts")))
        return
    if role == "user":
        _responses_user_texts(item, user_texts, doc_texts)
        return
    if role:
        # an unknown role still gets inspected, as a document
        doc_texts.extend(_as_texts(item.get("content")))
        doc_texts.extend(_as_texts(item.get("parts")))
        return
    if itype.endswith(("_output", "_call")):
        doc_texts.extend(_as_texts(item.get("output")))
        doc_texts.extend(_as_texts(item.get("outputs")))
        return
    if itype in RESPONSES_USER_TYPES:
        pieces = _as_texts(item.get("content")) + _as_texts(item.get("parts"))
        if isinstance(item.get("text"), str):
            pieces.append(item["text"])
        user_texts.extend(pieces)
        return
    # unknown item type: inspect it, never block on it
    doc_texts.extend(_as_texts(item.get("content")))
    doc_texts.extend(_as_texts(item.get("parts")))
    doc_texts.extend(_as_texts(item.get("output")))
    if isinstance(item.get("text"), str):
        doc_texts.append(item["text"])


def _responses_texts(payload: dict, user_texts: list[str], doc_texts: list[str]) -> None:
    """Responses input: a string or a list of items."""
    incoming = payload.get("input")
    if isinstance(incoming, str):
        user_texts.append(incoming)
        return
    if isinstance(incoming, list):
        for item in incoming:
            _responses_item_texts(item, user_texts, doc_texts)


def _wrapped_texts(payload: dict, user_texts: list[str], doc_texts: list[str]) -> None:
    """Prompt fields of Cohere, Hugging Face, Bedrock, Vertex, DashScope."""
    for key in ("message", "inputs", "inputText"):
        if isinstance(payload.get(key), str):
            user_texts.append(payload[key])
    instances = payload.get("instances")
    for item in instances if isinstance(instances, list) else []:
        if isinstance(item, dict):
            user_texts.extend(item[k] for k in ("content", "prompt", "text")
                              if isinstance(item.get(k), str))
    nested = payload.get("input")
    if not isinstance(nested, dict):
        return
    if isinstance(nested.get("prompt"), str):
        user_texts.append(nested["prompt"])
    if isinstance(nested.get("messages"), list):
        said, docs = _texts_by_channel({"messages": nested["messages"]})
        user_texts.extend(said)
        doc_texts.extend(docs)


def _texts_other_shapes(payload) -> tuple[list[str], list[str]]:
    """Gemini contents, Responses input, and the legacy prompt field."""
    user_texts: list[str] = []
    doc_texts: list[str] = []
    if not isinstance(payload, dict):
        # a top-level array: the walker masks and inspects each string
        return user_texts, doc_texts
    _gemini_texts(payload, user_texts, doc_texts)
    _responses_texts(payload, user_texts, doc_texts)
    _wrapped_texts(payload, user_texts, doc_texts)
    prompt = payload.get("prompt")
    if isinstance(prompt, str):
        user_texts.append(prompt)
    elif isinstance(prompt, list):
        user_texts.extend([p for p in prompt if isinstance(p, str)])
    return user_texts, doc_texts

def _as_texts(node) -> list[str]:
    """Text out of a string, a list, or a mapping."""
    if isinstance(node, str):
        return [node]
    out: list[str] = []
    nodes = node if isinstance(node, list) else [node]
    for item in nodes:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            for key in ("text", "logs", "content", "output", "results"):
                value = item.get(key)
                if isinstance(value, str):
                    out.append(value)
                elif isinstance(value, (list, dict)):
                    out.extend(_as_texts(value))
    return out


def _map_strings(node, fn):
    if isinstance(node, str):
        return fn(node)
    if isinstance(node, list):
        return [_map_strings(item, fn) for item in node]
    if isinstance(node, dict):
        return {key: _map_strings(value, fn) for key, value in node.items()}
    return node


def _apply_replaced(node, replaced: dict):
    """Replace whole strings a later layer rewrote (data-base pass)."""
    if isinstance(node, str):
        return replaced.get(node, node)
    if isinstance(node, list):
        return [_apply_replaced(item, replaced) for item in node]
    if isinstance(node, dict):
        return {key: _apply_replaced(value, replaced) for key, value in node.items()}
    return node


def _json_leaves(text: str) -> list[str]:
    """Strings inside a JSON container carried as one string."""
    head = text.lstrip()[:1]
    if head not in ("[", "{"):
        return []
    try:
        node = json.loads(text)
    except ValueError:
        return []
    out: list[str] = []
    stack = [node]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if len(item) >= SEM_SHORT_MIN_CHARS and " " in item.strip():
                out.append(item)
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, dict):
            stack.extend(item.values())
    return out


def _swap_leaf(container: str, leaf: str, new: str) -> str:
    """Replace one JSON string value inside its serialized container."""
    for ascii_only in (False, True):
        old_s = json.dumps(leaf, ensure_ascii=ascii_only)[1:-1]
        if old_s in container:
            return container.replace(old_s, json.dumps(new, ensure_ascii=ascii_only)[1:-1])
    return container


def _split_long(text: str, limit: int) -> list[str]:
    """Cut long text into model-sized pieces."""
    parts: list[str] = []
    i = 0
    while i < len(text):
        j = min(i + limit, len(text))
        if j < len(text):
            cut = text.rfind("\n", i, j)
            if cut <= i + limit // 2:
                cut = text.rfind(" ", i, j)
            if cut > i + limit // 2:
                j = cut + 1
        parts.append(text[i:j])
        i = j
    return parts


def _semantic_pass(node, counters: dict, mapping: dict, deadline: float,
                   user_texts: list[str], doc_texts: list[str], model_texts: list[str] | None = None,
                   system_texts: list[str] | None = None):
    """Layer 3: GLiNER entities from person, tool and model text."""
    ordered: list[tuple[str, str, str | None]] = []
    state = {
        "mode": rules.MODE, "candidates": 0, "scanned": 0, "skipped": 0, "too_long": 0, "model_unavailable": 0, "timeout": 0, "cached": 0, "used_chars": 0,
        "channels": [],
    }

    pieces: dict[str, list[str]] = {}

    def add(channel: str, text: str) -> None:
        leaves = _json_leaves(text)
        if leaves:
            ordered.extend((channel, leaf, text) for leaf in leaves)
        elif len(text) > rules.MAX_CHARS:
            # scan over-limit text in pieces
            pieces[text] = _split_long(text, rules.MAX_CHARS)
            ordered.extend((channel, p, None) for p in pieces[text] if eligible(p))
        else:
            ordered.append((channel, text, None))

    def eligible(t: str) -> bool:
        return bool(t) and len(t) >= SEM_SHORT_MIN_CHARS and " " in t.strip()

    for text in reversed([t for t in user_texts if eligible(t)]):
        add("user_input", text)
    for text in [t for t in doc_texts if eligible(t)]:
        add("document", text)
    for text in reversed([t for t in (model_texts or []) if eligible(t)]):
        add("model_text", text)
    state["candidates"] = len(ordered)
    # a load in progress is waited for, never forwarded around
    if ordered:
        rules.await_model(SEM_LOAD_WAIT_MS / 1000.0)
    # a slow model must not decide what leaves
    deadline = time.monotonic() + SEM_HARD_MS / 1000.0
    # uncached texts go to the model in batches
    rules.semantic_prefetch([t for _c, t, _p in ordered], deadline)
    chosen = ordered
    state["channels"] = [c for c, _t, _p in chosen]

    system_set = set(system_texts or [])
    for whole, parts in pieces.items():
        if whole in system_set:
            system_set.update(parts)
    kinds: list[str] = []
    replaced: dict[str, str] = {}
    nested: dict[str, str] = {}
    current: dict[tuple, str] = {}
    known = set(mapping)

    for channel, text, parent in chosen:
        if not rules.semantic_cached(text) and deadline - time.monotonic() <= 0.02:
            state["skipped"] += 1
            continue
        # a product naming itself is not a person
        ignore = IDENTITY_WORDS if text in system_set else None
        skip_labels = rules.SYSTEM_SKIP_LABELS if text in system_set else frozenset()
        short = len(text) < SEM_MIN_CHARS
        if short:
            skip_labels = skip_labels | SHORT_ONLY_PERSON
        new, found, stat = rules.semantic_mask(text, counters, mapping, rules.make_token,
                                               deadline=deadline, flat=channel != "user_input",
                                               ignore=ignore, skip_labels=skip_labels,
                                               min_words=2 if short else 1)
        reason = stat.get("reason", "")
        if reason == "too-long":
            state["too_long"] += 1
        elif reason.startswith("error:") or stat.get("action") == "model-error":
            state["model_unavailable"] += 1
        elif reason == "over-budget":
            state["timeout"] += 1
        elif reason == "cached":
            state["cached"] += 1
            state["scanned"] += 1
            state["used_chars"] += len(text)
        elif not reason:
            state["scanned"] += 1
            state["used_chars"] += len(text)
        kinds.extend(found)
        current[(channel, text, parent)] = new
        if new != text:
            if parent is None:
                replaced[text] = new
            else:
                nested[parent] = _swap_leaf(nested.get(parent, parent), text, new)

    # a found value is masked everywhere in the request
    learned = {mapping[t]: t for t in mapping if t not in known and len(mapping[t]) >= 4}
    if learned:
        names = sorted(learned, key=len, reverse=True)
        pattern = re.compile(r"(?<!\w)(?:" + "|".join(re.escape(v) for v in names) + r")(?!\w)")
        for channel, text, parent in chosen:
            have = current.get((channel, text, parent), text)
            new = pattern.sub(lambda m: learned[m.group(0)], have)
            if new == have:
                continue
            if parent is None:
                replaced[text] = new
            else:
                nested[parent] = _swap_leaf(nested.get(parent, parent), have, new)

    for whole, parts in pieces.items():
        done = "".join(replaced.get(p, p) for p in parts)
        if done != whole:
            replaced[whole] = done
    replaced.update(nested)
    # too_long is a stated limit, not degraded
    state["degraded"] = bool(state["skipped"] or state["timeout"] or state["model_unavailable"])
    if not replaced:
        return node, kinds, state

    return _apply_replaced(node, replaced), kinds, state


def _model_mode(setting) -> str:
    """yaml reads on and off as booleans; layers compare words."""
    if isinstance(setting, bool):
        return "budget" if setting else "off"
    return str(setting).strip().lower()


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _allow_hosts() -> list[str]:
    """Hosts to open: endpoints plus discovery; empty in mode on."""
    if rules.DISCOVERY_MODE == "on":
        return []
    hosts = rules.host_patterns()
    if rules.DISCOVERY_MODE != "off":
        hosts = hosts + list(rules.DISCOVERY_PATTERNS)
    return hosts


def _add_origin(record: dict, verdict: dict) -> None:
    """Copy origin; flag hosts caught only by shape."""
    record["origin"] = {"client": verdict.get("client"),
                        "matched_app": verdict.get("matched_app"),
                        "why": verdict.get("why")}
    if verdict.get("unlisted_host"):
        record["unlisted_host"] = verdict["unlisted_host"]


def _pac_proxy() -> str:
    """PROXY value for the PAC: the regular listener."""
    return os.environ.get("GUARDRAIL_PAC_PROXY", "").strip() or f"127.0.0.1:{rules.REGULAR_PORT}"


def _pac_text(header: str, proxy: str, patterns) -> str:
    """PAC source with a DIRECT fallback."""
    entries = ",\n    ".join(json.dumps(p) for p in patterns)
    return (
        header +
        "\nvar PROXY = \"PROXY " + proxy + "; DIRECT\";\n\n"
        "var ENDPOINTS = [\n    " + entries + "\n];\n\n"
        "function FindProxyForURL(url, host) {\n"
        "    host = host.toLowerCase();\n"
        "    for (var i = 0; i < ENDPOINTS.length; i++) {\n"
        "        try { if (new RegExp(ENDPOINTS[i]).test(host)) { return PROXY; } } catch (e) {}\n"
        "    }\n"
        "    return \"DIRECT\";\n"
        "}\n")


def _write_pac_file(target: Path, text: str) -> None:
    """Replace the PAC atomically."""
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    try:            # the desktop session reads this; runner uses umask 077
        os.chmod(tmp, 0o644)
    except OSError:
        pass
    os.replace(tmp, target)


def _flow_host(flow: http.HTTPFlow) -> str:
    """The real hostname, not the bare IP transparent mode gives."""
    host = flow.request.pretty_host
    if _is_ip(host):
        host = flow.client_conn.sni or host
    return host


def _rule_hits_for(text: str, lane: str) -> list:
    """Hits of one lane, block or warn, in a text."""
    if not text:
        return []
    return [h for h in rules.find_malicious(text) if h[2] == lane]


def _rule_classification(joined: str, turn: dict) -> tuple:
    """Block, warn and downgraded hits, by channel and by turn."""
    hits = rules.find_malicious(joined)
    keras_all = [h for h in hits if h[2] == "block"]
    keep_doc_block = rules.mode_settings()["document_block"] == "block"
    doc_joined = "\n".join(turn["docs"])
    near = "\n".join(turn["context"] + turn["docs"])
    keras_doc = _rule_hits_for(doc_joined, "block")
    keras = _rule_hits_for(turn["blocking"], "block") + (keras_doc if keep_doc_block else [])
    downgraded = [h for h in keras_all if h not in keras]
    # the newest turn raises it; older turns are logged
    near_rules = {h[0] for h in _rule_hits_for(near, "block")}
    lunak = (_rule_hits_for(turn["words"], "warn") + _rule_hits_for(doc_joined, "warn")
             + [(r, m, "warn") for r, m, _ in downgraded if r in near_rules])
    history = "\n".join(turn["earlier"] + turn["earlier_docs"])
    history_warnings = sorted({h[0] for h in _rule_hits_for(history, "warn")}
                              | {r for r, _, _ in downgraded if r not in near_rules})
    # the record's downgrade names only what now warns
    downgraded = [h for h in downgraded if h[0] in near_rules]
    return hits, keras, downgraded, lunak, history_warnings


def _body_text(flow, body) -> str:
    """The payload as it arrived: JSON or form."""
    from urllib.parse import urlencode
    form_prompt = flow.metadata.get("guardrail_form_prompt")
    if form_prompt:
        key, pairs = form_prompt
        content = body["messages"][0]["content"]
        return urlencode([(k, content if k == key else v) for k, v in pairs])
    text = json.dumps(body, ensure_ascii=False)
    form_field = flow.metadata.get("guardrail_form_field")
    if form_field:
        return urlencode([(form_field, text)] + list(flow.metadata.get("guardrail_form_rest") or []))
    return text


def _send_note(flow, body, tag_action: str) -> str:
    """Inject the proxy's note, and say which note went out."""
    note = rules.tag_note(tag_action) if tag_action else ""
    if not note:
        return ""
    if not _inject_note(body, note):
        return ""
    flow.request.set_text(_body_text(flow, body))
    return rules.TAG_WORDS.get(tag_action, "")


def _forward_warn_set(lunak: list, ext: list, action: str, person_hunt: list | None = None) -> list:
    """Rules behind a warning, own hits plus external ones."""
    own = {r for r, _, _ in lunak}
    if action != "WARN":
        return sorted(own)
    return sorted(own | {h["rule"] for h in _raising(ext) + list(person_hunt or [])})


def _layer_health() -> dict:
    """What the layers reported; a zero is not clean."""
    try:
        atr = rules.atr_status().get("atr") or {}
        if atr.get("error"):
            state = "error"
        elif atr.get("rules_used"):
            state = "loaded"
        else:
            state = "empty"
        return {"atr": state, "atr_rules": atr.get("rules_used", 0),
                "dlp": "on" if rules.DLP_ENABLED else "off", "model": rules.MODE}
    except Exception:  # noqa: BLE001 - a missing status must not drop the record
        return {}


def _record_extras(record: dict, state: dict, tag: str, tag_sent: str,
                   warn_rules: list, kinds: list, mapping: dict) -> dict:
    """Record the fields that depend on what the layers found."""
    if state["newest_turn_is_tool_output"]:
        record["newest_turn"] = "tool_output"
    if tag:
        record["tag"] = tag
    if state["prompt_sha"]:
        record["prompt_sha"] = state["prompt_sha"]
    if tag_sent:
        record["tag_injected"] = tag_sent
    if state["user_masked_kinds"]:
        record["masked_user_kinds"] = sorted(set(state["user_masked_kinds"]))
    if state["user_warn"]:
        record["user_warn"] = True
    if warn_rules:
        record["warn"] = warn_rules
    if state["history_warnings"]:
        # seen before, an earlier turn: not acted on
        record["history_warnings"] = state["history_warnings"]
    if mapping:
        record["masked_kinds"] = kinds
    atr_filtered = state.get("filtered_landed") or []
    if atr_filtered:
        record["atr_filtered"] = atr_filtered
    if state["downgraded"]:
        # recorded only: looked like a block, but tool output
        record["channel_downgrade"] = {
            "from": "BLOCK", "to": "WARN", "channel": "document",
            "rules": sorted({r for r, _, _ in state["downgraded"]}),
        }
    # layer health travels with the record
    health = _layer_health()
    if health:
        record["layers"] = health
    return record


NAT64 = ipaddress.ip_network("64:ff9b::/96")
RACE_DELAY_S = 0.25


def _nat64_v4(host) -> str | None:
    """The IPv4 inside a 64:ff9b::/96 literal, else None."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if ip.version == 6 and ip in NAT64:
        return str(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return None


async def _first_connect(original, hosts, port, kwargs):
    """First successful connect wins; the others are closed."""
    async def attempt(delay, host):
        await asyncio.sleep(delay)
        return await original(host, port, **kwargs)

    tasks = [asyncio.ensure_future(attempt(i * RACE_DELAY_S, h)) for i, h in enumerate(hosts)]
    pending, errors, winner = set(tasks), [], None
    try:
        while pending and winner is None:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                if task.cancelled():
                    errors.append(OSError("connection cancelled"))
                elif task.exception() is not None:
                    errors.append(task.exception())
                elif winner is None:
                    winner = task.result()
                else:
                    task.result()[1].close()
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
    if winner is None:
        raise errors[0]
    return winner


def _race_address_families() -> None:
    """Make upstream connects race IPv4 and IPv6 (RFC 8305)."""
    original = asyncio.open_connection
    if getattr(original, "_guardrail_race", False):
        return

    async def open_connection(host=None, port=None, **kwargs):
        kwargs.setdefault("happy_eyeballs_delay", RACE_DELAY_S)
        v4 = _nat64_v4(host)
        # transparent mode connects to a literal address
        if v4 is None:
            return await original(host, port, **kwargs)
        return await _first_connect(original, [v4, host], port, kwargs)

    open_connection._guardrail_race = True
    asyncio.open_connection = open_connection


def _loopback_only() -> bool:
    """True when every listener is bound to loopback."""
    for spec in ctx.options.mode:
        host = ProxyMode.parse(spec).listen_host(ctx.options.listen_host)
        try:
            if not ipaddress.ip_address(host).is_loopback:
                return False
        except ValueError:
            return False
    return True


class Guardrail:
    def __init__(self) -> None:
        self.allow: list[re.Pattern] = []

    def _write_pac(self) -> str:
        """Write proxy.pac from the loaded endpoint list."""
        target = rules.pac_file()
        proxy = _pac_proxy()
        # Only the configured endpoint list goes into the PAC.
        patterns = list(rules.host_patterns())
        try:
            _write_pac_file(target, _pac_text(
                "// proxy.pac - generated by guardrail.py from guardrail.yaml at startup.\n"
                "// PROXY for the listed endpoints; DIRECT when the proxy is down or unlisted.\n",
                proxy, patterns))
        except Exception as exc:  # noqa: BLE001 (the mapping may be read-only)
            return f"failed: {type(exc).__name__}: {exc}"
        return f"{target} ({len(patterns)} entries)"

    def _refresh_patterns(self) -> None:
        """Pick up endpoints learned while running, no restart."""
        if time.monotonic() - getattr(self, "_patterns_at", 0.0) < 5.0:
            return
        self._patterns_at = time.monotonic()
        hosts = _allow_hosts()
        self.allow = [re.compile(p) for p in hosts if p.strip()]
        self.explicit = [re.compile(p) for p in rules.host_patterns()]
        ctx.options.allow_hosts = hosts
        self.pac_written = self._write_pac()

    def load(self, loader) -> None:
        # mitmproxy tries only the first address; dead IPv6 hangs
        _race_address_families()
        # load rules before the loop serves; requests never load
        rules.atr_start()
        rules.ATR_LAZY = False

    def running(self) -> None:
        # redirected IPv6 clients arrive from the host's global address
        if _loopback_only():
            ctx.options.update(block_global=False)
        # guardrail.yaml is the one source; it writes the PAC too
        config = rules.load_config()
        # Close banners a previous run left behind.
        startup()
        debug(f"block_global={ctx.options.block_global}")
        # defaults in place must never be silent
        if not config.get("loaded"):
            warn_config(config.get("errors") or ["guardrail.yaml could not be read"])
            debug(f"guardrail.yaml not used: {config.get('errors')}")
        # allow list: endpoints plus discovery
        # patterns; content judged per request
        installed = rules.detect_ai_apps()
        hosts = _allow_hosts()
        ctx.options.allow_hosts = hosts
        self.allow = [re.compile(p) for p in hosts if p.strip()]
        self.explicit = [re.compile(p) for p in rules.host_patterns()]
        self._patterns_at = time.monotonic()
        # same list builds the PAC, so the two cannot disagree
        self.pac_written = self._write_pac()
        rules.MODE = _model_mode(rules.mode_settings()["model"])
        try:                                   # so 'run.sh --stop' can stop exactly this process
            (rules.state_dir() / "guardrail.pid").write_text(
                str(os.getpid()), encoding="utf-8")
        except OSError:
            pass
        # AI tool may already run; report it, do not wait
        self.desktop = None
        if rules.desktop_proxy_setting() == "auto":
            self.desktop = rules.set_desktop_proxy(True, rules.pac_file())
        # warm layers in the background; requests use what is up
        rules.model_start()
        warm = {"loaded": None, "seconds": None, "background": True}

        looked_up = []

        def _warm_background() -> None:
            try:
                # load first: lookups below can take minutes
                warm_result = rules.warm_up() if rules.MODE != "off" else None
                status = rules.routed_status()      # DNS lookups: never on the loop
                direct = [c for c in status["connections"]
                          if c.get("matched_app") and c.get("app") != "this guardrail"]
                for conn in direct:
                    debug(f"AI traffic seen outside the guardrail: {conn['app']} -> "
                          f"{conn['host']}:{conn['port']} (pid {conn['pid']})")
                if direct:
                    warn_outside([f"{c['app']} -> {c['host']}" for c in direct])
                debug(f"ai apps running={len(status['apps_running'])}, "
                      f"ai traffic outside this proxy={[c['app'] + '->' + c['host'] for c in direct]}")
                looked_up.append(True)
                if warm_result is not None:
                    debug(f"model warm-up finished: {warm_result}")
                rules.atr_start()
                atr = rules.atr_status()["atr"]
                # first line that may be read as layer health
                if atr.get("error"):
                    debug(f"layers ready: external rule set degraded, {atr['error']} "
                          f"(files seen {atr.get('files_seen', 0)}, rules used 0)")
                    if rules._atr_attempts >= rules.ATR_MAX_ATTEMPTS:
                        warn_atr_failed(atr.get("files_seen", 0))
                else:
                    debug(f"layers ready: external rule set {atr.get('rules_used', 0)} rules from "
                          f"{atr.get('files_seen', 0)} files, dropped {atr.get('dropped', 0)}, "
                          f"non-regex conditions {atr.get('conditions_not_regex', 0)}, "
                          f"skipped {atr.get('skipped', 0)}")
            except Exception as exc:  # noqa: BLE001 (the proxy keeps working without them)
                if not looked_up:
                    debug("ai apps running=unknown, ai traffic outside this proxy=unknown (lookup failed)")
                debug(f"layers ready: background warm-up failed: {type(exc).__name__}: {exc}")

        # pending until the thread writes the values
        debug("ai apps running=pending, ai traffic outside this proxy=pending (background lookup)")
        threading.Thread(target=_warm_background, name="guardrail-warm-up", daemon=True).start()
        rules.load_dlp()
        ext = rules.atr_status()
        dlp = rules.dlp_status()
        # Failure signals recorded by rules.py stay visible here.
        atr = ext["atr"]
        if not atr:
            # the loader is still running: no health report yet
            atr_note = ", still loading in the background (see the 'layers ready' line)"
        elif atr.get("error"):
            atr_note = (f", ERROR {atr['error']} (dropped {atr.get('dropped', 0)}, "
                        f"non-regex {atr.get('conditions_not_regex', 0)})")
        else:
            atr_note = (f", dropped {atr.get('dropped', 0)}, "
                        f"non-regex {atr.get('conditions_not_regex', 0)}")
        try:
            model_errors = (rules.summarize_metrics().get("reasons") or {}).get("model-error", 0)
        except Exception:  # noqa: BLE001 - an unreadable metrics file is not a crash
            model_errors = None
        debug(
            f"guardrail active: {len(self.allow)} host patterns from "
            f"{Path(str(config.get('path', '?'))).name}, port {ctx.options.listen_port}, "
            f"model layer={rules.MODE} (budget {SEM_BUDGET_MS} ms, "
            f"warm-up {warm.get('seconds')}s loaded={warm.get('loaded')}, "
            f"model-error={model_errors if model_errors is not None else 'unavailable'}), "
            f"strictness={rules.strictness()} {rules.mode_settings()} "
            f"external layer={external_mode()} "
            f"(atr {atr.get('rules_used', 0)} rules, {atr.get('conditions', 0)} patterns"
            + atr_note + "), "
            f"user dlp rules={len(config.get('user_rules') or [])}, "
            f"ai apps installed={len(installed)}, "
            f"desktop proxy={self.desktop}, "
            f"data base={'on' if rules.DLP_ENABLED else 'off'} "
            f"({dlp.get('patterns', 0)} patterns: "
            + ", ".join(f"{k} {v}" for k, v in (dlp.get('rules') or {}).items())
            + f"; {dlp.get('failed', 0)} unusable, budget {rules.DLP_BUDGET_MS} ms), "
            f"data errors={dlp.get('errors') or []}, "
            f"mapping: pac {getattr(self, 'pac_written', '-')}), "
            f"config errors={len(config.get('errors') or [])}"
        )

    @staticmethod
    def _matches(patterns: list[re.Pattern], *candidates: str) -> bool:
        return any(pattern.search(candidate) for pattern in patterns for candidate in candidates)

    def _explicit(self, flow: http.HTTPFlow) -> bool:
        """True when the host is in the person's own list."""
        return self._matches(self.explicit, _flow_host(flow))

    def request(self, flow: http.HTTPFlow) -> None:
        """Thin wrapper: failures are audited, blocked only if asked."""
        try:
            self._handle_request(flow)
        except Exception as exc:  # noqa: BLE001
            host = _flow_host(flow)
            request_id = uuid.uuid4().hex[:8]
            if rules.INTERNAL_ERROR_MODE == "block":
                self._block_on_internal_error(flow, host, request_id, exc)
            else:
                # Forwarded unchecked and recorded. Switch GUARDRAIL_ON_INTERNAL_ERROR=block to fail closed.
                debug(f"request handling failed, forwarding unchecked: {type(exc).__name__}: {exc}")
                stale = "STALE-MODULE: restart proxy; " if _rules_stamp() != _RULES_LOADED else ""
                audit(audit_record(
                    "ERROR", host, request_id,
                    findings=[f"{stale}unchecked, forwarded: {type(exc).__name__}: {exc}"[:140]]
                ))

    def _refuse_too_deep(self, flow, host: str) -> None:
        """Refuse a body nested too deep to inspect."""
        request_id = uuid.uuid4().hex[:8]
        audit(audit_record("BLOCK", host, request_id,
                                         findings=["body nested too deep to inspect"]))
        body = json.dumps(
            {"error": {"message": "LLM Guardrail refused this request: the body is nested too "
                                  "deeply to be inspected.", "type": "guardrail_too_deep",
                      "request_id": request_id}},
            ensure_ascii=False,
        ).encode("utf-8")
        flow.response = http.Response.make(
            400, body, {"Content-Type": "application/json", "X-LLM-Guardrail": "too-deep"}
        )

    def _block_on_internal_error(self, flow: http.HTTPFlow, host: str, request_id: str,
                                 exc: Exception) -> None:
        debug(f"request handling failed, blocking for safety: {type(exc).__name__}: {exc}")
        err_body = json.dumps(
            {"error": {"message": "LLM Guardrail failed to inspect this request; blocked for "
                                  "safety.", "type": "guardrail_error", "request_id": request_id}},
            ensure_ascii=False,
        ).encode("utf-8")
        flow.response = http.Response.make(
            502, err_body, {"Content-Type": "application/json", "X-LLM-Guardrail": "error"}
        )
        audit(audit_record(
            "ERROR", host, request_id, findings=[f"{type(exc).__name__}: {exc}"[:140]]
        ))

    def _audit_unparsed(self, flow: http.HTTPFlow, host: str, reason: str) -> None:
        """Forward untouched, record UNPARSED: body was not read."""
        raw = flow.request.get_text(strict=False) or ""
        if not raw:
            return
        verdict = rules.classify_request(host, flow.request.headers, raw,
                                         explicit=rules.AI_PROVIDER_HOSTS,
                                         path=flow.request.path)
        if verdict["verdict"] != "ai":
            return
        record = audit_record("UNPARSED", host, uuid.uuid4().hex[:8], chars_in=len(raw),
                                     chars_out=len(raw))
        record["unparsed"] = reason
        record["content_type"] = (flow.request.headers.get("content-type") or "")[:60]
        _add_origin(record, verdict)
        if _is_telemetry(flow.request.path):
            record["telemetry"] = True
        tag = request_tag()
        if tag:
            record["tag"] = tag
        audit(record)

    def _handle_request(self, flow: http.HTTPFlow) -> None:
        if flow.request.method == "CONNECT":
            return
        self._refresh_patterns()
        host = _flow_host(flow)
        loaded = self._load_payload(flow, host)
        if loaded is None:
            return
        payload, raw = loaded
        tag = request_tag()
        request_id = uuid.uuid4().hex[:8]
        state = self._inspect(payload)
        if _gemini_web_prompt(payload) is not None:
            # length-prefixed reply: notice goes out of band, never into it
            flow.metadata["guardrail_reply_untouched"] = True
        if state["action"] == "BLOCK":
            record = self._send_block(flow, host, raw, request_id, tag, state)
        else:
            record = self._send_forwarded(flow, host, payload, raw, request_id, tag, state)
        self._finish_record(flow, host, request_id, record, state)

    def _load_payload(self, flow: http.HTTPFlow, host: str):
        """Return (payload, raw) for AI requests, else None."""
        ctype = (flow.request.headers.get("content-type") or "").lower()
        raw = flow.request.get_text(strict=False) or ""
        # The content-type is a claim; judge the body.
        looks_json = "json" in ctype or raw.lstrip()[:1] in ("{", "[")
        as_chat = _form_prompt(flow, host, raw) if not looks_json and "form-urlencoded" in ctype else ""
        if as_chat:
            raw, looks_json = as_chat, True
        if not looks_json and "form-urlencoded" in ctype and raw:
            # Gemini web posts JSON in a form field.
            try:
                from urllib.parse import parse_qsl
                for key, value in parse_qsl(raw, keep_blank_values=True):
                    if value[:1] in ("{", "["):
                        flow.metadata["guardrail_form_field"] = key
                        flow.metadata["guardrail_form_rest"] = [
                            (k, v) for k, v in parse_qsl(raw, keep_blank_values=True) if k != key
                        ]
                        raw = value
                        looks_json = True
                        break
            except Exception:
                pass
        if not looks_json:
            debug(f"skipped (not JSON): {host}{flow.request.path}")
            self._audit_unparsed(flow, host, "not-json")
            return None
        flow.metadata["guardrail_t0"] = time.monotonic()
        try:
            payload = json.loads(raw)
        except RecursionError:
            # nested too deep for the interpreter to walk; refuse it
            debug(f"refused (JSON nested too deep to walk): {host}{flow.request.path}")
            self._refuse_too_deep(flow, host)
            return None
        except (ValueError, TypeError):
            debug(f"skipped (unreadable JSON): {host}{flow.request.path}")
            self._audit_unparsed(flow, host, "bad-json")
            return None
        if _too_deep(payload):
            # json.loads accepts depths the walkers cannot; refuse, never forward
            debug(f"refused (JSON deeper than {MAX_JSON_DEPTH}): {host}{flow.request.path}")
            self._refuse_too_deep(flow, host)
            return None
        if not isinstance(payload, (dict, list)):
            # valid JSON, no fields:
            # record like an unparsed body
            debug(f"skipped (JSON body carries no fields): {host}{flow.request.path}")
            self._audit_unparsed(flow, host, "json-scalar")
            return None
        # ordinary traffic is forwarded untouched, never audited
        verdict = rules.classify_request(host, flow.request.headers, raw,
                                         explicit=rules.AI_PROVIDER_HOSTS,
                                         path=flow.request.path)
        if verdict["verdict"] != "ai":
            debug(f"not AI traffic, forwarded untouched: {host}"
                  f"{flow.request.path} ({'; '.join(verdict['why'])})")
            return None
        flow.metadata["guardrail_origin"] = verdict
        debug(f"AI traffic: {host}{flow.request.path} "
              f"client={verdict['client']} why={'; '.join(verdict['why'])}")
        if verdict.get("matched_app") not in ("your endpoint list",):
            rules.note_candidate(host, flow.request.path, now_iso())
        return payload, raw

    def _own_layer(self, payload, joined: str) -> dict:
        """Layer 1: our own rules, and the person's own turn."""
        # a block hit in tool output warns instead
        user_texts, doc_texts = _texts_by_channel(payload)
        newest_turn_is_tool_output = _newest_turn_is_tool_output(payload)
        # a tool-only turn is the agent speaking, and never blocks
        turn = _person_turn(payload)
        current = turn["words"]
        _, user_masked_kinds = rules.mask_text(current, {}, {}) if current else ("", [])
        user_warn = bool([h for h in rules.find_malicious(current) if h[2] == "warn"]) if current else False
        # short hash of the newest message, ties record to prompt
        prompt_sha = hashlib.sha256(current.encode("utf-8", "replace")).hexdigest()[:12] \
            if current else ""
        hits, keras, downgraded, lunak, history_warnings = _rule_classification(joined, turn)
        return {
            "user_texts": user_texts, "doc_texts": doc_texts, "current": current, "turn": turn,
            "newest_turn_is_tool_output": newest_turn_is_tool_output,
            "user_masked_kinds": user_masked_kinds, "user_warn": user_warn,
            "prompt_sha": prompt_sha, "hits": hits, "keras": keras, "downgraded": downgraded,
            "lunak": lunak, "history_warnings": history_warnings,
            "turn_shape": {**_turn_shape(payload), "user_turns": len(user_texts),
                           "current_chars": len(current)},
        }

    def _data_layers(self, payload, joined: str, user_texts: list, doc_texts: list,
                     keras: list, turn: dict | None = None, unknown: bool = False) -> dict:
        """Layers 2 and 3: external rules, masking, the model."""
        if keras:
            ext, ext_state = [], {"mode": external_mode(), "skipped": "already-blocked-by-own-rules"}
        else:
            ext, ext_state = _external_hits(joined, user_texts, doc_texts, turn)

        # masking runs whatever the final action is
        counters: dict[str, int] = {}
        mapping: dict[str, str] = {}
        # token-shaped text switches this request to marked mode
        rules.mark_request(mapping, joined)
        rules.track_kinds(mapping)
        # Person, tool and model text; history is resent whole.
        replaced: dict[str, str] = {}
        model_texts = [] if unknown else _model_texts(payload)
        system_set = frozenset([] if unknown else _system_texts(payload))
        for text in [t for t in list(user_texts) + list(doc_texts) + model_texts if t]:
            skip = rules.SYSTEM_SKIP_GROUPS if text in system_set else frozenset()
            new, _ = rules.mask_text(text, counters, mapping, skip)
            if new != text:
                replaced[text] = new
        masked = _apply_replaced(payload, replaced)

        # 3b) model layer: patternless entities under a time budget
        sem_state = None
        if rules.MODE != "off":
            deadline = time.monotonic() + SEM_BUDGET_MS / 1000.0
            before_model, before_docs = _texts_by_channel(masked)
            try:
                masked, _sem_kinds, sem_state = _semantic_pass(
                    masked, counters, mapping, deadline, before_model, before_docs,
                    [] if unknown else _model_texts(masked), [] if unknown else _system_texts(masked)
                )
            except Exception as exc:  # noqa: BLE001 (degrade, never forward raw)
                # the pattern pass already masked; serve that and count it
                debug(f"semantic layer failed, serving pattern pass only: {type(exc).__name__}: {exc}")
                sem_state = {"mode": rules.MODE, "model_unavailable": 1, "degraded": True,
                             "error": f"{type(exc).__name__}"}

        # 3c) data base over the text the model just rewrote
        masked_user_texts, masked_docs = _texts_by_channel(masked)
        masked_docs = masked_docs + ([] if unknown else _model_texts(masked))
        if unknown:
            masked_user_texts = _long_strings(masked)
        dlp_state = None
        if rules.DLP_ENABLED and rules.DLP_STATE.get("loaded"):
            # masking is safe everywhere: earlier sweeps and tool output too
            try:
                # newest turn first, so the scan budget reaches it
                replaced, _extra_kinds, dlp_state = rules.mask_extra_pass(
                    masked_user_texts[-1:] + masked_user_texts[:-1] + masked_docs, counters, mapping,
                    system_texts=frozenset([] if unknown else _system_texts(masked)))
                if replaced:
                    masked = _apply_replaced(masked, replaced)
            except Exception as exc:  # noqa: BLE001 (reported, never fatal)
                dlp_state = {"error": f"{type(exc).__name__}: {exc}"}
                debug(f"data base layer skipped: {dlp_state['error']}")
        elif rules.DLP_ENABLED:
            # validators need no data base, so phones still mask
            replaced = {}
            for text in masked_user_texts + masked_docs:
                new, _ = rules._validator_pass(text, counters, mapping)
                if new != text:
                    replaced[text] = new
            masked = _apply_replaced(masked, replaced) if replaced else masked
            dlp_state = {"error": "data base not loaded; validators only"}
        return {"ext": ext, "ext_state": ext_state, "masked": masked, "counters": counters,
                "mapping": mapping, "kinds": sorted(counters), "sem_state": sem_state,
                "dlp_state": dlp_state}

    def _inspect(self, payload) -> dict:
        """Run layers 1-3 and arbitrate; masking always runs."""
        newest_said = _newest_said(payload)
        payload, stripped = _strip_blocked(payload, newest_said)
        strings: list[str] = []
        _collect_strings(payload, strings)
        joined = "\n".join(strings)
        own = self._own_layer(payload, joined)
        user_texts = own["user_texts"]
        # unlisted model-call shape: mask every string, block nothing
        unknown = not user_texts and not own["doc_texts"] and rules.ai_shaped_request(_blob(payload))
        if unknown:
            user_texts = _long_strings(payload)
        data = self._data_layers(payload, joined, user_texts, own["doc_texts"], own["keras"],
                                 own["turn"], unknown)
        person_hunt = _person_hunt(data["ext"], own["current"])
        # MASK means the person's own words exposed something.
        person_words = _person_turn(data["masked"])["words"]
        # bare arrays have no turns: masked means MASK
        bare = isinstance(payload, list)
        own_mask = (unknown or bare) and bool(data["mapping"]) or any(
            tok in data["mapping"] for tok in rules.TOKEN_SHAPE.findall(person_words))
        action, blocked_by, _, notes = arbitrate(
            bool(own["keras"]), bool(own["lunak"]), own_mask, data["ext"],
            person_hunt=person_hunt,
        )
        notes["external_state"] = data["ext_state"]
        if action == "BLOCK" and newest_said and not own["newest_turn_is_tool_output"]:
            _remember_blocked(newest_said)
        return {
            "stripped": stripped,
            "action": action, "blocked_by": blocked_by, "notes": notes,
            "ext": data["ext"], "ext_state": data["ext_state"], "lunak": own["lunak"],
            "keras": own["keras"], "hits": own["hits"], "downgraded": own["downgraded"],
            "history_warnings": own["history_warnings"], "mapping": data["mapping"],
            "masked": data["masked"], "counters": data["counters"], "kinds": data["kinds"],
            "sem_state": data["sem_state"], "dlp_state": data["dlp_state"],
            "newest_turn_is_tool_output": own["newest_turn_is_tool_output"],
            "prompt_sha": own["prompt_sha"], "user_masked_kinds": own["user_masked_kinds"],
            "user_warn": own["user_warn"], "current": own["current"],
            "person_hunt": person_hunt, "turn_shape": own["turn_shape"],
            "unknown_shape": unknown,
        }

    def _send_block(self, flow: http.HTTPFlow, host: str, raw: str, request_id: str,
                    tag: str, state: dict) -> dict:
        """Answer 403 and record the block."""
        keras = state["keras"]
        blocked_by = state["blocked_by"]
        notes = state["notes"]
        hits = state["hits"]
        newest_turn_is_tool_output = state["newest_turn_is_tool_output"]
        prompt_sha = state["prompt_sha"]
        if keras:
            rule, matched = keras[0][0], keras[0][1]
        else:
            rule, matched = str(blocked_by.get("rule", "external")), str(blocked_by.get("match", ""))
        # an external block names its category and severity
        named = rule if keras else f"{rule} ({rules.atr_label(blocked_by)})"
        findings = sorted(set(r for r, _, _ in hits) | set(notes["external_rules"]))
        body = json.dumps(
            {
                "error": {
                    "message": (
                        f"LLM Guardrail blocked this request. Rule matched: {named}. "
                        f"Nothing was sent to the provider. {BLOCK_NOT_KEY}"
                    ),
                    "type": "guardrail_block",
                    "rule": rule,
                    "category": blocked_by.get("category", ""),
                    "severity": blocked_by.get("severity", ""),
                    "findings": findings,
                    "blocked_by": blocked_by.get("source", "own"),
                    "request_id": request_id,
                }
            },
            ensure_ascii=False,
        ).encode("utf-8")
        flow.response = http.Response.make(
            403, body, {"Content-Type": "application/json", "X-LLM-Guardrail": "blocked"}
        )
        client = str((flow.metadata.get("guardrail_origin") or {}).get("client") or "")
        repeat, first_id = _block_repeat(rule, matched, client, request_id, host, prompt_sha)
        if not repeat:
            notify_block(host, rule, matched, request_id, model_of(raw), endpoint_of(flow))
        record = audit_record(
            "BLOCK", host, request_id, findings=findings, matched=matched,
            rule=rule, chars_in=len(raw),
        )
        if repeat:
            record["repeat_of_block"] = repeat
            record["block_group"] = first_id
        else:
            record["attempts"] = 1
        record["blocked_by"] = blocked_by.get("source", "own")
        if not keras and blocked_by.get("category"):
            record["atr_blocked"] = rules.atr_label(blocked_by)
        if newest_turn_is_tool_output:
            record["newest_turn"] = "tool_output"
        if tag:
            record["tag"] = tag
        if prompt_sha:
            record["prompt_sha"] = prompt_sha
        record["turn_shape"] = state["turn_shape"]
        return record

    def _send_forwarded(self, flow: http.HTTPFlow, host: str, payload, raw: str, request_id: str,
                        tag: str, state: dict) -> dict:
        """Mask and forward, warn or notify, then record."""
        action = state["action"]
        mapping = state["mapping"]
        masked = state["masked"]
        counters = state["counters"]
        kinds = state["kinds"]
        ext = state["ext"]
        lunak = state["lunak"]
        notes = state["notes"]
        tag_sent = ""
        masked, filtered = _filter_external(masked, ext, action, counters, mapping)
        state["filtered_landed"] = filtered
        scope = _person_scope(masked, mapping, ext, state["current"], filtered)
        flow.metadata["guardrail_filtered"] = filtered
        flow.metadata["guardrail_scope"] = scope
        body = payload
        if mapping or filtered or state.get("stripped"):
            body = masked
            masked_text = _body_text(flow, masked)
            flow.request.set_text(masked_text)
            flow.metadata["guardrail_map"] = mapping
        # the proxy asks for the tag, not the person
        tag_action = "MASK" if state["user_masked_kinds"] else ("WARN" if state["user_warn"] else "")
        tag_sent = _send_note(flow, body, tag_action)
        warn_rules = _forward_warn_set(lunak, ext, action, state["person_hunt"])
        if warn_rules:
            flow.metadata["guardrail_warn"] = (
                [(r, m, lv) for r, m, lv in lunak]
                or [(w, "", "external") for w in warn_rules]
            )
        client = str((flow.metadata.get("guardrail_origin") or {}).get("client") or "")
        # one notification per request, from the final action
        if action == "WARN":
            raised = _raising(ext) + state["person_hunt"]
            matched = lunak[0][1] if lunak else (raised[0].get("match", "") if raised else "")
            if not _banner_repeat(host, client, [f"warn\0{r}" for r in warn_rules]):
                notify_warn(host, warn_rules, matched, request_id, model_of(raw), endpoint_of(flow))
            debug(f"warned (forwarded): own={[r for r, _, _ in lunak]} "
                  f"external={notes['external_rules']}")
        elif action in ("FILTER", "MASK"):
            items = _scope_values(masked, mapping) + [f"filter\0{k}" for k in scope["filtered"]]
            _notify_changed(host, scope, request_id, model_of(raw), endpoint_of(flow),
                            _banner_repeat(host, client, items))
        record = audit_record(
            action, host, request_id,
            findings=sorted(set(kinds) | set(warn_rules)),
            chars_in=len(raw),
            chars_out=len(flow.request.get_text(strict=False) or ""),
        )
        record["user_scope"] = scope
        return _record_extras(record, state, tag, tag_sent, warn_rules, kinds, mapping)

    def _finish_record(self, flow: http.HTTPFlow, host: str, request_id: str,
                       record: dict, state: dict) -> None:
        """Add the shared tail, write history, audit it."""
        notes = state["notes"]
        ext_state = state["ext_state"]
        if ext_state.get("mode") != "off":
            record["external"] = notes["external_rules"]
            record["hunt"] = notes["external_hunt_rules"]
        record["external_state"] = ext_state
        if "layers" not in record and (health := _layer_health()):
            record["layers"] = health
        if state.get("unknown_shape"):
            record["unknown_shape"] = True
        if state.get("stripped"):
            record["history_stripped"] = state["stripped"]
        if flow.metadata.get("guardrail_reply_untouched"):
            record["reply_note"] = "out-of-band"
        if state["sem_state"] is not None:
            record["semantic"] = state["sem_state"]
            if state["sem_state"].get("degraded"):
                # some text reached the wire without a full model pass
                record["semantic_degraded"] = True
        if state["dlp_state"] is not None:
            record["dlp_data"] = state["dlp_state"]
        origin = flow.metadata.get("guardrail_origin")
        if origin:
            _add_origin(record, origin)
        if _is_telemetry(flow.request.path):
            record["telemetry"] = True
        t0 = flow.metadata.get("guardrail_t0")
        if t0:
            record["request_ms"] = round((time.monotonic() - t0) * 1000, 1)
        # Masked values on the wire audit as MASK.
        if record.get("action") in ("PASS", "WARN") and state["mapping"] and state["kinds"]:
            record["action"] = "MASK"
            record.setdefault("masked_kinds", state["kinds"])
        # registry is per request; drop after masking
        rules.release_request(state["mapping"])
        scope = flow.metadata.get("guardrail_scope") or {
            "values": 0, "kinds": [], "filtered": [], "hunt": []}
        # Session history: the stored text is masked; raw needs GUARDRAIL_HISTORY_RAW.
        last_user_text = _person_turn(state["masked"])["words"]
        flow.metadata["guardrail_note"] = rules.note_for(
            scope["values"], scope["kinds"], scope["filtered"], scope["hunt"])
        flow.metadata["guardrail_seed"] = dict(state["mapping"])
        if record.get("repeat_of_block"):
            debug(f"client retry of a blocked prompt: {record['repeat_of_block']} blocks so far")
            # each retry gets its own line, with a running count
            record["attempts"] = record["repeat_of_block"]
            audit(record)
            return
        write_history(
            record.get("action", state["action"]),
            host,
            request_id,
            kinds=record.get("findings") or sorted(state["counters"]),
            text=last_user_text,
            raw_text=state["current"],
        )
        audit(record)

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        """Thin wrapper: frame failures are audited, blocked only if asked."""
        try:
            self._handle_ws_message(flow)
        except Exception as exc:  # noqa: BLE001
            host = _flow_host(flow)
            debug(f"frame handling failed: {type(exc).__name__}: {exc}")
            audit(audit_record("ERROR", host, uuid.uuid4().hex[:8], findings=[
                f"unchecked frame, forwarded: {type(exc).__name__}: {exc}"[:140]]))
            if rules.INTERNAL_ERROR_MODE == "block":
                self._drop_frame(flow, self._ws_notice(
                    "LLM Guardrail could not inspect this frame and is set to block. "
                    f"Nothing was sent to the provider. {BLOCK_NOT_KEY}"))

    @staticmethod
    def _ws_notice(message: str) -> dict:
        """The error frame a websocket client gets for a block."""
        return {"type": "error", "status": 403, "error": {
            "type": "guardrail_block", "code": "guardrail_block", "message": message}}

    @staticmethod
    def _drop_frame(flow: http.HTTPFlow, reply: dict | None = None) -> None:
        """Drop the newest frame, tell the client, close."""
        flow.websocket.messages[-1].drop()
        if reply is not None:
            try:
                ctx.master.commands.call("inject.websocket", flow, True,
                                         json.dumps(reply).encode(), True)
            except Exception as exc:  # noqa: BLE001 (the close below still happens)
                debug(f"block reply not delivered: {type(exc).__name__}: {exc}")
        if flow.killable:
            flow.kill()

    def _ws_unparsed(self, flow: http.HTTPFlow, host: str, raw: str, reason: str) -> None:
        """Record an unread frame on an AI socket."""
        verdict = rules.classify_request(host, flow.request.headers, raw,
                                         explicit=rules.AI_PROVIDER_HOSTS, path=flow.request.path)
        if verdict["verdict"] != "ai":
            return
        record = audit_record("UNPARSED", host, uuid.uuid4().hex[:8], chars_in=len(raw),
                              chars_out=len(raw))
        record.update(unparsed=reason, channel="websocket")
        _add_origin(record, verdict)
        audit(record)

    def _handle_ws_message(self, flow: http.HTTPFlow) -> None:
        """Inspect the person's frames; the provider's own are left alone."""
        msg = flow.websocket.messages[-1]
        if not msg.from_client or not msg.is_text:
            return
        raw = msg.text
        host = _flow_host(flow)
        if raw.lstrip()[:1] not in ("{", "["):
            self._ws_unparsed(flow, host, raw, "not-json")
            return
        deep = False
        try:
            payload = json.loads(raw)
            deep = _too_deep(payload)
        except RecursionError:
            deep = True
        except (ValueError, TypeError):
            self._ws_unparsed(flow, host, raw, "bad-json")
            return
        request_id = uuid.uuid4().hex[:8]
        if deep:
            self._drop_frame(flow, self._ws_notice(
                "LLM Guardrail blocked a frame nested too deep to inspect. "
                f"Nothing was sent to the provider. {BLOCK_NOT_KEY}"))
            audit(audit_record("BLOCK", host, request_id, chars_in=len(raw),
                               findings=["frame nested too deep to inspect"]))
            return
        verdict = rules.classify_request(host, flow.request.headers, raw,
                                         explicit=rules.AI_PROVIDER_HOSTS, path=flow.request.path)
        if verdict["verdict"] != "ai":
            return
        flow.metadata["guardrail_origin"] = verdict
        state = self._inspect(payload)
        if state["action"] == "BLOCK":
            keras, by = state["keras"], state["blocked_by"]
            rule = keras[0][0] if keras else str(by.get("rule", "external"))
            matched = keras[0][1] if keras else str(by.get("match", ""))
            self._drop_frame(flow, self._ws_notice(
                f"LLM Guardrail blocked this request. Rule matched: {rule}. "
                f"Nothing was sent to the provider. {BLOCK_NOT_KEY}"))
            client = str((flow.metadata.get("guardrail_origin") or {}).get("client") or "")
            repeat, first_id = _block_repeat(rule, matched, client, request_id, host,
                                             state["prompt_sha"])
            if not repeat:
                notify_block(host, rule, matched, request_id, model_of(raw), endpoint_of(flow))
            findings = sorted(set(r for r, _, _ in state["hits"]) | set(state["notes"]["external_rules"]))
            record = audit_record("BLOCK", host, request_id, findings=findings, matched=matched,
                                  rule=rule, chars_in=len(raw))
            if repeat:
                record["repeat_of_block"] = repeat
                record["block_group"] = first_id
            else:
                record["attempts"] = 1
            record["blocked_by"] = by.get("source", "own")
        else:
            masked, filtered = _filter_external(state["masked"], state["ext"], state["action"],
                                                state["counters"], state["mapping"])
            if state["mapping"] or filtered or state.get("stripped"):
                msg.text = json.dumps(masked, ensure_ascii=False)
            record = audit_record(state["action"], host, request_id, findings=state["kinds"],
                                  chars_in=len(raw), chars_out=len(msg.text))
        record["channel"] = "websocket"
        self._finish_record(flow, host, request_id, record, state)

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        """Buffer responses that must be read whole before re-checking."""
        if flow.response is None:
            return
        if flow.metadata.get("guardrail_map") or flow.metadata.get("guardrail_note"):
            flow.response.stream = False
        warn = flow.metadata.get("guardrail_warn")
        if warn:
            # the warning trail is visible in the traffic too
            flow.response.headers["X-LLM-Guardrail-Warn"] = ",".join(sorted({r for r, _, _ in warn}))

    def response(self, flow: http.HTTPFlow) -> None:
        note = flow.metadata.get("guardrail_note") or ""
        if not (flow.metadata.get("guardrail_map") or note) or flow.response is None:
            return
        text = flow.response.get_text(strict=False)
        if not text:
            debug(f"answer: empty response body for {flow.request.host}")
            return
        ctype = (flow.response.headers.get("content-type") or "").lower()
        recheck = _recheck_sse if "event-stream" in ctype else _recheck_answer
        restored, hits = recheck(text, flow.metadata.get("guardrail_seed") or {})
        if hits:
            flow.metadata["guardrail_note"] = note = note + rules.ANSWER_RECHECK_NOTE.format(count=hits)
        if rules.NOTIFY_IN_REPLY and note and restored \
                and not flow.metadata.get("guardrail_reply_untouched"):
            # say it where the person looks: the answer
            restored = rules.append_note(restored, note, ctype)
        flow.response.set_text(restored)
        t0 = flow.metadata.get("guardrail_t0")
        dur = f"{(time.monotonic() - t0) * 1000:.0f} ms" if t0 else "?"
        debug(
            f"done in {dur} | recheck {flow.request.host}: {hits} tokens, "
            f"{len(text)} -> {len(restored)} chars, content changed={restored != text} "
            f"| type={flow.response.headers.get('content-type', '?')[:40]} "
            f"stream_attr={getattr(flow.response, 'stream', None)} "
            f"status={flow.response.status_code}"
        )


def _recheck_answer(text: str, seed: dict) -> tuple[str, int]:
    """Mask the answer again before it reaches the person."""
    mapping = dict(seed)
    counters: dict[str, int] = {}
    try:
        data = json.loads(text)
    except ValueError:
        out, _ = rules.mask_text(text, counters, mapping)
        return out, len(mapping) - len(seed)
    out = _map_strings(data, lambda t: rules.mask_text(t, counters, mapping)[0])
    if len(mapping) == len(seed):
        return text, 0
    return json.dumps(out, ensure_ascii=False), len(mapping) - len(seed)


def _recheck_sse(body: str, seed: dict) -> tuple[str, int]:
    """Mask a streamed answer again, per text slot."""
    chunks, sep = _sse_body_parts(body)
    slots, objs = _sse_slots(chunks)
    mapping, counters = dict(seed), {}
    groups: dict[tuple, list] = {}
    for slot in slots:
        groups.setdefault((slot[2], objs[slot[0]].get("index")), []).append(slot)
    for group in groups.values():
        joined = "".join(slot[3] for slot in group)
        masked = rules.mask_text(joined, counters, mapping)[0]
        if masked == joined:
            continue
        for slot in group:
            slot[1][slot[2]] = ""
        group[0][1][group[0][2]] = masked
    hits = len(mapping) - len(seed)
    return (_sse_write(chunks, slots, objs, sep), hits) if hits else (body, 0)


def _answer_slots(obj: dict) -> list[tuple[dict, str]]:
    """Every holder and key carrying answer text in one object."""
    out: list[tuple[dict, str]] = []
    holders: list[dict] = []
    for choice in obj.get("choices") or []:
        if not isinstance(choice, dict):
            continue
        for holder_name in ("delta", "message"):
            holder = choice.get(holder_name)
            if isinstance(holder, dict):
                holders.append(holder)
    for name in ("delta", "content_block"):
        holder = obj.get(name)
        if isinstance(holder, dict):
            holders.append(holder)
    for holder in holders:
        for key in ("content", "reasoning_content", "text", "thinking", "partial_json"):
            piece = holder.get(key)
            if isinstance(piece, str) and piece:
                out.append((holder, key))
    return out


def _sse_body_parts(body: str) -> tuple[list[str], str]:
    """Split an SSE body; CRLF framing is kept too."""
    if "\r\n\r\n" in body:
        return body.split("\r\n\r\n"), "\r\n\r\n"
    return body.split("\n\n"), "\n\n"


def _sse_slots(chunks: list[str]) -> tuple[list, dict]:
    """Every answer slot per chunk, with its parsed object."""
    slots: list[tuple[int, dict, str, str]] = []
    objs: dict[int, dict] = {}
    for idx, chunk in enumerate(chunks):
        lines = chunk.split("\n")
        data_at = next((n for n, line in enumerate(lines) if line.startswith("data:")), None)
        if data_at is None:
            continue
        raw = lines[data_at][5:].strip()
        if not raw or raw == "[DONE]":
            continue
        try:
            obj = json.loads(raw)
        except ValueError:
            # unparseable chunk: it carries no answer slot
            continue
        if not isinstance(obj, dict):
            continue
        pieces = _answer_slots(obj)
        if not pieces:
            continue
        for holder, key in pieces:
            slots.append((idx, holder, key, holder[key]))
        objs[idx] = obj
    return slots, objs


def _sse_write(chunks: list[str], slots: list[tuple[int, dict, str, str]],
               objs: dict[int, dict], sep: str = "\n\n") -> str:
    """Rebuild only the chunks whose answer text changed."""
    out = list(chunks)
    written = set()
    for idx, holder, key, piece in slots:
        if holder[key] == piece or idx in written:
            continue
        lines = out[idx].split("\n")
        data_at = next(n for n, line in enumerate(lines) if line.startswith("data:"))
        ending = "\r" if lines[data_at].endswith("\r") else ""
        lines[data_at] = "data: " + json.dumps(objs[idx], ensure_ascii=False,
                                               separators=(",", ":")) + ending
        out[idx] = "\n".join(lines)
        written.add(idx)
    return sep.join(out)


addons = [Guardrail()]

# --- CLI: run, inspect, switch off ---
def _cli() -> int:
    cmd = (sys.argv[1] if len(sys.argv) > 1 else "run").lower()
    tail = sys.argv[2:]
    if cmd == "run":
        return _cli_run(tail)
    if cmd == "status":
        return _cli_status()
    if cmd == "pac":
        return _cli_pac(tail)
    if cmd == "audit":
        return _cli_audit(tail)
    if cmd == "off":
        return _cli_off()
    if cmd == "last":
        return last()
    if cmd == "notify-test":
        return _cli_notify_test()
    print(__doc__)
    return 2


def _cli_run(argv: list[str]) -> int:
    """Start mitmdump with this file as the addon."""
    here = Path(__file__).resolve()
    # mitmdump console script from this venv
    # -m exits without starting
    binary = Path(sys.executable).with_name("mitmdump")
    if binary.exists():
        args = [str(binary)]
    else:
        args = [sys.executable, "-m", "mitmproxy.tools.main", "mitmdump"]
    # -s would load this twice
    # add only if not listed
    cfg = Path.home() / ".mitmproxy/config.yaml"
    listed = cfg.exists() and str(here) in cfg.read_text(encoding="utf-8")
    if not listed:
        args += ["-s", str(here)]
    return subprocess.call(args + argv)


def _model_layer_note() -> str:
    """One phrase about the model layer, including a recorded error."""
    if rules.MODE == "off":
        return "off: this layer is not running"
    try:
        errors = (rules.summarize_metrics().get("reasons") or {}).get("model-error", 0)
    except Exception:  # noqa: BLE001 - an unreadable metrics file is not a crash
        return "model-error count unavailable (metrics unreadable)"
    return f"model-error recorded {errors} time(s)"


def _dlp_report_lines(dlp: dict) -> list[str]:
    """The data base lines: what loaded, and what failed."""
    counts = ", ".join(f"{kind} {value}" for kind, value in (dlp.get("rules") or {}).items())
    errors = dlp.get("errors") or []
    return [
        f"data base         : {'on' if rules.DLP_ENABLED else 'off'} "
        f"({dlp.get('patterns', 0)} patterns: {counts}; {dlp.get('failed', 0)} unusable; "
        f"{dlp.get('places', 0)} place names, {dlp.get('postal', 0)} postal codes loaded on demand; "
        f"budget {rules.DLP_BUDGET_MS} ms)",
        "data errors       : " + ("; ".join(str(e) for e in errors) if errors else "none")
        + f"; {dlp.get('failed', 0)} corpus rules unusable",
    ]


def _atr_report_lines(atr: dict) -> list[str]:
    """The ATR lines: what loaded, what was dropped."""
    tail = (f"(dropped {atr.get('dropped', 0)} rules, "
            f"{atr.get('conditions_not_regex', 0)} conditions not regex, "
            f"{atr.get('skipped', 0)} files skipped)")
    return [
        f"ATR rules         : {atr.get('rules_used', 0)} rules, "
        f"{atr.get('conditions', 0)} patterns, lanes {atr.get('lanes')}",
        f"ATR load errors   : {atr.get('error') or 'none'} {tail}",
    ]


def _cli_status() -> int:
    """Print what the proxy loaded, no restart needed."""
    cfg = rules.load_config()   # reread the file so an edit shows up here
    rules.atr_start()           # load the rule set so the counts are real
    st = rules.atr_status()
    try:  # inside a running proxy the live options win
        host, port = ctx.options.listen_host, ctx.options.listen_port
    except AttributeError:  # from a shell: read the mitmproxy config file
        import yaml
        doc = yaml.safe_load((Path.home() / ".mitmproxy/config.yaml").read_text(
            encoding="utf-8")) or {}
        host, port = doc.get("listen_host"), doc.get("listen_port")
    print(f"listen            : {host}:{port}")
    print(f"config file       : {cfg['path']} (loaded: {cfg['loaded']})")
    print(f"AI endpoints      : {len(rules.AI_PROVIDER_HOSTS)} patterns, "
          f"e.g. {rules.AI_PROVIDER_HOSTS[:3]}")
    print(f"your dlp rules    : {[r['name'] + ':' + r['action'] for r in cfg['user_rules']] or '-'}")
    print(f"disabled built-ins: {cfg['disabled'] or '-'}")
    print(f"config errors     : {cfg['errors'] or '-'}")
    # a reported model-error is not a healthy layer
    print(f"model layer       : {rules.MODE} (budget {SEM_BUDGET_MS} ms, "
          f"threshold {rules.THRESHOLD}; {_model_layer_note()})")
    print(f"strictness       : {rules.strictness()} {rules.mode_settings()}")
    print(f"external layer    : {external_mode()} (budget {EXTERNAL_BUDGET_MS} ms)")
    if not rules.DLP_STATE.get("loaded"):
        rules.load_dlp()          # the status output reports the real counts
    dlp = rules.DLP_STATE
    for line in _dlp_report_lines(dlp):
        print(line)
    atr = st["atr"]
    for line in _atr_report_lines(atr):
        print(line)
    st2 = rules.routed_status()
    # counts here; tool names stay in the debug log
    print(f"AI apps installed : {len(rules.detect_ai_apps())} detected")
    print(f"AI apps running   : {len(st2['apps_running'])} detected")
    outside = [c["host"] for c in st2["connections"]][:6]
    print(f"AI traffic now    : {outside or '-'} (hosts leaving without inspection)")
    print(f"desktop proxy     : {rules.desktop_proxy_state()}")
    # unchecked (24h) count keeps silent fail-open visible
    print(f"unchecked (24h)   : {_unchecked_last_day()}")
    print(f"model-degraded 24h: {_degraded_last_day()}")
    stale = _stale_module_last_day()
    if stale:
        # rules.py changed under a live proxy
        print(f"stale module (24h): {stale}")
    print(f"audit log         : {AUDIT}")
    return 0


def _cli_pac(argv: list[str]) -> int:
    """Write proxy.pac from the endpoint list the proxy uses."""
    cfg = rules.load_config()
    target = Path(argv[0]) if argv else rules.pac_file()
    proxy = _pac_proxy()
    _write_pac_file(target, _pac_text(
        "// proxy.pac - generated by `python guardrail.py pac`. Do not edit by hand:\n"
        "// the endpoint list lives in guardrail.yaml, and this file is rebuilt from it.\n"
        "//\n"
        "// Enable in the browser:\n"
        "//   gsettings set org.gnome.system.proxy mode 'auto'\n"
        f"//   gsettings set org.gnome.system.proxy autoconfig-url 'file://{target}'\n"
        "// Disable:\n"
        "//   gsettings set org.gnome.system.proxy mode 'none'\n",
        proxy, rules.AI_PROVIDER_HOSTS))
    print(f"written: {target}  ({len(rules.AI_PROVIDER_HOSTS)} endpoints from {cfg['path']})")
    return 0


def _cli_audit(argv: list[str]) -> int:
    limit = int(argv[0]) if argv else 20
    lines = [l for l in AUDIT.read_text(encoding="utf-8").splitlines() if l.strip()] \
        if AUDIT.exists() else []
    for line in lines[-limit:]:
        print(line)
    print(f"({len(lines)} records in total)")
    return 0


def _cli_off() -> int:
    killed = subprocess.call(["pkill", "-f", "mitmdump.*guardrail.py"])
    desktop = rules.set_desktop_proxy(False)
    print("proxy stopped" if killed == 0 else "no proxy was running")
    print(f"desktop proxy released: {desktop.get('state') or desktop.get('error')}")
    print("traffic is normal again. If a shell still has the proxy variables set, start a new "
          "shell or run: unset https_proxy http_proxy HTTPS_PROXY HTTP_PROXY ALL_PROXY")
    return 0


def _cli_notify_test() -> int:
    """Three popups to test the desktop side."""
    notify_mask("example.com", ["EMAIL", "KUNCI_API"], 2, "test1234")
    notify_block("example.com", "jailbreak_override", "ignore all previous instructions", "test1234")
    notify_warn("example.com", ["destructive_command"], "dd if=/dev/zero of=/dev/sda", "test1234")
    print("three test notifications sent (check the corner of the screen)")
    # timers are daemon threads; wait or banners stay
    time.sleep(CLOSE_AFTER_S + 1)
    return 0


# ---------------------------------------------------------------------------
# notifications, audit, history, debug trace
# moved here from notify.py
# ---------------------------------------------------------------------------
BASE = rules.base_dir()
LOGS = BASE / "logs"
AUDIT = LOGS / "audit.jsonl"
DEBUG_LOG = LOGS / "debug.log"
DEBUG_ON = os.environ.get("GUARDRAIL_DEBUG", "0") == "1"
APP_NAME = "LLM Guardrail"
ICON_MASK = "dialog-information"
ICON_BLOCK = "security-high"
ICON_WARN = "dialog-warning"

# session history: what hit the proxy, tokenised only
DATA = BASE / "data"
HISTORY = DATA / "history.jsonl"
HISTORY_TXT = DATA / "history.log"
NOTIFY_STATE = DATA / "notify_state.json"
# a malformed value never breaks the addon
CLOSE_AFTER_S = rules.env_number("GUARDRAIL_NOTIFY_CLOSE_S", 6, float)
HISTORY_RAW = os.environ.get("GUARDRAIL_HISTORY_RAW", "0") == "1"
HISTORY_MAX_BYTES = rules.env_number("GUARDRAIL_HISTORY_MAX", 5 * 1024 * 1024)
HISTORY_TEXT_CHARS = 400
MATCHED_TEXT_CHARS = 60
SESSION = os.environ.get("GUARDRAIL_SESSION") or (
    f"{datetime.now().astimezone().strftime('%Y%m%d-%H%M%S')}-{os.getpid()}"
)


def _now() -> str:
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")


def now_iso() -> str:
    """Current time as an ISO 8601 string."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def debug(msg: str) -> None:
    """Technical trace, off by default (GUARDRAIL_DEBUG=1)."""
    if not DEBUG_ON:
        return
    LOGS.mkdir(parents=True, exist_ok=True)
    with DEBUG_LOG.open("a", encoding="utf-8") as fh:
        fh.write(f"{_now()} {msg}\n")


def audit(record: dict) -> None:
    """One JSON line per decision, never a raw value."""
    LOGS.mkdir(parents=True, exist_ok=True)
    record = {"ts": datetime.now().astimezone().isoformat(timespec="seconds"), **record}
    with _AUDIT_LOCK, AUDIT.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def _notify(title: str, body: str, urgency: int, icon: str = ICON_MASK) -> None:
    """Desktop notification through gdbus on the session bus."""
    cmd = [
        "gdbus", "call", "--session",
        "--dest", "org.freedesktop.Notifications",
        "--object-path", "/org/freedesktop/Notifications",
        "--method", "org.freedesktop.Notifications.Notify",
        APP_NAME, "0", icon, title, body,
        "[]", "{'urgency': <byte %d>, 'transient': <true>}" % urgency, "%d" % int(CLOSE_AFTER_S * 1000),
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if res.returncode != 0:
            debug(f"notification failed: {res.stderr.strip()[:200]}")
            return
        close_later(_notification_id(res.stdout))
    except Exception as exc:  # a notification must never kill the proxy
        debug(f"notification error: {exc}")


def _notification_id(stdout: str) -> int | None:
    """The service answers (uint32 42,); pull the id out."""
    match = re.search(r"uint32\s+(\d+)", stdout or "")
    return int(match.group(1)) if match else None


def _read_ids() -> list[int]:
    try:
        data = json.loads(NOTIFY_STATE.read_text(encoding="utf-8"))
        return [int(i) for i in data if str(i).isdigit()]
    except Exception:
        return []


def _write_ids(ids: list[int]) -> None:
    try:
        DATA.mkdir(parents=True, exist_ok=True)
        NOTIFY_STATE.write_text(json.dumps(sorted(set(ids))), encoding="utf-8")
    except Exception as exc:
        debug(f"notification state not written: {exc}")


def close_later(notification_id: int | None) -> None:
    """Remember the id and close the banner on a timer."""
    if notification_id is None:
        return
    _write_ids(_read_ids() + [notification_id])
    timer = threading.Timer(CLOSE_AFTER_S, close_notification, args=(notification_id,))
    timer.daemon = True
    timer.start()


def close_notification(notification_id: int) -> None:
    cmd = [
        "gdbus", "call", "--session",
        "--dest", "org.freedesktop.Notifications",
        "--object-path", "/org/freedesktop/Notifications",
        "--method", "org.freedesktop.Notifications.CloseNotification",
        str(notification_id),
    ]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except Exception as exc:
        debug(f"close notification {notification_id} failed: {exc}")
    _write_ids([i for i in _read_ids() if i != notification_id])


def startup() -> None:
    """Close banners a previous run left on screen."""
    ids = _read_ids()
    for notification_id in ids:
        close_notification(notification_id)
    _write_ids([])
    debug(f"session {SESSION} started; swept {len(ids)} notification(s) from earlier runs")


def write_history(action: str, host: str, request_id: str, kinds: list[str] | None = None,
            text: str = "", raw_text: str = "") -> None:
    """One line per decision that touched sensitive data."""
    findings = sorted(set(kinds or []))
    if not findings:
        # Nothing sensitive was touched, so nothing is kept.
        return
    shown = (raw_text if HISTORY_RAW and raw_text else text) or ""
    shown = " ".join(shown.split())[:HISTORY_TEXT_CHARS]
    record = {
        "ts": datetime.now().astimezone().isoformat(timespec="seconds"),
        "session": SESSION,
        "host": host,
        "request_id": request_id,
        "action": action,
        "findings": findings,
        "text_masked": shown,
        "raw": bool(HISTORY_RAW and raw_text),
    }
    try:
        DATA.mkdir(parents=True, exist_ok=True)
        if HISTORY.exists() and HISTORY.stat().st_size > HISTORY_MAX_BYTES:
            HISTORY.replace(HISTORY.with_suffix(".jsonl.1"))
            HISTORY_TXT.replace(HISTORY_TXT.with_suffix(".log.1"))
        with HISTORY.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        with HISTORY_TXT.open("a", encoding="utf-8") as fh:
            fh.write(
                f"{record['ts']}  session={SESSION}  {action:5s}  {host}  "
                f"id={request_id}  findings={','.join(record['findings']) or '-'}  "
                f"text={shown or '-'}\n"
            )
    except Exception as exc:  # history must never break a request
        debug(f"history not written: {exc}")


MODEL_RE = re.compile(r'"model"\s*:\s*"([^"]{1,64})"')
MODEL_PROBE_CHARS = 4000

# the vendor behind a model name
PROVIDER_BY_MODEL = (
    ("claude", "anthropic"), ("gpt", "openai"), ("o1", "openai"), ("o3", "openai"),
    ("o4", "openai"), ("deepseek", "deepseek"), ("gemini", "google"), ("gemma", "google"),
    ("llama", "meta"), ("mistral", "mistral"), ("mixtral", "mistral"), ("qwen", "alibaba"),
    ("grok", "xai"), ("command", "cohere"), ("phi", "microsoft"), ("glm", "zhipu"),
)


def model_of(text: str) -> str:
    """The model this request asks for."""
    found = MODEL_RE.search((text or "")[:MODEL_PROBE_CHARS])
    if not found:
        return ""
    value = found.group(1).strip()
    # a template or a variable is not a model name
    return "" if any(ch in value for ch in "{}$") else value


def provider_of(model: str) -> str:
    """The vendor behind a model name."""
    name = (model or "").strip().lower()
    for prefix, vendor in PROVIDER_BY_MODEL:
        if name.startswith(prefix):
            return vendor
    return ""


def endpoint_of(flow) -> str:
    """The URL this request is actually going to."""
    return flow.request.pretty_url.split("?")[0]


def _where(model: str, endpoint: str) -> str:
    """Who answers, and which URL was hit."""
    vendor = provider_of(model)
    if vendor and model:
        return f"provider {vendor}, model {model} via {endpoint}"
    if model:
        return f"model {model} via {endpoint}"
    return f"provider not named by the request, via {endpoint}"


def notify_mask(host: str, kinds: list[str], count: int, request_id: str,
                model: str = "", endpoint: str = "") -> None:
    uniq = ", ".join(sorted(set(kinds)))
    _notify("Sensitive data masked",
            f"{_where(model, endpoint or host)} - {uniq} ({count} findings). "
            f"Masked, then forwarded. ID: {request_id}",
            1, ICON_MASK)


def _matched_view(matched: str) -> str:
    """The matched text for the log: short, personal data masked."""
    full = " ".join(str(matched).split())
    try:
        # mask before cutting: a cut number is still a number
        short, _ = rules.mask_text(full, {}, {})
        short, _ = rules.mask_validated(short, {}, {})
    except Exception as exc:  # noqa: BLE001 - a log line never fails a request
        # a failed mask must not write the raw excerpt
        debug(f"excerpt withheld: masking failed: {type(exc).__name__}")
        return f"[excerpt withheld: {len(full)} chars]"
    return short[:MATCHED_TEXT_CHARS]


def notify_filter(host: str, what: list[str], request_id: str,
                  model: str = "", endpoint: str = "") -> None:
    _notify("Malicious part filtered",
            f"{_where(model, endpoint or host)} - {', '.join(what)}. "
            f"Replaced by [blocked], then forwarded. ID: {request_id}",
            2, ICON_BLOCK)


def notify_block(host: str, rule: str, matched: str, request_id: str,
                 model: str = "", endpoint: str = "") -> None:
    _notify("Prompt blocked",
            f"{_where(model, endpoint or host)} - rule: {rule}. Nothing was sent. "
            f"ID: {request_id}",
            2, ICON_BLOCK)


def notify_warn(host: str, rules: list[str], matched: str, request_id: str,
                model: str = "", endpoint: str = "") -> None:
    """The request goes through, the person is warned."""
    _notify("Risky command - check before running",
            f"{_where(model, endpoint or host)} - rule: {', '.join(sorted(set(rules)))}. "
            "Forwarded; check it before running anything. "
            f"ID: {request_id}",
            2, "dialog-warning")


def warn_outside(pairs: list[str]) -> None:
    """One banner when AI traffic leaves without passing the guardrail."""
    if not pairs:
        return
    body = "\n".join(f"  {p}" for p in pairs[:5])
    _notify("LLM Guardrail: AI traffic outside the guardrail",
            f"These are talking to an AI endpoint without being filtered:\n{body}\n"
            "Start them through run.sh, or leave the desktop proxy on for browser/desktop apps.",
            urgency=2, icon=ICON_WARN)


def warn_config(errors: list[str]) -> None:
    """One banner when guardrail.yaml was unusable."""
    if not errors:
        return
    _notify("LLM Guardrail: guardrail.yaml not used",
            f"Built-in defaults are in place because the rules file failed:\n  {errors[0]}\n"
            "Fix guardrail.yaml, or set GUARDRAIL_STRICT_CONFIG=1 to stop instead of guessing.",
            urgency=2, icon=ICON_WARN)


_atr_banner_sent = False


def warn_atr_failed(files_seen: int) -> None:
    """One banner per process when ATR failed twice."""
    global _atr_banner_sent
    if _atr_banner_sent:
        return
    _atr_banner_sent = True
    fate =("refused until the proxy restarts with the rules loaded"
            if rules.INTERNAL_ERROR_MODE == "block"
            else "forwarded without these rules and counted as unchecked")
    debug(f"atr-not-ready: rule set failed {rules.ATR_MAX_ATTEMPTS} times, banner sent")
    _notify("LLM Guardrail: attack rules not loaded",
            f"The ATR rule set failed to load {rules.ATR_MAX_ATTEMPTS} times "
            f"({files_seen} files seen).\nAI requests are {fate}.\nSee: guardrail.py status",
            urgency=2, icon=ICON_WARN)


def audit_record(action: str, host: str, request_id: str, findings: list[str] | None = None,
                 matched: str | None = None, rule: str | None = None,
                 chars_in: int = 0, chars_out: int = 0) -> dict:
    rec = {
        "action": action,
        "host": host,
        "request_id": request_id,
        "findings": sorted(set(findings or [])),
        "chars_in": chars_in,
        "chars_out": chars_out,
    }
    if rule:
        rec["rule"] = rule
    if matched:
        # Log a short masked view, never the raw text.
        rec["matched"] = _matched_view(matched)
    return rec


def last() -> int:
    """Most recent decision (guardrail-last)."""
    if not AUDIT.exists():
        print(f"no audit file yet: {AUDIT}")
        return 1
    lines = [ln for ln in AUDIT.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if not lines:
        print(f"audit file is empty: {AUDIT}")
        return 1
    try:
        rec = json.loads(lines[-1])
    except json.JSONDecodeError:
        print("last line is not readable:", lines[-1][:120])
        return 1
    print("time       :", rec.get("ts", "-"))
    print("host       :", rec.get("host", "-"))
    print("action     :", rec.get("action", "-"))
    print("rule       :", rec.get("rule", "-"))
    print("findings   :", ", ".join(rec.get("findings", [])) or "-")
    print("match      :", rec.get("matched", "-"))
    print("request_id :", rec.get("request_id", "-"))
    print("file       :", AUDIT)
    if len(lines) > 1:
        print(f"(total {len(lines)} records)")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
