from __future__ import annotations

import re
import stat
import sys
import urllib.parse
from pathlib import Path

_PATTERNS = [
    re.compile(r"fw_[A-Za-z0-9]{16,}"),
    re.compile(r"sk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"gsk_[A-Za-z0-9]{20,}"),
    re.compile(r"xai-[A-Za-z0-9]{16,}"),
    re.compile(r"pplx-[A-Za-z0-9]{16,}"),
    re.compile(r"csk-[A-Za-z0-9]{16,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"AIzaSy[A-Za-z0-9_-]{30,}"),
    re.compile(r"hf_[A-Za-z0-9]{30,}"),
    re.compile(
        r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}(?:\.[A-Za-z0-9_-]{4,}){0,2}"
    ),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]{16,}"),
    re.compile(
        r"(?i)(api[_-]?key|apikey|secret|token|password|passwd|pwd|authorization"
        r"|credential|credentials|subscription[_-]?key|ocp[-_]apim[-_]subscription[_-]?key)"
        r"[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9._+/=-]{12,}"
    ),
]
# Unanchored bare-base64 detector (e.g. AWS secret access keys). Deliberately
# NOT in _PATTERNS: it is only ever evaluated on gap-bounded squash spans (see
# _squashed_bare40_spans). Evaluated raw it false-positives on ordinary
# camelCase mashups once squash strips separators — that bug once corrupted a
# verifier's llm_status.json into invalid JSON.
_BARE40 = re.compile(
    r"(?<![A-Za-z0-9/+=])(?![0-9a-f]{40}[^A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])"
)
# Max skipped separator chars a bare-40 squash span may cover. Real split
# secrets span 1–3 separators; JSON syntax mashups span dozens.
_BARE40_MAX_GAP = 12
# Bare-40 also runs on gap-free views (plaintext, url/json-decoded), where the
# span cannot inflate across syntax. Same object, shared with the bounded
# squash path below.
_PATTERNS = _PATTERNS + [_BARE40]
_REPLACEMENT = "[REDACTED]"
_SKIP_CHARS = set(" \t\r\n\\\"'+,:;")
_HEX_DIGITS = set("0123456789abcdefABCDEF")
_MAX_FILE_BYTES = 256 * 1024 * 1024
_JSON_SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", '"': '"', "'": "'", "\\": "\\", "/": "/"}


def redact_text(text: str) -> tuple[str, int]:
    count = 0
    for pattern in _PATTERNS:
        text, n = pattern.subn(_REPLACEMENT, text)
        count += n
    return text, count


def _squash_map(text: str) -> tuple[str, list[int]]:
    chars: list[str] = []
    index: list[int] = []
    for i, ch in enumerate(text):
        if ch not in _SKIP_CHARS:
            chars.append(ch)
            index.append(i)
    return "".join(chars), index


def _unquote_map(text: str) -> tuple[str, list[int], list[int]]:
    chars: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    i, n = 0, len(text)
    while i < n:
        if (
            text[i] == "%"
            and i + 3 <= n
            and text[i + 1] in _HEX_DIGITS
            and text[i + 2] in _HEX_DIGITS
        ):
            j = i
            buf = bytearray()
            while (
                j + 3 <= n
                and text[j] == "%"
                and text[j + 1] in _HEX_DIGITS
                and text[j + 2] in _HEX_DIGITS
            ):
                buf.append(int(text[j + 1 : j + 3], 16))
                j += 3
            try:
                piece = buf.decode("utf-8")
            except UnicodeDecodeError:
                piece = buf.decode("latin-1")
            for c in piece:
                chars.append(c)
                starts.append(i)
                ends.append(j)
            i = j
        else:
            chars.append(text[i])
            starts.append(i)
            ends.append(i + 1)
            i += 1
    return "".join(chars), starts, ends


def _json_unescape_map(text: str) -> tuple[str, list[int], list[int]]:
    chars: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    i, n = 0, len(text)
    while i < n:
        if text[i] == "\\" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "u" and i + 6 <= n and all(c in _HEX_DIGITS for c in text[i + 2 : i + 6]):
                codepoint = int(text[i + 2 : i + 6], 16)
                try:
                    decoded = chr(codepoint)
                except ValueError:
                    decoded = "\ufffd"
                chars.append(decoded)
                starts.append(i)
                ends.append(i + 6)
                i += 6
                continue
            if nxt in _JSON_SIMPLE_ESCAPES:
                chars.append(_JSON_SIMPLE_ESCAPES[nxt])
                starts.append(i)
                ends.append(i + 2)
                i += 2
                continue
        chars.append(text[i])
        starts.append(i)
        ends.append(i + 1)
        i += 1
    return "".join(chars), starts, ends


def _view_spans(view: str, starts: list[int], ends: list[int]) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for pattern in _PATTERNS:
        for m in pattern.finditer(view):
            spans.append((starts[m.start()], ends[m.end() - 1]))
    return spans


def _multidecode_spans(text: str, decode_fn, max_depth: int = 3) -> list[tuple[int, int]]:
    """Collect secret spans through up to `max_depth` nested decodings.

    Handles double-encoded exfil (e.g. %252D) by composing index maps
    across layers instead of rewriting non-secret content.
    """
    spans: list[tuple[int, int]] = []
    if not text:
        return spans
    cur_view = text
    cur_starts = list(range(len(text)))
    cur_ends = [i + 1 for i in range(len(text))]
    for _ in range(max_depth):
        nxt_view, s2, e2 = decode_fn(cur_view)
        if nxt_view == cur_view:
            break
        for pattern in _PATTERNS:
            for m in pattern.finditer(nxt_view):
                s, e = s2[m.start()], e2[m.end() - 1]
                if not 0 <= s < len(cur_starts) or not 0 < e <= len(cur_starts):
                    continue
                lo = min(cur_starts[k] for k in range(s, e))
                hi = max(cur_ends[k] for k in range(s, e))
                if lo < hi:
                    spans.append((lo, hi))
        if not nxt_view:
            break
        new_starts: list[int] = []
        new_ends: list[int] = []
        for j in range(len(nxt_view)):
            s, e = s2[j], e2[j]
            new_starts.append(min(cur_starts[k] for k in range(s, e)))
            new_ends.append(max(cur_ends[k] for k in range(s, e)))
        cur_view, cur_starts, cur_ends = nxt_view, new_starts, new_ends
    return spans


def _apply_spans(text: str, spans: list[tuple[int, int]]) -> tuple[str, int]:
    if not spans:
        return text, 0
    spans.sort()
    merged: list[list[int]] = [list(spans[0])]
    for s, e in spans[1:]:
        if s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    out = text
    for s, e in reversed(merged):
        out = out[:s] + _REPLACEMENT + out[e:]
    return out, len(merged)


def _squashed_bare40_spans(text: str, squashed: str, index: list[int]
                           ) -> list[tuple[int, int]]:
    """Bare-40 matches whose original span covers at most _BARE40_MAX_GAP
    skipped separators. A 40-char run joined across real JSON syntax (quotes,
    colons, commas, newlines) is prose, not a key — replacing it corrupts
    structured artifacts (observed: llm_status.json)."""
    spans: list[tuple[int, int]] = []
    for m in _BARE40.finditer(squashed):
        s, e = index[m.start()], index[m.end() - 1] + 1
        if e - s - (m.end() - m.start()) <= _BARE40_MAX_GAP:
            spans.append((s, e))
    return spans


def _scrub_text(text: str) -> tuple[str, int]:
    total = 0
    # Fixpoint over plaintext + decodings: catches double-encoded exfil
    # without rewriting innocent %/backslash content.
    for _ in range(3):
        prev = text
        text, n = redact_text(text)
        total += n
        text, n = _apply_spans(text, _multidecode_spans(text, _unquote_map))
        total += n
        text, n = _apply_spans(text, _multidecode_spans(text, _json_unescape_map))
        total += n
        if text == prev:
            break
    squashed, index = _squash_map(text)
    spans = [
        (index[m.start()], index[m.end() - 1] + 1)
        for pattern in _PATTERNS
        if pattern is not _BARE40
        for m in pattern.finditer(squashed)
    ]
    spans.extend(_squashed_bare40_spans(text, squashed, index))
    text, n = _apply_spans(text, spans)
    total += n
    return text, total


def _scrub_json_value(obj, _depth: int = 0):
    """Scrub every string in a parsed JSON document individually.

    Span replacements inside one string cannot cross JSON syntax, so the
    re-serialized document stays valid — unlike whole-file scrubbing, where a
    squash-joined false positive can eat quotes/colons and corrupt the file.
    Returns (scrubbed_obj, count)."""
    if _depth > 100:
        return obj, 0
    if isinstance(obj, str):
        return _scrub_text(obj)
    if isinstance(obj, list):
        total = 0
        out = []
        for item in obj:
            item, n = _scrub_json_value(item, _depth + 1)
            total += n
            out.append(item)
        return out, total
    if isinstance(obj, dict):
        total = 0
        out = {}
        for key, value in obj.items():
            key, n = _scrub_json_value(key, _depth + 1)
            total += n
            value, n = _scrub_json_value(value, _depth + 1)
            total += n
            out[key] = value
        return out, total
    return obj, 0


def redact_bytes(data: bytes) -> tuple[bytes, int]:
    import json as _json

    text = data.decode("latin-1")
    # Whole-file pipeline first: it alone catches secrets split across JSON
    # syntax (e.g. {"a": "sk-abcd", "b": "efgh..."}). If the input was valid
    # JSON/JSONL and scrubbing broke a document line's structure
    # (squash-joined false positive eating quotes/colons — observed corruptor
    # of llm_status.json and judge_trajectory.jsonl), fall back to value-wise
    # scrubbing whose spans cannot cross JSON syntax.
    whole, whole_n = _scrub_text(text)
    if whole_n and _looks_structured(text):
        docs = _split_json_docs(text)
        if docs is not None:
            fixed, fixed_n = [], 0
            for doc in docs:
                if doc is None:
                    fixed.append(None)
                    continue
                scrubbed, n = _scrub_text(doc)
                try:
                    _json.loads(scrubbed)
                    fixed.append(scrubbed)
                    fixed_n += n
                    continue
                except ValueError:
                    pass
                try:
                    obj = _json.loads(doc)
                except ValueError:
                    fixed.append(scrubbed)
                    fixed_n += n
                    continue
                obj, n = _scrub_json_value(obj)
                # Compact: one document stays on one line (JSONL structure).
                fixed.append(_json.dumps(obj, ensure_ascii=False))
                fixed_n += n
            glued = _join_json_docs(text, fixed)
            if glued is not None:
                return glued.encode("latin-1", errors="replace"), fixed_n
    return whole.encode("latin-1", errors="replace"), whole_n


def _looks_structured(text: str) -> bool:
    stripped = text.lstrip()
    return stripped[:1] in "{["


def _split_json_docs(text: str) -> list[str | None] | None:
    """Split text into per-line JSON documents (JSONL) or a single document.

    Returns None when the text is not JSON / line-delimited JSON (caller keeps
    the whole-file result). Blank lines are preserved as None."""
    import json as _json

    if "\n" not in text:
        try:
            _json.loads(text)
        except ValueError:
            return None
        return [text]
    docs: list[str | None] = []
    for line in text.split("\n"):
        if not line.strip():
            docs.append(None)
            continue
        try:
            _json.loads(line)
        except ValueError:
            return None
        docs.append(line)
    return docs


def _join_json_docs(text: str, fixed: list[str | None]) -> str | None:
    lines = text.split("\n")
    if len(lines) != len(fixed):
        return None
    return "\n".join(f if f is not None else "" for f in fixed)


def redact_tree(root: Path) -> int:
    total = 0
    for path in sorted(root.rglob("*")):
        try:
            st = path.lstat()
        except OSError:
            continue
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            continue
        if st.st_size > _MAX_FILE_BYTES:
            print(f"warning: redaction skipped oversized file {path}", file=sys.stderr)
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            print(f"warning: unreadable file skipped {path}: {exc}", file=sys.stderr)
            continue
        try:
            scrubbed, count = redact_bytes(data)
        except Exception as exc:
            print(f"warning: redaction failed {path}: {exc}", file=sys.stderr)
            continue
        if count:
            try:
                path.write_bytes(scrubbed)
                total += count
            except OSError as exc:
                print(f"warning: rewrite failed {path}: {exc}", file=sys.stderr)
    return total
