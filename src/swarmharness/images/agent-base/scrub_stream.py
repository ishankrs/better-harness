import re
import sys

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
        r"(?<![A-Za-z0-9/+=])(?![0-9a-f]{40}[^A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])"
    ),
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
# Bare-40 kept out of the shared list: only evaluated gap-bounded, so
# squash-joined camelCase in JSONL transcript lines can't false-positive
# (same corruption class as the host redactor's llm_status.json bug).
_BARE40 = re.compile(
    r"(?<![A-Za-z0-9/+=])(?![0-9a-f]{40}[^A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])"
)
_PATTERNS = _PATTERNS + [_BARE40]
_BARE40_MAX_GAP = 12
_REPLACEMENT = "[REDACTED]"
_CHUNK = 1024 * 1024
_MAX_PENDING = 4 * 1024 * 1024
_SKIP_CHARS = set(" \t\r\n\\\"'+,:;")
_HEX_DIGITS = set("0123456789abcdefABCDEF")
_JSON_SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", '"': '"', "'": "'", "\\": "\\", "/": "/"}
# Best-effort live scrub only; the host-side redact_tree() after the run is
# authoritative and also handles multi-line splits spanning flush boundaries.


def _redact_text(text: str) -> str:
    for pattern in _PATTERNS:
        text = pattern.sub(_REPLACEMENT, text)
    return text


def _squash_map(text: str):
    chars: list[str] = []
    index: list[int] = []
    for i, ch in enumerate(text):
        if ch not in _SKIP_CHARS:
            chars.append(ch)
            index.append(i)
    return "".join(chars), index


def _unquote_map(text: str):
    chars: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    i, n = 0, len(text)
    while i < n:
        if text[i] == "%" and i + 3 <= n and text[i + 1] in _HEX_DIGITS and text[i + 2] in _HEX_DIGITS:
            j = i
            buf = bytearray()
            while j + 3 <= n and text[j] == "%" and text[j + 1] in _HEX_DIGITS and text[j + 2] in _HEX_DIGITS:
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


def _json_unescape_map(text: str):
    chars: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    i, n = 0, len(text)
    while i < n:
        if text[i] == "\\" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "u" and i + 6 <= n and all(c in _HEX_DIGITS for c in text[i + 2 : i + 6]):
                try:
                    decoded = chr(int(text[i + 2 : i + 6], 16))
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


def _spans_in_view(view: str, starts: list[int], ends: list[int]):
    spans: list[tuple[int, int]] = []
    for pattern in _PATTERNS:
        for m in pattern.finditer(view):
            spans.append((starts[m.start()], ends[m.end() - 1]))
    return spans


def _multidecode_spans(text: str, decode_fn, max_depth: int = 3):
    spans: list[tuple[int, int]] = []
    if not text:
        return spans
    cur_view, cur_starts, cur_ends = text, list(range(len(text))), [i + 1 for i in range(len(text))]
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
        new_starts, new_ends = [], []
        for j in range(len(nxt_view)):
            s, e = s2[j], e2[j]
            new_starts.append(min(cur_starts[k] for k in range(s, e)))
            new_ends.append(max(cur_ends[k] for k in range(s, e)))
        cur_view, cur_starts, cur_ends = nxt_view, new_starts, new_ends
    return spans


def _apply_spans(text: str, spans: list[tuple[int, int]]) -> str:
    if not spans:
        return text
    spans.sort()
    merged: list[list[int]] = [list(spans[0])]
    for s, e in spans[1:]:
        if s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    for s, e in reversed(merged):
        text = text[:s] + _REPLACEMENT + text[e:]
    return text


def scrub_block(text: str) -> str:
    for _ in range(2):  # fixpoint: catches double-encoded exfil per block
        prev = text
        text = _redact_text(text)
        text = _apply_spans(text, _multidecode_spans(text, _unquote_map))
        text = _apply_spans(text, _multidecode_spans(text, _json_unescape_map))
        squashed, index = _squash_map(text)
        spans = [
            (index[m.start()], index[m.end() - 1] + 1)
            for pattern in _PATTERNS
            if pattern is not _BARE40
            for m in pattern.finditer(squashed)
        ]
        for m in _BARE40.finditer(squashed):
            s, e = index[m.start()], index[m.end() - 1] + 1
            if e - s - (m.end() - m.start()) <= _BARE40_MAX_GAP:
                spans.append((s, e))
        text = _apply_spans(text, spans)
        if text == prev:
            break
    return text


def main() -> None:
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    tail = b""
    while True:
        chunk = stdin.read(_CHUNK)
        if not chunk:
            break
        data = tail + chunk
        nl = data.rfind(b"\n")
        if nl == -1 and len(data) < _MAX_PENDING:
            tail = data
            continue
        if nl == -1:
            cut = len(data)
            tail = b""
        else:
            cut = nl + 1
            tail = data[cut:]
        text = scrub_block(data[:cut].decode("latin-1"))
        stdout.write(text.encode("latin-1", "replace"))
        stdout.flush()
    text = scrub_block(tail.decode("latin-1"))
    stdout.write(text.encode("latin-1", "replace"))
    stdout.flush()


if __name__ == "__main__":
    main()
