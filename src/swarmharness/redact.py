from __future__ import annotations

import re
import urllib.parse
from pathlib import Path

_PATTERNS = [
    re.compile(r"fw_[A-Za-z0-9]{16,}"),
    re.compile(r"sk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"AIzaSy[A-Za-z0-9_-]{30,}"),
    re.compile(r"hf_[A-Za-z0-9]{30,}"),
    re.compile(
        r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}"
    ),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]{16,}"),
    re.compile(
        r"(?i)(api[_-]?key|secret|token|password|authorization)"
        r"[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9._+/=-]{12,}"
    ),
]
_REPLACEMENT = "[REDACTED]"
_SKIP_CHARS = set(" \t\r\n\\\"'+")


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


def _redact_squashed(text: str) -> tuple[str, int]:
    squashed, index = _squash_map(text)
    if not squashed:
        return text, 0
    spans: list[tuple[int, int]] = []
    for pattern in _PATTERNS:
        for m in pattern.finditer(squashed):
            orig_start = index[m.start()]
            orig_end = index[m.end() - 1] + 1
            spans.append((orig_start, orig_end))
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


def redact_bytes(data: bytes) -> tuple[bytes, int]:
    text = data.decode("latin-1")
    scrubbed, count = redact_text(text)
    if count:
        return scrubbed.encode("latin-1"), count
    decoded = urllib.parse.unquote(text)
    unescaped_scrubbed, unescaped_count = redact_text(decoded)
    if unescaped_count:
        return unescaped_scrubbed.encode("latin-1"), unescaped_count
    scrubbed, count = _redact_squashed(text)
    return scrubbed.encode("latin-1"), count


def redact_tree(root: Path) -> int:
    total = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        try:
            scrubbed, count = redact_bytes(data)
        except Exception:
            continue
        if count:
            try:
                path.write_bytes(scrubbed)
                total += count
            except OSError:
                continue
    return total
