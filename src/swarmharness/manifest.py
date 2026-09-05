from __future__ import annotations

import hashlib
import json
import stat
import time
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(results: Path, meta: dict) -> Path:
    files = []
    for path in sorted(results.rglob("*")):
        rel = path.relative_to(results)
        try:
            st = path.lstat()
        except OSError:
            continue
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            continue
        files.append(
            {
                "path": str(rel),
                "bytes": st.st_size,
                "sha256": sha256_file(path),
            }
        )
    payload = {
        **meta,
        "manifest_finished_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "files": files,
    }
    out = results / "run.json"
    out.write_text(json.dumps(payload, indent=2))
    return out
