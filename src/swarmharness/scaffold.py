from __future__ import annotations

import re
from pathlib import Path

from .spec import SpecError

NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")

TASK_TOML = """\
name = "{name}"
model = "x-preview-f-free"
net_egress = []
max_subagents = 4
subagent_depth = 4

[resources]
cpus = 1
memory_mb = 1024

[timeouts]
build_sec = 300
agent_sec = 1800
verifier_sec = 120

# [oracle]
# threshold = 1.0
"""

INSTRUCTION_MD = """\
Create the file `/logs/agent/deliverable.txt` containing exactly one line:

{marker}

No trailing spaces, no extra lines, nothing else.

Replace this instruction with your real task. Every deliverable must be
written under `/logs/agent/` using absolute paths — anything else does not
exist for grading purposes.
"""

DOCKERFILE = """\
FROM swarmharness/agent-base:latest
"""

VERIFY_PY = '''\
import json
from pathlib import Path

EXPECTED = "{marker}"


def main() -> None:
    target = Path("/deliverables/deliverable.txt")
    exists = target.is_file()
    content = target.read_text(encoding="utf-8", errors="replace").strip() if exists else ""

    checks = [
        {{"name": "file_exists", "score": 1.0 if exists else 0.0}},
        {{"name": "exact_content", "score": 1.0 if content == EXPECTED else 0.0}},
    ]
    score = sum(c["score"] for c in checks) / len(checks)

    reward_dir = Path("/reward")
    reward_dir.mkdir(parents=True, exist_ok=True)
    (reward_dir / "reward.json").write_text(
        json.dumps({{"score": round(score, 4), "status": "ok", "checks": checks}}, indent=2)
    )


try:
    main()
except Exception:
    import traceback

    traceback.print_exc()
    Path("/reward").mkdir(parents=True, exist_ok=True)
    Path("/reward/reward.json").write_text(
        json.dumps({{"score": 0.0, "status": "verifier_error"}}, indent=2)
    )
'''

SOLVE_SH = """\
#!/bin/bash
set -euo pipefail
mkdir -p /logs/agent
printf '{marker}\\n' > /logs/agent/deliverable.txt
"""

DECOMPOSITION_EXAMPLE = """\
# Rename this file to decomposition.yaml to activate multi-agent mode.
coordination_pattern: hierarchical

sub_tasks:
  - id: gather
    parallel_group: gather
    depends_on: []
    description: >-
      Describe the first stage of work here. Write intermediate results under /workspace/.

  - id: deliver
    parallel_group: deliver
    depends_on: [gather]
    description: >-
      Combine gathered results and write every required deliverable under /logs/agent/
      using absolute paths.
"""


def marker_for(name: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_")
    return f"{stem.upper()}_DONE"


def build_task_files(name: str) -> dict[str, str]:
    marker = marker_for(name)
    return {
        "task.toml": TASK_TOML.format(name=name),
        "instruction.md": INSTRUCTION_MD.format(marker=marker),
        "environment/Dockerfile": DOCKERFILE,
        "tests/verify.py": VERIFY_PY.format(marker=marker),
        "solution/solve.sh": SOLVE_SH.format(marker=marker),
        "decomposition.example.yaml": DECOMPOSITION_EXAMPLE,
    }


def create_task(name: str, parent: Path) -> Path:
    name = name.strip()
    if not NAME_RE.match(name):
        raise SpecError(
            f"invalid task name {name!r}: letters/digits/dots/dashes, "
            "must start with a letter, max 64 chars"
        )
    target = parent / name
    if target.exists():
        raise SpecError(f"refusing to overwrite existing path: {target}")

    files = build_task_files(name)
    for rel in files:
        dest = target / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(files[rel], encoding="utf-8")

    solve = target / "solution" / "solve.sh"
    solve.chmod(0o755)
    return target
