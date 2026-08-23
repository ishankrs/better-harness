from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")
DOMAIN_RE = re.compile(r"^(\*\.)?[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")

DEFAULTS = {
    "model": "",
    "verifier_image": "python:3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a",
    "cpus": 2.0,
    "memory_mb": 4096,
    "build_timeout_sec": 600,
    "agent_timeout_sec": 7200,
    "verifier_timeout_sec": 1800,
    "max_subagents": 8,
    "subagent_depth": 8,
    "context_limit": 262144,
    "output_token_max": 32768,
}

MAX_SUBTASKS = 512


class SpecError(Exception):
    pass


@dataclass
class TaskSpec:
    root: Path
    name: str
    model: str
    verifier_image: str
    cpus: float
    memory_mb: int
    build_timeout_sec: int
    agent_timeout_sec: int
    verifier_timeout_sec: int
    net_egress: list[str]
    internet_mode: str
    max_subagents: int
    subagent_depth: int
    context_limit: int
    output_token_max: int
    oracle_threshold: float
    sub_tasks: list[dict] = field(default_factory=list)

    @property
    def instruction_path(self) -> Path:
        return self.root / "instruction.md"

    @property
    def environment_dir(self) -> Path:
        return self.root / "environment"

    @property
    def tests_dir(self) -> Path:
        return self.root / "tests"

    @property
    def artifacts_dir(self) -> Path | None:
        p = self.root / "artifacts"
        return p if p.is_dir() else None

    @property
    def decomposition_path(self) -> Path | None:
        p = self.root / "decomposition.yaml"
        return p if p.is_file() else None

    @property
    def solution_dir(self) -> Path | None:
        p = self.root / "solution"
        return p if p.is_dir() else None

    @property
    def solution_script(self) -> Path | None:
        p = self.solution_dir
        return p / "solve.sh" if p and (p / "solve.sh").is_file() else None


def _merged(raw: dict) -> dict:
    merged = dict(DEFAULTS)
    for section in ("resources", "timeouts"):
        value = raw.get(section) or {}
        if not isinstance(value, dict):
            raise SpecError(f"task.toml: [{section}] must be a table")
        merged.update(value)
    for key in DEFAULTS:
        if key in raw:
            merged[key] = raw[key]
    return merged


def _oracle_threshold(raw: dict) -> float:
    section = raw.get("oracle") or {}
    if not isinstance(section, dict):
        raise SpecError("task.toml: [oracle] must be a table")
    t = float(section.get("threshold", 1.0))
    if not 0.0 < t <= 1.0:
        raise SpecError("task.toml: oracle.threshold must be in (0, 1]")
    return t


def load_task(root: Path) -> TaskSpec:
    root = root.resolve()
    cfg_path = root / "task.toml"
    if not cfg_path.is_file():
        if (root / "task.yaml").is_file():
            raise SpecError(
                "legacy task.yaml found — configuration is TOML now. "
                "Migrate: restructure into task.toml "
                "(top-level keys first, then [resources]/[timeouts] tables)"
            )
        raise SpecError(f"missing {cfg_path}")
    raw = tomllib.loads(cfg_path.read_text())
    if not isinstance(raw, dict):
        raise SpecError("task.toml must be a table")

    name = raw.get("name") or root.name
    if not ID_RE.match(str(name)):
        raise SpecError(f"invalid task name: {name!r}")

    for required in ("instruction.md", "tests", "environment"):
        if not (root / required).exists():
            raise SpecError(f"missing required path: {required}")
    if not (root / "tests" / "verify.py").is_file():
        raise SpecError("tests/verify.py is required")

    cfg = _merged(raw)
    model = str(cfg["model"]).strip()
    if not model:
        raise SpecError("task.toml: 'model' is required (any model id your endpoint serves)")

    verifier_image = str(cfg["verifier_image"])
    if (
        verifier_image != DEFAULTS["verifier_image"]
        and "@sha256:" not in verifier_image
    ):
        raise SpecError(
            "task.toml: verifier_image overrides must be digest-pinned "
            "(registry/image@sha256:<hash>) — the verifier computes your score"
        )

    egress_raw = raw.get("net_egress") or []
    if not isinstance(egress_raw, list):
        raise SpecError("task.toml: net_egress must be an array of domains")
    egress = []
    for d in egress_raw:
        d = str(d).strip().lower()
        if not DOMAIN_RE.match(d):
            raise SpecError(f"invalid net_egress domain: {d!r}")
        if d.startswith("*."):
            d = d[2:]
        if "." not in d:
            raise SpecError(
                f"invalid net_egress domain {d!r}: bare TLDs would allow too much"
            )
        egress.append(d)

    internet = str(raw.get("internet") or "").strip().lower()
    if not internet:
        internet = "allowlist" if egress else "none"
    if internet not in {"none", "allowlist", "allow"}:
        raise SpecError('task.toml: internet must be "none", "allowlist" or "allow"')
    if internet == "none" and egress:
        raise SpecError(
            'task.toml: internet = "none" conflicts with non-empty net_egress '
            '(use internet = "allowlist")'
        )
    if internet != "allowlist" and egress:
        raise SpecError(
            'task.toml: net_egress domains are only used when internet = "allowlist"'
        )

    spec = TaskSpec(
        root=root,
        name=str(name),
        model=model,
        verifier_image=str(cfg["verifier_image"]),
        cpus=float(cfg["cpus"]),
        memory_mb=int(cfg["memory_mb"]),
        build_timeout_sec=int(cfg["build_timeout_sec"]),
        agent_timeout_sec=int(cfg["agent_timeout_sec"]),
        verifier_timeout_sec=int(cfg["verifier_timeout_sec"]),
        net_egress=egress,
        internet_mode=internet,
        max_subagents=int(cfg["max_subagents"]),
        subagent_depth=int(cfg["subagent_depth"]),
        context_limit=int(cfg["context_limit"]),
        output_token_max=int(cfg["output_token_max"]),
        oracle_threshold=_oracle_threshold(raw),
    )

    decomp = spec.decomposition_path
    if decomp:
        spec.sub_tasks = parse_decomposition(decomp)
    return spec


def parse_decomposition(path: Path) -> list[dict]:
    data = yaml.safe_load(path.read_text()) or {}
    subs = data.get("sub_tasks")
    if not isinstance(subs, list) or not subs:
        raise SpecError("decomposition.yaml: sub_tasks must be a non-empty list")
    if len(subs) > MAX_SUBTASKS:
        raise SpecError(f"decomposition.yaml: more than {MAX_SUBTASKS} sub_tasks refused")

    seen: dict[str, dict] = {}
    for s in subs:
        if not isinstance(s, dict):
            raise SpecError("decomposition.yaml: each sub_task must be a mapping")
        sid = str(s.get("id") or "")
        if not ID_RE.match(sid):
            raise SpecError(f"decomposition.yaml: bad sub_task id {sid!r}")
        if sid in seen:
            raise SpecError(f"decomposition.yaml: duplicate sub_task id {sid!r}")
        deps = s.get("depends_on") or []
        if not isinstance(deps, list):
            raise SpecError(f"decomposition.yaml: depends_on of {sid!r} must be a list")
        seen[sid] = s

    for s in subs:
        for dep in s.get("depends_on") or []:
            if dep not in seen:
                raise SpecError(f"decomposition.yaml: {s['id']} depends on unknown id {dep!r}")

    _check_cycles(seen)
    return subs


def _check_cycles(seen: dict[str, dict]) -> None:
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {sid: WHITE for sid in seen}

    def visit(sid: str) -> None:
        color[sid] = GRAY
        for dep in seen[sid].get("depends_on") or []:
            if color[dep] == GRAY:
                raise SpecError(f"decomposition.yaml: dependency cycle through {dep!r}")
            if color[dep] == WHITE:
                visit(dep)
        color[sid] = BLACK

    for sid in seen:
        if color[sid] == WHITE:
            visit(sid)
