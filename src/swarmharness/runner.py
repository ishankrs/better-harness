from __future__ import annotations

import json
import os
import signal
import stat
import subprocess
import sys
import time
import urllib.parse
import uuid
from dataclasses import dataclass
from pathlib import Path

from .compose_gen import BASE_IMAGE, build_compose, write_compose
from .manifest import build_manifest
from .redact import redact_tree
from .spec import SpecError, TaskSpec, validate_judge_base_url, validate_model_id

IMAGES_DIR = Path(__file__).resolve().parent / "images"
_REDACTED_STAMP = ".redacted"


def _normalize_base_url(raw: str) -> tuple[str, str | None]:
    url = raw.strip().rstrip("/")
    warning = None
    if url.endswith("/chat/completions"):
        url = url[: -len("/chat/completions")]
        warning = (
            "SWARM_LLM_BASE_URL must be the API root — stripped trailing "
            "/chat/completions automatically"
        )
    if url.endswith("/v1"):
        url = url[: -len("/v1")]
        warning = (
            "SWARM_LLM_BASE_URL should exclude the /v1 version segment — "
            "the harness adds it; stripped automatically"
        )
    return url, warning


def _validate_base_url(url: str) -> str | None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise SpecError(
            f"SWARM_LLM_BASE_URL must use http:// or https:// (got {parts.scheme!r})"
        )
    if parts.username or parts.password:
        raise SpecError(
            "SWARM_LLM_BASE_URL must not embed credentials (userinfo) — "
            "they would be published in run.json and docker-compose.yml"
        )
    if parts.query or parts.fragment:
        raise SpecError(
            "SWARM_LLM_BASE_URL must not contain a query string or fragment — "
            "it would be published verbatim in run.json and docker-compose.yml"
        )
    return "key travels in cleartext over http:// upstream" if parts.scheme == "http" else None


def _detect_flavor(base_url: str) -> str:
    flavor = (os.environ.get("SWARM_LLM_FLAVOR") or "").strip().lower()
    if not flavor:
        key_hint = (os.environ.get("SWARM_LLM_API_KEY") or "").lower()
        if "anthropic" in base_url.lower() or key_hint.startswith("sk-ant-"):
            flavor = "anthropic"
        else:
            flavor = "openai"
    if flavor not in {"openai", "anthropic"}:
        raise SpecError("SWARM_LLM_FLAVOR must be 'openai' or 'anthropic'")
    return flavor


def _compose_token(compose: dict) -> str:
    try:
        return str(compose["services"]["llmproxy"]["environment"]["RUNNER_TOKEN"])
    except (KeyError, TypeError):
        return ""


def _scrub_compose_token(compose_file: Path, token: str) -> None:
    # NOTE: the placeholder must stay a plain YAML scalar. "[REDACTED]" would
    # parse as a flow sequence and break `docker compose down` validation
    # (that bug stranded every run's containers with "teardown incomplete").
    if not token or not compose_file.is_file():
        return
    try:
        text = compose_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    if token not in text:
        return
    try:
        compose_file.write_text(text.replace(token, "REDACTED"), encoding="utf-8")
    except OSError:
        pass


@dataclass
class RunResult:
    run_id: str
    results_dir: Path
    status: str
    exit_code: int | None
    reward: dict
    redactions: int
    internet_mode: str = ""


@dataclass
class OracleResult:
    run_id: str
    results_dir: Path
    status: str
    reward: dict
    threshold: float
    passed: bool


def _run(cmd: list[str], timeout: int | None = None) -> subprocess.CompletedProcess:
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            proc.kill()
        out, err = proc.communicate()
        return subprocess.CompletedProcess(cmd, -9, out, err)
    return subprocess.CompletedProcess(cmd, proc.returncode, out, err)


def _dc(compose_file: Path, project: str, *args: str, timeout: int = 600) -> subprocess.CompletedProcess:
    cmd = ["docker", "compose", "-f", str(compose_file), "-p", project, *args]
    return _run(cmd, timeout=timeout)


def _docker(*args: str) -> subprocess.CompletedProcess:
    return _run(["docker", *args])


def _ensure_base_image() -> None:
    probe = _docker("image", "inspect", BASE_IMAGE)
    if probe.returncode == 0:
        return
    build = _docker("build", "-t", BASE_IMAGE, str(IMAGES_DIR / "agent-base"))
    if build.returncode != 0:
        raise RuntimeError(f"agent base image build failed:\n{build.stderr[-3000:]}")


def _agent_state(compose_file: Path, project: str) -> tuple[str, dict] | None:
    listing = _dc(compose_file, project, "ps", "-aq", "agent")
    cid = listing.stdout.strip().split()
    if not cid:
        return None
    inspect = _docker("inspect", "-f", "{{json .State}}", cid[0])
    try:
        return cid[0], json.loads(inspect.stdout)
    except (json.JSONDecodeError, IndexError):
        return None


def _run_verifier(compose_file: Path, project: str, spec: TaskSpec, results: Path) -> int:
    cmd = [
        "docker", "compose", "-f", str(compose_file), "-p", project,
        "--profile", "verify", "run", "--rm", "verifier",
    ]
    rc = _run(cmd, timeout=spec.verifier_timeout_sec).returncode
    reward_path = results / "verification" / "reward.json"
    if not reward_path.exists():
        reward_path.parent.mkdir(parents=True, exist_ok=True)
        status = "verifier_timeout" if rc == -9 else "verifier_failed"
        reward_path.write_text(json.dumps({"score": 0.0, "status": status}))
    return rc


def _finalize_reward(results: Path, verifier_rc: int) -> dict:
    _strip_symlinks(results / "verification")
    redact_tree(results / "verification")
    reward = _parse_reward(results)
    if verifier_rc != 0 and reward.get("status") == "ok":
        reward = {
            **reward,
            "score": 0.0,
            "status": "verifier_failed",
            "note": f"score ignored — verifier exited {verifier_rc} after writing reward.json",
        }
    return reward


def _parse_reward(results: Path) -> dict:
    path = results / "verification" / "reward.json"
    try:
        reward = json.loads(path.read_text())
        score = float(reward.get("score"))
        if not 0.0 <= score <= 1.0:
            raise ValueError("score out of range")
        reward["score"] = round(score, 4)
        reward.setdefault("status", "ok")
        return reward
    except Exception:
        return {"score": 0.0, "status": "verifier_failed"}


def sweep_stale_results(root: Path) -> None:
    """Redact any pre-existing run directories that never completed (no run.json).

    Covers trees left raw by SIGKILL/power loss or by older harness versions.
    """
    results_dir = root / "results"
    if not results_dir.is_dir():
        return
    for run_dir in sorted(p for p in results_dir.iterdir() if p.is_dir()):
        if (run_dir / "run.json").exists():
            continue
        logs = run_dir / "agent_logs"
        verification = run_dir / "verification"
        if logs.is_dir() and not (logs / _REDACTED_STAMP).exists():
            print(f"sweeping unredacted stale run directory: {run_dir}", file=sys.stderr)
            try:
                _strip_symlinks(logs)
                redact_tree(logs)
            except Exception as exc:
                print(f"warning: sweep redaction failed for {run_dir}: {exc}", file=sys.stderr)
                continue
            try:
                (logs / _REDACTED_STAMP).write_text(time.strftime("%Y-%m-%dT%H:%M:%S%z"))
            except OSError:
                pass
        if verification.is_dir():
            try:
                _strip_symlinks(verification)
                redact_tree(verification)
            except Exception as exc:
                print(f"warning: sweep redaction failed for {verification}: {exc}", file=sys.stderr)


def _stamp_redacted(logs_dir: Path) -> None:
    try:
        (logs_dir / _REDACTED_STAMP).write_text(time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    except OSError:
        pass


def _strip_symlinks(root: Path) -> int:
    removed = 0
    if not root.is_dir():
        return removed
    for path in sorted(root.rglob("*")):
        try:
            if path.is_symlink():
                path.unlink()
                removed += 1
        except OSError:
            continue
    return removed


def _count_newlines_from(path: Path, pos: int) -> tuple[int, int]:
    try:
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode):
            return pos, 0
        size = st.st_size
        if size < pos:
            pos = 0
        if size == pos:
            return pos, 0
        count = 0
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        try:
            os.lseek(fd, pos, os.SEEK_SET)
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                count += chunk.count(b"\n")
        finally:
            os.close(fd)
        return size, count
    except OSError:
        return pos, 0


def run_task(
    spec: TaskSpec,
    mode: str = "multi",
    keep: bool = False,
    console=None,
    model_override: str | None = None,
    judge_model_override: str | None = None,
    judge_base_url_override: str | None = None,
) -> RunResult:
    base_url = os.environ.get("SWARM_LLM_BASE_URL")
    if not base_url:
        raise SpecError(
            "SWARM_LLM_BASE_URL is required in the environment "
            "(any OpenAI-compatible or Anthropic endpoint; omit SWARM_LLM_API_KEY only for keyless servers like local Ollama)"
        )
    if model_override is not None:
        spec.model = validate_model_id(model_override)
    if not spec.model:
        raise SpecError(
            "no model configured: set 'model' in task.toml or pass -m/--model"
        )
    if judge_model_override is not None:
        spec.judge_model = validate_model_id(judge_model_override)
    if judge_base_url_override is not None:
        spec.judge_base_url = validate_judge_base_url(judge_base_url_override)
    base_url, url_warning = _normalize_base_url(base_url)
    cleartext_warning = _validate_base_url(base_url)
    flavor = _detect_flavor(base_url)

    log = console.log if console else print
    if url_warning:
        log(f"[yellow]{url_warning}[/]")
    if cleartext_warning:
        log(f"[yellow]warning: {cleartext_warning} — prefer an https:// upstream[/]")
    if not os.environ.get("SWARM_LLM_API_KEY"):
        log("[yellow]SWARM_LLM_API_KEY not set — proxy will forward without auth header[/]")
    if (spec.judge_base_url
            and not os.environ.get("SWARM_JUDGE_API_KEY")
            and not os.environ.get("SWARM_LLM_API_KEY")):
        log("[yellow]SWARM_JUDGE_API_KEY not set — judge proxy will forward without auth header[/]")

    from .ui import make_display

    display = make_display(console)

    run_id = f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    project = f"swarm-{spec.name}-{run_id}".lower()
    sweep_stale_results(spec.root)
    results = spec.root / "results" / run_id
    for sub in ("work", "agent_logs", "verification"):
        (results / sub).mkdir(parents=True, exist_ok=True)

    compose = build_compose(spec, results, IMAGES_DIR, mode, base_url, flavor=flavor, judge_model=spec.judge_model, judge_base_url=spec.judge_base_url)
    compose_file = write_compose(compose, results)

    started = time.monotonic()
    agent_status = "completed"
    exit_code: int | None = None
    log_path = results / "agent_logs" / "opencode.txt"
    redactions = 0
    redacted = False

    def _scrub_unredacted() -> None:
        nonlocal redactions, redacted
        if redacted or not (results / "agent_logs").exists():
            return
        try:
            redactions = redact_tree(results / "agent_logs")
            _stamp_redacted(results / "agent_logs")
            redacted = True
        except Exception:
            pass

    try:
        with display:
            display.begin("images", cap=float(spec.build_timeout_sec))
            _ensure_base_image()
            _pull_verifier(spec)
            up = _dc(
                compose_file, project, "up", "-d", "--build",
                "llmproxy",
                *(["egress"] if spec.internet_mode == "allowlist" else []),
                *(["judgeproxy"] if "judgeproxy" in compose.get("services", {}) else []),
                timeout=spec.build_timeout_sec + 120,
            )
            if up.returncode != 0:
                display.finish("images", "failed", note="compose up error")
                raise RuntimeError(f"compose up failed:\n{up.stderr[-2000:]}")
            display.finish("images", "ok")

            display.begin("agent", cap=float(spec.agent_timeout_sec), label=f"agent ({mode})")
            agent_up = _dc(
                compose_file, project, "up", "-d", "--build", "agent",
                timeout=spec.build_timeout_sec + 120,
            )
            if agent_up.returncode != 0:
                display.finish("agent", "failed", note="launch error")
                raise RuntimeError(f"agent launch failed:\n{agent_up.stderr[-2000:]}")

            agent_started = time.monotonic()
            deadline = agent_started + spec.agent_timeout_sec
            state: dict = {}
            events = 0
            log_pos = 0
            while True:
                found = _agent_state(compose_file, project)
                if found is not None:
                    _, state = found
                    if not state.get("Running"):
                        break
                elif time.monotonic() > deadline:
                    break
                if time.monotonic() > deadline:
                    agent_status = "timed_out"
                    _dc(compose_file, project, "kill", "agent")
                    time.sleep(3)
                    found = _agent_state(compose_file, project)
                    state = found[1] if found else {}
                    break
                elapsed = time.monotonic() - agent_started
                if log_path.exists():
                    log_pos, delta = _count_newlines_from(log_path, log_pos)
                    events += delta
                display.tick("agent", elapsed, f"{events} events")
                time.sleep(2)

            exit_code = state.get("ExitCode")
            if agent_status == "completed" and exit_code not in (0, None):
                agent_status = "agent_error"
            outcome_note = f"exit {exit_code}" if exit_code is not None else agent_status
            display.finish(
                "agent",
                "ok" if (agent_status == "completed" and not exit_code) else ("timed out" if agent_status == "timed_out" else "error"),
                note=str(outcome_note),
            )

            display.begin("verify", cap=float(spec.verifier_timeout_sec))
            _strip_symlinks(results / "agent_logs")
            redactions = redact_tree(results / "agent_logs")
            redacted = True
            verifier_rc = _run_verifier(compose_file, project, spec, results)
            reward = _finalize_reward(results, verifier_rc)
            display.finish("verify", "ok", note=f"{len(reward.get('checks', []))} checks · {redactions} redactions")

            display.begin("finalize", cap=60.0)
            duration = round(time.monotonic() - started, 1)
            _scrub_compose_token(compose_file, _compose_token(compose))
            build_manifest(
                results,
                {
                    "run_id": run_id,
                    "task": spec.name,
                    "mode": mode,
                    "model": spec.model,
                    "llm_base_url": base_url,
                    "llm_flavor": flavor,
                    "status": agent_status,
                    "agent_exit_code": exit_code,
                    "reward": reward,
                    "secret_redactions": redactions,
                    "duration_sec": duration,
                    "internet_mode": spec.internet_mode,
                "net_egress": spec.net_egress,
                    "coordination_pattern": spec.coordination_pattern,
                    "tags": spec.tags,
                    "judge_model": spec.judge_model or spec.model,
                    "judge_base_url": spec.judge_base_url or "",
                    "provider_npm": spec.provider_npm or "",
                },
            )
            display.finish("finalize", "ok", note=f"{duration}s total")
            return RunResult(run_id, results, agent_status, exit_code, reward, redactions, spec.internet_mode)
    finally:
        _scrub_unredacted()
        if not keep:
            down = _dc(compose_file, project, "down", "-v", "--remove-orphans", timeout=120)
            if down.returncode != 0 and console:
                console.print(f"[yellow]warning:[/] teardown incomplete — check dangling containers/networks")



def _pull_verifier(spec: TaskSpec) -> None:
    pull = _docker("pull", "-q", spec.verifier_image)
    if pull.returncode != 0:
        raise RuntimeError(f"verifier image pull failed:\n{pull.stderr[-800:]}")


def _scrub_oracle_logs(results: Path) -> None:
    logs = results / "agent_logs"
    if logs.exists():
        try:
            redact_tree(logs)
            _stamp_redacted(logs)
        except Exception:
            pass


def regrade_task(
    spec: TaskSpec,
    logs_src: Path,
    keep: bool = False,
    console=None,
    judge_model_override: str | None = None,
    judge_base_url_override: str | None = None,
) -> RunResult:
    """Re-run ONLY the verifier over existing agent logs (e.g. judge was down).

    Never touches the source run: logs are copied into a fresh
    results/<id>-regrade/ directory with its own reward + manifest that links
    back via source_run. The original run.json stays tamper-evident, so this
    is not a reward re-minting path.
    """
    import shutil

    logs_src = Path(logs_src)
    if not logs_src.is_dir():
        raise SpecError(f"logs directory not found: {logs_src}")
    if judge_model_override is not None:
        spec.judge_model = validate_model_id(judge_model_override)
    if judge_base_url_override is not None:
        spec.judge_base_url = validate_judge_base_url(judge_base_url_override)
    if not (spec.judge_model or spec.model):
        raise SpecError(
            "no judge model configured: set 'judge_model'/'model' in task.toml "
            "or pass --judge-model"
        )
    base_url = os.environ.get("SWARM_LLM_BASE_URL")
    if not base_url:
        raise SpecError("SWARM_LLM_BASE_URL is required in the environment")
    base_url, url_warning = _normalize_base_url(base_url)
    cleartext_warning = _validate_base_url(base_url)
    flavor = _detect_flavor(base_url)

    from .ui import make_display

    display = make_display(console)
    log = console.log if console else print
    if url_warning:
        log(f"[yellow]{url_warning}[/]")
    if cleartext_warning:
        log(f"[yellow]warning: {cleartext_warning} — prefer an https:// upstream[/]")

    source_run = logs_src.parent.name if logs_src.name == "agent_logs" else logs_src.name
    run_id = f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}-regrade"
    project = f"swarm-regrade-{spec.name}-{run_id}".lower()
    sweep_stale_results(spec.root)
    results = spec.root / "results" / run_id
    for sub in ("work", "agent_logs", "verification"):
        (results / sub).mkdir(parents=True, exist_ok=True)
    for item in sorted(logs_src.iterdir()):
        if item.name == _REDACTED_STAMP or item.is_symlink():
            continue
        dest = results / "agent_logs" / item.name
        try:
            if item.is_dir():
                shutil.copytree(item, dest, symlinks=False)
            elif item.is_file():
                shutil.copy2(item, dest)
        except OSError as exc:
            print(f"warning: could not copy {item}: {exc}", file=sys.stderr)

    compose = build_compose(spec, results, IMAGES_DIR, mode="single",
                            upstream_base=base_url, flavor=flavor,
                            judge_model=spec.judge_model,
                            judge_base_url=spec.judge_base_url)
    compose_file = write_compose(compose, results)
    started = time.monotonic()
    redactions = 0
    try:
        with display:
            display.begin("images", cap=float(spec.build_timeout_sec))
            _pull_verifier(spec)
            up = _dc(
                compose_file, project, "up", "-d", "--build", "llmproxy",
                *(["judgeproxy"] if "judgeproxy" in compose.get("services", {}) else []),
                timeout=spec.build_timeout_sec + 120,
            )
            if up.returncode != 0:
                display.finish("images", "failed", note="compose up error")
                raise RuntimeError(f"compose up failed:\n{up.stderr[-2000:]}")
            display.finish("images", "ok")

            display.begin("verify", cap=float(spec.verifier_timeout_sec))
            _strip_symlinks(results / "agent_logs")
            redactions = redact_tree(results / "agent_logs")
            _stamp_redacted(results / "agent_logs")
            verifier_rc = _run_verifier(compose_file, project, spec, results)
            reward = _finalize_reward(results, verifier_rc)
            display.finish("verify", "ok", note=f"{len(reward.get('checks', []))} checks · {redactions} redactions")

            display.begin("finalize", cap=60.0)
            duration = round(time.monotonic() - started, 1)
            _scrub_compose_token(compose_file, _compose_token(compose))
            build_manifest(
                results,
                {
                    "run_id": run_id,
                    "kind": "regrade",
                    "source_run": source_run,
                    "task": spec.name,
                    "model": spec.model,
                    "judge_model": spec.judge_model or spec.model,
                    "judge_base_url": spec.judge_base_url or "",
                    "llm_base_url": base_url,
                    "llm_flavor": flavor,
                    "reward": reward,
                    "secret_redactions": redactions,
                    "duration_sec": duration,
                    "internet_mode": spec.internet_mode,
                    "net_egress": spec.net_egress,
                    "coordination_pattern": spec.coordination_pattern,
                    "tags": spec.tags,
                    "provider_npm": spec.provider_npm or "",
                },
            )
            display.finish("finalize", "ok", note=f"{duration}s total")
            return RunResult(run_id, results, "regraded", None, reward,
                             redactions, spec.internet_mode)
    finally:
        if not keep:
            down = _dc(compose_file, project, "down", "-v", "--remove-orphans", timeout=120)
            if down.returncode != 0 and console:
                console.print("[yellow]warning:[/] teardown incomplete — check dangling containers/networks")


def run_oracle(
    spec: TaskSpec,
    keep: bool = False,
    threshold: float | None = None,
    console=None,
    judge_model_override: str | None = None,
    judge_base_url_override: str | None = None,
) -> OracleResult:
    solution = spec.solution_script
    if not solution:
        raise SpecError(
            f"no solution/solve.sh found in {spec.root} — oracle mode is optional "
            "and only runs for tasks that ship a reference solution"
        )
    if judge_model_override is not None:
        spec.judge_model = validate_model_id(judge_model_override)
    if judge_base_url_override is not None:
        spec.judge_base_url = validate_judge_base_url(judge_base_url_override)
    base_url = os.environ.get("SWARM_LLM_BASE_URL")
    if not base_url:
        raise SpecError("SWARM_LLM_BASE_URL is required in the environment")
    base_url, url_warning = _normalize_base_url(base_url)
    cleartext_warning = _validate_base_url(base_url)
    flavor = _detect_flavor(base_url)

    eff_threshold = float(threshold) if threshold is not None else spec.oracle_threshold

    from .ui import make_display

    display = make_display(console)
    log = console.log if console else print
    if url_warning:
        log(f"[yellow]{url_warning}[/]")
    if cleartext_warning:
        log(f"[yellow]warning: {cleartext_warning} — prefer an https:// upstream[/]")
    if not os.environ.get("SWARM_LLM_API_KEY"):
        log("[yellow]SWARM_LLM_API_KEY not set — proxy will forward without auth header[/]")
    if (spec.judge_base_url
            and not os.environ.get("SWARM_JUDGE_API_KEY")
            and not os.environ.get("SWARM_LLM_API_KEY")):
        log("[yellow]SWARM_JUDGE_API_KEY not set — judge proxy will forward without auth header[/]")

    run_id = f"oracle-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    project = f"swarm-oracle-{spec.name}-{run_id}".lower()
    sweep_stale_results(spec.root)
    results = spec.root / "results" / run_id
    for sub in ("work", "agent_logs", "verification"):
        (results / sub).mkdir(parents=True, exist_ok=True)

    compose = build_compose(spec, results, IMAGES_DIR, mode="single", upstream_base=base_url, flavor=flavor, judge_model=spec.judge_model, judge_base_url=spec.judge_base_url)
    compose_file = write_compose(compose, results)

    oracle_status = "passed_execution"
    try:
        with display:
            display.begin("images", cap=float(spec.build_timeout_sec))
            _ensure_base_image()
            _pull_verifier(spec)
            up = _dc(
                compose_file, project, "up", "-d", "--build", "llmproxy",
                *(["egress"] if spec.internet_mode == "allowlist" else []),
                *(["judgeproxy"] if "judgeproxy" in compose.get("services", {}) else []),
                timeout=spec.build_timeout_sec + 120,
            )
            if up.returncode != 0:
                display.finish("images", "failed")
                raise RuntimeError(f"compose up failed:\n{up.stderr[-2000:]}")
            display.finish("images", "ok")

            display.begin("oracle", cap=float(spec.agent_timeout_sec), label="reference solution")
            rc = _run(
                ["docker", "compose", "-f", str(compose_file), "-p", project,
                 "--profile", "oracle", "run", "--rm", "oracle"],
                timeout=spec.agent_timeout_sec + 30,
            ).returncode
            if rc == -9:
                oracle_status = "timed_out"
            elif rc != 0:
                oracle_status = "execution_error"
            display.finish(
                "oracle",
                "ok" if oracle_status == "passed_execution" else ("timed out" if oracle_status == "timed_out" else "error"),
                note=f"exit {rc}",
            )

            display.begin("verify", cap=float(spec.verifier_timeout_sec))
            _strip_symlinks(results / "agent_logs")
            redact_tree(results / "agent_logs")
            _stamp_redacted(results / "agent_logs")
            verifier_rc = _run_verifier(compose_file, project, spec, results)
            reward = _finalize_reward(results, verifier_rc)
            passed = (
                oracle_status == "passed_execution"
                and reward.get("status") == "ok"
                and float(reward.get("score", 0.0)) >= eff_threshold
            )
            display.finish("verify", "ok" if passed else "below threshold",
                           note=f"{len(reward.get('checks', []))} checks")

            display.begin("finalize", cap=60.0)
            _scrub_compose_token(compose_file, _compose_token(compose))
            build_manifest(
                results,
                {
                    "run_id": run_id,
                    "kind": "oracle",
                    "task": spec.name,
                    "model": spec.model,
                    "llm_base_url": base_url,
                    "llm_flavor": flavor,
                    "oracle_status": oracle_status,
                    "threshold": eff_threshold,
                    "passed": passed,
                    "reward": reward,
                    "net_egress": spec.net_egress,
                    "coordination_pattern": spec.coordination_pattern,
                    "tags": spec.tags,
                    "judge_model": spec.judge_model or spec.model,
                    "judge_base_url": spec.judge_base_url or "",
                    "provider_npm": spec.provider_npm or "",
                },
            )
            display.finish("finalize", "ok")
            return OracleResult(run_id, results, oracle_status, reward, eff_threshold, passed)
    finally:
        _scrub_oracle_logs(results)
        if not keep:
            down = _dc(compose_file, project, "down", "-v", "--remove-orphans", timeout=120)
            if down.returncode != 0 and console:
                console.print("[yellow]warning:[/] teardown incomplete — check dangling containers/networks")
