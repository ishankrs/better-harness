from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from .compose_gen import BASE_IMAGE, build_compose, write_compose
from .manifest import build_manifest
from .redact import redact_tree
from .spec import SpecError, TaskSpec

IMAGES_DIR = Path(__file__).resolve().parent / "images"


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


@dataclass
class RunResult:
    run_id: str
    results_dir: Path
    status: str
    exit_code: int | None
    reward: dict
    redactions: int


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


def _run_verifier(compose_file: Path, project: str, spec: TaskSpec, results: Path) -> None:
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


def run_task(
    spec: TaskSpec,
    mode: str = "multi",
    keep: bool = False,
    console=None,
    model_override: str | None = None,
) -> RunResult:
    base_url = os.environ.get("SWARM_LLM_BASE_URL")
    if not base_url:
        raise SpecError(
            "SWARM_LLM_BASE_URL is required in the environment "
            "(any OpenAI-compatible or Anthropic endpoint; omit SWARM_LLM_API_KEY only for keyless servers like local Ollama)"
        )
    if model_override is not None:
        model_override = str(model_override).strip()
        if not model_override:
            raise SpecError("-m/--model must be a non-empty model id")
        spec.model = model_override
    flavor = (os.environ.get("SWARM_LLM_FLAVOR") or "").strip().lower()
    if not flavor:
        key_hint = (os.environ.get("SWARM_LLM_API_KEY") or "").lower()
        if "anthropic" in base_url.lower() or key_hint.startswith("sk-ant-"):
            flavor = "anthropic"
        else:
            flavor = "openai"
    if flavor not in {"openai", "anthropic"}:
        raise SpecError("SWARM_LLM_FLAVOR must be 'openai' or 'anthropic'")
    base_url, url_warning = _normalize_base_url(base_url)

    log = console.log if console else print
    if url_warning:
        log(f"[yellow]{url_warning}[/]")
    if not os.environ.get("SWARM_LLM_API_KEY"):
        log("[yellow]SWARM_LLM_API_KEY not set — proxy will forward without auth header[/]")

    from .ui import make_display

    display = make_display(console)

    run_id = f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    project = f"swarm-{spec.name}-{run_id}".lower()
    results = spec.root / "results" / run_id
    for sub in ("work", "agent_logs", "verification"):
        (results / sub).mkdir(parents=True, exist_ok=True)

    compose = build_compose(spec, results, IMAGES_DIR, mode, base_url, flavor=flavor)
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
            redacted = True
        except Exception:
            pass

    def phase(msg: str) -> None:
        sys.stdout.flush()

    try:
        with display:
            display.begin("images", cap=float(spec.build_timeout_sec))
            _ensure_base_image()
            _pull_verifier(spec)
            up = _dc(
                compose_file, project, "up", "-d", "--build",
                "llmproxy",
                *(["egress"] if spec.internet_mode == "allowlist" else []),
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
                events = 0
                if log_path.exists():
                    try:
                        events = log_path.read_bytes().count(b"\n")
                    except OSError:
                        pass
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
            redactions = redact_tree(results / "agent_logs")
            redacted = True
            _run_verifier(compose_file, project, spec, results)
            reward = _parse_reward(results)
            display.finish("verify", "ok", note=f"{len(reward.get('checks', []))} checks · {redactions} redactions")

            display.begin("finalize", cap=60.0)
            duration = round(time.monotonic() - started, 1)
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
                },
            )
            display.finish("finalize", "ok", note=f"{duration}s total")
            return RunResult(run_id, results, agent_status, exit_code, reward, redactions)
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
        except Exception:
            pass


def run_oracle(
    spec: TaskSpec,
    keep: bool = False,
    threshold: float | None = None,
    console=None,
) -> OracleResult:
    solution = spec.solution_script
    if not solution:
        raise SpecError(
            f"no solution/solve.sh found in {spec.root} — oracle mode is optional "
            "and only runs for tasks that ship a reference solution"
        )
    base_url = os.environ.get("SWARM_LLM_BASE_URL")
    if not base_url:
        raise SpecError("SWARM_LLM_BASE_URL is required in the environment")
    base_url, _ = _normalize_base_url(base_url)

    eff_threshold = float(threshold) if threshold is not None else spec.oracle_threshold

    from .ui import make_display

    display = make_display(console)

    run_id = f"oracle-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    project = f"swarm-oracle-{spec.name}-{run_id}".lower()
    results = spec.root / "results" / run_id
    for sub in ("work", "agent_logs", "verification"):
        (results / sub).mkdir(parents=True, exist_ok=True)

    compose = build_compose(spec, results, IMAGES_DIR, mode="single", upstream_base=base_url)
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
            _run_verifier(compose_file, project, spec, results)
            reward = _parse_reward(results)
            passed = (
                oracle_status == "passed_execution"
                and reward.get("status") == "ok"
                and float(reward.get("score", 0.0)) >= eff_threshold
            )
            display.finish("verify", "ok" if passed else "below threshold",
                           note=f"{len(reward.get('checks', []))} checks")

            display.begin("finalize", cap=60.0)
            build_manifest(
                results,
                {
                    "run_id": run_id,
                    "kind": "oracle",
                    "task": spec.name,
                    "model": spec.model,
                    "llm_base_url": base_url,
                    "oracle_status": oracle_status,
                    "threshold": eff_threshold,
                    "passed": passed,
                    "reward": reward,
                    "net_egress": spec.net_egress,
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
