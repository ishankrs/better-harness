from __future__ import annotations

import secrets
from pathlib import Path

import yaml

from .spec import TaskSpec

BASE_IMAGE = "swarmharness/agent-base:latest"
PROXY_PORT = 8080
EGRESS_PORT = 3128


def build_compose(
    spec: TaskSpec,
    results: Path,
    images_dir: Path,
    mode: str,
    upstream_base: str,
    flavor: str = "openai",
) -> dict:
    networks: dict = {"internal": {"internal": True}, "uplink": {}}
    agent_networks = ["internal"]
    proxy_networks = ["internal", "uplink"]
    egress_env: dict[str, str] = {}
    egress_services: list[str] = []
    runner_token = secrets.token_urlsafe(24)
    services: dict = {}

    if spec.internet_mode == "allow":
        networks["open"] = {}
        agent_networks.append("open")
    elif spec.internet_mode == "allowlist":
        networks["transit"] = {"internal": True}
        services["egress"] = {
            "build": {"context": str(images_dir / "egress")},
            "environment": {"ALLOW_DOMAINS": ",".join(spec.net_egress)},
            "networks": ["transit", "uplink"],
            "mem_limit": "128m",
            "pids_limit": 128,
            "restart": "on-failure",
            "healthcheck": {
                "test": [
                    "CMD",
                    "python",
                    "-c",
                    f"import socket;socket.create_connection(('127.0.0.1',{EGRESS_PORT}),2).close()",
                ],
                "interval": "3s",
                "timeout": "3s",
                "retries": 20,
                "start_period": "2s",
            },
        }
        egress_services = ["egress"]
        agent_networks.append("transit")
        egress_env = {
            "HTTPS_PROXY": f"http://egress:{EGRESS_PORT}",
            "HTTP_PROXY": f"http://egress:{EGRESS_PORT}",
            "NO_PROXY": "localhost,127.0.0.1,llmproxy",
        }

    services["llmproxy"] = {
        "build": {"context": str(images_dir / "proxy")},
        "environment": {
            "UPSTREAM_BASE": upstream_base,
            "LLM_API_KEY": "${SWARM_LLM_API_KEY:-}",
            "AUTH_MODE": flavor,
            "RUNNER_TOKEN": runner_token,
        },
        "networks": proxy_networks,
        "extra_hosts": ["host.docker.internal:host-gateway"],
        "mem_limit": "256m",
        "pids_limit": 128,
        "restart": "on-failure",
        "healthcheck": {
            "test": [
                "CMD",
                "python",
                "-c",
                f"import urllib.request;urllib.request.urlopen('http://127.0.0.1:{PROXY_PORT}/__health',timeout=2)",
            ],
            "interval": "3s",
            "timeout": "3s",
            "retries": 20,
            "start_period": "2s",
        },
    }

    volumes = [
        f"{spec.instruction_path}:/task/instruction.md:ro",
        f"{results / 'agent_logs'}:/logs/agent",
        "ws:/workspace",
    ]
    decomposition = spec.decomposition_path
    if mode == "multi" and decomposition:
        volumes.append(f"{decomposition}:/task/decomposition.yaml:ro")
    artifacts = spec.artifacts_dir
    if artifacts:
        volumes.append(f"{artifacts}:/input_artifacts:ro")

    services["agent"] = {
        "build": {"context": str(spec.environment_dir)},
        "depends_on": {
            **{"llmproxy": {"condition": "service_healthy"}},
            **{name: {"condition": "service_healthy"} for name in egress_services},
        },
        "environment": {
            "MODE": mode,
            "MODEL_ID": spec.model,
            "PROVIDER_KIND": "anthropic" if flavor == "anthropic" else "openai-compatible",
            "CONTEXT_LIMIT": str(spec.context_limit),
            "OUTPUT_TOKEN_MAX": str(spec.output_token_max),
            "SUBAGENT_DEPTH": str(spec.subagent_depth),
            "MAX_SUBAGENTS": str(spec.max_subagents),
            "PROXY_URL": f"http://llmproxy:{PROXY_PORT}/v1",
            "PROXY_KEY": runner_token,
            "OPENCODE_EXPERIMENTAL_OUTPUT_TOKEN_MAX": str(spec.output_token_max),
            **egress_env,
        },
        "networks": agent_networks,
        "mem_limit": f"{spec.memory_mb}m",
        "cpus": spec.cpus,
        "pids_limit": 512,
        "init": True,
        "restart": "no",
        "volumes": volumes,
    }

    verifier_depends = {"llmproxy": {"condition": "service_healthy"}}

    if spec.solution_dir:
        services["oracle"] = {
            "build": {"context": str(spec.environment_dir)},
            "depends_on": verifier_depends,
            "networks": agent_networks,
            "mem_limit": f"{spec.memory_mb}m",
            "cpus": spec.cpus,
            "pids_limit": 512,
            "init": True,
            "restart": "no",
            "profiles": ["oracle"],
            "entrypoint": ["bash", "/solution/solve.sh"],
            "volumes": [
                f"{spec.instruction_path}:/task/instruction.md:ro",
                f"{results / 'agent_logs'}:/logs/agent",
                "ws:/workspace",
                f"{spec.solution_dir}:/solution:ro",
                *([f"{spec.artifacts_dir}:/input_artifacts:ro"] if spec.artifacts_dir else []),
            ],
        }

    services["verifier"] = {
        "image": spec.verifier_image,
        "profiles": ["verify"],
        "depends_on": verifier_depends,
        "environment": {
            "LLM_BASE_URL": f"http://llmproxy:{PROXY_PORT}/v1",
            "LLM_API_KEY": runner_token,
        },
        "networks": ["internal"],
        "mem_limit": f"{min(spec.memory_mb, 4096)}m",
        "pids_limit": 256,
        "restart": "no",
        "entrypoint": [],
        "command": ["python3", "/tests/verify.py"],
        "volumes": [
            f"{spec.tests_dir}:/tests:ro",
            f"{results / 'agent_logs'}:/deliverables:ro",
            f"{results / 'verification'}:/reward",
        ],
    }

    return {
        "services": services,
        "networks": networks,
        "volumes": {"ws": {}},
    }


def write_compose(compose: dict, results: Path) -> Path:
    work = results / "work"
    work.mkdir(parents=True, exist_ok=True)
    path = work / "docker-compose.yml"
    path.write_text(yaml.safe_dump(compose, sort_keys=False))
    return path
