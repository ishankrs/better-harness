import json
import os
from pathlib import Path

MODE = os.environ.get("MODE", "single")
MODEL_ID = os.environ["MODEL_ID"]
PROXY_URL = os.environ.get("PROXY_URL", "http://llmproxy:8080/v1")
def _int_env(name: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(int(os.environ.get(name, str(default))), hi))
    except (TypeError, ValueError):
        return default


DEPTH = _int_env("SUBAGENT_DEPTH", 8, 0, 64)
PROVIDER_KIND = os.environ.get("PROVIDER_KIND", "openai-compatible")

if PROVIDER_KIND == "anthropic":
    PROVIDER_NPM = "@ai-sdk/anthropic"
else:
    PROVIDER_NPM = "@ai-sdk/openai-compatible"

HEADLESS_RULES = (
    "\n\n## Non-Interactive Execution\n"
    "No human is available in this run. Never end your turn with a question, "
    "a plan awaiting approval, or a status check-in expecting a reply. "
    "Continue autonomously until every deliverable is written under /logs/agent/. "
    "If the task is complete, say so and stop.\n"
)

GENERAL_PROMPT = (
    "You are a coordinator subagent. Delegate leaf-level work via subagent_type "
    "'explore'. Only spawn 'general' agents for genuinely different coordination "
    "scopes; never re-delegate your own assigned scope to another 'general' agent. "
    "Write all deliverables under /logs/agent/ using absolute paths."
)

EXPLORE_PROMPT = (
    "You are a leaf worker. Execute the assigned work yourself with Read, Grep, "
    "Glob, and Bash — including writing output files. Write deliverables under "
    "/logs/agent/ using absolute paths."
)

permission = {
    "task": "allow" if MODE == "multi" else "deny",
    "question": "deny",
    "plan_enter": "deny",
    "plan_exit": "deny",
    "external_directory": "allow",
    "read": "allow",
}

config = {
    "provider": {
        "swarmproxy": {
            "npm": PROVIDER_NPM,
            "env": ["PROXY_KEY"],
            "options": {"baseURL": PROXY_URL},
            "models": {
                MODEL_ID: {
                    "limit": {
                        "context": _int_env("CONTEXT_LIMIT", 262144, 1024, 10_000_000),
                        "output": _int_env("OUTPUT_TOKEN_MAX", 32768, 256, 1_000_000),
                    }
                }
            },
        }
    },
    "small_model": f"swarmproxy/{MODEL_ID}",
    "permission": permission,
    "subagent_depth": DEPTH,
}

if MODE == "multi":
    config["agent"] = {
        "plan": {"disable": True},
        "general": {"prompt": GENERAL_PROMPT},
        "explore": {
            "permission": {"task": {"*": "deny"}},
            "prompt": EXPLORE_PROMPT,
        },
    }

oc_dir = Path.home() / ".config" / "opencode"
oc_dir.mkdir(parents=True, exist_ok=True)
(oc_dir / "opencode.json").write_text(json.dumps(config, indent=2))
Path("/tmp/headless_rules.txt").write_text(HEADLESS_RULES)
