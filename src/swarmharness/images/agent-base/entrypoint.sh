#!/bin/bash
set -euo pipefail

if ! command -v opencode >/dev/null 2>&1; then
  echo "fatal: opencode not found on PATH" >&2
  exit 127
fi
if [ -z "${MODEL_ID:-}" ]; then
  echo "fatal: MODEL_ID env var is required" >&2
  exit 1
fi

python3 /opt/gen_config.py
mkdir -p /logs/agent /workspace

PROMPT=/tmp/task-prompt.txt
cat /task/instruction.md > "$PROMPT"
cat /tmp/headless_rules.txt >> "$PROMPT"

if [ "${MODE}" = "multi" ] && [ -f /task/decomposition.yaml ]; then
  printf '\n\n## Decomposition Guide\nFollow this structure exactly.\n\n' >> "$PROMPT"
  cat /task/decomposition.yaml >> "$PROMPT"
fi

set +e
opencode run \
  --model "swarmproxy/${MODEL_ID}" \
  --format=json \
  --dangerously-skip-permissions \
  < "$PROMPT" 2>&1 | tee /logs/agent/opencode.txt
RC=${PIPESTATUS[0]}
set -e

python3 /opt/export_trajectory.py || true
exit "$RC"
