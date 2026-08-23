#!/bin/bash
set -euo pipefail
mkdir -p /logs/agent
printf 'HELLO-FROM-SWARM\n' > /logs/agent/greeting.txt
