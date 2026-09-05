import json
from pathlib import Path

target = Path("/deliverables/greeting.txt")
exists = target.is_file()
content = target.read_text(encoding="utf-8", errors="replace").strip() if exists else ""
correct = content == "HELLO-FROM-SWARM"

checks = [
    {"name": "exact_content", "score": 1.0 if correct else 0.0},
]
score = sum(c["score"] for c in checks) / len(checks)

reward_dir = Path("/reward")
reward_dir.mkdir(parents=True, exist_ok=True)
(reward_dir / "reward.json").write_text(
    json.dumps({"score": round(score, 4), "status": "ok", "checks": checks}, indent=2)
)
