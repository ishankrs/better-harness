# SwarmHarness — Project Summary

> Full history of the session that took an insecure benchmark fork ("swarmbench-harness")
> through a security audit, a ground-up rewrite, live penetration testing of the new
> code, and a published CLI — authored by **ishankrs <ishankashyap1001@gmail.com>**.

---

## 1. Where we started — adversarial audit of `swarmbench-harness`

Acting as an adversarial testing agent against the old harness (`mascloud` client +
patched Harbor), the audit surfaced, among others:

| Severity | Finding |
|---|---|
| 🔴 CRITICAL | Live Fireworks API key `fw_46Ug…` committed in **6 git-tracked files** under `execution_logs/**/agent/`. Root cause chain: harness injects the raw key into the agent sandbox → agent ran an env dump → tool results captured it verbatim → logs committed to a public repo. |
| 🔴 HIGH | Verifiers **fail open**: `tests/verify.py` returned `1.0` on any judge/API exception (3 sites) — infrastructure failure silently *inflated* scores. |
| 🟠 HIGH | `verify-only` re-scored trainer-edited artifacts (reward re-minting oracle). |
| 🟠 HIGH | Path traversal in `_download()` via unsanitized `Content-Disposition` filename. |
| 🟠 MED | Bearer token stored world-readable; `MASCLOUD_ENDPOINT` env hijack redirected credentials. |
| 🟡 | Prompt-injection surface (agents browse untrusted content holding live keys), unpinned `curl \| sh` installers, `kill 0` process-group hacks, `lstrip("*.")`-style domain bugs, etc. |

**Key status check:** the leaked key was probed live against the Fireworks API →
`HTTP 401 invalid` — already revoked/dead. No rotation needed; history purge still advised.

---

## 2. The rebuild decision

User choices that shaped v2 (**clean slate**, not a patch):

1. Clean-slate task format (later refined: **TOML** for `task.toml`; decomposition stays YAML)
2. **Built-in API-key proxy** — the agent never holds a real credential
3. Both **single-agent and multi-agent** modes
4. **Provider-agnostic** endpoints (any OpenAI-compatible or native Anthropic), configured via env
5. Minimize **Node/npm** surface in the harness itself

Canonical project home: `/Users/ishan/advtest/better-harness`
(a working copy lived at `/Users/ishan/better-harness` at times — treat advtest as source of truth).

---

## 3. Architecture

```
swarm run/oracle/create ──► per-run docker compose project
┌───────────────────────────────────────────────────────────────────┐
│ network "internal" (internal:true — no direct internet)           │
│   agent ──dummy key──► llmproxy ──real key──► ANY LLM endpoint    │
│     ▲                                   (OpenAI-compat OR         │
│     │                                Anthropic dialect switch)    │
│   verifier (profile-gated, deliverables read-only, keyless judges)│
├───────────────────────────────────────────────────────────────────┤
│ optional egress tiers for the AGENT:                              │
│   internet="none"(default) │ "allowlist" (+egress CONNECT proxy)  │
│                            │ "allow" (plain open network)         │
└───────────────────────────────────────────────────────────────────┘
results/<run_id>/ : agent_logs/ (redacted) · verification/reward.json
                    work/docker-compose.yml · run.json (sha256 manifest)
```

### Package layout
```
src/swarmharness/
  cli.py         swarm run|oracle|create|validate|redact
  spec.py        task.toml loader + decomposition validator (cycles/dupes/TLD guard)
  scaffold.py    swarm create templates (self-consistent instruction+verifier+solution)
  compose_gen.py compose builder (networks, limits, healthchecks, profiles, flavors)
  runner.py      orchestration: build→proxy→agent→redact→verify(fail-closed)→manifest→teardown
  redact.py      secret scrubbing (10 pattern families, encoded + split-secret passes)
  manifest.py    sha256 artifact manifest
  ui.py          Rich TUI (stage bars toward timeout caps, event counter, summaries)
                  with automatic plain-text fallback for CI/pipes
  images/
    proxy/       aiohttp streaming gateway: path/method allowlist, auth-dialect switch,
                 redirects disabled, response-header filtering, pinned-IP egress upstream
    egress/      asyncio CONNECT allowlist proxy: header-drain fix, 443-only,
                 DNS-rebinding-proof resolve_pinned() blocking private ranges
    agent-base/  node:22-slim(digest-pinned)+opencode@pin, non-root user,
                 gen_config.py, entrypoint.sh (fail-fast + PIPESTATUS-safe),
                 export_trajectory.py (3-query SQLite dump, atomic writes)
examples/demo-task/   runnable sample (keyless green on x-preview-f-free)
```

### Environment contract
```
SWARM_LLM_BASE_URL   required — endpoint ROOT (auto-strips /v1, /chat/completions)
SWARM_LLM_API_KEY    optional — omit for keyless servers (Ollama/LM Studio)
SWARM_LLM_FLAVOR     openai|anthropic (auto-detected from sk-ant-/URL otherwise)
```

---

## 4. Security posture — old flaw → new guarantee

| Old harness flaw | SwarmHarness guarantee |
|---|---|
| Raw API key readable by agent (leaked!) | Key lives only in proxy container; agent gets `dummy-not-a-secret`; proven against forged-header probes |
| Fail-open scoring | Fail-closed everywhere: missing/crash/timeout/out-of-range ⇒ **0.0** |
| Reward re-minting | No re-verify path; sha256 manifest over every artifact |
| Unbounded fan-out/spend | CPU/mem/pids caps + wall-clock kills + subagent depth/count caps in spec |
| Prompt-injected decomposition | Structural validator (dupes, unknown deps, cycles, >512 refusal) |
| Secrets in committed logs | Redaction engine before verification/manifest; abort-path scrub in `finally` |
| nvm/`curl\|bash`, floating tags | Digest-pinned bases, ARG-pinned opencode, runtime npm fetch structurally impossible on airgapped tasks |

---

## 5. Second adversarial sweep — our own code, 8 findings, all closed with live proofs

| # | Finding (as reported) | Fix | Proof |
|---|---|---|---|
| N1 CRITICAL | egress service never written to compose — feature was dead code; any `net_egress` task crashed | inserted into `services{}` (+hoisted dict decl) | compose asserts + live oracle run on egress task |
| HIGH | DNS rebinding TOCTOU + arbitrary ports (nip.io→loopback PoC) | `resolve_pinned()` blocks loopback/RFC1918/link-local/ULA before connect; port locked to 443 | `<private-ip>.sslip.io`→403, victim container **0 hits**; `:8080`→403 |
| HIGH | Proxy forwards any path/method with real key (`POST /__health` authed PoC) | path-prefix + method allowlist; denied probes never touch upstream | `/admin`,`/__health`,`DELETE`→403; upstream log empty for them |
| MED | Redirect-following SSRF + response-header relay | `allow_redirects=False`; drop-list incl. set-cookie/server; `Server: swarm-proxy` | 302 passed verbatim, redirect target **0 hits** |
| HIGH | `lstrip("*.")` TLD takeover (`*.com`→all .com) *(initially missed — caught later and landed)* | proper prefix slice + bare-TLD rejection | unit: `"com"` rejected |
| HIGH | Redactor misses AIzaSy/hf_/JWT/base64/url-encoded/split-JSON | 3 new patterns + decoded pass + squashed span-mapped scan | full unit battery green |
| HIGH | NUL-byte files exempt from redaction; abort path skipped scrubbing | lossless latin-1 byte roundtrip for ALL files; `finally:` best-effort scrub | NUL-padded `fw_…` file redacted in place |
| MED-LOW | Unpinned `verifier_image` override; pull rc unchecked; dead except | digest-pin enforcement; `_pull_verifier` rc check; rc-based timeout-vs-failure statuses | unit accepts/rejects correctly |

Plus two regressions **caught by live testing, not review**:
- `STRIP_INBOUND` referenced `HOP_HEADERS` before definition → proxy NameError at startup
- Runner never actually launched the agent service (poll loop waited on nothing) → the
  25-minute hang that triggered deeper fixes: process-group kills
  (`Popen(start_new_session=True)`+`killpg`) eliminating orphaned-pipe eternal hangs

And one functional over-hardening: `external_directory:"deny"` blocked deliverable writes —
reverted to `allow` after a live network task failed; container boundary is the real fence.

---

## 6. Feature tour (final state)

- **CLI**: `swarm run · oracle · create · validate · redact` (global via `uv tool install`,
  per-project via `uv run`, ephemeral via `uvx`)
- **`-m/--model`** override on `run` — recorded in `run.json` (deliberately absent from oracle)
- **Oracle mode (opt-in)** — `solution/solve.sh` executed in the same sandbox and scored by
  the same verifier; threshold-gated exit codes for CI; never gates normal runs
- **`swarm create`** — scaffold whose built-in oracle scores **1.0 immediately**;
  name-regex + no-overwrite guards; next-step hints printed
- **Three-tier networking** — `internet = none | allowlist | allow` (+legacy `net_egress`
  auto-mapping), conflict/TLD validation, tier recorded in manifest
- **Anthropic dialect** — `x-api-key` + `anthropic-version` injection, `@ai-sdk/anthropic`
  provider wiring; auto-detect via `sk-ant-`/URL
- **Keyless operation** — Ollama/LM Studio via `host.docker.internal` (uplink network)
- **TUI** — per-stage progress bars filling toward their *timeout caps*, live agent event
  counter, ✓/✗ outcomes, rich summary tables; plain fallback when output isn't a TTY
- **URL normalization** — strips trailing `/chat/completions` and `/v1` with warnings
  (killed the user's double-`/v1` 404 class)
- **Robustness** — process-group timeouts, deleted-cwd self-heal, fail-fast entrypoint
  guards, trajectory export survives agent crashes, teardown warnings instead of silence

---

## 7. Verification highlights

- Synthetic opencode-schema SQLite test for the optimized exporter (corrupt rows, orphans,
  interleaved sessions, atomicity) — plus a first-run fixture bug caught & corrected
- Redaction unit battery: every pattern family incl. NUL-byte file and split-string secrets
- Decomposition validator: cycle/duplicate/unknown-dep refusals
- Compose dry-runs asserting topology per flavor/mode/network-tier
- Live PoC batteries: forged-header auth probes, CONNECT byte-level tunnel inspection,
  sslip.io rebinding repro, redirect-target hit counting, mock-upstream end-to-end runs
- **Real-model greens**: `completed · score 1.0` keyless on `x-preview-f-free`
  (user's own terminal: 144s; harness-side reruns down to ~60s in `internet="allow"`),
  plus honest `0.0` runs proving flaky-model laziness gets failed, not forgiven
- Oracle dual-path: good solution `PASSED·1.0`; typo'd solution `0.5 → FAILED, exit 1`

---

## 8. Packaging & distribution notes

- Wheel ships image sources inside the package (fixed site-packages build-context crash)
- `uv.lock` committed; `tomli>=2.0; python_version<"3.11"` added (system Python is 3.9);
  `requires-python` relaxed to `>=3.9` to match reality
- Global install: `uv tool install --force .` — this machine's uv relocates tool bins to
  `~/.local/share/bin/` (opencode-zen), bridged by symlink into `~/.local/bin/swarm`
- Editable dev installs need modern pip (`pip install --upgrade pip` first) — PEP-660
- `.gitignore`: `__pycache__/ *.egg-info/ .venv/ results/ .DS_Store`

---

## 9. Git / GitHub state

- Repo initialized at `/Users/ishan/advtest/better-harness` (branch `main`)
- Identity (repo-local): `ishankrs <ishankashyap1001@gmail.com>`
- Commit `980c7bc` — "Initial release: Docker-isolated agent eval harness" (25 files,
  secret-scanned clean pre-commit)
- **Push pending**: `gh` was unauthenticated. Finish with:
  ```bash
  gh auth login            # GitHub.com → HTTPS → browser, sign in as ishankrs
  cd ~/advtest/better-harness
  gh repo create better-harness --private --source=. --remote=origin --push
  ```
  Register the email on the GitHub account so commits link to the profile.

---

## 10. Known limitations & roadmap (deliberately open)

1. **Spend governor** — no rate/budget cap at the proxy yet (injected agents could burn credits)
2. **Disk governance** — result bind mounts uncapped
3. **Allowlist enforcement is advisory for proxy-oblivious clients** (env-var based); airtight mode needs host firewalling; `internet="none"` remains truly airgapped
4. **Verifier stdlib** — injection-hardened `llm_judge` helper + common checks (planned `swarmharness.checks`)
5. **Grounded grading** — optional verifier egress for live-web anti-fabrication checks
6. **Multi-mode E2E vs a real LLM** — subagent fan-out validated by construction/config only
7. **Auto-resume** — bounded `--continue` retry for transient provider errors (scope-cut)
8. **Ctrl-C teardown race** — one observed stray-container incident; signal-safe cleanup planned
9. **Fleet runner + local leaderboard** (`run-many`, `report`) for benchmark campaigns
10. Free reasoning models are nondeterministic (identical runs scored 1.0 and 0.0) —
    per-check breakdowns exist precisely to disambiguate lazy-model vs broken-task

---

*Generated from the full working session; timestamps reference 2026-08-23/24.*
