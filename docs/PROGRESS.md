# PacketWard — Progress (autonomous run)

Read this first when resuming after a stop or a context compaction.

## Handoff — state on 2026-11-21 (read before doing anything)
- Repo is **public**. `main` is fast-forwarded to `dev` on the owner's explicit OK (never force-push).
- **License (2026-11-21):** **PolyForm Shield 1.0.0** replaces GPL-3.0-or-later (source-available: use, modify
  and redistribute freely, including commercially; no selling it or offering a competing product). `LICENSE`
  carries the official text plus the Required Notice, every file has the SPDX line
  `LicenseRef-PolyForm-Shield-1.0.0`, and the Cargo/npm/Tauri metadata, About strings (en/es/pt-BR) and docs
  follow. `main` was fast-forwarded so the default branch carries it too. The published `v0.1.0-beta.1` stays
  GPL-3.0-or-later; the new terms apply from the next version. New dependencies only need a permissive,
  redistributable license (see `deny.toml`).
- **Releases (public):** `v0.1.0-beta.1` (pre-release, only its installer left), `v0.1.0-beta.2` (pre-release, published by the new
  workflow, only `PacketWard_0.1.0-beta.2_x64-setup.exe`) and **`v0.1.0-beta.3`** (pre-release, published 2026-11-21 from `0fdc172`,
  `PacketWard_0.1.0-beta.3_x64-setup.exe`; first release with the PolyForm Shield license, the MCP server and the Settings → MCP page).
  and **`v0.1.0`** (stable, published 2026-11-22, `PacketWard_0.1.0_x64-setup.exe`; GitHub marks it Latest). The old `updater-beta` release/tag is **deleted** (owner approved). Do not create or delete public releases, tags or the `updates` branch without asking the owner first.
- **Release pipeline is DONE and proven by beta.2, beta.3 and v0.1.0** (`.github/workflows/release.yml`, `.github/scripts/release.mjs`): tag-only, guard (tag on main),
  full CI, draft with only the installer, private `release-proof` artifact (hash, `.sig`, manifest), verify against the public key, publish,
  then commit `beta.json` / `stable.json` to the orphan **`updates`** branch (exists now; has README + `beta.json` pointing at 0.1.0 (stable channel `stable.json` also exists now, signed);
  `stable.json` exists since the first stable tag). Endpoints in `tauri.conf.json` / `updater.rs` = raw.githubusercontent.com `updates/*.json`.
- **Updater signing key:** generated, public key in `tauri.conf.json`, secrets `TAURI_SIGNING_PRIVATE_KEY(_PASSWORD)` set in GitHub; private
  key backed up by the owner and deleted from the VPS. Never print/log it; change secrets only with `gh secret set` from a file.
- beta.1 has the old endpoint compiled in → cannot auto-update; users install beta.2 by hand. beta.3 and stable v0.1.0 are published, both channels
  are signed and point at 0.1.0. The real auto-update checks (beta.2 → beta.3 and a beta → stable switch, verifying the signature) are still
  pending on a test machine (TESTING §F11).
- **First v0.1.0 attempt failed (2026-11-22):** RUSTSEC-2026-0592 (stack overflow in `Url::origin()` on nested `blob:` URLs) appeared after beta.3
  and CI rejected commit `0279fab` (`url` 2.5.8, reached via hickory/reqwest/tauri-updater). Fixed with `cargo update -p url` → 2.5.9 (`5879ae0`);
  the owner approved moving the tag, and the rerun `45032758378` was green. No release or channel file was published by the failed run.
- **Pipe ACL fix (`fa25739`)**: the agent adds each `PacketWard Operators` member's own SID to the pipe ACL, so the installing user connects
  without signing out (owner hit the "Cierra sesión" screen on a desktop PC). Unit-tested only; **not yet verified on a real install of beta.2**.
- SECURITY.md: GitHub private vulnerability reporting is the only channel; owner will provide a security email later.
- CI: reusable `ci.yml`, docs-only detection fixed, Windows job tests only Windows crates, cache saved from `main`. Known flaky test:
  `IpDetailDrawer.test.ts` "closes when the user goes to another page" (failed once in CI, passed on rerun and 6/6 locally).
- Still open (owner's call): Authenticode certificate, blocklist minisign key, `main` branch protection,
  live tests of TESTING §F4–F13 on a test VPS, restart of the agent on this VPS (needs owner OK).

**Branch:** `dev` (`main` only by fast-forward with the owner's OK; **pushing `dev` also needs the owner's OK**,
owner rule 2026-11-21 — commit locally, ask before pushing; never create/delete releases, tags or the `updates`
branch without asking). **Rules:** see the Phase 2 brief summarized below.
- Commit per completed task; push `dev` at the end of each milestone; CI of `dev` must be green (check with `gh`).
- A milestone is done only if fmt, clippy (Windows + Linux target), tests, cargo deny, lint, typecheck, build pass
  and CI is green. Advisor once at the end of each milestone.
- Unexpected decisions: pick the safest option, record it in DECISIONS.md → "Autonomous decisions — review".
- Subagents (worktree isolation, max 3 at a time) for independent crates; integrate/verify myself.
  Owner rules 2026-11-21: subagents run the **same model as the main session** (`opencode/deepseek-v4.1-flash-free`);
  **never create a separate build cache** — the disk has ~27 GB free of 149 GB. Point `CARGO_TARGET_DIR` at the
  existing `packetward\target`, or build inside each worktree's own `target/` and delete the worktree right after
  the merge; never leave a second `*-target` folder outside the repo.
- Live-VPS limits: **no** firewall rule changes, **no** Guardian Active, **no** RDP changes (port/rules/NLA/lockout),
  **no** network adapter changes, capture only with RawSocket (no Npcap), speed tests ≤ 1 GB. Service install/uninstall
  for tests is allowed; leave the VPS clean (verify with TESTING.md §G).
- Stop only if: something irreversible, a test would break the limits, or CI/tests still fail after 3 different
  attempts → note it under Blockers and continue with the next milestone that does not depend on it.

## Status
| Milestone | State |
|---|---|
| M0 Scaffold | done (main) |
| M1 Proto/IPC/agent | done (main) |
| M2 Netstat & dashboard | done (main) + RDP trust set |
| M3 Basic diagnostics | done on dev. Live smoke on this VPS: ping/MTR/DNS ALL/port check verified, MTR path identical to tracert. Pending on a test VPS: comparison with WinMTR against a XeroHost node (no node exists yet) |
| M4 Capture & support bundle | implemented on dev; live checks on this VPS done; Npcap/inbound/200k pps pending for a test VPS |
| M5 Detection & alerts | implemented on dev (4625 feed, inbox, toasts, tray badge); toast with the window closed pending for a test VPS |
| M6 Firewall manager | implemented on dev; real-firewall tests pending for a test VPS |
| M7 Guardian | implemented on dev (Monitor default, Active with confirmation, ladder, circuit breaker, audit); live Active test pending for a test VPS |
| M7b RDP Shield | implemented on dev; every write path fake-tested only (live tests pending for a test VPS). Country restriction (RS-2 A: reactive, through the Guardian, fail closed) implemented with its UI; its live behaviour is pending for a test VPS |
| M8 GeoIP, intel, blocklists | implemented on dev (IntelService, Threat Intel page, blocklists with confirmation, AbuseIPDB), attack map with flags and zoom, IP detail drawer (click any address). Live list activation pending for a test VPS. (CI of the M8 push failed once on the Windows job — reqwest without a rustls provider in the speed-server tests — fixed by `2979d19`) |
| M9 Speed test | implemented on dev (SpeedService, Speed Test page, bin tests), and since 2026-11-20 it works with no XeroHost node: built-in public providers (Cloudflare, Hetzner, OVHcloud) with a provider selector; checked live from the dev VPS (automatic run: Hetzner Ashburn 34 ms, 490 Mbps down, upload measured on Cloudflare 275 Mbps). Accuracy vs a reference tool (±10 %) **not measured**: needs a test VPS and a node |
| M10 MTR advanced | merged on dev (ICMP/UDP/TCP, ASN/country, export, UI). Acceptance "TCP reaches hosts that drop ICMP with Npcap" **pending** for a test VPS |
| M11 MCP server | implemented on dev (2026-11-21, protocol 1.15): `pw-mcp` (rmcp stdio, catalog, envelope, prompts), agent enforcement (`ConnCtx`, `mcp.json` fail-closed, approval queue, write/probe limits, protected set, audit actor `mcp`, `live.stats.get`), `pwctl mcp`, desktop banner/dialog/toast. Fake-tested on both sides; live client↔agent checks pending on a test VPS (TESTING §F13). The Settings → MCP page and the `pwctl mcp` launch check landed in M12 on 2026-11-21 |
| M12 Settings/logs/installer/updater | done (the Settings → MCP page landed 2026-11-21): master switch with confirmation, per-tool levels (approval-only tools cannot be automatic), write limit 1..60, Copy configuration for Claude Code/OpenCode/Cursor with the installed `pwctl.exe` path, and a bounded `pwctl mcp` smoke test. 10 component tests. Proxy setting with user name/password in the Windows Credential Manager, Logs page (audit), pw-store wired for the defense state, the audit log and the **alert inbox** (retention 90 days / 10 000 rows, legacy `alerts.jsonl` imported once). Updater checks at start and every 24 h (switch in Settings, on by default) and never installs without the button. Packaging (NSIS installer, updater, release workflow) is merged but untested live: see "Packaging" below |
| M13 Hardening & 1.0 | partly: threat model, IPC robustness tests (CI) + cargo-fuzz target (**not run**, needs nightly), README. CPU budget met on the dev VPS (below), to confirm on a 1 vCPU test VPS |
| UI redesign (2026-11-20) | done: floating-panel shell, own title bar, Warm Sentinel palette with the logo blue, per-icon motion, flags, attack map, themed dropdowns/checkboxes everywhere, IP detail drawer |

## Packaging (M12) — status
Merged into `dev`: NSIS release config (`tauri.release.conf.json`) + `installer/hooks.nsh`, two-channel updater that fails closed
with the placeholder public key, tag-driven `release.yml` (unsigned build without secrets; no channel files without the signing key),
docs ARCHITECTURE §9 and TESTING §F11. Update 2026-11-21: the release workflow ran for real (`v0.1.0-beta.2`, see Handoff above) and the
owner installed beta.1 on a desktop PC (that is how the sign-out bug was found). Still pending: upgrade/uninstall on test VMs, RDP reset on
uninstall, an end-to-end signed auto-update (beta.2 → beta.3). Known caveats in ARCHITECTURE §9.1 (manual "uninstall first" upgrade path resets
RDP Shield; the updater uses the Windows system proxy, not the agent-config proxy). The old "stable hotfix overwrites the beta manifest" gap is gone
(channel files never move backwards).

## Resource budget (M13 acceptance: idle < 1 % CPU, < 60 MB RAM)
Measured on the dev VPS (16 logical cores; release build; `run --console`; capture on, 1 s poll, ~60 connections, ~3 Mbps):
- Working set 27 MB, private 15 MB → **RAM criterion met**.
- Before optimizing: CPU **1.7 – 2.9 % of one core** (60 s window, spread across the tokio workers and the blocking pool).
- After (2026-11-20, measured at commit `803e721`, before the country loop and the alert database were merged): the engine polls the network and ticks the detectors every 5 s / 2 s while **no UI is subscribed** to `live.stats`
  (a viewer wakes them at once), the agent runtime has 2 worker threads, and the RDP Shield checks every 2 s. Measured on the same VPS
  (release, Monitor, UI closed, 60 s window after 10 s of warm-up): **0.68 % of one core with capture on, 0.86 % with `--no-capture`**
  (noise of the same order), RAM 39 – 45 MB → **both criteria met**. With the UI open the 1 s pace applies again (not measured separately).
  Script: `tools/dev/measure-idle.ps1`; the sources' own cost is `cargo test -p pw-netstat --release --
  --ignored --nocapture idle_poll_costs` (about 4 ms of work per second). To confirm on a 1 vCPU test VPS with the attack-fixture replay.

## VPS clean-up (TESTING §G), 2026-11-19 at the end of the run
No service was ever installed here; agent processes were stopped; `%ProgramData%\PacketWard` (captures, logs, support, alerts.jsonl,
audit.jsonl, packetward.db + wal/shm) was deleted. Result of the §G block: service `False`, group `PacketWard Operators` `False`,
HKCU/HKLM Run `False`/`False`, `Test-Path ProgramData\PacketWard` `False`, agent/app processes `0`, firewall rules in group
`PacketWard` `0`, `%AppData%\PacketWard` `False`. Build outputs (`target/`) and worktrees under `.claude/` are git-ignored and were left.

## Blockers
No open blockers. The MCP server (M11) is designed and waiting its turn; everything that needs live firewall/RDP/service
changes is deferred to a test VPS (TESTING §0 and §F4–F12).

## Live tests pending for a test VPS
See docs/TESTING.md §0 (inbound capture rule, first step) and §F4–F11 (capture/Npcap, alerts, firewall + Guardian, RDP Shield, threat-intel
lists, speed test, MTR modes, installer/upgrade/uninstall/updater), plus §F12 (country restriction, proxy with basic auth, alerts in SQLite,
automatic update check) for what was added on 2026-11-20.

Note: a `ui.json` written before 2026-11-20 keeps `checkOnStart: false`, so the automatic update check shows as OFF on machines that already
ran the app; new installs get it ON.

## How to run everything
```powershell
cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo test --workspace; cargo deny check
$env:Path = "$env:APPDATA\npm;" + $env:Path      # pnpm lives here on this machine (bash cannot run it)
cd apps\desktop; pnpm lint; pnpm typecheck; pnpm test; pnpm build
```
Machine-specific notes (this dev VPS): the Linux-target check is
`cargo clippy --workspace --exclude packetward-desktop --exclude packetward-agent --exclude pw-store --exclude pw-speed-server --all-targets --target x86_64-unknown-linux-gnu -- -D warnings`
(speed-server and pw-store need a C compiler for ring/SQLite; CI covers them). Vitest is reliable here with
`pnpm exec vitest run --maxWorkers=3 --testTimeout=60000`. Disk is tight: remove merged subagent worktrees under `.claude/worktrees`.
Developer agent without installing the service: `cargo run -p packetward-agent -- run --console` (elevated).

## Notes for the final summary
- **The working tree contains changes to `branding-kit/` that I did not make (deleted and modified files).** I never commit them (commits use `git add -A -- . ':!branding-kit'`). Earlier, one commit accidentally included them and was pushed to `dev`; it was undone with a revert-style commit (the history keeps both). Tell the user.
- Updater key: generated 2026-11-21, public key committed, secrets loaded; the owner backed it up and the VPS copy was securely deleted on 2026-11-21 (docs/RELEASE-KEYS.md §1.4). Blocklist minisign key: still to generate on the owner's PC; until then the XeroHost blocklist stays disabled (fail closed).
- RDP Shield calls `restore_snapshot` before any purge/uninstall/`pwctl rdp reset`; the ORIGINAL pre-shield snapshot is persisted once.
- Live check on the dev VPS (agent in Monitor, read-only): real RDP brute-force bots hit this server; the Guardian protected set listed gateway, DNS, 127/8 and the trusted RDP client, and a Medium RdpBruteForce alert became a `would_block` decision. Nothing was blocked.
- pw-store holds the defense state, the audit log and the alert inbox. RDP Shield state, the country policy (`rdp_country.json`), intel lists and `settings.json` stay JSON files (decision recorded: they are tiny, human-readable and the agent must start even if the database is broken).
- No config.toml (each area has its own file); proxy applies at the next agent start.

## Findings to act on
- **RawSocket backend saw 0 inbound packets on the dev VPS** (outbound is seen). Hypothesis (unverified): Windows Firewall drops inbound delivery to raw sockets of an app without an allow rule. The engine warns ("capture is blind"); the packaging adds an inbound allow rule for `packetward-agent.exe` in group `PacketWard` (to verify on a test VPS, TESTING §F4); other detectors do not depend on capture.
- `pw-capture` Npcap FFI was never executed (Npcap must not be installed here): test on a test VPS with Npcap.
- UDP/TCP MTR intermediate hops are invisible with the raw-socket backend here (same inbound-blind issue).
