# PacketWard — Progress (autonomous run)

Read this first when resuming after a stop or a context compaction.

**Branch:** `dev` (never touch `main`). **Rules:** see the Phase 2 brief summarized below.
- Commit per completed task; push `dev` at the end of each milestone; CI of `dev` must be green (check with `gh`).
- A milestone is done only if fmt, clippy (Windows + Linux target), tests, cargo deny, lint, typecheck, build pass
  and CI is green. Advisor once at the end of each milestone.
- Unexpected decisions: pick the safest option, record it in DECISIONS.md → "Autonomous decisions — review".
- Subagents (worktree isolation, max 3 at a time) for independent crates; integrate/verify myself.
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
| M11 MCP server | **designed, not implemented** (ARCHITECTURE §6.14, ROADMAP M11, DECISIONS "MCP"). It sits before Settings/installer (now M12) and is the next milestone to implement; M12 gained two unchecked items that depend on it (Settings → MCP page, `pwctl mcp` launch check) |
| M12 Settings/logs/installer/updater | done, except the Settings → MCP page and the `pwctl mcp` launch check (they need M11): proxy setting with user name/password in the Windows Credential Manager, Logs page (audit), pw-store wired for the defense state, the audit log and the **alert inbox** (retention 90 days / 10 000 rows, legacy `alerts.jsonl` imported once). Updater checks at start and every 24 h (switch in Settings, on by default) and never installs without the button. Packaging (NSIS installer, updater, release workflow) is merged but untested live: see "Packaging" below |
| M13 Hardening & 1.0 | partly: threat model, IPC robustness tests (CI) + cargo-fuzz target (**not run**, needs nightly), README. CPU budget met on the dev VPS (below), to confirm on a 1 vCPU test VPS |
| UI redesign (2026-11-20) | done: floating-panel shell, own title bar, Warm Sentinel palette with the logo blue, per-icon motion, flags, attack map, themed dropdowns/checkboxes everywhere, IP detail drawer |

## Packaging (M12) — status
Merged into `dev`: NSIS release config (`tauri.release.conf.json`) + `installer/hooks.nsh`, two-channel updater that fails closed
with the placeholder public key, tag-driven `release.yml` (unsigned build without secrets; no `latest.json` without the signing key),
docs ARCHITECTURE §9 and TESTING §F11. The installer was **built** on the dev VPS (setup .exe) but **never run**: install,
upgrade, uninstall, the raw-socket firewall rule, RDP reset on uninstall, signed updates and the release workflow itself are
pending (needs Windows Server 2019/2022 test VMs and the owner's keys, docs/RELEASE-KEYS.md). Known caveats are in ARCHITECTURE §9.1
(manual "uninstall first" upgrade path resets RDP Shield; a stable hotfix lower than the newest beta overwrites the beta manifest;
the updater uses the Windows system proxy, not the agent-config proxy).

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
- Updater key: generated 2026-11-21, public key committed, secrets loaded; the VPS copy is deleted once the owner confirms the backup (docs/RELEASE-KEYS.md §1.4). Blocklist minisign key: still to generate on the owner's PC; until then the XeroHost blocklist stays disabled (fail closed).
- RDP Shield calls `restore_snapshot` before any purge/uninstall/`pwctl rdp reset`; the ORIGINAL pre-shield snapshot is persisted once.
- Live check on the dev VPS (agent in Monitor, read-only): real RDP brute-force bots hit this server; the Guardian protected set listed gateway, DNS, 127/8 and the trusted RDP client, and a Medium RdpBruteForce alert became a `would_block` decision. Nothing was blocked.
- pw-store holds the defense state, the audit log and the alert inbox. RDP Shield state, the country policy (`rdp_country.json`), intel lists and `settings.json` stay JSON files (decision recorded: they are tiny, human-readable and the agent must start even if the database is broken).
- No config.toml (each area has its own file); proxy applies at the next agent start.

## Findings to act on
- **RawSocket backend saw 0 inbound packets on the dev VPS** (outbound is seen). Hypothesis (unverified): Windows Firewall drops inbound delivery to raw sockets of an app without an allow rule. The engine warns ("capture is blind"); the packaging adds an inbound allow rule for `packetward-agent.exe` in group `PacketWard` (to verify on a test VPS, TESTING §F4); other detectors do not depend on capture.
- `pw-capture` Npcap FFI was never executed (Npcap must not be installed here): test on a test VPS with Npcap.
- UDP/TCP MTR intermediate hops are invisible with the raw-socket backend here (same inbound-blind issue).
