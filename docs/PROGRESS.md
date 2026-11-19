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
| M7b RDP Shield | implemented on dev; every write path fake-tested only (live tests pending for a test VPS). **Not built:** country restriction |
| M8 GeoIP, intel, blocklists | implemented on dev (IntelService, Threat Intel page, blocklists with confirmation, AbuseIPDB). **Not built:** attack map (ECharts), IP detail drawer. Live list activation pending for a test VPS. (CI of the M8 push failed once on the Windows job — reqwest without a rustls provider in the speed-server tests — fixed by `2979d19`) |
| M9 Speed test | implemented on dev (SpeedService, Speed Test page, bin tests). Accuracy vs a reference tool (±10 %) **not measured**: needs a test VPS and a node |
| M10 MTR advanced | merged on dev (ICMP/UDP/TCP, ASN/country, export, UI). Acceptance "TCP reaches hosts that drop ICMP with Npcap" **pending** for a test VPS |
| M11 Settings/logs/installer/updater | done: proxy setting, Logs page (audit), pw-store wired for the defense state + audit log. **Packaging (NSIS installer, updater, release workflow): see "Packaging" below** |
| M12 Hardening & 1.0 | partly: threat model, IPC robustness tests (CI) + cargo-fuzz target (**not run**, needs nightly), README. **CPU budget NOT met** (below) |

## Packaging (M11) — status
Delegated to a subagent working in a worktree branch (`worktree-agent-a8bc3af9dedd69989`). See the end of this file for
the final state once it has reported.

## Resource budget (M12 acceptance: idle < 1 % CPU, < 60 MB RAM)
Measured on the dev VPS (16 logical cores; release build; `run --console`; capture on, 1 s poll, ~60 connections, ~3 Mbps):
- Working set 27 MB, private 15 MB → **RAM criterion met**.
- CPU **1.7 – 2.9 % of one core** (60 s window, spread across the tokio workers and the blocking pool, no single hot thread) →
  **CPU criterion NOT met**. Not optimized and not measured with capture stopped. Candidates: the 1 s netstat/adapter poll, the detector
  tick, the raw-socket capture thread. To do on a 1 vCPU / 2 GB test VPS together with the attack-fixture replay.

## Blockers
None open. Everything that needs live firewall/RDP/service changes is deferred to a test VPS (TESTING §F4–F11).

## Live tests pending for a test VPS
See docs/TESTING.md §F4–F11 (capture/Npcap, alerts, firewall + Guardian, RDP Shield, threat-intel lists, speed test, MTR modes,
installer/upgrade/uninstall/updater).

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
- Keys to generate on the user's own PC: updater key and blocklist minisign key (docs/RELEASE-KEYS.md). Until then the updater and the XeroHost blocklist are disabled (fail closed).
- RDP Shield calls `restore_snapshot` before any purge/uninstall/`pwctl rdp reset`; the ORIGINAL pre-shield snapshot is persisted once.
- Live check on the dev VPS (agent in Monitor, read-only): real RDP brute-force bots hit this server; the Guardian protected set listed gateway, DNS, 127/8 and the trusted RDP client, and a Medium RdpBruteForce alert became a `would_block` decision. Nothing was blocked.
- pw-store is wired only for the defense state and the audit log (decision recorded); alerts, RDP Shield, intel and settings are still JSON files.
- No config.toml (each area has its own file); proxy applies at the next agent start.

## Findings to act on
- **RawSocket backend saw 0 inbound packets on the dev VPS** (outbound is seen). Hypothesis (unverified): Windows Firewall drops inbound delivery to raw sockets of an app without an allow rule. The engine warns ("capture is blind"); the packaging adds an inbound allow rule for `packetward-agent.exe` in group `PacketWard` (to verify on a test VPS, TESTING §F4); other detectors do not depend on capture.
- `pw-capture` Npcap FFI was never executed (Npcap must not be installed here): test on a test VPS with Npcap.
- UDP/TCP MTR intermediate hops are invisible with the raw-socket backend here (same inbound-blind issue).
