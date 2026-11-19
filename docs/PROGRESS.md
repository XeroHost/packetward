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
| M3 Basic diagnostics | integrated on dev (see below) |
| M4 Capture & support bundle | not started |
| M5 Detection & alerts | not started |
| M6 Firewall manager | not started |
| M7 Guardian | not started |
| M7b RDP Shield | not started |
| M8 GeoIP, intel, blocklists | not started |
| M9 Speed test | not started |
| M10 MTR advanced | not started |
| M11 Settings/logs/installer/updater | not started |
| M12 Hardening & 1.0 | not started |

## Now / next
Now: M3 integrated and checked locally (fmt, clippy Windows + Linux, tests, deny, lint, typecheck, build). Next: commit + push dev, verify CI, advisor; then merge the pw-capture (`worktree-agent-a2611a6e633529557`) and pw-detect (`worktree-agent-a2991347640d9fe8e`) branches and integrate M4/M5; launch wave 2 subagents (pw-firewall, pw-intel, speed-server).
Note: pw-core (PacketMeta, CIDR sets) was written first on dev so capture/detect share it. Subagent worktrees live in .claude/worktrees (ignored by git).

## Blockers
None.

## Live tests pending for a test VPS
See docs/TESTING.md (sections are added per milestone).

## How to run everything
```powershell
cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings; cargo test --workspace; cargo deny check
cd apps\desktop; pnpm lint; pnpm typecheck; pnpm test; pnpm build
```

## Findings to act on
- **RawSocket backend saw 0 inbound packets on the dev VPS** (pw-capture live test, elevated; outbound is seen). Hypothesis (unverified): Windows Firewall drops inbound delivery to raw sockets of an app without an allow rule. Not tested further because firewall changes are prohibited here. Actions: (1) the engine must warn when outbound flows but inbound stays at 0 for N seconds ("capture is blind"), (2) test on a test VPS with an inbound allow rule for `packetward-agent.exe` in the `PacketWard` group (TESTING.md), (3) fall back to netstat-based counters (ConnFlood/Aggregate/RDP detectors do not need capture), (4) later alternative: NDIS ETW provider.
- `pw-capture` Npcap FFI was never executed (Npcap must not be installed here): test on a test VPS with Npcap.
- Subagent wave 2 (pw-firewall, pw-intel, speed-server) launched after M3 was pushed.
