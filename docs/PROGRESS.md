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
| M3 Basic diagnostics | not started |
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
Now: wave 1 of crate-level subagents running in worktrees (pw-diag, pw-capture, pw-detect). When they report: merge their branches into dev, verify, then integrate M3 (proto types, engine, UI Diagnostics page), M4, M5.
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
