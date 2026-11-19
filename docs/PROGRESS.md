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
| M3 Basic diagnostics | done on dev (CI run 44496262640 green). Live smoke on this VPS: ping/MTR/DNS ALL/port check verified, MTR path identical to tracert. Pending on a test VPS: comparison with WinMTR against a XeroHost node (no node exists yet) |
| M4 Capture & support bundle | implemented on dev (capture manager, recordings, support bundle, Traffic/Capture pages); live checks on this VPS done; Npcap/inbound/200k pps pending for a test VPS |
| M5 Detection & alerts | implemented on dev (engine service, 4625 feed, inbox, toasts, tray badge); live tests pending for a test VPS |
| M6 Firewall manager | pw-firewall core merged; engine/IPC/UI pending |
| M7 Guardian | not started |
| M7b RDP Shield | not started |
| M8 GeoIP, intel, blocklists | pw-intel core merged; integration/UI pending |
| M9 Speed test | tools/speed-server merged; client/UI pending |
| M10 MTR advanced | not started |
| M11 Settings/logs/installer/updater | not started |
| M12 Hardening & 1.0 | not started |

## Now / next
Now: M4 and M5 pushed to dev (CI being verified). Wave 3 subagents running in worktrees: pw-store (SQLite), speed-test client (pw-diag::speed), advanced MTR (pw-diag::mtr_adv). Meanwhile I integrate M6 (firewall IPC + block manager + UI), then M7 Guardian and M7b RDP Shield (these need pw-store for persistence). Order after that: M8 integration, M9/M10 integration, M11, M12.
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

## Notes for the final summary
- M4 acceptance items pending for a test VPS: Npcap + Wireshark check of the pcapng, 200k pps responsiveness. M5: a toast for a critical alert while the window is closed.
- RDP Shield (M7b) must: call `restore_snapshot` before any purge/uninstall/`pwctl rdp reset` (a purge with the shield active leaves the built-in RDP rules disabled), and persist the ORIGINAL pre-shield snapshot once (`kv_set_if_absent` in pw-store), never overwriting it.
- **The working tree contains changes to `branding-kit/` that I did not make (deleted and modified files).** I never commit them (commits use `git add -A -- . ':!branding-kit'`); tell the user.
- Live check on the dev VPS (agent in Monitor, read-only): real RDP brute-force bots hit this server; the Guardian protected set listed gateway, DNS, 127/8 and the trusted RDP client, and a Medium RdpBruteForce alert became a `would_block` decision. Nothing was blocked.
- Cleanup at the end: remove `%ProgramData%PacketWard` (alerts.jsonl, audit.jsonl, defense.json, captures, support, logs), stop any agent process, uninstall nothing else (no service was installed).

## Findings to act on
- **RawSocket backend saw 0 inbound packets on the dev VPS** (pw-capture live test, elevated; outbound is seen). Hypothesis (unverified): Windows Firewall drops inbound delivery to raw sockets of an app without an allow rule. Not tested further because firewall changes are prohibited here. Actions: (1) the engine must warn when outbound flows but inbound stays at 0 for N seconds ("capture is blind"), (2) test on a test VPS with an inbound allow rule for `packetward-agent.exe` in the `PacketWard` group (TESTING.md), (3) fall back to netstat-based counters (ConnFlood/Aggregate/RDP detectors do not need capture), (4) later alternative: NDIS ETW provider.
- `pw-capture` Npcap FFI was never executed (Npcap must not be installed here): test on a test VPS with Npcap.
- Subagent wave 2 (pw-firewall, pw-intel, speed-server) launched after M3 was pushed.
