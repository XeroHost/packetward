# PacketWard — Roadmap

Work top to bottom. Each milestone ends with all checks green (fmt, clippy, tests, lint, typecheck) and its
acceptance criteria demonstrably met. Tick boxes in the same PR that completes them.
Product decisions are fixed in `docs/DECISIONS.md`.

## M0 — Scaffold
- [x] Cargo workspace with all crates from ARCHITECTURE §3 (empty but compiling), shared lints, `deny.toml`
      allowing only GPLv3-compatible licenses.
- [x] `LICENSE` (GPL-3.0 full text from gnu.org), SPDX header `GPL-3.0-or-later` policy in CONTRIBUTING.
- [x] `apps/desktop`: Tauri 2 + Vue 3 + TS + Vite + Pinia + Router + Tailwind v4 + shadcn-vue + vue-i18n.
- [x] i18n: `en` base/fallback, `es`, `pt-BR`; locale auto-detection + override.
- [x] Fonts self-hosted: Bricolage Grotesque (headings), Geist Sans (body), JetBrains Mono + Geist Mono.
- [x] Design tokens from `docs/DESIGN.md` as CSS variables; Appearance settings store (theme dark/light/system,
      mono font, density, text size, reduce motion), persisted.
- [x] App shell: sidebar nav (Dashboard, Traffic, Connections, Capture, Guardian, Firewall, Diagnostics,
      Speed Test, Threat Intel, Logs, Settings), "by XeroHost" footer, top bar with agent status + Guardian pill.
- [x] CI: Linux (core crates + frontend), Windows (full build). `cargo deny`, `cargo audit`.
      (Workflows in `.github/workflows/ci.yml`; every command was run locally on Windows with Node 26; CI pins Node 24, both inside the dependencies' `engines`. The first remote run on `main` was reported green by the maintainer.)
**Accept:** `pnpm tauri dev` opens the shell on Windows; all Appearance options work live; CI green.

## M1 — Proto, IPC, agent service
- [x] `pw-proto` envelope + handshake + ts-rs export into `apps/desktop/src/types/generated`.
- [x] `pw-ipc`: named pipe transport with restricted ACL + in-memory transport (tests only); framing tests.
      (ACL = SYSTEM + Administrators + local group `PacketWard Operators`, because an unelevated admin cannot use an
      Administrators-only ACE; see ARCHITECTURE §7/§8.)
- [x] `pw-engine` skeleton with `system.info` and a `live.heartbeat` subscription.
- [x] `apps/agent`: Windows service (`install`, `uninstall`, `run`), logs to ProgramData.
      (Also `start`, `stop`, `repair`.)
- [x] Desktop: connects to agent; "Agent not running / not installed" screen with Start/Repair (UAC prompt).
      (Also the "access denied / sign out required" and version-mismatch states. On the dev VPS Admin Approval Mode is
      off, so no UAC prompt was ever shown; the `runas` path ran and worked.)
- [x] Tray icon + autostart of the UI at user logon (minimized to tray).
      (Close hides to the tray, single instance, `--minimized` starts hidden: verified. Autostart is an opt-in switch in
      Settings → Startup; registering it by default belongs to the installer (M11). The tray icon itself was not
      looked at on screen.)
- [x] `apps/cli`: `pwctl status`.
- [x] `docs/TESTING.md` manual checklist.
**Accept:** heartbeat visible in UI; stopping the service shows the repair screen; non-admin cannot open the pipe.
(Met: the first two were checked live against the installed service; "non-admin cannot open the pipe" is proven by
automated tests on a real pipe with a restricted token and by reading the live DACL. A run with a real second
standard account is TESTING.md §D and has not been done yet. The M1 run on GitHub Actions was reported green by the maintainer.)

## M2 — Netstat & dashboard
- [x] TCP/UDP tables with PID/process, IPv4+IPv6; adapters; interface counters → bps/pps in/out.
      (Only real adapters are summed: filter layers, loopback and VPN/tunnel adapters are excluded from the total;
      tunnels with traffic are listed apart.)
- [x] RDP sessions + client IPs.
      (Client IPs are the TCP peers of the RDP port. `WTSClientAddress` is only what the client reports about itself
      and differed from the real peer on a live session. IPv6 clients are not identified by WTS yet.)
- [x] Dashboard: live in/out bandwidth chart, connection count, top remote IPs by connections.
- [x] Connections page: virtualized, filterable table (proto, state, process, remote IP), copy IP.
      (Sortable, keyboard-navigable. The context menu with Lookup/Block/Allow/MTR waits for the features it calls.)
**Accept:** values match `netstat -ano` and Task Manager within tolerance; 5k connections stay smooth.
(Met on the dev VPS: counts equal `netstat -ano` (63=63; 70/25/21 as a service; 5027/5075 vs 5026/5077 at 5k rows);
inbound bandwidth integrated over 661.8 MB was -4.9 % (UI) and +2.6 % (Windows perf counter) against the OS byte
counter; scroll at 5k real and 50k synthetic rows stays at the idle frame cadence of that VM (p95 ≈ 43 ms, the
VM caps at ~31 ms per frame). Not seen yet: the GitHub Actions run of M2, and the page at 1280×720 Compact by eye.)

## M3 — Basic diagnostics
- [ ] Ping (v4/v6), MTR simple with streaming per-cycle results, DNS lookup (all record types), port check.
- [ ] "Copy report" for MTR.
**Accept:** MTR to a XeroHost node matches WinMTR within reason; DNS ALL returns every type present.

## M4 — Capture & support bundle
- [ ] Npcap detection + lazy load; RawSocket backend; backend selection & UI explanation.
- [ ] Decode → `PacketMeta`; bounded pipeline with dropped counter.
- [ ] Live stats: pps/bps per protocol, top talkers (src IP, packets, bytes, proto mix).
- [ ] Timed capture to `.pcapng` with filter, ring buffer option.
- [ ] Support bundle → **local zip only**, with preview and local-IP anonymize option (`pwctl support-bundle` too).
**Accept:** app starts without Npcap; with Npcap the pcapng opens in Wireshark; 200k pps synthetic load does
not freeze the UI (drops are counted, not hidden).

## M5 — Detection engine & alerts
- [ ] Sliding windows per source IP; detectors SynFlood, UdpFlood, IcmpFlood, PortScan, ConnFlood, Aggregate.
- [ ] RDP brute-force watcher (Security log 4625) → RdpBruteForce detector.
- [ ] Alerts stored + `alerts` subscription + in-app inbox.
- [ ] Windows toast notifications (from the UI/tray process) + tray icon state (neutral/monitor/active/blocking),
      with per-severity mute in Settings.
- [ ] Fixtures + synthetic generators; deterministic tests per detector.
**Accept:** each detector fires on its fixture and stays quiet on a "normal traffic" fixture; a toast appears
for a critical alert while the main window is closed.

## M6 — Firewall manager
- [ ] COM API: list (with filters), create, edit, enable/disable, delete user rules; group `PacketWard`.
- [ ] Batched block lists; manual block/unblock IP or CIDR from anywhere in the UI (context menu).
- [ ] `pwctl firewall purge`.
**Accept:** rules appear in `wf.msc`; purge leaves no PacketWard rules; 5k blocked IPs use < 10 rules.

## M7 — Guardian mode
- [ ] Policy editor (presets: Gentle / Balanced / Strict + custom), modes Off / **Monitor (default)** / Active.
- [ ] Protected set (RDP clients, allowlist, gateway, DNS, mgmt ranges), circuit breaker, TTL + escalation.
- [ ] Reconcile on start; expiry task; `pwctl unblock --all`, `pwctl guardian off|monitor|active`.
- [ ] Guardian page: live blocks with countdown, history, "why was this blocked", Monitor report
      ("would have blocked N IPs in the last 24 h") with a one-click "Switch to Active".
**Accept:** tests prove the current RDP client IP is never blocked; blocks survive agent restart and expire;
fresh install is in Monitor.

## M8 — GeoIP map, threat intel & blocklists
- [ ] DB-IP Lite country + ASN lookup, update check.
- [ ] Attack map: origin points/arcs to the server, intensity by pps, country leaderboard, click → IP detail.
- [ ] IP detail drawer: geo, ASN, connections, alerts, AbuseIPDB (if key), block/allow actions.
- [ ] Blocklists: XeroHost shared list (minisign-verified, pinned key) + opt-in public lists; scheduled refresh;
      applied through batched firewall rules and the protected set.
**Accept:** map stays > 30 fps with 500 active sources (and static under reduce motion); a tampered blocklist
is rejected; works offline except AbuseIPDB and list refresh.

## M9 — Speed test
- [ ] `tools/speed-server` (axum) with limits + Dockerfile + deploy notes for XeroHost nodes.
- [ ] Client: latency/jitter, multi-stream download/upload, server picker (auto by latency), custom servers.
- [ ] Bin tests 1 GB / 10 GB / 50 GB with confirmation for 50 GB, progress, cancel.
**Accept:** results within ~10% of a reference tool on the same link; cancel stops traffic immediately.

## M10 — MTR advanced
- [ ] ICMP/UDP/TCP modes, packet size, interval, hop limit, ASN/country per hop, IPv6, export.
**Accept:** TCP mode reaches hosts that drop ICMP (with Npcap).

## M11 — Settings, logs, proxy, updates, installer
- [ ] Settings UI for everything in ARCHITECTURE §10; proxy applied to all outbound HTTP.
- [ ] Logs page over `audit_events` (filters, export CSV/JSON).
- [ ] NSIS installer with service hooks, WebView2 handling, uninstall purge.
- [ ] Tauri updater with signed artifacts; **Stable + Beta** channels; release workflow on tag
      (`vX.Y.Z` → stable, `vX.Y.Z-beta.N` → beta).
- [ ] Optional Authenticode step in CI (runs only when signing secrets exist).
**Accept:** clean install/upgrade/uninstall on Windows Server 2019 and 2022 VMs; switching channel works.

## M12 — Hardening & 1.0
- [ ] Threat-model review, fuzz IPC decoder (`cargo fuzz`), CPU/RAM budget check on 1 vCPU / 2 GB VPS.
- [ ] README (en, with es/pt summaries), SmartScreen note, screenshots, CONTRIBUTING, SECURITY.md.
**Accept:** agent idle < 1% CPU and < 60 MB RAM; under attack fixture replay it stays responsive.
