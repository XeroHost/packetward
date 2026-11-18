# PacketWard — Architecture

## 1. Goals and non-goals

**Goals**
- Give a Windows Server VPS owner a clear, live picture of inbound traffic and attacks (who, how much, what kind).
- One-click evidence for support: a packet capture + summary report bundle they can attach to a XeroHost ticket.
- Host-level mitigation: firewall management and an automatic "Guardian" blocker with strong safety rails.
- Network diagnostics: MTR (simple/advanced), ping, DNS, port check, speed test against XeroHost nodes.
- Keep protecting when the RDP session disconnects or the UI is closed.

**Non-goals (be honest in the UI too)**
- PacketWard cannot stop a volumetric DDoS that saturates the VPS uplink. Once the pipe is full, only upstream
  mitigation helps. The UI must say so when inbound bandwidth is near the link capacity, and point to the
  provider's DDoS protection / support.
- Not an IDS with deep payload inspection, not an antivirus, not a VPN.

## 2. Process model

```
┌────────────────────────────── Windows host ──────────────────────────────┐
│                                                                          │
│  packetward-agent.exe  (Windows Service, LocalSystem)                    │
│  ├─ pw-engine: orchestrates everything below                            │
│  ├─ capture  → detect → guardian → firewall                              │
│  ├─ netstat poller, RDP-logon watcher (Security log 4625)                │
│  ├─ store (SQLite)                                                       │
│  └─ IPC server on \\.\pipe\packetward  (ACL: SYSTEM + Administrators)    │
│           ▲                       ▲                                      │
│           │ length-prefixed JSON  │                                      │
│  PacketWard.exe (Tauri 2)     pwctl.exe (CLI, basic)                     │
│  ├─ src-tauri: IPC client,    └─ status, guardian mode, unblock --all,   │
│  │   commands, event bridge,      firewall purge, support-bundle         │
│  │   tray + toast notifications                                          │
│  └─ Vue 3 UI (WebView2)                                                  │
└──────────────────────────────────────────────────────────────────────────┘
```

- **Agent (service)** owns every privileged operation and all long-running work. It survives RDP disconnects,
  logoffs and UI crashes. Guardian mode runs here. **The agent is required — there is no portable mode.**
- **Desktop app** is a viewer/controller that runs **unelevated**, starts at user logon minimized to the tray,
  and shows Windows toast notifications (the service runs in session 0 and cannot show UI). If the agent is
  missing or stopped, it shows an "Agent unavailable" screen with Start/Repair (elevated via UAC).
- **CLI (`pwctl`)** talks to the same pipe. Basic scope in v1: emergency recovery and scripting
  (`status`, `guardian off|monitor|active`, `unblock --all`, `firewall purge`, `support-bundle`).
- Dev convenience only: `packetward-agent run --console` runs the engine in a terminal without installing the service.

## 3. Repository layout

```
PacketWard/
├─ Cargo.toml                 # workspace, shared deps, lints
├─ rust-toolchain.toml  deny.toml  .cargo/config.toml
├─ crates/
│  ├─ pw-proto/     # IPC + shared DTOs (serde + ts-rs). Versioned. No logic.
│  ├─ pw-core/      # config model, IP/CIDR sets, allowlist, time windows, errors. No OS deps.
│  ├─ pw-detect/    # pure detection engine: flow table, sliding windows, detectors. No OS deps.
│  ├─ pw-capture/   # capture backends (Npcap, RawSocket), packet decode, pcapng writer, ring buffer
│  ├─ pw-netstat/   # TCP/UDP tables with PID, adapters, interface counters, RDP sessions
│  ├─ pw-firewall/  # Windows Firewall (COM INetFwPolicy2) behind a trait; batching; reconcile
│  ├─ pw-diag/      # ping, mtr, dns, port check, speed test client
│  ├─ pw-intel/     # GeoIP/ASN (mmdb), AbuseIPDB client, reputation cache
│  ├─ pw-store/     # SQLite: audit log, blocks, settings, intel cache, migrations
│  ├─ pw-ipc/       # transport (named pipe + in-memory), framing, client/server, subscriptions
│  └─ pw-engine/    # orchestrator: wires everything, owns tasks and state, exposes the API
├─ apps/
│  ├─ agent/        # Windows service host for pw-engine (+ install/uninstall subcommands)
│  ├─ desktop/      # Tauri 2: src-tauri/ (Rust) + src/ (Vue 3)
│  └─ cli/          # pwctl
├─ tools/
│  └─ speed-server/ # tiny axum server for XeroHost nodes: /ping /download /upload /info
├─ fixtures/        # small synthetic .pcapng files for detector tests (<1 MB each)
└─ docs/
```

Dependency direction (no cycles): `proto, core` ← `detect` ← `capture, netstat, firewall, diag, intel, store`
← `engine` ← `ipc` ← `apps/*`. The desktop's `src-tauri` and `pwctl` depend only on `pw-proto` + `pw-ipc`.

## 4. Key dependencies (choose these unless there is a written reason)

| Concern | Crate / lib |
|---|---|
| Async | `tokio` (rt-multi-thread, net, time, sync, signal) |
| Windows APIs | `windows` (Win32_NetworkManagement_IpHelper, _WindowsFirewall, Win32_System_Services, _EventLog, _RemoteDesktop, Win32_Networking_WinSock) |
| Service host | `windows-service` |
| Packet capture | `pcap` (Npcap, **lazy-loaded**), raw sockets via `windows`/`socket2` |
| Packet parsing | `etherparse` |
| pcapng writing | `pcap-file` |
| DNS | `hickory-resolver` |
| HTTP | `reqwest` (rustls, stream, socks) |
| GeoIP | `maxminddb` + DB-IP Lite Country/ASN `.mmdb` |
| Storage | `rusqlite` (bundled) + `rusqlite_migration` |
| Serialization / TS types | `serde`, `serde_json`, `ts-rs` |
| Errors / logs | `thiserror`, `anyhow` (bins), `tracing`, `tracing-subscriber`, `tracing-appender` |
| Secrets | `keyring` (Windows Credential Manager) |
| Desktop | `tauri` 2 (tray-icon), `tauri-plugin-updater`, `-notification`, `-autostart`, `-single-instance`, `-dialog`, `-opener`; `sys-locale` |
| Blocklist signature | `minisign-verify` |
| CLI | `clap` |
| Speed server | `axum` |

Frontend: see `apps/desktop/CLAUDE.md`.

## 5. Data flow (live traffic)

```
NIC ─► CaptureBackend ─► decode (etherparse, no alloc) ─► PacketMeta
        (Npcap | RawSocket)                                │
                                                           ▼
                                 FlowTable / per-src-IP windows (pw-detect)
                                     │                │
                     every tick (1 s)│                │ on detection
                                     ▼                ▼
                               StatsSnapshot      Alert ─► Guardian policy ─► Firewall
                                     │                │                         │
                                     └──── pw-store (audit) ◄───────────────────┘
                                     │
                                     ▼
                        IPC topic "live.stats" ─► desktop ─► Pinia store ─► charts/map
```

- `PacketMeta` is a small `Copy` struct: timestamp, src/dst IP, ports, proto, TCP flags, length, direction.
- The decode thread is a dedicated OS thread (not a tokio task) feeding a bounded `crossbeam`/`tokio::mpsc`
  channel. On overflow: drop, increment `dropped_packets`, surface it in the UI.
- The UI receives **aggregates only**: top N talkers, pps/bps in/out, per-protocol counts, per-country counts,
  new alerts. Default tick 1 s (configurable 250 ms – 2 s).
- Optional ring-buffer capture to pcapng runs in parallel (bounded by size, e.g. last 200 MB).

## 6. Feature modules

### 6.1 Capture (`pw-capture`)
- `trait CaptureBackend { fn open(&InterfaceId, &CaptureOpts) -> Result<Box<dyn PacketSource>>; fn caps() -> BackendCaps; }`
- **NpcapBackend** — best fidelity (L2, BPF filters, outbound + inbound). `wpcap.dll` must be loaded lazily
  (delay-load or `libloading`): the exe must start when Npcap is absent. Detect via
  `%SystemRoot%\System32\Npcap\wpcap.dll`.
- **RawSocketBackend** — built-in fallback using `SIO_RCVALL` on a bound interface address. Needs admin
  (the agent has it). IP-level only, no BPF; filtering done in Rust. Good enough for flood/scan detection.
- Backend selection: Npcap if present, else RawSocket; the UI shows which one is active and what is missing.
- Outputs: live `PacketMeta` stream, timed capture to `.pcapng` (duration/size/filter), ring buffer.

### 6.2 Detection (`pw-detect`) — pure, deterministic, heavily tested
Per source IP, sliding windows (e.g. 1 s, 10 s, 60 s) tracking: packets, bytes, SYN count, SYN-ACK/ACK ratio,
UDP packets, ICMP packets, distinct destination ports, new connections.
Detectors (each with configurable thresholds and a severity):
- `SynFlood` — high SYN rate with low completion ratio.
- `UdpFlood` — UDP pps/bps per source or aggregate above threshold.
- `IcmpFlood`.
- `PortScan` — distinct dst ports per source in window (horizontal and vertical).
- `ConnFlood` — too many concurrent/new TCP connections from one IP (works **without capture** using netstat).
- `RdpBruteForce` — failed logons (Security event 4625, logon type 10/3) per source IP, from the event log watcher.
- `Aggregate` — total inbound bps near link capacity → "volumetric, upstream mitigation required" notice.
Detectors receive time explicitly (`now: Instant`) so tests are deterministic. Test with `fixtures/*.pcapng` and
synthetic generators.

### 6.3 Guardian / auto-blocker (`pw-engine::guardian`)
- Policy = list of rules: `detector + threshold + window → action (Alert | Block { ttl })`.
- Escalation: repeat offenders get TTL × 2 up to a max (e.g. 15 min → 30 → 60 … → 24 h).
- **Protected set** (never blocked, checked before every block): allowlist IPs/CIDRs, active RDP client
  addresses (WTSQuerySessionInformation `WTSClientAddress`, refreshed every few seconds), default gateways,
  DNS servers, loopback/link-local, configured management ranges, speed-test servers.
- Circuit breaker: max N new blocks per minute; beyond that → alert "possible distributed attack, upstream
  mitigation recommended" instead of creating thousands of rules.
- Modes: `Off`, `Monitor` (dry-run: logs what it would block), `Active`. **Default after install: `Monitor`.**
  The Guardian page shows a Monitor report ("would have blocked N IPs in 24 h") with a one-click switch to Active.
- Expiry task removes blocks on TTL; on agent start, **reconcile** firewall state with `pw-store`.

### 6.4 Firewall (`pw-firewall`)
- COM `INetFwPolicy2` via `windows` crate. Never `netsh`.
- `trait Firewall { list, add_rule, remove_rule, set_enabled, block_ips(batch), unblock_ips }`.
- Manual rules: full CRUD on user rules; PacketWard-created rules carry group `PacketWard`.
- Auto-blocks are **batched**: a handful of rules (`PW-AutoBlock-001…`) each holding many remote addresses,
  instead of one rule per IP. Updates rewrite the batch's address list.
- Read-only view of non-PacketWard rules with a clear warning before editing them.
- Uninstall / `pwctl firewall purge` removes everything in group `PacketWard`.

### 6.5 Netstat (`pw-netstat`)
- `GetExtendedTcpTable` / `GetExtendedUdpTable` (IPv4+IPv6, with owning PID → process name).
- `GetAdaptersAddresses`, `GetIfTable2` for adapters and byte/packet counters (bandwidth without capture).
- Active RDP sessions and client IPs (WTS API).
- Connections-per-remote-IP aggregation feeds `ConnFlood` when no capture backend is running.

### 6.6 Diagnostics (`pw-diag`)
- **Ping**: `IcmpSendEcho2Ex` / `Icmp6SendEcho2` (no raw socket needed).
- **MTR simple**: ICMP with incremental TTL via ICMP API, N cycles, per hop: loss %, sent, last/avg/best/worst,
  stdev, jitter, rDNS. Streams progress per cycle.
- **MTR advanced**: protocol choice (ICMP / UDP / TCP SYN to a port — TCP/UDP require a capture backend to read
  replies), packet size, interval, max hops, ASN + country per hop, IPv4/IPv6, and **"Copy report for support"**
  (plain-text table + timestamp + source public IP).
- **DNS lookup**: A, AAAA, MX, TXT, NS, SOA, CNAME, PTR, ALL; choose resolver (system, 1.1.1.1, 8.8.8.8, custom).
- **Port check**: local listening ports (with process) + remote TCP connect test. UDP checks are best-effort and
  labeled "inconclusive" when there is no reply.
- **Speed test client**: download/upload/latency/jitter against XeroHost nodes (default list, JSON fetched from
  XeroHost and cached) plus **user-defined custom servers** running `tools/speed-server`. Parallel streams (default 4–8), warm-up period excluded, data sent to a sink (never to disk).
  **Bin tests 1 GB / 10 GB / 50 GB**: download of a fixed size with progress, avg/peak Mbps and duration; 50 GB
  requires an explicit confirmation (bandwidth/time warning). All tests cancellable.

### 6.7 Speed server (`tools/speed-server`)
axum service deployable on XeroHost nodes (Miami, Brazil, …):
`GET /ping`, `GET /download?bytes=N` (streams generated data, no files on disk), `POST /upload` (discards, returns
bytes/time), `GET /info` (location, node name, max size). Rate limits and max concurrent tests per IP.

### 6.8 Intel (`pw-intel`)
- GeoIP/ASN from DB-IP Lite `.mmdb` (bundled at release, monthly update check). Attribution in About.
- AbuseIPDB `check` endpoint only if the user stored a key; results cached in SQLite (default 24 h); respect
  rate limits; show "not configured" state otherwise. Optional "report IP" action, always manual.
- **Blocklists** (`pw-intel::blocklist`), each with enable toggle, refresh interval and last-update status:
  - **XeroHost shared list** — public repo `XeroHost/packetward-blocklist` (`blocklist.txt` + `blocklist.txt.minisig`),
    fetched from the raw GitHub URL; rejected unless the signature verifies against the public key compiled
    into the app. Enabled by default only after the user confirms on first run.
  - **Public lists** (opt-in, e.g. Spamhaus DROP, FireHOL level 1) — downloaded at runtime, never bundled.
  - Parsed into CIDR sets, de-duplicated, minus the Guardian protected set, applied as batched firewall rules
    in their own rule names (`PW-List-<name>-NNN`) so they can be toggled independently of auto-blocks.

### 6.9 Store and logs (`pw-store`)
- SQLite at `%ProgramData%\PacketWard\packetward.db`.
- Tables: `audit_events`, `blocks`, `rules_meta`, `settings`, `intel_cache`, `alerts`. Retention policy
  (default 30 days) with periodic pruning.
- Text logs via `tracing-appender` daily rotation in `%ProgramData%\PacketWard\logs`.
- Audit event categories: network, capture, detection, guardian, firewall, settings, update.

### 6.10 Support bundle
`pwctl support-bundle` / UI button → zip with: 60 s pcapng (configurable), stats summary (top talkers, protocols,
countries, alerts), MTR to the chosen XeroHost node, adapter info, firewall rule summary, last 24 h audit log,
app/OS versions. **Preview before saving**, with an option to anonymize local IPs. Saved **locally only**
(default `Documents\PacketWard\support\`); the app never uploads it — the user attaches it to their ticket.

### 6.11 Notifications and tray
- The agent publishes alerts on the `alerts` topic; the desktop process (running in the user's session, started
  at logon via autostart, minimized to tray) turns them into Windows toast notifications.
- Tray icon states: neutral (Guardian off), amber (Monitor), crimson (Active), crimson blinking (blocking now;
  static when reduce motion is on). Tray menu: Open, Guardian mode, Pause notifications 1 h, Quit UI.
- Per-severity mute and quiet hours in Settings. If no user is logged in, alerts are only stored in the audit log.
- No webhooks or email in v1.

### 6.12 Branding
Discreet XeroHost presence: "by XeroHost" in the sidebar footer and About, a "Contact XeroHost support" link
(opens xerohost.net), XeroHost speed-test nodes and shared blocklist as defaults. No plan promotion or upsell.

## 7. IPC protocol (`pw-ipc` + `pw-proto`)
- Transport: Windows named pipe `\\.\pipe\packetward`, security descriptor granting SYSTEM and
  BUILTIN\Administrators only. An in-memory transport exists for tests only.
- Framing: 4-byte little-endian length + JSON (`serde_json`). Max frame 4 MB.
- Envelope: `{ v: 1, id?: u64, kind: "req" | "res" | "event" | "err", method|topic, payload }`.
- Request/response: `capture.start`, `firewall.list`, `guardian.setMode`, `diag.mtr.start`, …
- Server push via subscriptions: `live.stats`, `alerts`, `capture.progress`, `diag.progress`, `guardian.blocks`.
- Version handshake on connect; desktop shows "agent outdated" if major versions differ.
- Desktop bridge: `src-tauri` exposes typed Tauri commands and forwards subscriptions to the webview using
  `tauri::ipc::Channel` (one channel per subscription).

## 8. Security model
- Only the agent is privileged. The pipe ACL is the authorization boundary.
- Input validation in the engine for every IPC request (IP/CIDR parsing, port ranges, size limits, file paths
  restricted to the PacketWard data/export folders).
- Tauri: strict CSP, no remote content, capabilities limited to what the UI uses, no shell plugin.
- Secrets in Credential Manager. Logs never contain API keys or full packet payloads.
- Releases: signed updater artifacts (Tauri updater keypair), Authenticode signing of exe/installer when a
  certificate is available, `cargo deny` + `cargo audit` + SBOM in CI.

## 9. Packaging and updates
- Tauri bundler, **NSIS** installer with hooks to install/start/stop/remove the agent service
  (`packetward-agent.exe install|uninstall`) and purge the `PacketWard` firewall group on uninstall.
- WebView2: use an embedded bootstrapper or offline installer mode — many Windows Server images do not ship it.
- `tauri-plugin-updater` against GitHub Releases with **two channels**: `stable` (tags `vX.Y.Z`) and `beta`
  (tags `vX.Y.Z-beta.N`), each with its own `latest.json` endpoint; channel chosen in Settings.
  The update installer also updates the service.
- Code signing: no certificate yet. Releases start unsigned (README documents the SmartScreen prompt); the CI
  release job has an Authenticode step that runs only when signing secrets are configured.
- Npcap: not bundled; first-run screen explains benefits and links to npcap.com.
- Installer also registers UI autostart at user logon (tray).

## 10. Configuration
**Agent config** — `%ProgramData%\PacketWard\config.toml`, edited through the UI/CLI, validated by `pw-core`:
capture interface + backend, tick interval, retention, guardian mode (default Monitor)/rules/allowlist/management
ranges, blocklists (enabled, refresh interval), speed-test server list URL + custom servers, proxy
(HTTP/HTTPS/SOCKS5, applies to all outbound HTTP), update channel.

**UI preferences** — per user, `%AppData%\PacketWard\ui.json` (owned by the desktop app, not the agent):
language (auto: `es-*`→es, `pt-*`→pt-BR, else en; or manual), Appearance (theme dark/light/system, mono font,
density, text size, reduce motion), notification mutes/quiet hours.

## 11. Testing strategy
- `pw-detect`, `pw-core`, `pw-proto`, `pw-ipc` (in-memory), `pw-engine` (with fakes): unit + property tests on Linux CI.
- Fakes for `CaptureBackend`, `Firewall`, `NetStat`, `Clock`. Guardian safety rules have dedicated tests
  (RDP client IP never blocked, circuit breaker, TTL expiry, reconcile after restart).
- Windows CI (`windows-latest`): build everything, run Windows-impl tests that do not need admin.
- Manual test checklist for privileged paths in `docs/TESTING.md` (created in M1).
- Frontend: Vitest for stores/utils, component tests for critical views.

## 12. Decisions log (short ADRs)
1. **Tauri 2 over Electron** — smaller footprint on 1–2 GB RAM VPS, Rust end to end.
2. **Required service agent, no portable mode** — protection must outlive RDP sessions and UI; UI runs
   unelevated; one code path to test.
3. **Npcap optional + raw-socket fallback** — license forbids bundling; app must work out of the box.
4. **COM firewall API, batched rules** — no `netsh` parsing, no rule explosion.
5. **Aggregates over IPC, never per-packet** — WebView and IPC are not packet-rate systems.
6. **DB-IP Lite** — redistributable GeoIP with attribution.
7. **GPL-3.0-or-later** — forks must stay open.
8. **Signed shared blocklist on GitHub** — free hosting, public audit trail, tamper-evident via minisign.
9. **Toasts from the UI process** — services in session 0 cannot notify; the tray app is the notifier.

See `docs/DECISIONS.md` for the full list of product decisions.
