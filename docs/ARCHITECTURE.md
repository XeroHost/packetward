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
│  └─ IPC server on \\.\pipe\packetward  (ACL: SYSTEM + Administrators   │
│                     + "PacketWard Operators", see §7/§8)                │
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
- Agent subcommands: `run [--console]` (service entry point / dev), `install`, `uninstall`, `start`, `stop`
  and `repair`. `install`/`repair` also create the local group `PacketWard Operators` and add a user to it
  (`--operator-sid`, default the invoking user); `uninstall` removes the service and the group. The desktop's
  Start/Repair buttons run `start`/`repair` elevated (UAC) from the agent executable next to the app.

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
│  ├─ pw-ipc/       # transport (named pipe + in-memory), framing, client/server, subscriptions,
│  │                #   pipe ACL, operators group and service-state helpers (Windows)
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

Dependency direction (no cycles): `proto, core` ← `detect` ← `capture, netstat, firewall, diag, intel, store`;
`proto` ← `ipc` ← `engine` ← `apps/agent`. `pw-ipc` defines the `Handler` trait and `pw-engine` implements it, so
the desktop's `src-tauri` and `pwctl` depend only on `pw-proto` + `pw-ipc` and never pull in the engine.
(Earlier drafts had `engine` ← `ipc`; that would have linked the whole engine into every client.)
`src-tauri` also uses the `windows` crate directly for the elevated launch (`ShellExecuteExW` with `runas`); the
service-state and group checks live in `pw-ipc`.

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
| Charts (UI) | `echarts` + `vue-echarts` (tree-shaken imports) |
| Tables (UI) | `@tanstack/vue-table` + `@tanstack/vue-virtual` |
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

**Integration (M4).** `pw-engine::capture::CaptureManager` owns the live capture (one `pw_capture::Capture` thread, a bounded
batch queue, a `StatsAggregator` ticked once per second) and publishes `CaptureLive` on the `capture.stats` topic. It is
generic over a `CaptureHost` (the real machine or a fake), which is how it is tested without a network. The agent starts it
at launch (`EngineConfig::capture_autostart`); an optional `PacketSink` receives every batch (the detection engine, M5).
**Blind detection**: when the backend sees outbound packets but inbound stays at zero for 10 s the status says `blind`
(the raw socket can be starved by Windows Firewall inbound filtering; detection must not depend on capture alone).
Recordings (`capture.record.*`) open a second source on the same adapter, write `.pcapng` into
`%ProgramData%\PacketWard\captures` (SYSTEM + Administrators only, protected DACL), keep headers only (128 bytes) unless the
user confirms full payload, one recording at a time, files older than 7 days are deleted. `pw-capture` talks to Npcap through a
hand-written `libloading` binding (absolute path to `System32\Npcap\wpcap.dll`), not the `pcap` crate.
Default adapter: the first one that is up, not loopback and has a routable IPv4 address.

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

**Integration (M5).** `pw-engine::detect::DetectionService` owns one `pw_detect::Engine` and ticks it every second (wall-clock
nanoseconds since the Unix epoch, the same clock as `PacketMeta`; `pw-detect` takes `now_ns: u64`, not `Instant`). Inputs that exist
without capture: **netstat** (per-remote concurrent and new TCP connections → ConnFlood), the **adapter counters** (inbound bps and link
speed → Aggregate) and the **failed-logon feed** (Security 4625, LogonType 3/7/10 from a remote address → RdpBruteForce; subscribed
live, no history). **Capture** (when the backend actually sees inbound packets) adds the SYN/UDP/ICMP flood and scan detectors through
the capture `PacketSink`. The protected set (trusted RDP clients) only sets the alert's `protected` flag: alerts are always raised and
nothing is blocked here. `AlertStore` keeps the 500 most recent incidents (one per id, merged across started/escalated/ended, peak
severity kept), appends every change to `%ProgramData%\PacketWard\alerts.jsonl` (rotated at 10 MB; reloaded at start, incidents that were
running are shown as ended) and pushes them on the `alerts` topic; `alerts.list` / `alerts.clear` (removes ended incidents). The
desktop app turns them into the inbox, the unread badge, the tray badge and Windows notifications (severities chosen in Settings; default
critical + high).

### 6.3 Guardian / auto-blocker (`pw-engine::guardian`)
- Policy = list of rules: `detector + threshold + window → action (Alert | Block { ttl })`.
- Escalation: repeat offenders get TTL × 2 up to a max (e.g. 15 min → 30 → 60 … → 24 h).
- **Protected set** (never blocked, checked before every block): allowlist IPs/CIDRs, **trusted RDP clients**
  (below), default gateways, DNS servers, loopback/link-local, configured management ranges, speed-test servers.
- **Trusted RDP clients = addresses with a successful RDP logon in the last N days** (N = 30, configurable
  `1..=365`), *not* only the ones connected now. Rationale: a legitimate user who mistypes the password when
  reconnecting must not lock themselves out, while a bot that merely connects to the RDP port, or only fails to
  sign in, never earns protection (measured on the dev VPS: the peers of port 3389 included addresses from the
  top failed-logon list, and `WTSClientAddress` is only what the client reports about itself).
  - Counted events: Security **4624** with `LogonType` 10 (new RDP session) **or 7** (an RDP *reconnect*; a type 7
    without a remote address is a console unlock and is ignored), and TerminalServices-RemoteConnectionManager
    **1149** (authentication succeeded). Failed logons (4625) never count.
  - **No long searches.** The agent subscribes with `EvtSubscribe` (future events) and does one *bounded* initial
    load of recent history (newest first, XPath time filter, at most 5000 events and 10 s); the subscription is
    opened first so nothing is missed in between. Implemented in `pw-netstat` (`sys/eventlog.rs`, parser and
    `TrustSet` are pure and tested on Linux) and published by the engine in `live.stats.rdp_trust`.
  - **Audit policy check.** The agent reads the "Audit Logon" subcategory (`AuditQuerySystemPolicy`, success and
    failure). Without success events no logon can be learned; without failure events `RdpBruteForce` cannot work.
    When either is off (or cannot be read) the UI shows a banner on every page and `pwctl status` prints a warning
    with the fix (`auditpol /set /subcategory:"Logon" /success:enable /failure:enable`). PacketWard does not change
    the audit policy itself.
  - **Limitation to close in M-store:** the Security log can be much shorter than 30 days (the dev VPS only reached
    back two days, flooded by brute force) and a clean install knows nothing yet. The learned set must be persisted
    in `pw-store` and merged on start so trust survives log rollover; until then the protection is only as old as the
    log. While the set is empty (or the feed is `unavailable`) the Guardian must stay in Monitor behaviour for RDP
    rules rather than guess.
  - IPv6 clients are handled when the event reports them; `WTSClientAddress` is informational only.
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
- `GetIfTable2` for adapters and byte/packet counters (bandwidth without capture) and `GetIpForwardTable2` for
  which interface carries a default route. Windows lists several rows per NIC (filter/QoS layers repeat the
  adapter's counters, loopback, tunnels), so totals only sum **real adapters**: up, not a filter layer, Ethernet or
  Wi-Fi, and either a hardware NIC with a connector or the holder of a default route (virtio NICs are not always
  flagged as hardware). VPN/tunnel adapters (WireGuard, ZeroTier, Radmin, TAP...) are never summed but are listed
  when they carry traffic.
- Active RDP sessions (WTS API) and the **established TCP peers of the RDP port** (port read from the registry,
  default 3389), reported as `rdp_peers`. Two different things, neither alone identifies "the current RDP client":
  `WTSClientAddress` is what the client reports about itself (NAT, VPN, overlay networks) and differed from the TCP
  peer on a live session; and a TCP peer on the RDP port may be a brute-force bot sitting in NLA before any logon.
  The UI labels peers as "connected to the RDP port", not as the legitimate client.
  **Decision (2026-11-19):** the Guardian protects addresses with a successful RDP logon in the last N days; see §6.3 and DECISIONS.md.
- Table buffers are parsed from raw bytes with explicit offsets (no unsafe, tested on Linux). Process names are
  cached by PID + creation time to survive PID reuse.
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

**Integration (M3).** `pw-engine::Diag<P: Pinger>` owns the jobs: `diag.ping.start` / `diag.mtr.start` return a job id
and stream `DiagEvent`s (ping reply, MTR snapshot per cycle, done, failed) on the `diag.progress` topic (every
subscriber sees every job; the client filters by id). At most 4 jobs run at once (`ErrorCode::Busy` beyond that);
`diag.cancel` is idempotent; the last MTR snapshot of a job is kept (16 finished jobs) so `diag.mtr.report` can
render the support report. `diag.dns.lookup`, `diag.port.check` (rate-limited by pw-diag's limiter) and `diag.ports.local` (listening sockets taken from the latest netstat
snapshot, nothing is probed) are plain request/response. The desktop shell exposes them through a single
`agent_call` Tauri command with a method **allowlist** (`CALLABLE_METHODS` in `bridge.rs`) and forwards
`diag.progress` as `BridgeEvent::Diag`. The source public IP line of the report is omitted until a XeroHost node
reports it (M9). Protocol minor is 3.

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

**Integration (M4).** `support.bundle.preview|create|read|discard` (engine `support.rs`): the text files are built in memory
(summary, traffic, adapters, capture backend, last-24 h agent log tails, `ipconfig /all` + `route print` — the only commands the
project runs, read-only), optionally anonymized (this machine's addresses and name → `LOCAL-IPV4-n`/`HOSTNAME`, whole tokens
only; the pcapng is then left out because it cannot be anonymized), previewed, then zipped. The agent keeps the zip in
`%ProgramData%\PacketWard\support` (admin-only, deleted after 1 h) and the client reads it in 256 KiB base64 chunks and writes it to
`Documents\PacketWard\support` with its own permissions (so non-admin operators can save it; no path is ever supplied by the
client). `pwctl support-bundle` and the desktop command `support_bundle_save` do exactly that. Nothing is uploaded.

### 6.11 Notifications and tray
- The agent publishes alerts on the `alerts` topic; the desktop process (running in the user's session, started
  at logon via autostart, minimized to tray) turns them into Windows toast notifications.
- Tray icon states: neutral (Guardian off), amber (Monitor), crimson (Active), crimson blinking (blocking now;
  static when reduce motion is on). Tray menu: Open, Guardian mode, Pause notifications 1 h, Quit UI.
- Per-severity mute and quiet hours in Settings. If no user is logged in, alerts are only stored in the audit log.
- No webhooks or email in v1.

### 6.13 RDP Shield (`pw-engine::rdp_shield`, UI page "RDP Shield", milestone M7b)
Dedicated protection for the one service most VPS owners expose. Built on detection (M5), the firewall (M6),
the Guardian (M7) and the trusted-RDP-client set (§6.3).

**Read-only parts**
- *Exposure audit*: RDP enabled (`fDenyTSConnections`), port (`PortNumber`), NLA (`UserAuthentication`), security
  layer / TLS, account-lockout policy (`NetUserModalsGet`), members of `Remote Desktop Users`, and the scope of the
  inbound firewall rules that allow the RDP port (open to any address or restricted). Each finding has a severity
  and a plain-language recommendation with copyable manual steps.
- *Live monitor*: failed and successful logons per source IP (Security 4625 / 4624 / 1149 via the event feed),
  timeline, sessions, the trusted set and its audit-policy warnings.
- *Sessions*: list with **disconnect** and **log off** (`WTSDisconnectSession` / `WTSLogoffSession`), each confirmed.
- *Notification* when a successful logon comes from an address never seen before.

**Configurable actions** (each one is a transaction, see below)
1. **Restrict RDP to trusted addresses/CIDRs**: PacketWard-owned rules (group `PacketWard`) allow the RDP port only
   from the configured list. The built-in "Remote Desktop" rules are disabled **only while the restriction is
   active** and restored when it is turned off or reverted.
2. **Attempt limit per IP**: threshold, window, TTL and escalation, enforced through the Guardian (Monitor by default).
3. **Change the RDP port**: `PortNumber` + firewall rules + restart of `TermService`.
4. **Force NLA**: `UserAuthentication = 1`.
5. **Windows account lockout** (optional, **off by default**): warns that an attacker can lock a legitimate account on
   purpose (a denial of service), which is why PacketWard prefers blocking the source address.

**Safety framework (mandatory for every action)**
- A transaction stores the **previous state** (registry values, rule ids/enabled flags) in `pw-store` before changing
  anything, applies the change, and starts a **confirmation timer** (120 s, configurable). The UI asks the user to
  confirm from a **new connection**; without confirmation the **agent itself reverts** the change (the UI may be
  unreachable precisely because the change cut the connection). Pending transactions survive an agent restart: on
  start, any transaction past its deadline is reverted before anything else.
- The addresses with a successful RDP logon (including the current client) are **always** in the allow-list of a
  restriction and can never be blocked by the attempt limit.
- Actions that need a tool the agent cannot verify (port change when the new port is not reachable from the
  client's address) are refused or require the explicit "I understand" confirmation.
- `pwctl rdp reset` restores RDP to factory state: port 3389, built-in rules enabled, no PacketWard restrictions
  or blocks, NLA unchanged. The UI names the provider's **VNC/console** as the recovery path if RDP is lost.
- All of it is covered by fakes and tests; live runs are documented in `docs/TESTING.md` for a **test VPS** only.

### 6.12 Branding
Discreet XeroHost presence: "by XeroHost" in the sidebar footer and About, a "Contact XeroHost support" link
(opens xerohost.net), XeroHost speed-test nodes and shared blocklist as defaults. No plan promotion or upsell.

## 7. IPC protocol (`pw-ipc` + `pw-proto`)
- Transport: Windows named pipe `\\.\pipe\packetward`. The DACL is protected and grants:
  - **SYSTEM** and **BUILTIN\Administrators**: full control;
  - **`PacketWard Operators`** (local group created by the installer / `repair`): only `FILE_READ_DATA |
    FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE` (`0x120083`);
  - nobody else.

  Why the group: the desktop runs **unelevated**, and under UAC an unelevated administrator carries Administrators
  as a *deny-only* SID, so an Administrators-only ACE would lock the app out. Group membership is not filtered by
  UAC. The group ACE must **not** include `FILE_CREATE_PIPE_INSTANCE` (`FILE_APPEND_DATA`, part of `GENERIC_WRITE`):
  that would let a member stand up a second server on the same name and answer clients in place of the agent.
  Clients therefore open the pipe with the exact mask above (not `GENERIC_READ|GENERIC_WRITE`) and
  `SECURITY_IDENTIFICATION`, so a rogue server cannot impersonate them.
  The server creates the first instance with `FILE_FLAG_FIRST_PIPE_INSTANCE` (nobody can squat the name) and
  rejects remote clients. An in-memory transport exists for tests only.
- Windows applies group membership when a logon token is created: after a user is added to the group they must
  **sign out and back in** (disconnecting/reconnecting RDP is not enough). `repair` prints this, and the desktop
  tells the user when it detects "member of the group, but not in this token" (`access_denied: sign_out_required`).
- Framing: 4-byte little-endian length + JSON (`serde_json`). Max frame 4 MB.
- Envelope: `{ v: 1, id?: u64, kind: "req" | "res" | "event" | "err", method|topic, payload }`.
- Request/response: `capture.start`, `firewall.list`, `guardian.setMode`, `diag.mtr.start`, …
- Server push via subscriptions: `live.stats`, `alerts`, `capture.progress`, `diag.progress`, `guardian.blocks`.
  One subscription per topic per connection (`subscribe` / `unsubscribe` requests). Client-side queues are bounded;
  a lagging consumer loses events and the loss is counted, never buffered without limit.
- Handshake: the first request on every connection must be `session.hello` (client kind and version, protocol
  major/minor). The agent always answers with its own versions; if the majors differ it then sends a
  `version_mismatch` error and closes. The desktop shows "agent outdated" or "app outdated" accordingly.
- Error codes: `bad_request`, `not_handshaken`, `version_mismatch`, `unknown_method`, `unknown_topic`,
  `frame_too_large` (the connection is closed because the stream cannot be re-aligned), `internal`.
- Surface: `session.hello`, `system.info`, `subscribe`/`unsubscribe`, `netstat.connections`; topics
  `live.heartbeat` and `live.stats` (1 s; per-interface and total bps/pps, link speed, connection counts by state,
  top remote addresses, RDP sessions and RDP peers). Protocol 1.1 added the last two items. `netstat.connections`
  returns at most 20 000 rows and is also cut by a byte budget so it always fits one frame, with `total` and
  `truncated`; counts and rankings are computed from the full table. Process names are sent once per PID.
  An agent older than the app answers `unknown_method`/`unknown_topic` and the UI says so.
- Desktop bridge: `src-tauri` runs one supervisor task per window that (re)connects to the pipe and sends the webview
  a single `tauri::ipc::Channel` stream of `BridgeEvent`s: connection status (`connected`, `not_installed`,
  `stopped`, `starting`, `access_denied` + reason, `agent_outdated`, `ui_outdated`, `error`) and, when connected,
  the agent's pushed events. Anything but `connected` makes the UI show the "agent unavailable" screen.
  The bridge types live in `pw-proto` so they are exported to TypeScript like the protocol.
  The shell also announces `window-visibility` (hidden to the tray, shown, minimized): WebView2 keeps reporting
  `document.visibilityState = "visible"` after `window.hide()`, so the UI combines both signals to stop drawing
  charts and polling the connection table for a window nobody sees.

## 8. Security model
- Only the agent is privileged. The pipe ACL is the authorization boundary: SYSTEM, Administrators and members of
  `PacketWard Operators` (limited rights, see §7). Membership of that group is therefore a security-relevant grant:
  an Operator can control the agent (Guardian mode, unblocking) though not become an administrator through it.
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
- Installer also registers UI autostart at user logon (tray), creates the `PacketWard Operators` group and adds the
  installing user (`packetward-agent install`), and tells that user to sign out and back in once.
- Autostart is toggled in Settings → Startup and registers `PacketWard.exe --minimized` under the Run key. The UI is
  meant to run unelevated, which registers it for the current user (HKCU). The autostart library writes to
  **HKLM** instead when the process is elevated, so only toggle it from an unelevated session.

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
