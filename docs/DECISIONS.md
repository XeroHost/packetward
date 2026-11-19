# PacketWard — Product decisions (from the founder interview, 2026-11-18)

These are settled. Do not re-open them in code; if one blocks you, ask.

| Topic | Decision |
|---|---|
| License | **GPL-3.0-or-later**. All dependencies must be GPLv3-compatible (MIT, Apache-2.0, BSD, ISC, Zlib, MPL-2.0, Unicode, OFL for fonts). |
| Minimum OS | **Windows Server 2019+ / Windows 10 1809+**, x64. |
| Run model | **Agent service + desktop UI only. No portable mode.** The UI requires the agent service; if it is missing or stopped, the UI shows a screen to start/repair it. |
| Branding | **Discreet**: "by XeroHost" in sidebar footer and About, a "Contact XeroHost support" link, XeroHost speed-test nodes as defaults. No upsell or plan promotion in the app. Useful to anyone, not only XeroHost customers. |
| Guardian default | **Monitor** (dry-run) after install. User switches to Active explicitly. |
| Support bundle | **Local zip only.** Never uploaded. The user attaches it to their ticket. |
| Speed test servers | **XeroHost nodes (Miami, Brazil, …) + user-defined custom servers.** `tools/speed-server` is deployed by XeroHost. |
| Threat intel v1 | GeoIP + ASN offline (DB-IP Lite) · AbuseIPDB (user's own key) · public blocklists (opt-in, downloaded at runtime) · **XeroHost shared blocklist** from a public GitHub repo, signature-verified. |
| Shared blocklist source | Public repo `XeroHost/packetward-blocklist`: plain-text CIDR list + minisign signature, fetched via raw GitHub URL. Public key pinned in the app. |
| Languages | **English is the base and fallback.** Auto-detect system locale: `es-*` → Spanish, `pt-*` → Portuguese (BR), anything else → English. User can override in Settings. |
| Fonts | Headings **Bricolage Grotesque**, body **Geist Sans**, mono **configurable** (default **JetBrains Mono**; options Geist Mono, System mono/Consolas). |
| Settings → Appearance | Theme (Dark default / Light / System), mono font, density (Comfortable / Compact), text size (90 / 100 / 110 / 125 %), reduce motion. |
| Palette | **Crimson Sentinel** (see DESIGN.md). |
| Code signing | Not available yet. Releases start unsigned (SmartScreen warning documented in README); CI has an optional signing step that activates when secrets exist. |
| Repo docs language | English. |
| Alerts | **Windows toast notifications + tray icon** (color/state changes). No webhooks/email in v1. |
| CLI | **Basic `pwctl` in v1**: `status`, `guardian off|monitor|active`, `unblock --all`, `firewall purge`, `support-bundle`. |
| UI kit | **shadcn-vue** (components copied into the repo, on Reka UI + Tailwind v4). |
| Update channels | **Stable + Beta**, selectable in Settings. |
| RDP Shield (2026-11-19) | New milestone **M7b**: audit + live monitor + Guardian blocks + recommendations, **plus configurable actions** (restrict RDP to trusted IPs/CIDRs, attempt limit per IP, change port, force NLA, optional account lockout off by default). Every action is a transaction confirmed within 120 s (configurable) or **reverted by the agent**; previous state stored; trusted-logon IPs always allowed; `pwctl rdp reset`; UI mentions the provider's VNC console. Optional country restriction (off by default). See ARCHITECTURE §6.13. |
| XeroHost nodes (2026-11-19) | Miami, Dallas, São Paulo (Ashburn soon). `nodes.json` lives in the public repo `XeroHost/packetward-blocklist`, read from its raw GitHub URL. **Hostnames do not exist yet: shipped as placeholders; an empty list works with custom servers. Never invent hostnames.** |
| Report source IP | Asked from the speed-server `/info` of a XeroHost node (no third party); omitted when no node is available. |
| Captures | Headers only (first 128 bytes per packet) by default; full payload is an explicit option with a warning. |
| Support bundle | "Anonymize local IPs" **on** by default; remote IPs kept. |
| Notifications | Toasts for **critical and high** only by default; quiet hours off. |
| Guardian Active | Allowed after a confirmation dialog stating the consequences and showing the Monitor report; no minimum Monitor time. |
| Windows Firewall | PacketWard never turns it off; only rules. Deleting/disabling the rule that allows RDP needs a typed confirmation. |
| Blocklist signing key | Real minisign public key not available yet: a test key is used only in tests; the production key is a placeholder and the XeroHost list stays **disabled (fail closed)** until it is set. |
| Release keys | Keys are **not** generated on the dev VPS. Everything is prepared with placeholders; `docs/RELEASE-KEYS.md` gives the steps to generate the Tauri updater key and the blocklist minisign key on the owner's PC and load them with `gh secret set`. |
| WebView2 | Installer uses the **embedded bootstrapper**. |
| Security contact | GitHub private vulnerability reporting; email is a placeholder until provided. |

## Autonomous decisions — review
Decisions taken during the unattended run (no questions asked): the safest option was chosen, applied and recorded
here with its reason. Review them when you are back.

| Date | Milestone | Decision | Reason |
|---|---|---|---|
| 2026-11-19 | setup | Work on branch `dev`; CI runs on pushes to `main` and `dev` | `main` must stay untouched during the run |
| Guardian: which RDP clients are protected (2026-11-19) | **Addresses with a successful RDP logon in the last 30 days** (configurable, 1–365): Security 4624 type 10 or 7 (remote address only) and TerminalServices 1149. Not "connected now", not `WTSClientAddress`, not every peer of the RDP port. Learned with `EvtSubscribe` plus one bounded initial load, never by searching the log. If the "Audit Logon" policy (success/failure) is off, the UI and `pwctl status` warn, because without those events neither the protection nor RdpBruteForce work. See ARCHITECTURE §6.3. |
| 2026-11-19 | M3 | Port checks and diagnostics are plain agent methods reachable from the webview only through `agent_call` with a method allowlist; MTR report omits the source public IP until a XeroHost node reports it (M9) | Smallest surface for a compromised webview; never invent data |
| 2026-11-19 | M4 | `pw-capture` talks to Npcap through a hand-written `libloading` FFI instead of the `pcap` crate | Nothing links Npcap, no SDK needed, absolute-path DLL load (no PATH/cwd search) |
| 2026-11-19 | M4 | RawSocket backend uses `RCVALL_IPLEVEL` (no promiscuous mode) | Least intrusive on the NIC |
| 2026-11-19 | M5 | `pw-detect` takes time as u64 ns since the Unix epoch (same clock as `PacketMeta`), not `Instant` | Deterministic tests and one clock for capture and detection; ARCHITECTURE §6.2 to be updated at M5 integration |
| 2026-11-19 | M4 | The live capture starts with the agent (`capture_autostart`) and can be stopped from the Capture page | It is passive and bounded (drops are counted); the traffic page and detectors need it |
| 2026-11-19 | M4 | Detection must not depend on capture alone: the RawSocket backend is inbound-blind on the dev VPS | Feed pw-detect also from netstat counts, adapter bps and the 4625 feed; show a "blind" warning |
| 2026-11-19 | M4 | An inbound allow rule for the agent exe is needed for raw-socket delivery (hypothesis, untested here) | Firewall changes are prohibited on the dev VPS: documented in TESTING §F4 and to be added by the installer (M11) in group `PacketWard` |
| 2026-11-19 | M4 | Support bundle is delivered to the client in chunks and saved by the client in its own Documents folder; with anonymization on, the pcapng is left out | Operators may not be administrators; a pcapng cannot be anonymized; the agent must never write to client-supplied paths |
| 2026-11-19 | M4 | Support bundle runs `ipconfig /all` and `route print` | The documented exception for read-only diagnostics; support always asks for them |
| 2026-11-19 | M5 | Alerts are persisted as JSON lines (`alerts.jsonl`, 500 kept in memory, rotated at 10 MB) instead of SQLite | `pw-store` does not exist yet; the file is enough for the inbox and is replaced when the store lands (M11 logs) |
| 2026-11-19 | M5 | Failed-logon detection counts LogonType 3, 7 and 10 with a remote address | RDP with NLA logs failures as type 3; this also covers other network password guessing, which is the same attack |
| 2026-11-19 | M5 | Toasts only for critical + high by default, no quiet hours; tray badge neutral/warning/alert | Decision M5-1=A; monitor/active/blocking tray states need the Guardian (M7) |
| 2026-11-19 | M6/M7 | The agent restricts `%ProgramData%\PacketWard` to SYSTEM and Administrators at start, before reading any state; engine tests and `Engine::new` use an in-memory firewall, only `Engine::with_system_firewall` (the agent) touches the real one | A writable state folder would let a non-admin plant `defense.json` (Active mode, allowlist). Residual risk: a state file owned by a non-admin before the first protected start is not detected |
| 2026-11-19 | M7 | The Guardian acts once per incident (ids already decided are ignored when the incident escalates; below-threshold or failed attempts may act later); RdpBruteForce qualifies from Medium while other detectors need High | One incident must not climb the TTL ladder or the circuit breaker twice; password guessing is the attack automatic blocking exists for (a live bot on the dev VPS raised a Medium alert) |
| 2026-11-19 | M7 | Blocks wider than /8 (IPv4) or /16 (IPv6) are not supported (`allow_broad` is refused) | Reconcile rebuilds blocks from state; a broad block would be dropped by the guard on the next pass |
| 2026-11-19 | M7b | One RDP change may wait for confirmation at a time; the revert plan is saved before the timer starts; the factory baseline is written once | Predictable recovery after any failure or restart |
| 2026-11-19 | M7b | `rdp_new_logon` is a Medium alert (no Windows toast by default); it fires only after the event-log history has loaded | Legitimate users on new networks should not be nagged; the initial load must not alert on old logons |
| 2026-11-19 | M7b | The country restriction is not implemented yet | It needs the GeoIP integration (M8); it stays off by default and never applies to trusted addresses |
| 2026-11-19 | M8 | Blocklists are applied through the Guardian's protected set and re-applied every pass; a list is cleaned (private ranges, too-broad blocks dropped) before it reaches the firewall; failed refresh keeps the last good list | A hostile or broken list must never cut the gateway, DNS, RDP clients or the allowlist, nor wipe the firewall |
| 2026-11-19 | M8 | Switching a list on needs an explicit confirmation in the UI; every list is off by default; the XeroHost list is fail-closed until a minisign key is pinned | Lists add real firewall rules; there is no key yet and none may be generated on this VPS |
| 2026-11-19 | M8 | GeoIP update is manual (button), no scheduled check; the attack map and IP drawer are not built; country restriction of RDP Shield is not built | Time: leaderboard + local lookups cover the "from where" question; recorded as not done in ROADMAP/PROGRESS |
| 2026-11-19 | M8 | Intel state (lists, enable flags, schedule) is stored in `%ProgramData%\PacketWard\intel\` files, not SQLite | `pw-store` is not wired into the engine yet (see PROGRESS) |
| 2026-11-19 | M9 | Speed nodes come only from `nodes.json` of the blocklist repo or from the user; no node hostname is invented; `http://` accepted only for custom servers | The node list is XeroHost's to publish |
| 2026-11-19 | M5 | SynFlood is suppressed for a source that is also port-scanning unless its SYN rate is ≥ 10× threshold | One scan = one alert |
