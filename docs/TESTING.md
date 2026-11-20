# PacketWard — Testing

Automated tests cover everything that does not need privileges (see ARCHITECTURE §11). This file is the
**manual checklist for the privileged paths**: the Windows service, the pipe ACL, UAC, the tray and autostart.
Run it on a Windows Server 2019+ / Windows 10+ machine, ideally a disposable VM: several steps install a service,
create a local group and write to the registry. Every step lists how to undo it.

## What the automated tests already prove

| Area | Where | Notes |
|---|---|---|
| Envelope / handshake / TS export | `pw-proto` | Wire format is pinned by tests; `ts-export` regenerates `apps/desktop/src/types/generated` and CI fails if it is stale. |
| Framing | `pw-ipc` `framing` | Partial reads, 0-length frame, 4 MB cap checked **before** allocating, truncated frames, bad JSON. |
| Client / server | `pw-ipc` `tests` (in-memory transport) | Handshake, version mismatch, requests before `hello`, concurrent requests, subscriptions, back-pressure drop-and-count, cleanup on disconnect. |
| Named pipe + ACL | `pw-ipc` `pipe` (Windows) | Real pipe; first-instance squatting refused; an **unelevated administrator** (Administrators "deny-only" in the token) is refused by an Administrators-only ACL but admitted by a group ACE; an unrelated SID is refused; an operator cannot create extra pipe instances; the real client connects with the narrow access mask. |
| Engine | `pw-engine` | `system.info`, heartbeat cadence (paused clock), per-subscription sequence. |
| Desktop stores / views | `apps/desktop` (Vitest) | Status reduction, stale-heartbeat detection, elevated-action outcomes, every "agent unavailable" state, i18n. |

The restricted-token tests need no second account: they simulate UAC by turning Administrators into a deny-only SID
on one thread.

## Prerequisites

- Elevated PowerShell for the install steps; an **unelevated** session of a user for the UI steps (see "Two users").
- Built binaries: `cargo build -p packetward-agent -p packetward-cli` and `pnpm tauri build --no-bundle`
  (or `pnpm tauri dev` from `apps/desktop`). Paths below use `target\debug`.
- No other program may be using `\\.\pipe\packetward`.

## 0. FIRST STEP on the test VPS: inbound capture with the raw-socket backend

Do this before anything else on the test VPS: the whole detection story depends on the agent seeing inbound packets. On the
development VPS the raw socket saw **outbound packets only** (hypothesis: Windows Firewall does not deliver inbound packets to a
raw socket of a program without an allow rule). The installer creates that rule; this step proves it. Never do it on the
development VPS (no firewall changes there).

**With the installer** (the real case):
1. Baseline, before installing: nothing to check yet. Install `PacketWard_x.y.z_x64-setup.exe` (elevated).
2. `Get-NetFirewallRule -Name 'PacketWard agent (raw capture)' | Format-List Name,Group,Enabled,Direction,Action` →
   `Group: PacketWard`, `Enabled: True`, `Direction: Inbound`, `Action: Allow`; and
   `(Get-NetFirewallRule -Name 'PacketWard agent (raw capture)' | Get-NetFirewallApplicationFilter).Program` is the installed
   `packetward-agent.exe`. It is ONE rule: `Get-NetFirewallRule -Group PacketWard` shows only it (the Guardian is in Monitor).
3. Generate inbound traffic from **another machine** (ping the VPS, `iperf3 -c <vps> -u -b 20M`, or an RDP session).
   `pwctl status` → the *Capture* line shows inbound **and** outbound packets, and **no** "sees outbound packets but no inbound ones"
   warning (it appears after ~10 s when blind). Dashboard → Traffic shows inbound rates and top sources.
4. **Control (proves the rule is what fixed it)**: `Disable-NetFirewallRule -Name 'PacketWard agent (raw capture)'`, restart the agent
   (`Restart-Service PacketWard`), repeat step 3 → the blind warning must come back after ~10 s (if inbound still shows with the
   rule disabled the hypothesis is wrong: record it). `Enable-NetFirewallRule …` and restart again → inbound is back.
5. Uninstall (or `pwctl firewall purge`) → `Get-NetFirewallRule -Group PacketWard` is empty.

**Development build on a test VPS** (no installer): `.\tools\dev\capture-rule.ps1 -Action Add -WhatIf` shows what it would create,
then `-Action Add` (elevated) creates the same rule for `target\debug\packetward-agent.exe`; `-Action Status` shows it;
`-Action Remove` deletes it. Then run `packetward-agent run --console` and repeat steps 3–4.

**Result to record in docs/PROGRESS.md**: Windows build (`winver`), rule on/off result, and — if inbound is still blind with the rule — the
fallback decision (NDIS ETW provider, ARCHITECTURE §6.2).

## A. Agent without installing (development)

1. Elevated: `target\debug\packetward-agent.exe run --console`.
2. Another shell: `target\debug\pwctl.exe status` → `Agent: running (console)`, version, protocol `1.0`; exit code `0`.
3. Ctrl-C the agent. `pwctl status` → `Agent not running`, exit code `2`.

Undo: nothing persists (logs go to `%ProgramData%\PacketWard\logs`; delete that folder to remove them).

## B. Service lifecycle

Elevated PowerShell:

| Step | Command | Expected |
|---|---|---|
| Install | `packetward-agent.exe install` | Creates the service and the group `PacketWard Operators`, adds you to it, starts the agent. Prints the **sign out and back in** notice. |
| Registered | `Get-Service PacketWard` | `Running`, start type `Automatic`. |
| Status | `pwctl.exe status` | `running (service)`; exit `0`. |
| Logs | `%ProgramData%\PacketWard\logs\agent.log.<date>` | Contains `agent started ... service_mode=true`. |
| Stop | `Stop-Service PacketWard` | `pwctl status` → exit `2`. |
| Start | `packetward-agent.exe start` | Running again. |
| Crash recovery | kill the agent process | The service restarts within ~5 s (failure actions). |
| Uninstall | `packetward-agent.exe uninstall` | Service and group removed; pipe gone. |

Undo everything: `packetward-agent.exe uninstall; Remove-Item -Recurse -Force $env:ProgramData\PacketWard`.
Manual fallback: `sc.exe stop PacketWard; sc.exe delete PacketWard; net localgroup "PacketWard Operators" /delete`.

## C. Pipe ACL

With the service running, read the live DACL (Windows PowerShell 5.1):

```powershell
$c = New-Object System.IO.Pipes.NamedPipeClientStream('.','packetward',[System.IO.Pipes.PipeDirection]::InOut)
$c.Connect(3000); $c.GetAccessControl().GetSecurityDescriptorSddlForm('Access'); $c.Dispose()
```

Expected: `D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120083;;;<SID of PacketWard Operators>)`. In particular the operators entry
must **not** include `CreateNewInstance` (`0x4`).

## D. Non-privileged users (needs a second, standard account)

Create a standard local user `pwtest` (not an administrator). Undo at the end: `net user pwtest /delete`.

1. Without adding it to the group, run `runas /user:pwtest "target\debug\pwctl.exe status"`
   → `Access to the agent was denied` and the hint that the account is not in `PacketWard Operators`; exit code `3`.
   **This is the "non-admin cannot open the pipe" acceptance check.**
2. As an administrator: `net localgroup "PacketWard Operators" pwtest /add`. While `pwtest` stays signed in,
   `pwctl status` still fails with the **sign out and back in** message (the token predates the group).
3. Sign `pwtest` out and in again → `pwctl status` works, and so does the desktop app, **unelevated**.
4. Remove `pwtest` from the group → after the next sign-in access is denied again.

## E. Desktop app

Run it **unelevated** as a user that is in the operators group (see D3).

1. Open PacketWard: Dashboard shows the agent card with a heartbeat counter that grows once per second, and the
   top-bar pill reads *Connected*.
2. `Stop-Service PacketWard` (elevated): within ~3 s the app switches to *The PacketWard agent is not running*
   with **Start agent** / **Repair installation**. (**Accept: stopping the service shows the repair screen.**)
3. Click **Start agent**: a UAC prompt appears (unless Admin Approval Mode is off); accept → the app returns to the
   dashboard on its own. Decline the prompt → a message says nothing changed.
4. `packetward-agent.exe uninstall`: the app shows *The PacketWard agent is not installed*. Click **Repair
   installation** → service and group are recreated, the invoking user is added, and the app connects or, if the
   token is stale, shows *Sign out of Windows and sign back in*.
5. Kill the agent process with Task Manager: the app shows the unavailable screen and reconnects after the service
   restarts.
6. Switch the language in Settings: the tray menu labels change too.

## F. Tray, single instance, autostart

1. Close the window with ✕: the process keeps running and the tray icon stays. Click the tray icon: the window
   returns. Tray menu → *Quit* ends the UI only; the service keeps running.
2. Launch `PacketWard.exe` a second time: no second window, the existing one comes to the front.
3. Settings → Startup → *Start with Windows* on, from an **unelevated** session: a `PacketWard` value appears in
   `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` with `--minimized`. Sign out and in: the app starts hidden in
   the tray. Switch it off: the value is gone.
   *Do not toggle this from an elevated session: the autostart library then writes to `HKLM`, which affects every
   user.* Undo: `Remove-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name PacketWard`.

## F2. Network data (M2)

With the agent running (console or service):

1. `pwctl status` prints traffic, connection counts and `RDP peers`. Compare with `netstat -ano`: totals and
   ESTABLISHED/LISTENING counts must match (a couple of rows of churn between the two reads is normal).
2. Dashboard: the *Established connections* tile and the hint (total / waiting to close) match `netstat -ano`.
3. **RDP clients**: connect over RDP from another machine. *Connected from* lists the address
   `netstat -ano | findstr :3389` shows as the peer, with the RDP badge in *Top remote addresses* and in
   Connections. The address under "client reports" may differ (NAT/VPN); that is expected.
4. **Bandwidth**: start a sustained download and compare. Use the OS byte counter as ground truth
   (`(Get-NetAdapterStatistics).ReceivedBytes` before/after) against the integral of the chart; compare with the
   Windows performance counter via `Get-CimInstance Win32_PerfFormattedData_Tcpip_NetworkInterface` (counter names
   are localized, the WMI class is not). Expect within ±10 % over a window of tens of seconds; second-by-second
   values of bursty traffic will not line up because the two samplers are not aligned.
5. **Adapters**: only real adapters say *Counted in the totals*. Filter layers (names ending in `-WFP...` /
   `-QoS Packet Scheduler`) must not appear; a VPN adapter with traffic appears as *Tunnel / VPN* and is not summed.
6. **Many connections**: open a few thousand loopback connections (a small script that holds N sockets) and open
   Connections: the summary says "Showing N of N", scrolling stays smooth, sort and filter respond. The table keeps
   one request in flight and refreshes every 2 s only while the window is visible.
7. **Hide to tray**: hide the window with ✕; the "Updated hh:mm:ss" time on Connections must stop changing, and
   resume when the window is shown again.
8. Keyboard: in the connections grid, arrows/PageUp/PageDown/Home/End move the active row, `c` copies its address.
9. Layout: 1280×720 with *Compact* density shows no horizontal scrolling and no clipped tiles.

10. **Logon audit and trusted RDP clients** (needs the agent running as administrator or SYSTEM):
    - `pwctl status` prints `Logon audit: success on, failure on` when the "Logon" audit subcategory is enabled
      (check with `auditpol /get /subcategory:"Logon"`; the output is localized). Turn one off with
      `auditpol /set /subcategory:"Logon" /failure:disable`, restart nothing: within ~30 s `pwctl status` shows OFF
      with a WARNING and the app shows a banner on every page. **Restore it afterwards** with
      `auditpol /set /subcategory:"Logon" /success:enable /failure:enable`.
    - `RDP trusted: N address(es)` lists addresses with a successful RDP logon in the last 30 days. Cross-check with
      `Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4624)] and EventData[Data[@Name='LogonType']='10']]"`
      (and type 7). Note the Security log may be much shorter than 30 days.
    - Sign in over RDP from another machine: the new address appears within seconds (live subscription, no restart).
    - A bot's failed attempts (4625) or a bare connection must **not** add an address.

Dev only: a dev build (`pnpm tauri dev` or `pnpm dev`) accepts `?rows=N` in the URL to show N synthetic
connections instead of the agent's table, for performance checks.

## F3. Diagnostics (M3)

The automated tests use a fake pinger; these steps prove the real ICMP/DNS/TCP paths (any machine with internet).

1. Diagnostics → Ping: `1.1.1.1`, count 10. Replies show RTT/TTL; loss 0 %. Compare with `ping 1.1.1.1`.
   Ping an unroutable address (`192.0.2.1`): every row says *Timed out*, loss 100 %. Ping a host name and an IPv6
   literal (`2606:4700:4700::1111`) if the machine has IPv6.
2. **Stop** during a long ping (count 100) ends it within about a second and says *Stopped*.
3. MTR: trace to `1.1.1.1` and to a XeroHost node, 20 rounds. Compare the hops, loss and averages with WinMTR run
   at the same time (expect the same path; numbers within reason). **Copy report** puts the plain-text table on the
   clipboard; paste it into a text editor. A hop with loss that does not continue in later hops shows the `*` note.
4. DNS: `example.com` with *ALL* returns A, AAAA, MX, NS, SOA, TXT (every type present); try Cloudflare, Google and a
   custom server; an unknown name shows a clear *no records* or error line; a literal IP does a PTR lookup.
5. Port check: `127.0.0.1` and a listening port (for example 3389 on an RDP server) → *open*; a closed port →
   *closed*; a port behind a dropping firewall → *filtered*; UDP without a reply → *no answer* (inconclusive).
6. Local ports: matches `netstat -ano -p tcp | findstr LISTENING` plus UDP endpoints; RDP shows its tag; the
   *Reachable from* column says *all interfaces* for `0.0.0.0`/`::`.
7. Start 5 long pings: the fifth is refused with the *Too many diagnostics* message.

## F4. Capture and support bundle (M4)

Automated tests cover the pipeline, stats, recorder, blind detection, support bundle and anonymizer with fake sources. Live:

1. `packetward-agent run --console` (elevated), then `pwctl status`: the *Capture* line names the backend (raw socket without
   Npcap), the adapter and packets seen. Dashboard → Traffic shows inbound/outbound rates, the protocol table and top sources.
2. **Raw socket inbound visibility (known issue)**: see **section 0** (first step on the test VPS): the installer creates the
   inbound allow rule; `tools\dev\capture-rule.ps1` does the same for a development build.
3. **Npcap** (test VPS only; never on the dev VPS): install Npcap from npcap.com, restart the agent, confirm the backend switches
   to Npcap (*kernel filters*, inbound and outbound), record 30 s with filter `tcp and port 3389` and open the .pcapng in
   Wireshark (timestamps, 128-byte snaplen, original lengths). Uninstall Npcap and confirm the agent falls back without errors.
4. **200k pps**: with Npcap, generate a flood from another machine (hping3/iperf3 UDP small packets); the UI stays responsive,
   *Packets dropped* counts what was lost (never hidden), CPU of the agent stays bounded.
5. Recording: timed (60 s), ring (stop after a minute; total of files ≤ 200 MB), full payload requires the explicit tick; files list
   shows only .pcapng and a deleted file disappears; non-admin users cannot read the folder
   (`icacls %ProgramData%\PacketWard\captures` shows only SYSTEM and Administrators).
6. Support bundle: Capture → *Show what will be included*, open a few files in the preview, *Save bundle*; the zip is in
   `Documents\PacketWard\support`, opens, and contains no file you did not see in the preview. With *Hide this machine's own
   addresses* none of the server's addresses or its name appear in any text file (search them), and `capture.pcapng` is absent.
   `pwctl support-bundle --capture-secs 10` produces the same zip from the command line.

## F5. Alerts and notifications (M5)

Automated tests cover every detector on its fixture and the quiet "normal traffic" fixture, the engine wiring (netstat, failed logons,
capture sink), the alert store and the inbox/notification logic. Live, on a **test VPS**:

1. **RDP brute force**: from another machine try 15 wrong passwords against the server's RDP within a minute. An *RDP password guessing*
   alert appears in Alerts with the attacker's address; *Audit Logon* failure auditing must be on (`pwctl status` warns if not). With
   NLA the events are LogonType 3, without it type 10: test both if you can. Your own RDP address (with a successful logon) is shown as
   *protected source*, never blocked.
2. **Connection flood**: from another machine open 300+ connections to a listening port (for example with a small script); a *Connection
   flood* alert shows the address and the number of connections and ends about a minute after you stop.
3. **SYN / UDP / ICMP flood and port scan** (needs working capture: Npcap, or the firewall rule from §F4): `hping3 -S --flood`, UDP
   flood, `ping -f`, and `nmap -p 1-1000` from another machine each raise their alert; a normal day of traffic raises none.
4. **Notifications**: with the window closed to the tray, trigger a high alert: a Windows toast appears naming the attack and the source;
   the tray icon gets a red badge and a tooltip while it lasts. In Settings → Notifications, switch High off: no toast for the next high
   alert, but it is still in the inbox. Medium/low never pop up by default.
5. Restart the agent: the inbox still lists the earlier alerts (marked finished); *Clear finished* removes them for good.

## F6. Firewall manager and Guardian (M6/M7) — TEST VPS ONLY

The automated tests drive the real manager/guards against an in-memory firewall. These steps change real firewall rules: do NOT run
them on a production machine without a console (VNC) fallback.

1. **Block / unblock**: Firewall → Blocks: block `203.0.113.7` for 15 minutes. `wf.msc` shows the rule `PW-Manual-001` (group PacketWard)
   with that address; `ping` from that address (another machine, or a VPN exit) is dropped. Unblock removes the address; the rule is
   deleted when empty. Block 5000 addresses (paste a list): fewer than 10 rules. Apply the same list twice: no rule writes the second time.
2. **Protected**: try to block your own RDP client address, the gateway, a DNS server: each is refused with its reason, nothing is created.
3. **Foreign rules**: toggle a built-in Remote Desktop rule: a warning and the typed phrase are required; with the phrase RDP stops accepting
   new connections only after you confirm (keep the VNC console open!). Re-enable it.
4. **Purge**: *Remove all PacketWard rules* (or `pwctl firewall purge`) leaves no rule of the group in `wf.msc`.
5. **Guardian Monitor → Active**: leave Monitor for a day on an exposed server: *Would block* lists the bots. Switch to Active (confirm):
   a RDP guessing bot gets a 15-minute block; a second incident from the same address 1 hour; your own RDP address is never blocked even
   if you mistype passwords 15 times. Stop and restart the agent: the blocks are re-applied; they expire on time. `pwctl unblock --all`
   removes everything.
6. **Circuit breaker**: lower the limit to 2/hour, trigger three attackers: the third is not blocked, the page says the breaker is open.
7. `icacls %ProgramData%\PacketWard` shows only SYSTEM and Administrators.

## F7. RDP Shield (M7b) — TEST VPS WITH A VNC/CONSOLE FALLBACK ONLY

Every step below can cut Remote Desktop. Keep the provider's console open and a second RDP window ready.

1. **Audit** (safe anywhere): RDP Shield lists port, NLA, firewall exposure and findings with fixes; `pwctl rdp status` shows the same.
2. **Restrict + auto-revert**: restrict to your own address (+ trusted ones), *without* confirming: after 120 s the banner disappears and the
   firewall is back (`wf.msc`: no `PW-RDP-Allow`). Repeat and *Keep the change* from a second RDP connection: it stays. Try excluding your
   own address: it is added anyway. Turn the built-in rules off (typed phrase): a connection from an address not in the list is refused.
3. **Change port**: change to 43389, do NOT confirm: after 120 s the agent restores 3389 and restarts the service (you are disconnected twice).
   Repeat, reconnect on 43389 within the time and confirm. Restart the agent while a change is pending: on start it reverts when the deadline passed.
4. **NLA / lockout**: toggle NLA with and without confirming; account lockout needs the acknowledgement and reverts when unconfirmed
   (`net accounts` shows the values).
5. **Attempt limit**: set 3 failures / 60 s and guess a wrong password 3 times from another machine: an RDP guessing alert and (Active) a block.
6. **Sessions**: disconnect and log off a test session from the list.
7. **Reset**: after the above, *Restore Remote Desktop to factory settings* and `pwctl rdp reset --offline` (agent stopped) both give port
   3389, built-in rules enabled, no PacketWard RDP rules.
8. **New address**: log in from an address that never logged in: an `rdp_new_logon` alert appears; logging in again from it does not repeat it.

## F8. Threat intel and blocklists (M8) — TEST VPS ONLY for list activation

1. **GeoIP** (safe anywhere): Threat Intel → *Download database*; status becomes *Installed* with a build date, the attribution line is shown, and
   the country table fills with the countries of the current remote addresses. Private addresses never appear.
2. **Blocklists** (changes the real firewall: test VPS only): switch on *Spamhaus DROP* and confirm. Within a minute `Get-NetFirewallRule -Group PacketWard`
   (or `pwctl firewall list`) shows `PW-List-spamhaus-drop-NNN` rules; your own RDP session keeps working. Switch it off: the rules are gone.
   `pwctl firewall purge` also removes them.
3. **Protected addresses**: add an address of a list entry to the allowlist; after the next pass (≤ 10 min, or *Refresh now*) it is no longer blocked.
4. **Failure**: disconnect the network, press *Refresh now*: the error is shown, the old rules stay. Restart the agent offline: the list is still in force.
5. **XeroHost list**: the switch is disabled with the reason until a key is pinned in the build.
6. **AbuseIPDB**: with no key nothing is sent (check the firewall log / a packet capture of the agent); with your key, check a public address; the key must
   not appear in logs, `pwctl support-bundle` output or `ProgramData`.

## F9. Speed test (M9)

1. Run `tools/speed-server` on a second machine (see its README / Dockerfile), add `https://host:port` on the Speed Test page, run *Quick test*:
   latency/jitter/download/upload and your public address are shown. Compare with a reference tool (iperf3/speedtest) on the same link: target ±10 %.
2. Bin tests 1 GB and 10 GB with progress; **cancel** mid-way: the transfer stops immediately (watch the adapter counters on the dashboard).
   The 50 GB test stays disabled until its checkbox is ticked. On the dev VPS never run more than 1 GB per test.
3. Exceed the server's per-address budget: the page shows the *budget exceeded* message with no retry loop.

## F10. Advanced MTR (M10) — TEST VPS

Needs a Windows VPS with the agent running elevated, plus WinMTR (or `mtr`/`tracert`) for comparison. Nothing here changes firewall rules.

1. **ICMP baseline.** Diagnostics → MTR → ICMP to a public host (e.g. `1.1.1.1`), 20 rounds. Hops, loss and latency should match WinMTR
   run at the same time (±10 % on latency). The *Network (ASN)* and *Country* columns are filled for public hops (needs the GeoIP
   database from Threat Intel → Update) and show `—` for private addresses. Install nothing yet.
2. **UDP.** Mode UDP (default port 33434): the trace ends when the destination answers port-unreachable ("destination answered (port
   unreachable)" in the header). Compare the path with `tracert`/WinMTR in UDP mode. If the agent cannot read replies, the red note
   shows the agent's message and the Npcap hint; ICMP must keep working.
3. **TCP SYN.** Mode TCP SYN, port 443 against a host that **drops ICMP** (a cloud host with ICMP blocked, or block ICMP echo in that
   host's firewall for the test). ICMP shows the last hops as "no reply"; TCP must reach the destination ("destination answered (port open)",
   or "port closed" for a closed port). Try a closed port too.
4. **Npcap acceptance (roadmap M10).** Repeat step 3 first **without** Npcap (the built-in raw-socket capture, agent elevated), then install
   Npcap yourself from npcap.com and repeat **without restarting the agent**: the backend is chosen per trace. Record which of the
   two reached the destination. Stop the agent's elevation or use a non-admin context to check the *mode unavailable* message too.
5. **Options.** Packet size 1400 (UDP/ICMP) and TCP (field disabled), interval 500 ms, max hops 8 (the trace stops at 8), IPv6 target
   (`2606:4700:4700::1111`) and *Prefer IPv6* with a dual-stack name. A port of 0 is refused.
6. **Export.** After a run: Export → Save as CSV / JSON / support report; open each file (names look like
   `packetward-mtr-1.1.1.1-20261119-120000.csv`, no `:` for IPv6). *Copy as CSV/JSON* pastes the same text. After running a speed test
   the support report shows *Source public IP*. Check that the browser-style download prompt of the webview appears and writes the file.
7. **Old agent.** With an agent older than protocol 1.10 the mode/interval/IPv6 fields and Export are hidden and a note explains why.

## F11. Installer, upgrade, uninstall, updater (M11) — TEST VPS ONLY (Windows Server 2019 AND 2022, fresh snapshots)

The installer was only compiled and statically checked on the development VPS (nothing was installed there). Every step
below changes the machine: use a throwaway VPS with a provider console (VNC) as fallback. Installer log:
`%TEMP%\packetward-installer.log` (elevated user's temp). Build the installer with the release workflow (tag a beta, take
the artifact) or locally: `cargo build --release -p packetward-agent -p packetward-cli`, then in `apps\desktop`
`pnpm tauri build --config src-tauri/tauri.release.conf.json` with `createUpdaterArtifacts` set to `false` in that file
when you have no signing key. Output: `target\release\bundle\nsis\PacketWard_<version>_x64-setup.exe`.

1. **Clean install, GUI** (a machine without WebView2 if possible): the language selector appears (English / Español /
   Português) and the GPL-3.0 license page; the WebView2 bootstrapper runs. After finishing:
   `Get-Service PacketWard` is *Running* and *Automatic*; `Get-LocalGroupMember 'PacketWard Operators'` lists the installing
   user; `Get-NetFirewallRule -Group PacketWard` lists exactly one rule, `PacketWard agent (raw capture)` (inbound, allow,
   program `…\packetward-agent.exe`); `pwctl status` answers; the files are in `C:\Program Files\PacketWard`
   (`PacketWard.exe`, `packetward-agent.exe`, `pwctl.exe`). Sign out and in once, start PacketWard: the dashboard opens and the
   Guardian is in **Monitor**. The log shows `exit=0` for *register and start the service* and *firewall rule (add)*.
2. **Raw-socket hypothesis** (the reason for the rule, DECISIONS M4 row): with the rule present, `pwctl status` shows inbound
   packets and no *blind* warning; delete only that rule, restart the agent, and confirm the warning returns. Record the
   Windows build and the result in PROGRESS.
3. **Silent install**: `PacketWard_x64-setup.exe /S /OPERATORSID=<sid>` from an elevated prompt as another account: no windows,
   service running, that SID (not the installing account) in the operators group.
4. **Upgrade through the installer**: install version N, change something (Guardian to Monitor with an allowlist entry, one
   manual block, RDP Shield restriction confirmed), then run installer N+1 and choose *Do not uninstall*: the service was
   stopped and started again (log: `stop the existing service`, `register and start the service`), the settings, blocks and
   the RDP restriction are all still there, still exactly one `PacketWard agent (raw capture)` rule, no duplicate service.
   Repeat with the default *Uninstall before installing*: expect a full uninstall and a fresh install (RDP reset to factory,
   see ARCHITECTURE §9.1) — note the result.
5. **Uninstall, normal** (Apps & features, or `"C:\Program Files\PacketWard\uninstall.exe"`), after step 4 with an active RDP
   Shield restriction: Remote Desktop is back to port 3389 with the built-in rules enabled and no `PW-RDP-*` rules (check
   from a *new* RDP connection before closing the old one); `Get-NetFirewallRule -Group PacketWard` is empty;
   `Get-Service PacketWard` and the operators group are gone; `%ProgramData%\PacketWard` is **kept** (log says so).
   Then the §G leave-no-trace check, except the data folder.
6. **Uninstall with purge**: reinstall, then `uninstall.exe /S /PURGE` (and once through the GUI with *Delete the application
   data* ticked): `%ProgramData%\PacketWard` and `%AppData%\PacketWard` are gone; §G is fully clean.
7. **Uninstall tolerance**: stop the service first, then uninstall: the log shows the purge fallback and the uninstall still
   completes. Make the RDP reset fail (for example rename `pwctl.exe`, keep an RDP Shield restriction): the uninstall finishes,
   a message says the PacketWard rules were left in place, and RDP still works.
8. **Updater** (needs the keys of docs/RELEASE-KEYS.md; without a public key the Updates section says *not configured* and
   no request is made — verify that first with a build from this repository):
   - With a real public key in `tauri.conf.json` and the secrets loaded, tag `v0.0.1-beta.1`, then `v0.0.1-beta.2`. The
     pre-release `updater-beta` exists and its `latest.json` names beta.2; the stable `releases/latest/download/latest.json`
     does not exist yet (404) until a normal tag.
   - Install beta.1, Settings → Updates: channel *Beta*, *Check for updates* offers beta.2; *Download and install*: the
     installer runs passively (UAC prompt), the app closes, the service is stopped and started again, the app can be started
     again and shows beta.2. Switch to *Stable*: *Check* answers "latest version" or a not-found error, not beta.2.
   - Tag `v0.0.1`: both channels now offer it (a beta user is offered the stable release); a stable user never sees betas.
   - Tamper with an installer in a copy of the release (or serve a manifest with a wrong signature): the update is refused.
   - *Check when PacketWard starts* defaults to off: with a packet capture or firewall log confirm no connection to
     github.com is made at start; switch it on and restart: exactly one request, about five seconds after start.
9. **Authenticode** (only when a certificate exists): the installer, `PacketWard.exe`, `packetward-agent.exe` and `pwctl.exe`
   have a valid signature (`Get-AuthenticodeSignature`) and the SmartScreen prompt names the publisher.

## G. Leave-no-trace check

After testing, all of these must be empty / `False`:

```powershell
[bool](Get-Service PacketWard -ErrorAction SilentlyContinue)
[bool](Get-LocalGroup 'PacketWard Operators' -ErrorAction SilentlyContinue)
foreach ($k in 'HKCU','HKLM') { [bool](Get-ItemProperty "${k}:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue).PacketWard }
Test-Path "$env:ProgramData\PacketWard"
Get-Process packetward-agent, PacketWard -ErrorAction SilentlyContinue
```
