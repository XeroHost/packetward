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
2. **Raw socket inbound visibility (known issue)**: on the development VPS the raw socket saw outbound packets only; `pwctl status`
   then shows the *blind* warning after about 10 s. On a **test VPS** create an inbound allow rule for `packetward-agent.exe`
   (program-scoped, group `PacketWard`, e.g. with the firewall page once M6 is wired) and confirm inbound packets and top
   sources appear and the warning goes away. If not, record the Windows build and report: the NDIS ETW provider is the fallback.
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

## G. Leave-no-trace check

After testing, all of these must be empty / `False`:

```powershell
[bool](Get-Service PacketWard -ErrorAction SilentlyContinue)
[bool](Get-LocalGroup 'PacketWard Operators' -ErrorAction SilentlyContinue)
foreach ($k in 'HKCU','HKLM') { [bool](Get-ItemProperty "${k}:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue).PacketWard }
Test-Path "$env:ProgramData\PacketWard"
Get-Process packetward-agent, PacketWard -ErrorAction SilentlyContinue
```
