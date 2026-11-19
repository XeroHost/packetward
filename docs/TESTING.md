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

Dev only: a dev build (`pnpm tauri dev` or `pnpm dev`) accepts `?rows=N` in the URL to show N synthetic
connections instead of the agent's table, for performance checks.

## G. Leave-no-trace check

After testing, all of these must be empty / `False`:

```powershell
[bool](Get-Service PacketWard -ErrorAction SilentlyContinue)
[bool](Get-LocalGroup 'PacketWard Operators' -ErrorAction SilentlyContinue)
foreach ($k in 'HKCU','HKLM') { [bool](Get-ItemProperty "${k}:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue).PacketWard }
Test-Path "$env:ProgramData\PacketWard"
Get-Process packetward-agent, PacketWard -ErrorAction SilentlyContinue
```
