# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Idle CPU/RAM of an agent process: starts it, waits for the warm-up, then samples CPU time over a window.
# Example (release build, UI closed): .\tools\dev\measure-idle.ps1 -Exe .\target\release\packetward-agent.exe -ArgList run,--console
# Add --no-capture to measure without the live capture. Do it on a machine where stopping the agent is fine.
param([string]$Exe, [string[]]$ArgList, [int]$Warm = 10, [int]$Window = 60)
$p = Start-Process -FilePath $Exe -ArgumentList $ArgList -PassThru -WindowStyle Hidden
Start-Sleep -Seconds $Warm
$p.Refresh()
$t0 = $p.TotalProcessorTime.TotalSeconds
$th0 = @{}; foreach ($t in $p.Threads) { $th0[$t.Id] = $t.TotalProcessorTime.TotalSeconds }
Start-Sleep -Seconds $Window
$p.Refresh()
$t1 = $p.TotalProcessorTime.TotalSeconds
$cpu = ($t1 - $t0) / $Window * 100
$ws = [math]::Round($p.WorkingSet64 / 1MB, 1)
$busy = @()
foreach ($t in $p.Threads) {
  $d = $t.TotalProcessorTime.TotalSeconds - $(if ($th0.ContainsKey($t.Id)) { $th0[$t.Id] } else { 0 })
  if ($d -gt 0.05) { $busy += ("{0}:{1:N2}%" -f $t.Id, ($d / $Window * 100)) }
}
"{0} {1} -> CPU {2:N2} % of one core, RAM {3} MB, threads {4}; busy: {5}" -f (Split-Path $Exe -Leaf), ($ArgList -join ' '), $cpu, $ws, $p.Threads.Count, ($busy -join ' ')
Stop-Process -Id $p.Id -Force
