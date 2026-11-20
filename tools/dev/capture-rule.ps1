# SPDX-License-Identifier: GPL-3.0-or-later
<#
.SYNOPSIS
  Development equivalent of the rule the installer creates: one INBOUND allow rule for the agent
  executable, so the raw-socket capture backend receives inbound packets (docs/TESTING.md section 0).

.DESCRIPTION
  The installer (apps/desktop/src-tauri/installer/hooks.nsh) creates `PacketWard agent (raw capture)`
  in the `PacketWard` rule group for `$INSTDIR\packetward-agent.exe`. A development build runs from
  `target\debug`, so this script creates the same rule for that path.

  RUN IT ON A TEST VPS ONLY, never on the development VPS (the working VPS must not get firewall
  changes). It changes only this one rule; `-Action Remove` deletes it again, and `pwctl firewall
  purge` / the installer's uninstall remove the whole `PacketWard` group anyway.

.EXAMPLE
  .\tools\dev\capture-rule.ps1 -Action Status
  .\tools\dev\capture-rule.ps1 -Action Add -WhatIf        # shows what would be created
  .\tools\dev\capture-rule.ps1 -Action Add
  .\tools\dev\capture-rule.ps1 -Action Remove
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('Add', 'Remove', 'Status')]
  [string] $Action,

  # The executable to allow. Default: the debug build of this checkout.
  [string] $Agent = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path 'target\debug\packetward-agent.exe')
)

$ErrorActionPreference = 'Stop'
$RuleName = 'PacketWard agent (raw capture)'   # the same name the installer uses
$Group = 'PacketWard'

function Get-AgentRule {
  Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue
}

switch ($Action) {
  'Status' {
    $rule = Get-AgentRule
    if (-not $rule) { Write-Output "No rule named '$RuleName'."; return }
    $app = $rule | Get-NetFirewallApplicationFilter
    [pscustomobject]@{
      Name      = $rule.Name
      Group     = $rule.Group
      Enabled   = $rule.Enabled
      Direction = $rule.Direction
      Action    = $rule.Action
      Program   = $app.Program
    } | Format-List
  }
  'Add' {
    if (-not (Test-Path -LiteralPath $Agent)) { throw "Agent executable not found: $Agent (build it first)." }
    $program = (Resolve-Path -LiteralPath $Agent).Path
    if ($PSCmdlet.ShouldProcess($program, "Create inbound allow rule '$RuleName' (group $Group)")) {
      Get-AgentRule | Remove-NetFirewallRule -ErrorAction SilentlyContinue
      New-NetFirewallRule -Name $RuleName -DisplayName $RuleName -Group $Group `
        -Description 'Lets the PacketWard agent receive raw-socket capture traffic. [PacketWard]' `
        -Direction Inbound -Action Allow -Program $program -Profile Any -Enabled True | Out-Null
      Write-Output "Created '$RuleName' for $program."
    }
  }
  'Remove' {
    if ($PSCmdlet.ShouldProcess($RuleName, 'Remove the rule')) {
      Get-AgentRule | Remove-NetFirewallRule -ErrorAction SilentlyContinue
      Write-Output "Removed '$RuleName' (if it existed)."
    }
  }
}
