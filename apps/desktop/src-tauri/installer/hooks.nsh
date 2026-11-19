; SPDX-License-Identifier: GPL-3.0-or-later
;
; PacketWard installer hooks for the Tauri NSIS template (docs/ARCHITECTURE.md section 9).
;
; Shelling out (netsh/PowerShell) is allowed here and only here: this is the installer script, not the
; product. Every step is tolerant: a failed step is logged and never aborts the install or uninstall.
; Everything is logged to "$TEMP\packetward-installer.log".
;
; Update mode: the Tauri updater runs the new installer with /UPDATE and it does NOT run the old
; uninstaller, so PREINSTALL stops the service, the files are replaced and POSTINSTALL registers and
; starts it again. When the old uninstaller does run with /UPDATE ($UpdateMode = 1) the uninstall hooks
; only stop the service and change nothing else (no RDP reset, no purge, the operators group stays).
;
; Silent switches understood by the uninstaller (besides the template's /S, /P, /UPDATE):
;   /PURGE            also delete %ProgramData%\PacketWard (the "Delete the application data" check
;                     box of the uninstall page does the same).
; and by the installer:
;   /OPERATORSID=<SID> add this SID (not the installing user) to the "PacketWard Operators" group.

Var PwFile
Var PwExit
Var PwOut
Var PwArgs
Var PwSid
Var PwData
Var PwRdpOk
Var PwPurge

; Appends one line to the installer log.
!macro PW_Log _MSG
  ClearErrors
  FileOpen $PwFile "$TEMP\packetward-installer.log" a
  ${IfNot} ${Errors}
    FileWrite $PwFile "${_MSG}$\r$\n"
    FileClose $PwFile
  ${EndIf}
  ClearErrors
!macroend

; Runs a command without a window, logs its exit code and output. The exit code stays in $PwExit
; ("error" or "timeout" when the command could not be run at all).
!macro PW_Run _LABEL _CMD
  ClearErrors
  nsExec::ExecToStack '${_CMD}'
  Pop $PwExit
  Pop $PwOut
  !insertmacro PW_Log "${_LABEL}: exit=$PwExit"
  ${If} $PwOut != ""
    !insertmacro PW_Log "  $PwOut"
  ${EndIf}
!macroend

; %ProgramData%\PacketWard into $PwData.
!macro PW_DataDir
  ReadEnvStr $PwData "ProgramData"
  ${If} $PwData == ""
    StrCpy $PwData "C:\ProgramData"
  ${EndIf}
  StrCpy $PwData "$PwData\PacketWard"
!macroend

; ---------------------------------------------------------------------------------------------
; Install / upgrade
; ---------------------------------------------------------------------------------------------

; Before any file is replaced: the running service holds packetward-agent.exe open.
!macro NSIS_HOOK_PREINSTALL
  !insertmacro PW_Log "=== PacketWard ${VERSION}: install (update mode=$UpdateMode, passive=$PassiveMode) ==="
  ${If} ${FileExists} "$INSTDIR\packetward-agent.exe"
    !insertmacro PW_Run "stop the existing service" '"$INSTDIR\packetward-agent.exe" stop'
  ${EndIf}
!macroend

; After the files are in place: register and start the service (the same command repairs an existing
; registration, so it serves install and upgrade), then the firewall rule raw capture needs.
!macro NSIS_HOOK_POSTINSTALL
  StrCpy $PwArgs ""
  ClearErrors
  ${GetOptions} $CMDLINE "/OPERATORSID=" $PwSid
  ${IfNot} ${Errors}
  ${AndIf} $PwSid != ""
    StrCpy $PwArgs ' --operator-sid "$PwSid"'
  ${EndIf}
  ClearErrors
  !insertmacro PW_Run "register and start the service" '"$INSTDIR\packetward-agent.exe" install$PwArgs'

  ; ONE inbound allow rule for the agent executable, in the PacketWard rule group. `netsh ... add rule`
  ; has no group parameter, so this uses the NetSecurity cmdlets. Raw-socket capture delivery needs the
  ; rule (hypothesis, docs/DECISIONS.md M4 row and docs/TESTING.md F4). Re-created on every run.
  ${DisableX64FSRedirection}
  !insertmacro PW_Run "firewall rule (remove old)" '"$WINDIR\System32\netsh.exe" advfirewall firewall delete rule name="PacketWard agent (raw capture)"'
  !insertmacro PW_Run "firewall rule (add)" '"$WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "New-NetFirewallRule -Name $\'PacketWard agent (raw capture)$\' -DisplayName $\'PacketWard agent (raw capture)$\' -Group $\'PacketWard$\' -Description $\'Lets the PacketWard agent receive raw-socket capture traffic. [PacketWard]$\' -Direction Inbound -Action Allow -Program $\'$INSTDIR\packetward-agent.exe$\' -Profile Any -Enabled True | Out-Null"'
  ${EnableX64FSRedirection}
  !insertmacro PW_Log "=== install finished ==="
!macroend

; ---------------------------------------------------------------------------------------------
; Uninstall
; ---------------------------------------------------------------------------------------------

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro PW_Log "=== PacketWard: uninstall (update mode=$UpdateMode, passive=$PassiveMode) ==="
  StrCpy $PwPurge 0
  ClearErrors
  ${GetOptions} $CMDLINE "/PURGE" $PwOut
  ${IfNot} ${Errors}
    StrCpy $PwPurge 1
  ${EndIf}
  ClearErrors

  ${If} $UpdateMode = 1
    ; Replaced by a newer version: keep the service registration, rules, RDP state and data.
    ${If} ${FileExists} "$INSTDIR\packetward-agent.exe"
      !insertmacro PW_Run "update: stop the service" '"$INSTDIR\packetward-agent.exe" stop'
    ${EndIf}
  ${Else}
    !insertmacro PW_DataDir
    StrCpy $PwRdpOk 1

    ; 1. Remote Desktop first. If the RDP Shield changed anything it left a state file; putting RDP back to
    ;    factory settings must happen BEFORE the PacketWard rules (the shield's allow rules) are purged,
    ;    otherwise the built-in rules could stay disabled with nothing allowing RDP. Through the agent
    ;    when it runs (pwctl falls back to a direct reset when it cannot connect), then --offline.
    ${If} ${FileExists} "$PwData\rdp_shield.json"
    ${AndIf} ${FileExists} "$INSTDIR\pwctl.exe"
      !insertmacro PW_Log "RDP Shield state found: restoring Remote Desktop"
      !insertmacro PW_Run "rdp reset" '"$INSTDIR\pwctl.exe" rdp reset'
      ${If} $PwExit != 0
        ${If} ${FileExists} "$INSTDIR\packetward-agent.exe"
          !insertmacro PW_Run "stop the service before the offline reset" '"$INSTDIR\packetward-agent.exe" stop'
        ${EndIf}
        !insertmacro PW_Run "rdp reset --offline" '"$INSTDIR\pwctl.exe" rdp reset --offline'
        ${If} $PwExit != 0
          StrCpy $PwRdpOk 0
        ${EndIf}
      ${EndIf}
    ${EndIf}

    ${If} $PwRdpOk = 1
      ; 2. Every rule of the PacketWard group (blocks, lists, RDP allow rules, the agent rule), through the
      ;    agent. If the agent is not reachable, remove what PowerShell finds in the group but never the
      ;    RDP shield rules (they are only safe to remove after a successful RDP reset).
      ${If} ${FileExists} "$INSTDIR\pwctl.exe"
        !insertmacro PW_Run "firewall purge" '"$INSTDIR\pwctl.exe" firewall purge'
      ${Else}
        StrCpy $PwExit "missing"
      ${EndIf}
      ${If} $PwExit != 0
        ${DisableX64FSRedirection}
        !insertmacro PW_Run "firewall purge (fallback)" '"$WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$ErrorActionPreference = $\'SilentlyContinue$\'; Get-NetFirewallRule -Group $\'PacketWard$\' | Where-Object { $$_.Name -notlike $\'PW-RDP-*$\' } | Remove-NetFirewallRule"'
        ${EnableX64FSRedirection}
      ${EndIf}
      ; 3. The agent rule by name (exit 1 just means it was already gone).
      ${DisableX64FSRedirection}
      !insertmacro PW_Run "firewall rule by name" '"$WINDIR\System32\netsh.exe" advfirewall firewall delete rule name="PacketWard agent (raw capture)"'
      ${EnableX64FSRedirection}
    ${Else}
      !insertmacro PW_Log "WARNING: Remote Desktop could not be restored; the PacketWard firewall rules were left in place"
      MessageBox MB_OK|MB_ICONEXCLAMATION "PacketWard could not restore the Remote Desktop settings. The PacketWard firewall rules were left in place so remote access keeps working. Run 'pwctl rdp reset --offline' from an elevated prompt (see https://github.com/XeroHost/packetward) or restore the settings from the provider console." /SD IDOK
    ${EndIf}

    ; 4. Stop and remove the service (and the operators group).
    ${If} ${FileExists} "$INSTDIR\packetward-agent.exe"
      !insertmacro PW_Run "remove the service" '"$INSTDIR\packetward-agent.exe" uninstall'
    ${EndIf}
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ${If} $UpdateMode <> 1
    ; The template's "Delete the application data" check box (not shown in silent mode) or /PURGE.
    ${If} $DeleteAppDataCheckboxState = 1
    ${OrIf} $PwPurge = 1
      !insertmacro PW_DataDir
      !insertmacro PW_Log "purge: removing $PwData"
      RMDir /r "$PwData"
      ; The signed-in user's own preferences (ui.json); other users' profiles are not touched.
      SetShellVarContext current
      RMDir /r "$APPDATA\PacketWard"
      !insertmacro PW_Log "purge done"
    ${Else}
      !insertmacro PW_Log "settings and logs kept in %ProgramData%\PacketWard (use /PURGE or the check box to remove them)"
    ${EndIf}
  ${EndIf}
  !insertmacro PW_Log "=== uninstall finished ==="
!macroend
