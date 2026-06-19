#Requires -Version 5.1
<#
.SYNOPSIS
  Installs RDP-Guard and applies RDP hardening. MUST be run as Administrator.

.DESCRIPTION
  Part A  Firewall: disable stale 3389 rules, replace ad-hoc/older rules with
          one clean RDP allow rule for the configured port (port stays public on
          purpose - no VPN/geo is possible from the user's side).
  Part B  Hardening: password policy, RDP encryption/NLA/TLS, session timeouts,
          larger Security log. Reports on the built-in Administrator + RDP group
          (only disables Administrator if you pass -DisableBuiltinAdmin).
  Part C  RDP-Guard: custom event log, state file, and a SYSTEM scheduled task
          that runs the engine at startup and every minute.

.PARAMETER SkipHardening
  Install only RDP-Guard (Part C) + firewall cleanup (Part A); skip Part B.

.PARAMETER DisableBuiltinAdmin
  Also disable the built-in Administrator account (only do this if you have
  another working admin account!).
#>
[CmdletBinding()]
param(
    [switch]$SkipHardening,
    [switch]$DisableBuiltinAdmin
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

# ---- elevation check ----
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning 'This installer must be run as Administrator.'
    Write-Host 'Open PowerShell as administrator and run:' -ForegroundColor Yellow
    Write-Host "  powershell -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -ForegroundColor Yellow
    exit 1
}

. (Join-Path $root 'RDP-Guard.Common.ps1')
$cfg  = Get-RGConfig
$port = [int]$cfg.rdpPort
$h    = $cfg.hardening
$allowRuleName = Get-RGProp $cfg 'allowRuleName' 'RDP-Guard-Allow'

Write-Host '==================== RDP-Guard install ====================' -ForegroundColor Cyan

# ----------------------------------------------------------------------------
# Part A - Firewall cleanup & exposure tightening
# ----------------------------------------------------------------------------
Write-Host "`n[A] Firewall" -ForegroundColor Cyan
foreach ($d in @('Remote Desktop - User Mode (TCP-In)', 'Remote Desktop - User Mode (UDP-In)')) {
    $r = Get-NetFirewallRule -DisplayName $d -ErrorAction SilentlyContinue
    if ($r) { $r | Disable-NetFirewallRule -ErrorAction SilentlyContinue; Write-Host "  disabled stale rule: $d" }
}
foreach ($d in @('01-RDP', 'Allow TCP 4002', 'RDP-In-4002', 'RDP-Guard-Allow', "RDP-In-$port", $allowRuleName) | Select-Object -Unique) {
    Get-NetFirewallRule -DisplayName $d -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
}
New-NetFirewallRule -DisplayName $allowRuleName `
    -Description "Intentional public RDP exposure on TCP $port (no VPN/geo possible). Managed by RDP-Guard." `
    -Direction Inbound -Action Allow -Protocol TCP -LocalPort $port -Profile Any | Out-Null
Write-Host "  created clean allow rule: $allowRuleName (TCP $port, all profiles)"

# ----------------------------------------------------------------------------
# Part B - Hardening
# ----------------------------------------------------------------------------
if (-not $SkipHardening) {
    Write-Host "`n[B] Hardening" -ForegroundColor Cyan

    # Password policy via secedit
    try {
        $inf = Join-Path $env:TEMP 'rg_secpol.inf'
        $sdb = Join-Path $env:TEMP 'rg_secpol.sdb'
        secedit /export /cfg $inf /quiet | Out-Null
        $content = Get-Content $inf
        $set = [ordered]@{
            'MinimumPasswordLength' = [int]$h.minPasswordLength
            'PasswordComplexity'    = [int][bool]$h.passwordComplexity
            'PasswordHistorySize'   = [int]$h.passwordHistory
        }
        foreach ($key in $set.Keys) {
            if ($content -match "^$key\s*=") {
                $content = $content -replace "^$key\s*=.*", "$key = $($set[$key])"
            } else {
                $content = $content -replace '(\[System Access\])', "`$1`r`n$key = $($set[$key])"
            }
        }
        Set-Content -Path $inf -Value $content -Encoding Unicode
        secedit /configure /db $sdb /cfg $inf /areas SECURITYPOLICY /quiet | Out-Null
        Remove-Item $inf, $sdb -ErrorAction SilentlyContinue
        Write-Host "  password policy: min length $($set['MinimumPasswordLength']), complexity $($set['PasswordComplexity']), history $($set['PasswordHistorySize'])"
    } catch { Write-Warning "  password policy step failed: $($_.Exception.Message)" }

    # RDP encryption + confirm NLA/TLS
    $rdpKey = 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    Set-ItemProperty -Path $rdpKey -Name 'MinEncryptionLevel' -Value ([int]$h.minEncryptionLevel) -Type DWord
    Set-ItemProperty -Path $rdpKey -Name 'UserAuthentication'  -Value 1 -Type DWord
    Set-ItemProperty -Path $rdpKey -Name 'SecurityLayer'       -Value 2 -Type DWord
    Write-Host "  RDP-Tcp: MinEncryptionLevel=$($h.minEncryptionLevel) (High), NLA required, TLS"

    # Session timeouts (0 = no limit)
    $tsPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    if (-not (Test-Path $tsPol)) { New-Item -Path $tsPol -Force | Out-Null }
    Set-ItemProperty -Path $tsPol -Name 'MaxIdleTime'          -Value ([int]$h.idleTimeoutMinutes * 60000)         -Type DWord
    Set-ItemProperty -Path $tsPol -Name 'MaxDisconnectionTime' -Value ([int]$h.disconnectedTimeoutMinutes * 60000) -Type DWord
    Set-ItemProperty -Path $tsPol -Name 'fResetBroken'         -Value 1 -Type DWord
    Write-Host "  session limits: idle $($h.idleTimeoutMinutes)m -> disconnect, disconnected $($h.disconnectedTimeoutMinutes)m -> end session"

    # Security log size
    try {
        wevtutil sl Security /ms:$([int]$h.securityLogSizeMB * 1MB) | Out-Null
        Write-Host "  Security event log max size: $($h.securityLogSizeMB) MB"
    } catch { Write-Warning "  could not set Security log size: $($_.Exception.Message)" }

    # Account audit (non-destructive unless -DisableBuiltinAdmin)
    try {
        $admin = Get-LocalUser -Name 'Administrator' -ErrorAction SilentlyContinue
        if ($admin) {
            Write-Host "  built-in Administrator enabled: $($admin.Enabled)"
            if ($admin.Enabled -and $DisableBuiltinAdmin) {
                Disable-LocalUser -Name 'Administrator'
                Write-Host '    -> disabled built-in Administrator (per -DisableBuiltinAdmin)' -ForegroundColor Yellow
            } elseif ($admin.Enabled) {
                Write-Warning '    Recommend: use a non-obvious RDP username, then re-run with -DisableBuiltinAdmin.'
            }
        }
    } catch { Write-Warning "  built-in Administrator check failed: $($_.Exception.Message)" }

    # RDP group membership - Get-LocalGroupMember can throw on unresolvable SIDs,
    # so fall back to 'net localgroup' parsing.
    $rdpUsers = @()
    try {
        $members = @(Get-LocalGroupMember -Group 'Remote Desktop Users' -ErrorAction Stop)
        $rdpUsers = @($members | ForEach-Object { $_.Name })
    } catch {
        try {
            $raw = net localgroup 'Remote Desktop Users' 2>$null
            $sep = ($raw | Select-String '^----' | Select-Object -First 1).LineNumber
            if ($sep) {
                $rdpUsers = @($raw | Select-Object -Skip $sep |
                    Where-Object { $_ -and ($_ -notmatch 'The command completed') })
            }
        } catch { }
    }
    Write-Host "  Remote Desktop Users: $(if ($rdpUsers.Count) { $rdpUsers -join ', ' } else { '(only Administrators)' })"
    Write-Host '  NOTE: Administrators can always RDP. Give that account a long unique passphrase and a non-obvious name.'
} else {
    Write-Host "`n[B] Hardening skipped (-SkipHardening)" -ForegroundColor Yellow
}

# ----------------------------------------------------------------------------
# Part C - RDP-Guard engine
# ----------------------------------------------------------------------------
Write-Host "`n[C] RDP-Guard engine" -ForegroundColor Cyan

if (-not [System.Diagnostics.EventLog]::SourceExists($cfg.eventSource)) {
    [System.Diagnostics.EventLog]::CreateEventSource($cfg.eventSource, $cfg.eventLogName)
    Write-Host "  created event log '$($cfg.eventLogName)' (source '$($cfg.eventSource)')"
} else {
    Write-Host "  event source '$($cfg.eventSource)' already present"
}

$statePath = Join-Path $root $cfg.stateFile
if (-not (Test-Path $statePath)) { Set-Content -Path $statePath -Value '{}' -Encoding UTF8; Write-Host '  initialized state.json' }

$taskName   = 'RDP-Guard'
$enginePath = Join-Path $root 'RDP-Guard.ps1'
$action     = New-ScheduledTaskAction -Execute 'powershell.exe' `
                -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$enginePath`""
$tStart     = New-ScheduledTaskTrigger -AtStartup
$tRepeat    = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
                -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 3650)
$principal  = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings   = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable `
                -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($tStart, $tRepeat) `
    -Principal $principal -Settings $settings -Force | Out-Null
Write-Host "  registered scheduled task '$taskName' (SYSTEM, at startup + every 1 min)"
Start-ScheduledTask -TaskName $taskName
Write-Host '  started initial run'

# ----------------------------------------------------------------------------
# Part C2 - Local toast alerts (user-context, event-triggered)
# ----------------------------------------------------------------------------
# The engine runs as SYSTEM (session 0) and can't draw a toast on the desktop,
# so toasts are shown by separate tasks that run in the interactive user session.
$alerts      = Get-RGProp $cfg 'alerts' $null
$toastScript = Join-Path $root 'RDP-Guard.Toast.ps1'
$toastUser   = "$env:USERDOMAIN\$env:USERNAME"
foreach ($tn in @('RDP-Guard-Toast-Ban', 'RDP-Guard-Toast-Login')) {
    Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue
}
if ([bool](Get-RGProp $alerts 'toast' $false)) {
    Write-Host "`n[C2] Local toast alerts (shown to: $toastUser)" -ForegroundColor Cyan
    $toastPrincipal = New-ScheduledTaskPrincipal -UserId $toastUser -LogonType Interactive -RunLevel Limited
    $toastSettings  = New-ScheduledTaskSettingsSet -MultipleInstances Parallel -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
    $evtClass = Get-CimClass -Namespace ROOT/Microsoft/Windows/TaskScheduler -ClassName MSFT_TaskEventTrigger

    if ([bool](Get-RGProp $alerts 'onBan' $true)) {
        $tBan = New-CimInstance -CimClass $evtClass -ClientOnly
        $tBan.Enabled = $true
        $tBan.Subscription = '<QueryList><Query Id="0" Path="RDP-Guard"><Select Path="RDP-Guard">*[System[(EventID=1001 or EventID=1003)]]</Select></Query></QueryList>'
        $aBan = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$toastScript`" -Kind Ban"
        Register-ScheduledTask -TaskName 'RDP-Guard-Toast-Ban' -Action $aBan -Trigger $tBan -Principal $toastPrincipal -Settings $toastSettings -Force | Out-Null
        Write-Host '  toast on IP ban: enabled'
    }
    if ([bool](Get-RGProp $alerts 'onLogin' $true)) {
        $tLog = New-CimInstance -CimClass $evtClass -ClientOnly
        $tLog.Enabled = $true
        $tLog.Subscription = '<QueryList><Query Id="0" Path="Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"><Select Path="Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational">*[System[(EventID=1149)]]</Select></Query></QueryList>'
        $aLog = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$toastScript`" -Kind Login"
        Register-ScheduledTask -TaskName 'RDP-Guard-Toast-Login' -Action $aLog -Trigger $tLog -Principal $toastPrincipal -Settings $toastSettings -Force | Out-Null
        Write-Host '  toast on RDP login: enabled'
    }
} else {
    Write-Host "`n[C2] Local toast alerts: disabled in config" -ForegroundColor Yellow
}

Write-Host "`nDone." -ForegroundColor Green
Write-Host "  Validate setup:  double-click Validate-Setup.cmd   (recommended first step)"
Write-Host "  View activity:   double-click View-Activity.cmd   (or Get-WinEvent -LogName '$($cfg.eventLogName)' -MaxEvents 20)"
Write-Host "  Admin commands:  Import-Module `"$root\RDP-Guard.Admin.psm1`"; Get-RDPGuardReport"
