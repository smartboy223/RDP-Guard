#Requires -Version 5.1
<#
.SYNOPSIS
  Validates an RDP-Guard install end-to-end. Run after Install.ps1 (or any time).
  Self-elevates. Safe and self-cleaning.

.DESCRIPTION
  Checks config, event log, scheduled tasks, firewall, and the listening port,
  then performs a LIVE ban-pipeline self-test using a reserved TEST-NET IP
  (blocks it -> verifies state/firewall/log -> unblocks it). Finally shows two
  example toasts. Prints a PASS/WARN/FAIL summary.

.PARAMETER NoToast
  Skip the example toasts.
#>
[CmdletBinding()]
param([switch]$NoToast)

$root = $PSScriptRoot

# Reading the Security/scheduled-task state needs admin -> relaunch elevated.
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $argl = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', "`"$PSCommandPath`"")
    if ($NoToast) { $argl += '-NoToast' }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argl
    return
}

. (Join-Path $root 'RDP-Guard.Common.ps1')
$cfg = Get-RGConfig

$script:pass = 0; $script:warn = 0; $script:fail = 0
function Result {
    param($State, [string]$Name, [string]$Detail = '')
    # NOTE: test ($State -is [string]) FIRST. A bare ($State -eq 'WARN') is buggy:
    # when $State is [bool]$true, PowerShell coerces 'WARN' to [bool] (true), so
    # every PASS would wrongly match the WARN branch.
    if (($State -is [string]) -and ($State -eq 'WARN')) { Write-Host ("  [WARN] {0} {1}" -f $Name, $Detail) -ForegroundColor Yellow; $script:warn++; return }
    if ($State)            { Write-Host ("  [PASS] {0}" -f $Name)            -ForegroundColor Green;  $script:pass++; return }
    Write-Host ("  [FAIL] {0} {1}" -f $Name, $Detail) -ForegroundColor Red; $script:fail++
}

Write-Host "==================== RDP-Guard validation ====================" -ForegroundColor Cyan
Write-Host "`n[1] Configuration & logging"
Result ($null -ne $cfg) "config.json loads and parses"
Result ([System.Diagnostics.EventLog]::SourceExists($cfg.eventSource)) "event log source '$($cfg.eventSource)' exists"

Write-Host "`n[2] Scheduled tasks"
$engine = Get-ScheduledTask -TaskName 'RDP-Guard' -ErrorAction SilentlyContinue
Result ($null -ne $engine) "engine task 'RDP-Guard' registered"
if ($engine) {
    Result ($engine.State -ne 'Disabled') "engine task enabled (state: $($engine.State))"
    $info = Get-ScheduledTaskInfo -TaskName 'RDP-Guard' -ErrorAction SilentlyContinue
    if ($info) {
        if ($info.LastTaskResult -eq 0) { Result $true "engine last run succeeded (result 0)" }
        elseif ($info.LastTaskResult -eq 267009) { Result $true "engine is currently running" }
        else { Result 'WARN' "engine last run result = $($info.LastTaskResult)" "(0 = success; run the task once if this is a fresh install)" }
    }
}
$alerts = Get-RGProp $cfg 'alerts' $null
if ([bool](Get-RGProp $alerts 'toast' $false)) {
    Result ($null -ne (Get-ScheduledTask -TaskName 'RDP-Guard-Toast-Ban'   -ErrorAction SilentlyContinue)) "toast task 'RDP-Guard-Toast-Ban' registered"
    Result ($null -ne (Get-ScheduledTask -TaskName 'RDP-Guard-Toast-Login' -ErrorAction SilentlyContinue)) "toast task 'RDP-Guard-Toast-Login' registered"
}

Write-Host "`n[3] Firewall & listener"
$allowRuleName = Get-RGProp $cfg 'allowRuleName' 'RDP-Guard-Allow'
$allow = Get-NetFirewallRule -DisplayName $allowRuleName -ErrorAction SilentlyContinue
Result ($allow -and "$($allow.Enabled)" -eq 'True') "firewall allow rule '$allowRuleName' present & enabled"
$listen = Get-NetTCPConnection -State Listen -LocalPort ([int]$cfg.rdpPort) -ErrorAction SilentlyContinue
Result ($null -ne $listen) "RDP is listening on TCP $($cfg.rdpPort)"

Write-Host "`n[4] Live ban-pipeline self-test (reserved TEST-NET IP, auto-cleaned)"
$testIp = '198.51.100.7'
Import-Module (Join-Path $root 'RDP-Guard.Admin.psm1') -Force
try {
    Block-RDPGuardIP -IP $testIp -Hours 1 | Out-Null
    Start-Sleep -Milliseconds 600
    $state = Get-RGState -Config $cfg
    Result ($state.ContainsKey($testIp)) "test IP added to state.json"

    $rule = Get-NetFirewallRule -DisplayName $cfg.blockRuleName -ErrorAction SilentlyContinue
    $addrs = @(); if ($rule) { $addrs = @(($rule | Get-NetFirewallAddressFilter).RemoteAddress) }
    Result ($addrs -contains $testIp) "test IP present in firewall block rule '$($cfg.blockRuleName)'"

    $ev = Get-WinEvent -FilterHashtable @{ LogName = $cfg.eventLogName; StartTime = (Get-Date).AddMinutes(-2) } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match [regex]::Escape($testIp) } | Select-Object -First 1
    Result ($null -ne $ev) "block event written to '$($cfg.eventLogName)' log"
    Write-Host "        (a 'Threat blocked' toast should also pop now - that proves the event trigger works)" -ForegroundColor DarkGray
}
finally {
    Unblock-RDPGuardIP -IP $testIp | Out-Null
    $state2 = Get-RGState -Config $cfg
    Result (-not $state2.ContainsKey($testIp)) "test IP cleaned up (unblocked & removed)"
}

if (-not $NoToast) {
    Write-Host "`n[5] Example toasts (two notifications should appear)"
    & (Join-Path $root 'RDP-Guard.Toast.ps1') -Kind Login -Demo
    Start-Sleep -Seconds 2
    & (Join-Path $root 'RDP-Guard.Toast.ps1') -Kind Ban -Demo
    Result $true "example toasts fired"
}

$color = 'Green'
if ($script:fail -gt 0) { $color = 'Red' } elseif ($script:warn -gt 0) { $color = 'Yellow' }
Write-Host "`n==================== $($script:pass) passed, $($script:warn) warning(s), $($script:fail) failed ====================" -ForegroundColor $color
if ($script:fail -gt 0) {
    Write-Host "Some checks failed. Re-run Install.ps1 as admin, then validate again." -ForegroundColor Red
} else {
    Write-Host "RDP-Guard is installed and working." -ForegroundColor Green
}

Read-Host "`nPress Enter to close"
