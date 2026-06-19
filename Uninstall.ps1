#Requires -Version 5.1
<#
.SYNOPSIS
  Removes the RDP-Guard scheduled task and block rule. Run as Administrator.

.DESCRIPTION
  By default this leaves your RDP access (RDP-In-4002) and the hardening
  (password policy, encryption, timeouts) in place, and only removes the
  active RDP-Guard pieces. Use the switches to remove more.

.PARAMETER RemoveEventLog
  Also delete the custom 'RDP-Guard' event log.

.PARAMETER RemoveAllowRule
  Also remove the RDP-In-4002 allow rule. WARNING: this stops RDP reaching
  the machine through the firewall.
#>
[CmdletBinding()]
param([switch]$RemoveEventLog, [switch]$RemoveAllowRule)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning 'Run as Administrator.'; exit 1
}

. (Join-Path $root 'RDP-Guard.Common.ps1')
$cfg = Get-RGConfig

foreach ($tn in @('RDP-Guard', 'RDP-Guard-Toast-Ban', 'RDP-Guard-Toast-Login')) {
    Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue
}
Write-Host 'Removed scheduled tasks: RDP-Guard (+ toast alert tasks)'

Get-NetFirewallRule -DisplayName $cfg.blockRuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
Write-Host "Removed firewall block rule: $($cfg.blockRuleName)"

if ($RemoveAllowRule) {
    Get-NetFirewallRule -DisplayName 'RDP-In-4002' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Write-Host 'Removed RDP-In-4002 - RDP is no longer allowed through the firewall!' -ForegroundColor Yellow
}

if ($RemoveEventLog) {
    try {
        if ([System.Diagnostics.EventLog]::SourceExists($cfg.eventSource)) {
            [System.Diagnostics.EventLog]::Delete($cfg.eventLogName)
            Write-Host "Removed event log: $($cfg.eventLogName)"
        }
    } catch { Write-Warning "Could not remove event log: $($_.Exception.Message)" }
}

Write-Host 'Note: hardening (password policy, encryption, session timeouts) was left in place intentionally.'
