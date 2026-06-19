#Requires -Version 5.1
<#
.SYNOPSIS
  Friendly "what happened" view for RDP-Guard - anytime activity report.

.DESCRIPTION
  Shows, for the chosen window: successful RDP logins (who/when/from where),
  top offending source IPs, most-targeted usernames, current bans, and the most
  recent RDP-Guard ban/unban events. Reading the Security log needs admin, so
  this self-elevates (one UAC prompt).

.PARAMETER Hours
  How far back to look (default 24).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File Show-Activity.ps1 -Hours 72
#>
[CmdletBinding()]
param([double]$Hours = 24)
$root = $PSScriptRoot

# Reading the Security log requires elevation - relaunch elevated if needed.
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit',
        '-File', "`"$PSCommandPath`"", '-Hours', $Hours
    )
    return
}

Import-Module (Join-Path $root 'RDP-Guard.Admin.psm1') -Force
Get-RDPGuardReport -Hours $Hours

Write-Host 'Recent RDP-Guard events (bans / unbans / errors):' -ForegroundColor Cyan
$evts = Get-WinEvent -LogName 'RDP-Guard' -MaxEvents 15 -ErrorAction SilentlyContinue
if ($evts) {
    $evts | Select-Object TimeCreated, Id, Message | Format-Table -AutoSize -Wrap | Out-Host
} else {
    Write-Host '  (no ban/unban events yet - nothing has crossed the threshold)' -ForegroundColor DarkGray
}

Read-Host "`nPress Enter to close"
