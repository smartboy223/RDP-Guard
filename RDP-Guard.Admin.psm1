# RDP-Guard.Admin.psm1 - admin & reporting commands for RDP-Guard.
#
# Import (run PowerShell as Administrator for block/unblock to touch the firewall):
#   Import-Module C:\Security\RDP-Guard\RDP-Guard.Admin.psm1
#
# Commands:
#   Get-RDPGuardBans [-IncludeExpired]
#   Block-RDPGuardIP -IP <ip> [-Hours <n> | -Permanent]
#   Unblock-RDPGuardIP -IP <ip>
#   Get-RDPGuardReport [-Hours <n>] [-Top <n>]

. (Join-Path $PSScriptRoot 'RDP-Guard.Common.ps1')

function Get-RDPGuardBans {
    [CmdletBinding()]
    param([switch]$IncludeExpired)
    $cfg = Get-RGConfig
    $state = Get-RGState -Config $cfg
    $now = Get-Date
    $rows = foreach ($ip in $state.Keys) {
        $e  = $state[$ip]
        $bu = if ($e['banUntil']) { [datetime]$e['banUntil'] } else { $null }
        $active = [bool]($bu -and ($bu -gt $now))
        if (-not $IncludeExpired -and -not $active) { continue }
        [pscustomobject]@{
            IP        = $ip
            Active    = $active
            BanUntil  = $bu
            Strikes   = $e['strikes']
            LastCount = $e['lastCount']
            Manual    = [bool]$e['manual']
            FirstSeen = if ($e['firstSeen']) { [datetime]$e['firstSeen'] } else { $null }
            LastSeen  = if ($e['lastSeen'])  { [datetime]$e['lastSeen'] }  else { $null }
        }
    }
    $rows | Sort-Object Active, BanUntil -Descending
}

function Block-RDPGuardIP {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$IP,
        [double]$Hours,
        [switch]$Permanent
    )
    $cfg = Get-RGConfig
    $tmp = $null
    if (-not [System.Net.IPAddress]::TryParse($IP, [ref]$tmp)) { throw "Not a valid IP address: $IP" }
    $state = Get-RGState -Config $cfg
    $now = Get-Date
    $banUntil =
        if     ($Permanent) { $now.AddYears(100) }
        elseif ($Hours)     { $now.AddHours($Hours) }
        else                { $now.AddHours([double]$cfg.banHours) }

    $existing = if ($state.ContainsKey($IP)) { $state[$IP] } else { $null }
    $state[$IP] = @{
        ip        = $IP
        firstSeen = if ($existing -and $existing['firstSeen']) { $existing['firstSeen'] } else { $now.ToString('o') }
        lastSeen  = $now.ToString('o')
        banUntil  = $banUntil.ToString('o')
        strikes   = if ($existing -and $existing['strikes']) { [int]$existing['strikes'] } else { 1 }
        lastCount = if ($existing -and $existing['lastCount']) { $existing['lastCount'] } else { 0 }
        active    = $true
        manual    = $true
    }
    Update-RGFirewall -State $state -Config $cfg | Out-Null
    Save-RGState -Config $cfg -State $state
    Write-RGLog -Config $cfg -Level Warning -EventId 1003 -Message "Manually blocked $IP until $($banUntil.ToString('u'))."
    Write-Host "Blocked $IP until $($banUntil.ToString('u'))."
}

function Unblock-RDPGuardIP {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$IP)
    $cfg = Get-RGConfig
    $state = Get-RGState -Config $cfg
    if ($state.ContainsKey($IP)) { $state.Remove($IP) }
    Update-RGFirewall -State $state -Config $cfg | Out-Null
    Save-RGState -Config $cfg -State $state
    Write-RGLog -Config $cfg -Level Information -EventId 1004 -Message "Manually unblocked $IP."
    Write-Host "Unblocked $IP (removed from state and firewall)."
}

function Get-RDPGuardReport {
    [CmdletBinding()]
    param([double]$Hours = 24, [int]$Top = 20)
    $start = (Get-Date).AddHours(-$Hours)
    $counts = @{}; $userCounts = @{}

    try {
        $sec = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4625; StartTime=$start } -ErrorAction SilentlyContinue
        foreach ($e in @($sec)) {
            $x  = [xml]$e.ToXml()
            $ip = ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
            $u  = ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
            if ($ip -and $ip -ne '-') { $counts[$ip] = 1 + ($counts[$ip]) }
            if ($u) { $userCounts[$u] = 1 + ($userCounts[$u]) }
        }
    } catch { }

    try {
        $rdp = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'; Id=140; StartTime=$start } -ErrorAction SilentlyContinue
        foreach ($e in @($rdp)) {
            $x  = [xml]$e.ToXml()
            $ip = $null
            if ($x.Event.UserData -and $x.Event.UserData.EventXML) { $ip = $x.Event.UserData.EventXML.Param1 }
            if (-not $ip -and $e.Message -match '(\d{1,3}\.){3}\d{1,3}') { $ip = $Matches[0] }
            if ($ip) { $counts[$ip] = 1 + ($counts[$ip]) }
        }
    } catch { }

    $success = @()
    try {
        $sx = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Id=1149; StartTime=$start } -ErrorAction SilentlyContinue
        foreach ($e in @($sx)) {
            $x = [xml]$e.ToXml()
            $u = $x.Event.UserData.EventXML.Param1
            $d = $x.Event.UserData.EventXML.Param2
            $src = $x.Event.UserData.EventXML.Param3
            $success += [pscustomobject]@{ Time = $e.TimeCreated; User = "$d\$u"; Source = $src }
        }
    } catch { }

    Write-Host "`n=== RDP-Guard report (last $Hours h) ===" -ForegroundColor Cyan
    Write-Host "`nTop offending source IPs (failed attempts):"
    $counts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First $Top |
        ForEach-Object { [pscustomobject]@{ IP = $_.Key; Failures = $_.Value } } | Format-Table -AutoSize | Out-Host
    Write-Host "Most-targeted usernames:"
    $userCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First $Top |
        ForEach-Object { [pscustomobject]@{ User = $_.Key; Attempts = $_.Value } } | Format-Table -AutoSize | Out-Host
    Write-Host "Successful RDP authentications (Event 1149) - review these closely:"
    if (@($success).Count) { $success | Sort-Object Time -Descending | Format-Table -AutoSize | Out-Host }
    else { Write-Host "  (none in window)`n" }
    Write-Host "Currently active bans:"
    $bans = Get-RDPGuardBans
    if (@($bans).Count) { $bans | Format-Table -AutoSize | Out-Host } else { Write-Host "  (none)`n" }
}

Export-ModuleMember -Function Get-RDPGuardBans, Block-RDPGuardIP, Unblock-RDPGuardIP, Get-RDPGuardReport
