# RDP-Guard.ps1 - engine. Run by the scheduled task at startup and every minute.
# Reads failed RDP attempts from the Security log (4625) AND the RDP core log
# (RdpCoreTS/Operational 140), bans source IPs over threshold via one firewall
# rule, enforces ban expiry, and logs to the RDP-Guard event log.
#
# Manual / test run:   powershell -ExecutionPolicy Bypass -File RDP-Guard.ps1 -DryRun
[CmdletBinding()]
param([switch]$DryRun)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'RDP-Guard.Common.ps1')

# Single-instance guard so overlapping runs can't race on state/firewall.
$mutex = New-Object System.Threading.Mutex($false, 'Global\RDP-Guard-Engine')
if (-not $mutex.WaitOne(0)) { return }

try {
    $cfg   = Get-RGConfig
    $state = Get-RGState -Config $cfg
    $now   = Get-Date

    # ---- 1) Expire old bans (log transitions); purge ancient records ----
    $retentionDays = [int](Get-RGProp $cfg 'retentionDays' 30)
    $toRemove = @()
    foreach ($ip in @($state.Keys)) {
        $e = $state[$ip]
        $until    = if ($e['banUntil']) { [datetime]$e['banUntil'] } else { [datetime]::MinValue }
        $wasActive = [bool]$e['active']
        $isActive  = $until -gt $now
        if ($wasActive -and -not $isActive) {
            Write-RGLog -Config $cfg -Level Information -EventId 1002 `
                -Message "Ban expired for $ip (strikes=$($e['strikes'])). Unblocking."
        }
        $e['active'] = $isActive
        if (-not $isActive -and $until -ne [datetime]::MinValue) {
            $lastSeen = if ($e['lastSeen']) { [datetime]$e['lastSeen'] } else { $until }
            if ($lastSeen -lt $now.AddDays(-$retentionDays)) { $toRemove += $ip }
        }
    }
    foreach ($ip in $toRemove) { $state.Remove($ip) }

    # ---- 2) Collect failed-attempt source IPs from both logs ----
    $startTime = $now.AddMinutes(-[int]$cfg.lookbackMinutes)
    $counts = @{}

    # 2a) Security log, Event 4625 (failed credential logon)
    try {
        $sec = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4625; StartTime=$startTime } -ErrorAction SilentlyContinue
        foreach ($evt in @($sec)) {
            try {
                $x  = [xml]$evt.ToXml()
                $ip = ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
                if ($ip) {
                    $ip = $ip.Trim()
                    if ($ip -and $ip -ne '-' -and $ip -ne '::1' -and $ip -ne '127.0.0.1') {
                        if ($counts.ContainsKey($ip)) { $counts[$ip]++ } else { $counts[$ip] = 1 }
                    }
                }
            } catch { }
        }
    } catch { }

    # 2b) RDP core log, Event 140 (failed/aborted RDP connection - catches NLA
    #     pre-auth scanner hits that never produce a 4625)
    try {
        $rdp = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'; Id=140; StartTime=$startTime } -ErrorAction SilentlyContinue
        foreach ($evt in @($rdp)) {
            try {
                $x  = [xml]$evt.ToXml()
                $ip = $null
                if ($x.Event.UserData -and $x.Event.UserData.EventXML) { $ip = $x.Event.UserData.EventXML.Param1 }
                if ([string]::IsNullOrWhiteSpace($ip) -and $evt.Message -match '(\d{1,3}\.){3}\d{1,3}') { $ip = $Matches[0] }
                if ($ip) {
                    $ip = $ip.Trim()
                    if ($ip -and $ip -ne '-' -and $ip -ne '::1' -and $ip -ne '127.0.0.1') {
                        if ($counts.ContainsKey($ip)) { $counts[$ip]++ } else { $counts[$ip] = 1 }
                    }
                }
            } catch { }
        }
    } catch { }

    # ---- 3) Apply bans ----
    $threshold    = [int]$cfg.threshold
    $baseBanHours = [double]$cfg.banHours
    $esc          = Get-RGProp $cfg 'escalation' $null
    $escalationOn = [bool](Get-RGProp $esc 'enabled' $false)
    $mult         = [double](Get-RGProp $esc 'multiplierPerStrike' 2)
    $maxBan       = [double](Get-RGProp $esc 'maxBanHours' 720)

    $newBans = @()
    foreach ($ip in $counts.Keys) {
        if ($counts[$ip] -lt $threshold) { continue }
        if (Test-RGWhitelisted -IP $ip -Config $cfg) { continue }

        $existing = if ($state.ContainsKey($ip)) { $state[$ip] } else { $null }
        $alreadyActive = $false
        if ($existing -and $existing['banUntil']) {
            $alreadyActive = ([datetime]$existing['banUntil']) -gt $now
        }
        if ($alreadyActive) {
            $existing['lastSeen']  = $now.ToString('o')
            $existing['lastCount'] = $counts[$ip]
            continue
        }

        $strikes = if ($existing -and $existing['strikes']) { [int]$existing['strikes'] + 1 } else { 1 }
        $banHours = if ($escalationOn) { [Math]::Min($baseBanHours * [Math]::Pow($mult, $strikes - 1), $maxBan) } else { $baseBanHours }
        $banUntil = $now.AddHours($banHours)

        $state[$ip] = @{
            ip        = $ip
            firstSeen = if ($existing -and $existing['firstSeen']) { $existing['firstSeen'] } else { $now.ToString('o') }
            lastSeen  = $now.ToString('o')
            banUntil  = $banUntil.ToString('o')
            strikes   = $strikes
            lastCount = $counts[$ip]
            active    = $true
            manual    = $false
        }
        $newBans += "$ip ($($counts[$ip]) fails, strike #$strikes, $([Math]::Round($banHours,2))h)"
        if (-not $DryRun) {
            Write-RGLog -Config $cfg -Level Warning -EventId 1001 `
                -Message "Blocked $ip after $($counts[$ip]) failed RDP attempts in $($cfg.lookbackMinutes) min. Strike #$strikes, banned $([Math]::Round($banHours,2)) h (until $($banUntil.ToString('u')))."
        }
    }

    # ---- 4) Rebuild firewall + persist ----
    if ($DryRun) {
        $activeNow = @(Get-RGActiveIPs -State $state)
        Write-Host "[DryRun] window start: $startTime"
        Write-Host "[DryRun] distinct source IPs seen: $($counts.Count)"
        Write-Host "[DryRun] would newly ban: $(if ($newBans.Count) { $newBans -join '; ' } else { '(none)' })"
        Write-Host "[DryRun] active bans after run: $($activeNow.Count) -> $($activeNow -join ', ')"
        Write-Host "[DryRun] no firewall/state changes were written."
    } else {
        Update-RGFirewall -State $state -Config $cfg | Out-Null
        Save-RGState -Config $cfg -State $state
    }
}
catch {
    Write-RGLog -Level Error -EventId 1009 -Message "RDP-Guard engine error: $($_.Exception.Message)"
}
finally {
    $mutex.ReleaseMutex() | Out-Null
    $mutex.Dispose()
}
