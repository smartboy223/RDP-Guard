# RDP-Guard.Common.ps1
# Shared helpers for the RDP-Guard engine, admin module, and installer.
# Dot-source this file:  . (Join-Path $PSScriptRoot 'RDP-Guard.Common.ps1')
#
# Works in both Windows PowerShell 5.1 and PowerShell 7+. Event logging uses the
# .NET System.Diagnostics.EventLog API (not the *-EventLog cmdlets, which are
# absent from PowerShell 7) so it behaves identically under either host.

# Root folder = folder containing this file (set even when dot-sourced).
$script:RGRoot = $PSScriptRoot

function Get-RGProp {
    # Safe optional-property read for ConvertFrom-Json objects (PSCustomObject).
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    $prop = $Object.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $Default
}

function Get-RGConfig {
    $path = Join-Path $script:RGRoot 'config.json'
    if (-not (Test-Path $path)) { throw "Config not found: $path" }
    return (Get-Content -Path $path -Raw | ConvertFrom-Json)
}

function Get-RGStatePath {
    param($Config)
    $name = Get-RGProp $Config 'stateFile' 'state.json'
    if ([System.IO.Path]::IsPathRooted($name)) { return $name }
    return (Join-Path $script:RGRoot $name)
}

function ConvertTo-RGHashtable {
    # Flatten a JSON state entry (PSCustomObject) into a mutable hashtable.
    param($Object)
    $h = @{}
    if ($null -eq $Object) { return $h }
    foreach ($p in $Object.PSObject.Properties) { $h[$p.Name] = $p.Value }
    return $h
}

function Get-RGState {
    # Returns a hashtable keyed by IP; each value is itself a hashtable.
    param($Config)
    $path = Get-RGStatePath -Config $Config
    if (-not (Test-Path $path)) { return @{} }
    try {
        $raw = Get-Content -Path $path -Raw
        if ([string]::IsNullOrWhiteSpace($raw)) { return @{} }
        $obj = $raw | ConvertFrom-Json
        $ht = @{}
        foreach ($p in $obj.PSObject.Properties) {
            $ht[$p.Name] = ConvertTo-RGHashtable $p.Value
        }
        return $ht
    } catch {
        return @{}
    }
}

function Save-RGState {
    param($Config, [hashtable]$State)
    $path = Get-RGStatePath -Config $Config
    $obj = [ordered]@{}
    foreach ($k in ($State.Keys | Sort-Object)) { $obj[$k] = $State[$k] }
    if ($obj.Count -eq 0) {
        Set-Content -Path $path -Value '{}' -Encoding UTF8
    } else {
        ($obj | ConvertTo-Json -Depth 6) | Set-Content -Path $path -Encoding UTF8
    }
}

function Test-IpInCidr {
    # Correct CIDR membership for IPv4 and IPv6 (replaces the original -like hacks).
    param([string]$IP, [string]$Cidr)
    if ([string]::IsNullOrWhiteSpace($Cidr)) { return $false }
    if ($Cidr -notmatch '/') { return ($IP -eq $Cidr) }

    $parts   = $Cidr.Split('/')
    $network = $parts[0]
    [int]$prefix = $parts[1]

    $ipAddr = $null; $netAddr = $null
    if (-not [System.Net.IPAddress]::TryParse($IP, [ref]$ipAddr))      { return $false }
    if (-not [System.Net.IPAddress]::TryParse($network, [ref]$netAddr)) { return $false }
    if ($ipAddr.AddressFamily -ne $netAddr.AddressFamily) { return $false }

    $ipBytes  = $ipAddr.GetAddressBytes()
    $netBytes = $netAddr.GetAddressBytes()
    if ($ipBytes.Length -ne $netBytes.Length) { return $false }

    $bitsLeft = $prefix
    for ($i = 0; $i -lt $ipBytes.Length; $i++) {
        if ($bitsLeft -le 0) { break }
        $take = [Math]::Min(8, $bitsLeft)
        $mask = [byte](((0xFF -shl (8 - $take)) -band 0xFF))
        if (($ipBytes[$i] -band $mask) -ne ($netBytes[$i] -band $mask)) { return $false }
        $bitsLeft -= 8
    }
    return $true
}

function Test-RGWhitelisted {
    param([string]$IP, $Config)
    if ([string]::IsNullOrWhiteSpace($IP) -or $IP -eq '-' -or $IP -eq '::') { return $true }
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($IP, [ref]$parsed)) { return $true }  # junk -> never block
    foreach ($entry in (Get-RGProp $Config 'whitelist' @())) {
        if (Test-IpInCidr -IP $IP -Cidr $entry) { return $true }
    }
    return $false
}

function Write-RGLog {
    param(
        [string]$Message,
        [ValidateSet('Information','Warning','Error')][string]$Level = 'Information',
        [int]$EventId = 1000,
        $Config
    )
    $logName = Get-RGProp $Config 'eventLogName' 'RDP-Guard'
    $source  = Get-RGProp $Config 'eventSource'  'RDP-Guard'
    $type    = [System.Diagnostics.EventLogEntryType]::$Level
    try {
        [System.Diagnostics.EventLog]::WriteEntry($source, $Message, $type, $EventId)
    } catch {
        try {
            $fallback = Join-Path $script:RGRoot 'rdp-guard.log'
            Add-Content -Path $fallback -Value ("{0} [{1}] ({2}) {3}" -f (Get-Date).ToString('s'), $Level, $EventId, $Message)
        } catch { }
    }
}

function Get-RGActiveIPs {
    param([hashtable]$State)
    $now = Get-Date
    $active = @()
    foreach ($k in $State.Keys) {
        $bu = $State[$k]['banUntil']
        if ($bu -and ([datetime]$bu) -gt $now) { $active += $k }
    }
    # Return plainly; callers normalize with @(...). (Do NOT use ',$active' here -
    # combined with the callers' @() it double-nests the array.)
    return $active
}

function Update-RGFirewall {
    # Rebuilds the single block rule from currently-active bans. Block rules
    # take precedence over the RDP allow rule, so listed IPs cannot reach RDP.
    param([hashtable]$State, $Config)
    $ruleName = Get-RGProp $Config 'blockRuleName' 'RDP-Guard-Block'
    $active   = @(Get-RGActiveIPs -State $State)

    $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    $current = @()
    if ($existingRule) {
        try { $current = @(($existingRule | Get-NetFirewallAddressFilter).RemoteAddress) } catch { $current = @() }
        $current = @($current | Where-Object { $_ -and $_ -ne 'Any' })
    }

    # No-op if the desired set already matches (avoids needless churn / gaps).
    $diff = Compare-Object -ReferenceObject @($current | Sort-Object) -DifferenceObject @($active | Sort-Object)
    if (-not $diff) { return $active.Count }

    if ($existingRule) { $existingRule | Remove-NetFirewallRule -ErrorAction SilentlyContinue }
    if ($active.Count -gt 0) {
        New-NetFirewallRule -DisplayName $ruleName `
            -Description 'Auto-managed by RDP-Guard. Blocks inbound from IPs with repeated failed RDP logons. Do not edit by hand.' `
            -Direction Inbound -Action Block -RemoteAddress $active -Profile Any -ErrorAction Stop | Out-Null
    }
    return $active.Count
}
