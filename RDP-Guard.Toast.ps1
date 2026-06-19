#Requires -Version 5.1
<#
.SYNOPSIS
  Shows a local Windows toast for an RDP-Guard event. Run by user-context,
  event-triggered tasks (RDP-Guard-Toast-Ban / -Login). Nothing leaves the
  machine. Modern ToastGeneric layout, branded "RDP-Guard" app name, tray-balloon
  fallback.

.NOTES
  This file is intentionally ASCII-only. Windows PowerShell 5.1 reads .ps1 files as
  the system ANSI code page when there is no BOM, which corrupts characters like an
  em-dash. Any non-ASCII glyphs (emoji) are therefore built at runtime from numeric
  code points via [char]::ConvertFromUtf32(), which is encoding-safe.

.PARAMETER Kind
  'Ban'   -> latest RDP-Guard block event.   'Login' -> latest successful RDP logon.
.PARAMETER Demo
  Show representative example text instead of reading the event logs.
#>
[CmdletBinding()]
param(
    [ValidateSet('Ban', 'Login')][string]$Kind = 'Ban',
    [switch]$Demo
)

$AppId = 'RDPGuard.Alerts'

function Register-RGAppId {
    # Brands the toast as "RDP-Guard" (per-user, HKCU; no admin needed).
    try {
        $reg = "HKCU:\Software\Classes\AppUserModelId\$AppId"
        if (-not (Test-Path $reg)) { New-Item -Path $reg -Force | Out-Null }
        Set-ItemProperty -Path $reg -Name 'DisplayName' -Value 'RDP-Guard' -ErrorAction SilentlyContinue
        foreach ($ic in @("$env:SystemRoot\System32\SecurityAndMaintenance.png", "$env:SystemRoot\System32\@WLOGO_48x48.png")) {
            if (Test-Path $ic) { Set-ItemProperty -Path $reg -Name 'IconUri' -Value $ic -ErrorAction SilentlyContinue; break }
        }
    } catch { }
}

function ConvertTo-XmlText { param([string]$s) ($s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;') }

function Show-Toast {
    param([string]$Title, [string]$Body, [string]$Attribution)
    try {
        $null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
        $null = [Windows.UI.Notifications.ToastNotification, Windows.UI.Notifications, ContentType = WindowsRuntime]
        $null = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, ContentType = WindowsRuntime]
        $t = ConvertTo-XmlText $Title
        $b = ConvertTo-XmlText $Body
        $a = ConvertTo-XmlText $Attribution
        $xmlStr = "<toast><visual><binding template=`"ToastGeneric`"><text>$t</text><text>$b</text><text placement=`"attribution`">$a</text></binding></visual></toast>"
        $xml = [Windows.Data.Xml.Dom.XmlDocument]::new()
        $xml.LoadXml($xmlStr)
        $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AppId).Show($toast)
        return $true
    } catch { return $false }
}

function Show-Balloon {
    param([string]$Title, [string]$Body)
    try {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        $ni = New-Object System.Windows.Forms.NotifyIcon
        $ni.Icon = [System.Drawing.SystemIcons]::Shield
        $ni.Visible = $true
        $ni.ShowBalloonTip(8000, $Title, $Body, [System.Windows.Forms.ToolTipIcon]::Warning)
        Start-Sleep -Seconds 9
        $ni.Dispose()
    } catch { }
}

# Encoding-safe glyphs
$gShield = [char]::ConvertFromUtf32(0x1F6E1) + [char]::ConvertFromUtf32(0xFE0F)  # shield
$gKey    = [char]::ConvertFromUtf32(0x1F511)                                      # key

$plainTitle = 'RDP-Guard'
$body       = ''
$attr       = 'RDP-Guard | ' + (Get-Date).ToString('ddd HH:mm')

try {
    if ($Kind -eq 'Ban') {
        $plainTitle = 'Threat blocked'
        if ($Demo) {
            $body = '6 failed sign-ins from 203.0.113.45 - now blocked.'
        } else {
            $e = Get-WinEvent -FilterHashtable @{ LogName = 'RDP-Guard' } -MaxEvents 1 -ErrorAction SilentlyContinue
            $msg = if ($e) { $e.Message } else { 'An IP was blocked.' }
            if ($msg -match 'Blocked (\S+) after (\d+) failed') {
                $body = "$($Matches[2]) failed sign-ins from $($Matches[1]) - now blocked."
            } elseif ($msg -match 'Manually blocked (\S+)') {
                $body = "Manually blocked $($Matches[1])."
            } elseif ($msg -match 'Ban expired for (\S+)') {
                $plainTitle = 'Ban lifted'; $body = "Ban expired for $($Matches[1])."
            } else { $body = $msg }
        }
        $toastTitle = "$gShield $plainTitle"
    } else {
        $plainTitle = 'New RDP sign-in'
        if ($Demo) {
            $body = "$env:USERDOMAIN\$env:USERNAME connected from 45.155.44.49"
        } else {
            $e = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Id = 1149 } -MaxEvents 1 -ErrorAction SilentlyContinue
            if ($e) {
                $x = [xml]$e.ToXml()
                $u = $x.Event.UserData.EventXML.Param1
                $d = $x.Event.UserData.EventXML.Param2
                $src = $x.Event.UserData.EventXML.Param3
                $who = if ([string]::IsNullOrWhiteSpace($d)) { $u } else { "$d\$u" }
                $body = "$who connected from $src"
            } else { $body = 'An RDP login was detected.' }
        }
        $toastTitle = "$gKey $plainTitle"
    }
} catch { $body = 'RDP-Guard event.'; $toastTitle = $plainTitle }

if ($body.Length -gt 160) { $body = $body.Substring(0, 160) + '...' }

Register-RGAppId
if (-not (Show-Toast -Title $toastTitle -Body $body -Attribution $attr)) {
    Show-Balloon -Title $plainTitle -Body $body
}
