@echo off
setlocal

set "RDP_GUARD_CMD_PATH=%~f0"
set "RDP_GUARD_PS1=%TEMP%\Install-RDPGuard-%RANDOM%-%RANDOM%.ps1"

powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $cmd=$env:RDP_GUARD_CMD_PATH; $marker=':__RDP_GUARD_PS1__'; $raw=Get-Content -LiteralPath $cmd -Raw; $idx=$raw.LastIndexOf($marker); if ($idx -lt 0) { throw 'PowerShell payload marker not found.' }; $script=$raw.Substring($idx + $marker.Length); Set-Content -LiteralPath $env:RDP_GUARD_PS1 -Value $script -Encoding UTF8"
if errorlevel 1 exit /b %errorlevel%

powershell -NoProfile -ExecutionPolicy Bypass -File "%RDP_GUARD_PS1%" %*
set "RDP_GUARD_EXIT=%ERRORLEVEL%"
del "%RDP_GUARD_PS1%" >nul 2>nul
exit /b %RDP_GUARD_EXIT%

:__RDP_GUARD_PS1__
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repoZip = 'https://github.com/smartboy223/RDP-Guard/archive/refs/heads/main.zip'
$repoPattern = 'smartboy223[/\\]RDP-Guard'
$installRoot = 'C:\Security\RDP-Guard'
$installParent = Split-Path -Parent $installRoot

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Read-JsonFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
    } catch {
        Write-Warning "Could not parse existing config: $Path"
        return $null
    }
}

function Merge-ConfigObject {
    param($Base, $Override)
    if ($null -eq $Base) { return $Override }
    if ($null -eq $Override) { return $Base }

    foreach ($prop in $Override.PSObject.Properties) {
        $target = $Base.PSObject.Properties[$prop.Name]
        if ($target -and $target.Value -is [pscustomobject] -and $prop.Value -is [pscustomobject]) {
            Merge-ConfigObject -Base $target.Value -Override $prop.Value | Out-Null
        } elseif ($target) {
            $target.Value = $prop.Value
        } else {
            $Base | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $prop.Value
        }
    }
    return $Base
}

function Save-JsonFile {
    param($Object, [string]$Path)
    $Object | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Test-GitAvailable {
    try {
        & git --version *> $null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

function Update-FromGit {
    if (-not (Test-GitAvailable)) { return $false }
    if (-not (Test-Path -LiteralPath (Join-Path $installRoot '.git'))) { return $false }

    Push-Location $installRoot
    try {
        $origin = (& git remote get-url origin 2>$null)
        if ($LASTEXITCODE -ne 0 -or $origin -notmatch $repoPattern) { return $false }

        $dirty = @(& git status --porcelain)
        $blockingDirty = @($dirty | Where-Object {
            $_ -notmatch '^\s*M\s+config\.json$' -and
            $_ -notmatch '^\s*\?\?\s+'
        })
        if ($blockingDirty.Count -gt 0) {
            Write-Warning 'This git checkout has local source changes. Update stopped so they are not overwritten.'
            $blockingDirty | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
            throw 'Commit, stash, or remove local source changes, then rerun Install-RDPGuard.cmd.'
        }

        if ($dirty -match 'config\.json$') {
            & git checkout -- config.json *> $null
        }

        Write-Host 'Updating existing git checkout...' -ForegroundColor Cyan
        & git fetch origin main
        if ($LASTEXITCODE -ne 0) { throw 'git fetch failed.' }
        & git pull --ff-only origin main
        if ($LASTEXITCODE -ne 0) { throw 'git pull --ff-only failed.' }
        return $true
    } finally {
        Pop-Location
    }
}

function Update-FromZip {
    Write-Host 'Downloading latest RDP-Guard files...' -ForegroundColor Cyan
    New-Item -ItemType Directory -Force -Path $installParent | Out-Null
    if (-not (Test-Path -LiteralPath $installRoot)) {
        New-Item -ItemType Directory -Force -Path $installRoot | Out-Null
    }

    $tempRoot = Join-Path $env:TEMP ("RDP-Guard-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null
    try {
        $zip = Join-Path $tempRoot 'RDP-Guard.zip'
        Invoke-WebRequest -UseBasicParsing -Uri $repoZip -OutFile $zip
        Expand-Archive -Path $zip -DestinationPath $tempRoot -Force
        $source = Join-Path $tempRoot 'RDP-Guard-main'
        if (-not (Test-Path -LiteralPath $source)) { throw 'Downloaded archive did not contain RDP-Guard-main.' }

        Get-ChildItem -LiteralPath $source -Force | ForEach-Object {
            Copy-Item -LiteralPath $_.FullName -Destination $installRoot -Recurse -Force
        }
    } finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Read-RdpPort {
    param([int]$DefaultPort)
    while ($true) {
        $raw = Read-Host "RDP listening port to protect [$DefaultPort]"
        if ([string]::IsNullOrWhiteSpace($raw)) { return $DefaultPort }

        $port = 0
        if ([int]::TryParse($raw, [ref]$port) -and $port -ge 1 -and $port -le 65535) {
            return $port
        }
        Write-Host 'Enter a TCP port from 1 to 65535.' -ForegroundColor Yellow
    }
}

try {
    if (-not (Test-Admin)) {
        $cmd = $env:RDP_GUARD_CMD_PATH
        Write-Host 'RDP-Guard installer needs Administrator rights. Opening UAC prompt...' -ForegroundColor Yellow
        Start-Process -FilePath $env:ComSpec -ArgumentList @('/c', "`"$cmd`"") -Verb RunAs
        exit 0
    }

    Write-Host '==================== RDP-Guard bootstrap install ====================' -ForegroundColor Cyan
    Write-Host "Install folder: $installRoot"
    Write-Host 'Existing config/state are preserved; source files are updated in place.'

    $existingConfigPath = Join-Path $installRoot 'config.json'
    $existingConfig = Read-JsonFile -Path $existingConfigPath

    $updatedWithGit = $false
    if (Test-Path -LiteralPath $installRoot) {
        $updatedWithGit = Update-FromGit
    }
    if (-not $updatedWithGit) {
        Update-FromZip
    }

    $configPath = Join-Path $installRoot 'config.json'
    $config = Read-JsonFile -Path $configPath
    if ($null -eq $config) { throw "Missing or invalid config after update: $configPath" }
    if ($existingConfig) { $config = Merge-ConfigObject -Base $config -Override $existingConfig }

    $defaultPort = 4002
    if ($config.PSObject.Properties['rdpPort']) { $defaultPort = [int]$config.rdpPort }
    $port = Read-RdpPort -DefaultPort $defaultPort

    $config.rdpPort = $port
    if (-not $config.PSObject.Properties['allowRuleName']) {
        $config | Add-Member -NotePropertyName 'allowRuleName' -NotePropertyValue 'RDP-Guard-Allow'
    }
    Save-JsonFile -Object $config -Path $configPath
    Write-Host "Configured RDP port: $port" -ForegroundColor Green

    Write-Host "`nRunning installer..." -ForegroundColor Cyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $installRoot 'Install.ps1')
    if ($LASTEXITCODE -ne 0) { throw "Install.ps1 failed with exit code $LASTEXITCODE." }

    Write-Host "`nRunning validation..." -ForegroundColor Cyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $installRoot 'Test-RDPGuard.ps1')
    exit $LASTEXITCODE
} catch {
    Write-Host "`nRDP-Guard install failed: $($_.Exception.Message)" -ForegroundColor Red
    Read-Host 'Press Enter to close'
    exit 1
}
