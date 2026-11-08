# Builds the release archives (see build/release/main.go for what is produced).
#
#   powershell -NoProfile -File build\build.ps1 [-Version X] [-Go path\to\go] [-Targets os/arch,...] [-Out dir]
#
# -Version defaults to the tag on HEAD without the leading "v"; an untagged HEAD needs -Version.
param(
    [string]$Version = '',
    [string]$Go = 'go',
    [string]$Targets = '',
    [string]$Out = ''
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not $Version) {
    $tag = $null
    try { $tag = (& git describe --tags --exact-match HEAD 2>$null) } catch { $tag = $null }
    if ($LASTEXITCODE -ne 0 -or -not $tag) {
        Write-Host 'HEAD is not tagged: pass -Version <version>.'
        exit 1
    }
    $Version = ([string]$tag).Trim() -replace '^v', ''
}

$env:GOTOOLCHAIN = 'local'
$env:GOFLAGS = '-mod=mod'
$env:CGO_ENABLED = '0'
if (-not $env:GOMODCACHE) { $env:GOMODCACHE = Join-Path $root '.modcache' }
if (-not $env:GOCACHE) { $env:GOCACHE = Join-Path $root '.gocache' }

$goArgs = @('run', './build/release', '-version', $Version, '-go', $Go)
if ($Targets) { $goArgs += @('-targets', $Targets) }
if ($Out) { $goArgs += @('-out', $Out) }

& $Go @goArgs
exit $LASTEXITCODE
