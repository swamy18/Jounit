#requires -Version 5.1
<#
.SYNOPSIS
    Deletes build trash once the repository grows past a size threshold.

.DESCRIPTION
    `target/` is regenerable and already gitignored, but a few test runs put it
    back at multiple gigabytes. This deletes only regenerable, gitignored paths,
    and only when the repository is actually over the threshold - so a small
    checkout is never touched.

    Safety, because a wrong cleanup costs a full rebuild:
      * it refuses to run while cargo or rustc is building (unless -Force);
      * it deletes only paths matched by the trash list, which .gitignore
        already excludes, so no tracked file can ever be removed;
      * it has a cooldown, so a scheduled task cannot thrash the target dir.

.PARAMETER ThresholdGB
    Size, in GB, over which cleanup happens. Default 1.

.PARAMETER CooldownHours
    Minimum hours between cleanups. Default 6. Ignored by -Force.

.PARAMETER Force
    Clean even if a build is running or the cooldown has not elapsed.

.EXAMPLE
    .\scripts\clean-trash.ps1
    .\scripts\clean-trash.ps1 -ThresholdGB 0.5 -WhatIf
    .\scripts\clean-trash.ps1 -Force
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [double]$ThresholdGB = 1.0,
    [int]$CooldownHours = 6,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The script lives in <repo>/scripts, so one level up is the repository root.
# Guard it: a wrong root here would aim the cleanups somewhere else entirely,
# which is the one failure this script must not have.
$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot '.git'))) {
    throw "no .git at '$RepoRoot' - refusing to clean an unknown directory"
}
$StateDir = Join-Path $env:LOCALAPPDATA 'Jounit'
$StateFile = Join-Path $StateDir 'clean-trash.state'
$LogFile = Join-Path $StateDir 'clean-trash.log'

# Only regenerable, gitignored paths. The whole `target/` is the point: it is a
# build cache, so deleting it costs rebuild time and nothing else.
$TrashDirs = @(
    'target'
    '.freebuff'
    'fuzz/artifacts'
    'fuzz/corpus'
    'sim/__pycache__'
)

function Write-Log {
    param([string]$Message)
    $line = "{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Write-Host $line
    # A dry run reports and stops there: it must leave no trace of itself.
    if ($WhatIfPreference) { return }
    if (-not (Test-Path -LiteralPath $StateDir)) {
        New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
    }
    Add-Content -LiteralPath $LogFile -Value $line -ErrorAction SilentlyContinue
}

function Get-DirSizeBytes {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    $sum = (Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum).Sum
    if ($null -eq $sum) { return 0 }
    return [int64]$sum
}

$thresholdBytes = [int64]($ThresholdGB * 1GB)
$before = Get-DirSizeBytes -Path $RepoRoot

if ($before -le $thresholdBytes) {
    Write-Log ("under threshold: {0:N2} GB of {1:N2} GB - nothing to do" -f ($before/1GB), $ThresholdGB)
    exit 0
}

# A cleanup mid-build throws the build away and can leave a half-written cache.
$building = Get-Process -Name cargo, rustc -ErrorAction SilentlyContinue
if ($building -and -not $Force) {
    Write-Log ("{0:N2} GB but a build is running ({1}) - skipping" -f ($before/1GB), ($building.Name -join ', '))
    exit 0
}

if (-not $Force) {
    $lastClean = 0L
    if (Test-Path -LiteralPath $StateFile) {
        $raw = (Get-Content -LiteralPath $StateFile -Raw -ErrorAction SilentlyContinue)
        [void][int64]::TryParse($raw, [ref]$lastClean)
    }
    $elapsedHours = ((Get-Date).ToUniversalTime() - [DateTimeOffset]::FromUnixTimeSeconds($lastClean).UtcDateTime).TotalHours
    if ($lastClean -gt 0 -and $elapsedHours -lt $CooldownHours) {
        Write-Log ("{0:N2} GB but cleaned {1:N1} h ago (cooldown {2} h) - skipping" -f ($before/1GB), $elapsedHours, $CooldownHours)
        exit 0
    }
}

$freed = 0L
foreach ($rel in $TrashDirs) {
    $path = Join-Path $RepoRoot $rel
    if (-not (Test-Path -LiteralPath $path)) { continue }

    # Never remove anything git tracks: a tracked path in the list would be a
    # mistake, and this makes that mistake impossible rather than unlikely.
    $tracked = & git -C $RepoRoot ls-files -- "$rel" 2>$null
    if ($tracked) {
        Write-Log "REFUSING to delete '$rel': git tracks files under it"
        continue
    }

    $size = Get-DirSizeBytes -Path $path
    if ($size -eq 0) { continue }
    if ($PSCmdlet.ShouldProcess($path, "delete")) {
        Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
        $freed += $size
        Write-Log ("deleted {0,-16} {1,8:N1} MB" -f $rel, ($size/1MB))
    }
}

if (-not $WhatIfPreference) {
    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
    Set-Content -LiteralPath $StateFile -Value ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) -NoNewline
}

$after = Get-DirSizeBytes -Path $RepoRoot
Write-Log ("freed {0:N2} GB, repository now {1:N2} GB" -f ($freed/1GB), ($after/1GB))
exit 0
