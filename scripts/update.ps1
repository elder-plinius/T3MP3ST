#Requires -Version 5.1
<#
.SYNOPSIS
  Safe upstream sync for T3MP3ST from elder-plinius/T3MP3ST.

.DESCRIPTION
  Backs up local secrets/config/artifacts, fetches upstream main, applies the update,
  restores protected paths, then runs npm install.

  Config outside this repo is never touched:
    %APPDATA%\t3mp3st-nodejs\Config\config.json  (npm run setup wizard)
    Browser localStorage "t3mp3st" on the War Room origin
    Local agent auth (~/.codex, %LOCALAPPDATA%\hermes, etc.)

.PARAMETER DryRun
  Preview only; no git or npm changes.

.PARAMETER Hard
  git reset --hard upstream/main after fetch (source edits in repo are discarded;
  protected files are still restored from backup).

.PARAMETER Force
  Skip the y/N confirmation prompt.

.PARAMETER KeepBackup
  Do not delete the temp backup folder after a successful run.
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Hard,
    [switch]$Force,
    [switch]$KeepBackup
)

$ErrorActionPreference = 'Stop'

$UpstreamUrl = 'https://github.com/elder-plinius/T3MP3ST.git'
$UpstreamBranch = 'main'
$UpstreamRemote = 'upstream'

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $RepoRoot

function Get-TerminalColumns {
    try {
        if ($Host.UI -and $Host.UI.RawUI) {
            $width = [int]$Host.UI.RawUI.WindowSize.Width
            if ($width -gt 0) { return $width }
        }
    } catch { }
    return 80
}

function Get-BannerCharDensity {
    param([char]$Char)
    $code = [int][char]$Char
    switch ($code) {
        0x2588 { return 5 } # █
        0x2593 { return 4 } # ▓
        0x2592 { return 3 } # ▒
        0x2584 { return 3 } # ▄
        0x2580 { return 3 } # ▀
        0x2591 { return 2 } # ░
        default { return 0 }
    }
}

function Merge-BannerChars {
    param([char]$Left, [char]$Right)
    $leftDensity = Get-BannerCharDensity $Left
    $rightDensity = Get-BannerCharDensity $Right
    if ($leftDensity -ge $rightDensity) { return $Left }
    return $Right
}

function Merge-BannerLines {
    param([string]$Top, [string]$Bottom)
    $length = [Math]::Max($Top.Length, $Bottom.Length)
    $top = $Top.PadRight($length)
    $bottom = $Bottom.PadRight($length)
    $builder = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $length; $i++) {
        [void]$builder.Append((Merge-BannerChars $top[$i] $bottom[$i]))
    }
    return $builder.ToString().TrimEnd()
}

function Scale-BannerLineHorizontal {
    param([string]$Line)
    if (-not $Line) { return '' }
    $builder = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $Line.Length; $i += 2) {
        $left = $Line[$i]
        $right = if (($i + 1) -lt $Line.Length) { $Line[$i + 1] } else { ' ' }
        [void]$builder.Append((Merge-BannerChars $left $right))
    }
    return $builder.ToString().TrimEnd()
}

function Scale-BannerLines {
    param([string[]]$Lines)
    $horizontal = foreach ($line in $Lines) {
        if ($line) { Scale-BannerLineHorizontal $line } else { '' }
    }
    $vertical = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $horizontal.Count; $i += 2) {
        if (($i + 1) -lt $horizontal.Count) {
            [void]$vertical.Add((Merge-BannerLines $horizontal[$i] $horizontal[$i + 1]))
        } else {
            [void]$vertical.Add($horizontal[$i])
        }
    }
    return @($vertical.ToArray())
}

function Get-BannerMaxWidth {
    param([string[]]$Lines)
    $max = 0
    foreach ($line in $Lines) {
        if ($line.Length -gt $max) { $max = $line.Length }
    }
    return $max
}

function Get-FitBannerLines {
    param(
        [string[]]$Lines,
        [int]$TerminalWidth
    )
    $margin = 2
    $target = [Math]::Max(24, $TerminalWidth - $margin)
    $current = @($Lines)
    while ((Get-BannerMaxWidth $current) -gt $target -and $current.Count -gt 1) {
        $current = @(Scale-BannerLines $current)
    }
    return @($current)
}

function Write-Banner {
    try {
        if ($Host.UI.RawUI) {
            $Host.UI.RawUI.WindowTitle = 'T3MP3ST Updater'
        }
        chcp 65001 | Out-Null
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    } catch { }

    $bannerFile = Join-Path $PSScriptRoot 'update-banner.txt'
    if (Test-Path $bannerFile) {
        $lines = @(Get-Content -Path $bannerFile -Encoding UTF8 | Where-Object { $_.Trim().Length -gt 0 })
        $fit = Get-FitBannerLines -Lines $lines -TerminalWidth (Get-TerminalColumns)
        foreach ($line in $fit) {
            Write-Host $line -ForegroundColor Cyan
        }
    } else {
        Write-Host 'T3MP3ST' -ForegroundColor Cyan
    }
    Write-Host '  T3MP3ST Updater' -ForegroundColor White
    Write-Host '  Safe upstream sync - secrets, config, and bench artifacts stay local' -ForegroundColor DarkGray
    Write-Host ''
}

$script:StepIndex = 0
$script:StepTotal = 0

function Write-Rule {
    param([string]$Title = '')
    $width = [Math]::Min(68, [Math]::Max(40, (Get-TerminalColumns)))
    Write-Host ''
    if ($Title) {
        $head = "-- $Title "
        $fill = [Math]::Max(0, $width - $Title.Length - 4)
        Write-Host ($head + ('-' * $fill)) -ForegroundColor Cyan
    } else {
        Write-Host ('-' * $width) -ForegroundColor DarkGray
    }
}

function Write-Kv {
    param(
        [string]$Key,
        [string]$Value,
        [ConsoleColor]$ValueColor = 'White'
    )
    Write-Host ('  {0,-12}' -f ($Key + ':')) -NoNewline -ForegroundColor DarkGray
    Write-Host $Value -ForegroundColor $ValueColor
}

function Write-PlanLine {
    param([string]$Icon, [string]$Text)
    Write-Host "    $Icon  $Text" -ForegroundColor Gray
}

function Get-UpdateStrategyLabel {
    if ($Hard) { return 'Hard reset to upstream/main' }
    if ((Get-LocalCommitCount) -eq 0) { return 'First-time sync (upstream snapshot)' }
    return 'Merge upstream/main'
}

function Get-UpdatePlanSteps {
    param([int]$ProtectedCount)
    $steps = New-Object System.Collections.Generic.List[string]
    if ($ProtectedCount -gt 0) {
        [void]$steps.Add("Back up $ProtectedCount protected path(s) to a temp folder")
    } else {
        [void]$steps.Add('Skip in-repo backup (no protected project files found)')
    }
    if (-not (Test-Path (Join-Path $RepoRoot '.git'))) {
        [void]$steps.Add('Initialize git and add upstream remote')
    } else {
        [void]$steps.Add('Use existing git repo and upstream remote')
    }
    [void]$steps.Add("Fetch $UpstreamRemote/$UpstreamBranch")
    if ($Hard) {
        [void]$steps.Add('Reset working tree to upstream/main')
    } elseif ((Get-LocalCommitCount) -eq 0) {
        [void]$steps.Add('Apply upstream snapshot to project files')
    } else {
        [void]$steps.Add('Merge upstream changes into your local branch')
    }
    if ($ProtectedCount -gt 0) {
        [void]$steps.Add('Restore backed-up protected paths')
    }
    [void]$steps.Add('Run npm install to refresh dependencies')
    return ,$steps.ToArray()
}

function Write-UpdatePlan {
    param([string[]]$Steps)
    $n = 1
    foreach ($step in $Steps) {
        Write-Host ('  {0,2}.' -f $n) -NoNewline -ForegroundColor Cyan
        Write-Host " $step" -ForegroundColor White
        $n++
    }
}

function Start-UpdateStep {
    param([string]$Message)
    $script:StepIndex++
    if ($script:StepTotal -gt 0) {
        Write-Host ""
        Write-Host "  [$($script:StepIndex)/$($script:StepTotal)] $Message" -ForegroundColor Cyan
    } else {
        Write-Host ""
        Write-Info $Message
    }
}

function Write-DoneBox {
    param(
        [string]$FromSha,
        [string]$ToSha,
        [switch]$Preview
    )
    Write-Rule 'Done'
    if ($Preview) {
        Write-Host '  Preview only - no files were changed.' -ForegroundColor Yellow
        Write-Host '  Run without --dry-run when you are ready.' -ForegroundColor DarkGray
    } else {
        Write-Host '  Update complete' -ForegroundColor Green
        Write-Kv 'Before' $FromSha
        Write-Kv 'After' $ToSha 'Green'
    }
    Write-Host ''
}

function Write-GitInstallHelp {
    Write-Err 'Git is required but was not found on PATH.'
    Write-Host ''
    Write-Host 'Install Git for Windows:' -ForegroundColor Yellow
    Write-Host '  https://git-scm.com/download/win'
    Write-Host ''
    Write-Host 'During setup, choose "Git from the command line and also from 3rd-party software".'
    Write-Host 'Then reopen your terminal and run:  npm run update'
}

function Write-NpmInstallHelp {
    Write-Err 'npm is required but was not found on PATH.'
    Write-Host ''
    Write-Host 'Install Node.js (includes npm): https://nodejs.org/' -ForegroundColor Yellow
    Write-Host 'Then run:  npm run update'
}

function Write-Info([string]$Message) { Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Ok([string]$Message) { Write-Host "[+] $Message" -ForegroundColor Green }
function Write-Warn([string]$Message) { Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Err([string]$Message) { Write-Host "[x] $Message" -ForegroundColor Red }

function Test-Command([string]$Name) {
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Invoke-Git {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$GitArgs)
    $oldErrorAction = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        # Git writes progress ("From https://...") to stderr even on success.
        # With $ErrorActionPreference = 'Stop' that can throw unless we normalize it.
        $output = & git @GitArgs 2>&1 | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) {
                $_.ToString()
            } else {
                $_
            }
        }
        if ($LASTEXITCODE -ne 0) {
            $text = ($output | Where-Object { $_ } | Out-String).Trim()
            throw "git $($GitArgs -join ' ') failed: $text"
        }
        if ($output) { return ($output | Out-String).Trim() }
        return ''
    } finally {
        $ErrorActionPreference = $oldErrorAction
    }
}

function Read-ProtectedManifest {
    $files = @(
        (Join-Path $PSScriptRoot 'update-protected.txt'),
        (Join-Path $PSScriptRoot 'update-protected.local.txt')
    )

    $patterns = New-Object System.Collections.Generic.List[string]
    foreach ($manifest in $files) {
        if (-not (Test-Path $manifest)) { continue }
        Get-Content $manifest | ForEach-Object {
            $line = $_.Trim()
            if (-not $line -or $line.StartsWith('#')) { return }
            [void]$patterns.Add($line)
        }
    }

    if ($patterns.Count -eq 0) {
        throw 'No protection patterns found in scripts/update-protected.txt'
    }
    return ,$patterns
}

function Test-MatchesProtectedPattern {
    param(
        [string]$RelativePath,
        [string]$Pattern
    )
    $rel = $RelativePath -replace '\\', '/'
    $pat = $Pattern -replace '\\', '/'

    if ($pat.StartsWith('!')) { return $false }

    if ($pat -match '[\*\?]') {
        $regex = '^' + ($pat -replace '\.', '\.' -replace '\*\*', '::DOUBLESTAR::' -replace '\*', '[^/]*' -replace '::DOUBLESTAR::', '.*') + '$'
        return [bool]($rel -match $regex)
    }

    if ($rel -eq $pat) { return $true }
    if ($pat.EndsWith('/') -and $rel.StartsWith($pat.TrimEnd('/'))) { return $true }
    return $false
}

function Get-ProtectedPaths {
    param([string[]]$Patterns)

    $results = New-Object System.Collections.Generic.HashSet[string]
    $negations = $Patterns | Where-Object { $_.StartsWith('!') } | ForEach-Object { $_.Substring(1) }

    foreach ($pattern in ($Patterns | Where-Object { -not $_.StartsWith('!') })) {
        $isDirPattern = $pattern.EndsWith('/')
        $normalized = ($pattern -replace '\\', '/').TrimEnd('/')

        if ($pattern -match '[\*\?]') {
            $glob = if ($isDirPattern) { $pattern } else { $pattern }
            $search = Join-Path $RepoRoot (($glob -split '/')[0])
            if (-not (Test-Path $search)) {
                $hits = Get-ChildItem -Path $RepoRoot -Recurse -Force -ErrorAction SilentlyContinue |
                    Where-Object {
                        $rel = $_.FullName.Substring($RepoRoot.Length).TrimStart('\', '/')
                        Test-MatchesProtectedPattern -RelativePath $rel -Pattern $pattern
                    }
            } else {
                $hits = Get-ChildItem -Path $RepoRoot -Recurse -Force -ErrorAction SilentlyContinue |
                    Where-Object {
                        $rel = $_.FullName.Substring($RepoRoot.Length).TrimStart('\', '/')
                        Test-MatchesProtectedPattern -RelativePath $rel -Pattern $pattern
                    }
            }
            foreach ($hit in $hits) {
                $rel = $hit.FullName.Substring($RepoRoot.Length).TrimStart('\', '/')
                [void]$results.Add($rel)
            }
            continue
        }

        $full = Join-Path $RepoRoot $normalized
        if (Test-Path $full) {
            $rel = $full.Substring($RepoRoot.Length).TrimStart('\', '/')
            [void]$results.Add($rel)
        }
    }

    $final = New-Object System.Collections.Generic.List[string]
    foreach ($rel in ($results | Sort-Object)) {
        $skip = $false
        foreach ($neg in $negations) {
            if (Test-MatchesProtectedPattern -RelativePath $rel -Pattern $neg) {
                $skip = $true
                break
            }
        }
        if (-not $skip) { [void]$final.Add($rel) }
    }
    return ,$final
}

function Backup-ProtectedPaths {
    param(
        [string[]]$RelativePaths,
        [string]$BackupRoot
    )

    New-Item -ItemType Directory -Path $BackupRoot -Force | Out-Null
    $manifest = Join-Path $BackupRoot 'manifest.json'
    $entries = @()

    foreach ($rel in $RelativePaths) {
        $src = Join-Path $RepoRoot $rel
        if (-not (Test-Path $src)) { continue }
        $dest = Join-Path $BackupRoot $rel
        $destParent = Split-Path $dest -Parent
        if (-not (Test-Path $destParent)) {
            New-Item -ItemType Directory -Path $destParent -Force | Out-Null
        }
        Copy-Item -Path $src -Destination $dest -Recurse -Force
        $entries += $rel
    }

    $entries | ConvertTo-Json | Set-Content -Path $manifest -Encoding UTF8
    return $entries
}

function Restore-ProtectedPaths {
    param([string]$BackupRoot)

    $manifest = Join-Path $BackupRoot 'manifest.json'
    if (-not (Test-Path $manifest)) {
        Write-Warn 'No backup manifest found; skipping restore.'
        return
    }

    $entries = Get-Content $manifest | ConvertFrom-Json
    foreach ($rel in $entries) {
        $src = Join-Path $BackupRoot $rel
        if (-not (Test-Path $src)) { continue }
        $dest = Join-Path $RepoRoot $rel
        $destParent = Split-Path $dest -Parent
        if (-not (Test-Path $destParent)) {
            New-Item -ItemType Directory -Path $destParent -Force | Out-Null
        }
        if (Test-Path $dest) {
            Remove-Item -Path $dest -Recurse -Force
        }
        Copy-Item -Path $src -Destination $dest -Recurse -Force
    }
}

function Get-ShortSha {
    param([string]$Ref)
    try {
        return (Invoke-Git rev-parse --short $Ref)
    } catch {
        return '(unknown)'
    }
}

function Ensure-GitRepository {
    if (Test-Path (Join-Path $RepoRoot '.git')) { return }

    Write-Warn 'No .git directory - bootstrapping a local repository.'
    if ($DryRun) {
        Write-Info '[dry-run] would run: git init'
        return
    }

    Invoke-Git init | Out-Null
    Invoke-Git branch -M $UpstreamBranch | Out-Null
}

function Ensure-UpstreamRemote {
    $remotes = @()
    if (Test-Path (Join-Path $RepoRoot '.git')) {
        $remotes = (Invoke-Git remote) -split "`n" | Where-Object { $_ }
    }

    if ($remotes -contains $UpstreamRemote) {
        $url = Invoke-Git remote get-url $UpstreamRemote
        if ($url -ne $UpstreamUrl) {
            Write-Warn "Remote $UpstreamRemote points to $url - updating to $UpstreamUrl"
            if (-not $DryRun) {
                Invoke-Git remote set-url $UpstreamRemote $UpstreamUrl | Out-Null
            }
        }
        return
    }

    Write-Info "Adding remote $UpstreamRemote -> $UpstreamUrl"
    if (-not $DryRun) {
        Invoke-Git remote add $UpstreamRemote $UpstreamUrl | Out-Null
    }
}

function Get-LocalCommitCount {
    if (-not (Test-Path (Join-Path $RepoRoot '.git'))) { return 0 }
    try {
        $count = Invoke-Git rev-list --count HEAD
        return [int]$count
    } catch {
        return 0
    }
}

function Clear-WorkingTreeExceptGit {
    Get-ChildItem -Path $RepoRoot -Force |
        Where-Object { $_.Name -ne '.git' } |
        Remove-Item -Recurse -Force
}

function Apply-UpstreamUpdate {
    if ($DryRun) {
        Write-Info "[dry-run] would run: git fetch $UpstreamRemote $UpstreamBranch"
        if ($Hard) {
            Write-Info "[dry-run] would run: git reset --hard $UpstreamRemote/$UpstreamBranch"
        } elseif ((Get-LocalCommitCount) -eq 0) {
            Write-Info '[dry-run] would apply upstream snapshot (checkout upstream/main)'
            Write-Info "[dry-run] would run: git checkout -B $UpstreamBranch $UpstreamRemote/$UpstreamBranch"
        } else {
            Write-Info "[dry-run] would run: git merge $UpstreamRemote/$UpstreamBranch"
        }
        return
    }

    Invoke-Git fetch $UpstreamRemote $UpstreamBranch | Out-Null

    if ($Hard) {
        Invoke-Git reset --hard "$UpstreamRemote/$UpstreamBranch" | Out-Null
        return
    }

    if ((Get-LocalCommitCount) -eq 0) {
        # Copied/zipped folder without git history: untracked files block checkout.
        # Protected paths are already in temp backup, so replace the tree with upstream.
        Write-Info 'First-time git sync: applying upstream snapshot (local copy had no commits)...'
        Clear-WorkingTreeExceptGit
        Invoke-Git checkout -B $UpstreamBranch "$UpstreamRemote/$UpstreamBranch" | Out-Null
        return
    }

    try {
        Invoke-Git merge "$UpstreamRemote/$UpstreamBranch" --no-edit | Out-Null
    } catch {
        Write-Err 'Merge failed - resolve conflicts manually or re-run with -Hard.'
        throw
    }
}

function Install-NpmPackages {
    if (-not (Test-Path (Join-Path $RepoRoot 'package.json'))) {
        throw 'package.json not found in repo root.'
    }
    if (-not (Test-Command 'npm')) {
        throw 'npm is not installed or not on PATH.'
    }

    if ($DryRun) {
        Write-Info '[dry-run] would run: npm install'
        return
    }

    Write-Info 'Running npm install...'
    & npm install
    if ($LASTEXITCODE -ne 0) {
        throw 'npm install failed.'
    }
}

# --- main ---
Write-Banner

if (-not (Test-Path (Join-Path $RepoRoot 'package.json'))) {
    Write-Err "Not a T3MP3ST repo (package.json missing): $RepoRoot"
    exit 1
}

if (-not (Test-Command 'git')) {
    Write-GitInstallHelp
    exit 1
}
if (-not (Test-Command 'npm')) {
    Write-NpmInstallHelp
    exit 1
}

$patterns = Read-ProtectedManifest
$protected = Get-ProtectedPaths -Patterns $patterns
$planSteps = Get-UpdatePlanSteps -ProtectedCount $protected.Count
$platformLabel = if ($IsWindows -or $env:OS -match 'Windows') { 'Windows' } else { 'Unix' }

Write-Rule 'Overview'
Write-Kv 'Platform' "$platformLabel (PowerShell)"
Write-Kv 'Repository' $RepoRoot
Write-Kv 'Upstream' "$UpstreamUrl @ $UpstreamBranch"
$strategyLabel = Get-UpdateStrategyLabel
$strategyColor = if ($Hard) { 'Yellow' } elseif ((Get-LocalCommitCount) -eq 0) { 'Cyan' } else { 'White' }
Write-Kv 'Strategy' $strategyLabel $strategyColor
if ($DryRun) { Write-Kv 'Mode' 'Dry run (preview only)' 'Yellow' }

Write-Rule 'Protected paths in this repo'
if ($protected.Count -eq 0) {
    Write-PlanLine '-' 'No protected project files in this repo (.env, .keys.*, bench output, etc.)'
} else {
    foreach ($p in $protected) { Write-PlanLine '+' $p }
}

Write-Rule 'Never touched (outside repo)'
Write-PlanLine '-' '%APPDATA%\t3mp3st-nodejs\Config\config.json'
Write-PlanLine '-' 'War Room browser localStorage'
Write-PlanLine '-' 'Codex / Hermes local agent auth'

$localSha = '(no git yet)'
$upstreamSha = '(unknown)'
if (Test-Path (Join-Path $RepoRoot '.git')) {
    try { $localSha = Get-ShortSha 'HEAD' } catch { $localSha = '(no commits yet)' }
}
try {
    Ensure-GitRepository
    Ensure-UpstreamRemote
    if (-not $DryRun) {
        Invoke-Git fetch $UpstreamRemote $UpstreamBranch | Out-Null
        $upstreamSha = Get-ShortSha "$UpstreamRemote/$UpstreamBranch"
    } else {
        $upstreamSha = '(preview)'
    }
} catch {
    Write-Warn "Could not prefetch upstream: $($_.Exception.Message)"
}

Write-Rule 'Revisions'
Write-Kv 'Local' $localSha
Write-Kv 'Upstream' $upstreamSha 'Cyan'

Write-Rule 'Sync plan'
Write-UpdatePlan -Steps $planSteps

if (-not $Force) {
    Write-Host ''
    $answer = Read-Host 'Proceed with update? [y/N]'
    if ($answer -notmatch '^(y|yes)$') {
        Write-Warn 'Cancelled - no changes made.'
        exit 0
    }
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backupRoot = Join-Path ([System.IO.Path]::GetTempPath()) "t3mp3st-update-backup-$timestamp"
$oldSha = $localSha
$script:StepTotal = 2 + $(if ($protected.Count -gt 0) { 2 } else { 0 })
$script:StepIndex = 0

try {
    if ($protected.Count -gt 0) {
        Start-UpdateStep "Backing up protected files"
        if (-not $DryRun) {
            $backedUp = Backup-ProtectedPaths -RelativePaths $protected -BackupRoot $backupRoot
            Write-Ok "Backed up $($backedUp.Count) path(s)"
        } else {
            Write-Info '[dry-run] would back up protected paths'
        }
    }

    Start-UpdateStep 'Syncing from upstream'
    Ensure-GitRepository
    Ensure-UpstreamRemote
    Apply-UpstreamUpdate
    if (-not $DryRun) { Write-Ok 'Git sync finished' }

    if ($protected.Count -gt 0) {
        Start-UpdateStep 'Restoring protected files'
        if (-not $DryRun) {
            Restore-ProtectedPaths -BackupRoot $backupRoot
            Write-Ok 'Protected paths restored'
        } else {
            Write-Info '[dry-run] would restore protected paths'
        }
    }

    Start-UpdateStep 'Refreshing npm packages'
    Install-NpmPackages
    if (-not $DryRun) { Write-Ok 'npm install finished' }

    $newSha = if ($DryRun) { $upstreamSha } else { Get-ShortSha 'HEAD' }

    Write-DoneBox -FromSha $oldSha -ToSha $newSha -Preview:($DryRun)

    if (-not $KeepBackup -and -not $DryRun -and (Test-Path $backupRoot)) {
        Remove-Item -Path $backupRoot -Recurse -Force
    } elseif ((Test-Path $backupRoot)) {
        Write-Info "Backup kept at $backupRoot"
    }
} catch {
    Write-Host ''
    Write-Err $_.Exception.Message
    if ((Test-Path $backupRoot)) {
        Write-Warn "Backup preserved at $backupRoot"
    }
    exit 1
}
