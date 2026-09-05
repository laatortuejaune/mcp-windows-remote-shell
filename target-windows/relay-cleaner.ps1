#requires -version 5.1
param(
  [Parameter(Mandatory = $true)][string]$Folder,
  [switch]$Detached,
  [switch]$PauseOnFailure
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'relay-common.ps1')
$Folder = Get-RelayFullPath $Folder
if (-not $Detached) {
  Start-RelayCleanup $Folder -PauseOnFailure:$PauseOnFailure
  exit 0
}
Set-Location -LiteralPath $env:TEMP
$temporary = $PSScriptRoot
$directory = Join-Path $Folder '.relay-session'
$lock = $null; $failed = $false
$completed = Join-Path $directory 'cleanup.completed'
$lockPath = Join-Path $directory 'cleanup.lock'

function Remove-KnownFile([string]$Path) {
  if (Test-Path -LiteralPath $Path) {
    Assert-RelayNoReparse $Path
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw (New-RelayFailure 'An expected file has been replaced by a directory.') }
    Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
  }
}

try {
  if (-not (Test-Path -LiteralPath $Folder)) { Write-Host 'The package directory has already been removed.'; return }
  Assert-RelayPrivateDirectory $directory
  if (-not (Test-Path -LiteralPath $completed)) {
    try {
      $lock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    } catch { Write-Host 'Cleanup is already running or its lock is unavailable. Nothing was deleted.'; return }
    $state = Get-Content -LiteralPath (Join-Path $directory 'state.json') -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($state.version -ne 1 -or -not (Test-RelaySamePath ([string]$state.folder) $Folder)) { throw (New-RelayFailure 'Invalid session state.') }
    $stopFailed = $false
    foreach ($identity in @($state.cloudflared, $state.agent)) {
      try { Stop-RelayOwnedProcess $identity } catch { $stopFailed = $true }
    }
    if ($stopFailed) { throw (New-RelayFailure 'Some processes could not be verified or stopped. The directory was preserved.') }
    $null = Assert-RelayCleanupFolder $Folder
    # Validate the entire known inventory before removing any file.
    $sessionNames = @('state.json', 'state.pending.json', 'cloudflared-out.log', 'cloudflared-err.log', 'cleanup.lock', 'cleanup.completed')
    $dataNames = @('rendezvous.json', 'relay-agent-windows-amd64.exe', 'cloudflared.exe', 'rendezvous.example.json', 'README.txt', 'tests.ps1')
    $entryNames = @('start-relay.cmd', 'start-relay.ps1', 'cleanup.cmd', 'relay-cleaner.ps1', 'relay-common.ps1')
    foreach ($base in @(@{path=$directory; names=$sessionNames}, @{path=$Folder; names=($dataNames + $entryNames)})) {
      foreach ($name in $base.names) {
        $path = Join-Path $base.path $name
        if (Test-Path -LiteralPath $path) {
          Assert-RelayNoReparse $path
          if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw (New-RelayFailure 'An expected file has been replaced by a directory. Nothing was deleted.') }
        }
      }
    }
    # The launch ticket is unnecessary for a retry: state retains only DELETE rights.
    Remove-KnownFile (Join-Path $Folder 'rendezvous.json')
    Remove-RelayRemoteSession $state
    foreach ($name in @('cloudflared-out.log', 'cloudflared-err.log', 'state.pending.json')) { Remove-KnownFile (Join-Path $directory $name) }
    foreach ($name in $dataNames) { Remove-KnownFile (Join-Path $Folder $name) }
    # Keep retry entrypoints and state until binaries and other data are gone.
    foreach ($name in $entryNames) { Remove-KnownFile (Join-Path $Folder $name) }
    [IO.File]::WriteAllText($completed, 'complete', [Text.Encoding]::ASCII)
    $lock.Dispose(); $lock = $null
  }
  # A retry after the final stage never needs to stop or revoke anything again.
  $null = Assert-RelayCleanupFolder $Folder
  Remove-KnownFile (Join-Path $directory 'state.json')
  Remove-KnownFile $lockPath
  Remove-KnownFile $completed
  if (@(Get-ChildItem -LiteralPath $directory -Force).Count -eq 0) { [IO.Directory]::Delete($directory) }
  if (@(Get-ChildItem -LiteralPath $Folder -Force).Count -eq 0) {
    [IO.Directory]::Delete($Folder)
    Write-Host 'Relay stopped. The remote session and package files were removed.' -ForegroundColor Green
  } else {
    Write-Host 'Relay stopped. Package files were removed; other files were preserved.' -ForegroundColor Yellow
  }
} catch {
  $failed = $true
  Write-Host 'CLEANUP INCOMPLETE. Some or all package files have been preserved.' -ForegroundColor Red
  if ($_.Exception.Data.Contains('RelaySafeMessage')) { Write-Host $_.Exception.Data['RelaySafeMessage'] }
  else { Write-Host 'Permissions, locked files, or an unavailable rendezvous prevented complete cleanup.' }
  Write-Host 'Run cleanup.cmd if available. Otherwise, open retry-cleanup.cmd in:'
  Write-Host $temporary
} finally {
  if ($null -ne $lock) { $lock.Dispose() }
  # Preserve this private retry copy on failure, including if entrypoints went.
  if (-not $failed -and -not (Test-RelaySamePath $temporary $Folder)) {
    foreach ($name in @('relay-cleaner.ps1', 'relay-common.ps1', 'retry-cleanup.cmd')) {
      Remove-Item -LiteralPath (Join-Path $temporary $name) -Force -ErrorAction SilentlyContinue
    }
    try { [IO.Directory]::Delete($temporary) } catch {}
  }
}
if ($failed) {
  if ($PauseOnFailure) { $null = Read-Host 'Press Enter to close this window' }
  exit 1
}
Start-Sleep -Seconds 3
