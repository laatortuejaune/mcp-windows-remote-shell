#requires -version 5.1
[CmdletBinding()]
param(
  [ValidateRange(1, 65535)][int]$Port = 47600,
  [ValidateRange(1, 3600)][int]$Timeout = 30,
  [string]$Token,
  [switch]$RevealToken
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'relay-common.ps1')
$here = Get-RelayFullPath $PSScriptRoot
$exe = Join-Path $here 'relay-agent-windows-amd64.exe'
$stateDirectory = Join-Path $here '.relay-session'
$state = $null; $agent = $null; $cf = $null
$ownsState = $false; $failed = $false
# Always generate a new session unless -Token was explicitly supplied.
Remove-Item Env:RELAY_TOKEN -ErrorAction SilentlyContinue
Remove-Item Env:RELAY_TOKEN_FILE -ErrorAction SilentlyContinue

function Resolve-Cloudflared {
  $found = Get-Command cloudflared.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($found) { return $found.Source }
  $local = Join-Path $here 'cloudflared.exe'
  if (Test-Path -LiteralPath $local) { return $local }
  Write-Host 'Downloading cloudflared from GitHub...'
  # Unpinned upstream release: explicitly accepted for this POC.
  $url = 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe'
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  $partial = Join-Path $here ('cloudflared-' + [Guid]::NewGuid().ToString('N') + '.download')
  try {
    Invoke-WebRequest -Uri $url -OutFile $partial -UseBasicParsing -ErrorAction Stop
    if ((Get-Item -LiteralPath $partial).Length -lt 1MB) { throw (New-RelayFailure 'Incomplete cloudflared download.') }
    Move-Item -LiteralPath $partial -Destination $local -ErrorAction Stop
  } finally { Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue }
  return $local
}

function Assert-LocalAgent {
  if ($agent.HasExited) { throw (New-RelayFailure 'The agent stopped. The tunnel must be closed.') }
  $response = Invoke-RelayHttp "http://127.0.0.1:$Port/health" 'GET' @{ Authorization = "Bearer $Token" } -TimeoutMs 1500
  if ($response.status -ne 200) { throw (New-RelayFailure 'The local agent rejected the authenticated check.') }
  $health = $response.body | ConvertFrom-Json -ErrorAction Stop
  if ($health.status -ne 'ok' -or $health.agent -ne 'relay-agent' -or [int]$health.pid -ne $agent.Id -or $agent.HasExited) {
    throw (New-RelayFailure 'The selected port does not belong to the agent that was started.')
  }
  $listeners = @(Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort $Port -State Listen -ErrorAction Stop)
  if ($listeners.Count -ne 1 -or [int]$listeners[0].OwningProcess -ne $agent.Id) {
    throw (New-RelayFailure 'The local port does not belong to the agent that was started.')
  }
}

function Read-TunnelLog([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { return '' }
  $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    $reader = New-Object IO.StreamReader($stream)
    try {
      $buffer = New-Object char[] 65536
      $count = $reader.Read($buffer, 0, $buffer.Length)
      if ($count -eq 0) { return '' }
      return -join $buffer[0..($count - 1)]
    } finally { $reader.Dispose() }
  } finally { $stream.Dispose() }
}

try {
  Write-Host 'MCP WINDOWS REMOTE SHELL - starting...' -ForegroundColor Cyan
  Assert-RelayNoReparse $here
  if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw (New-RelayFailure 'Missing relay-agent-windows-amd64.exe.') }
  Assert-RelayNoReparse $exe
  if (-not $Token) { $Token = New-RelayRandomHex 32 }
  if ($Token -notmatch '^[0-9a-fA-F]{64}$') { throw (New-RelayFailure 'An explicit agent token must contain 64 hexadecimal characters.') }
  $rzUrl = ''; $rzTicketSecret = ''; $rzTicketId = ''
  $rzCfg = Join-Path $here 'rendezvous.json'
  if (Test-Path -LiteralPath $rzCfg) {
    Assert-RelayNoReparse $rzCfg
    if ((Get-Item -LiteralPath $rzCfg -ErrorAction Stop).Length -gt 4096) { throw (New-RelayFailure 'Configuration exceeds the size limit. Export a valid package.') }
    $config = Get-RelayTicketConfig (ConvertFrom-RelayTicketJson (Get-Content -LiteralPath $rzCfg -Raw -ErrorAction Stop))
    $rzUrl = $config.url; $rzTicketSecret = $config.ticket_secret; $rzTicketId = $config.ticket_id
  } elseif (-not $RevealToken) { throw (New-RelayFailure 'Missing rendezvous.json. Static configuration requires -RevealToken.') }
  $state = @{
    version = 1; folder = $here; session_id = (New-RelayRandomHex 16)
    delete_token = (New-RelayRandomHex 32); rendezvous_url = $rzUrl
    agent = $null; cloudflared = $null
  }
  New-RelayPrivateDirectory $stateDirectory
  $ownsState = $true
  Write-RelayState $stateDirectory $state
  $cfPath = Resolve-Cloudflared
  Assert-RelayNoReparse $cfPath
  Unblock-File -LiteralPath $exe -ErrorAction Stop
  Unblock-File -LiteralPath $cfPath -ErrorAction Stop
  $env:RELAY_TOKEN = $Token
  try {
    $agent = Start-Process -FilePath $exe -ArgumentList @('--port', "$Port", '--timeout', "$Timeout") -WindowStyle Minimized -PassThru -ErrorAction Stop
  } finally { Remove-Item Env:RELAY_TOKEN -ErrorAction SilentlyContinue }
  $state.agent = Get-RelayProcessIdentity $agent
  Write-RelayState $stateDirectory $state
  $ready = $false
  for ($attempt = 0; $attempt -lt 20; $attempt++) {
    if ($agent.HasExited) { throw (New-RelayFailure 'The agent could not start. The selected port may already be in use.') }
    try { Assert-LocalAgent; $ready = $true; break } catch { Start-Sleep -Milliseconds 250 }
  }
  if (-not $ready) { throw (New-RelayFailure 'Agent identity and port ownership could not be verified. Tunnel refused.') }
  $cfOut = Join-Path $stateDirectory 'cloudflared-out.log'
  $cfErr = Join-Path $stateDirectory 'cloudflared-err.log'
  $cf = Start-Process -FilePath $cfPath -ArgumentList @('tunnel', '--url', "http://127.0.0.1:$Port") -PassThru -WindowStyle Minimized -RedirectStandardOutput $cfOut -RedirectStandardError $cfErr -ErrorAction Stop
  $state.cloudflared = Get-RelayProcessIdentity $cf
  Write-RelayState $stateDirectory $state
  $tunnelUrl = ''
  for ($attempt = 0; $attempt -lt 60; $attempt++) {
    if ($agent.HasExited -or $cf.HasExited) { throw (New-RelayFailure 'A relay process stopped during startup.') }
    $log = (Read-TunnelLog $cfErr) + (Read-TunnelLog $cfOut)
    if ($log -match 'https://[a-z0-9-]+\.trycloudflare\.com(?=[/\s]|$)') {
      $tunnelUrl = ([Uri]$Matches[0]).GetLeftPart([UriPartial]::Authority)
      break
    }
    Start-Sleep -Milliseconds 500
  }
  if (-not $tunnelUrl) { throw (New-RelayFailure 'No valid tunnel URL was received before the deadline.') }
  Assert-LocalAgent
  if ($rzUrl) {
    $payload = @{
      url = $tunnelUrl; token = $Token; host = $env:COMPUTERNAME; os = 'windows'
      session_id = $state.session_id; delete_token = $state.delete_token; ticket_id = $rzTicketId
    } | ConvertTo-Json -Compress
    Publish-RelaySession $rzUrl $rzTicketSecret $payload
    $payload = $null; $rzTicketSecret = $null; $config = $null
    Write-Host 'Session published. Automatic connection is ready.' -ForegroundColor Green
  }
  if ($RevealToken) {
    Write-Warning 'SECRET: the following values grant command access to this machine. Avoid screenshots and transcripts.'
    Write-Host "RELAY_URL=$tunnelUrl"
    Write-Host "RELAY_TOKEN=$Token"
  }
  Write-Host 'Relay is running. Press Ctrl+C to stop it and start cleanup.' -ForegroundColor Green
  while (-not $agent.HasExited -and -not $cf.HasExited) { Start-Sleep -Milliseconds 250 }
  throw (New-RelayFailure 'The agent or tunnel stopped. Closing the session.')
} catch {
  $failed = $true
  Write-Host 'The relay cannot continue. Startup or verification failed.' -ForegroundColor Red
  if ($_.Exception.Data.Contains('RelaySafeMessage')) {
    Write-Host $_.Exception.Data['RelaySafeMessage'] -ForegroundColor Yellow
  } else {
    Write-Host 'Check the port, executable files, and rendezvous configuration.' -ForegroundColor Yellow
  }
} finally {
  Remove-Item Env:RELAY_TOKEN -ErrorAction SilentlyContinue
  $Token = $null
  $rzTicketSecret = $null; $payload = $null; $config = $null
  if ($ownsState) {
    # These are handles returned by our own Start-Process calls. They remain
    # usable if capturing identity or persisting state failed after creation.
    foreach ($process in @($cf, $agent)) {
      if ($null -ne $process) {
        try {
          if (-not $process.HasExited) {
            $process.Kill()
            if (-not $process.WaitForExit(5000)) { throw (New-RelayFailure 'Process termination could not be confirmed.') }
          }
        } catch { Write-Warning 'Termination incomplete: cleanup will retry.' }
      }
    }
    try { Remove-RelayRemoteSession $state } catch { Write-Warning 'Remote session removal was not confirmed: cleanup will retry.' }
    try {
      Start-RelayCleanup $here -PauseOnFailure
      Write-Host 'The cleanup window will show the result. Keep it open if cleanup fails.'
    } catch { Write-Warning 'Cleanup could not start. Run cleanup.cmd; files have been preserved.' }
  }
}
if ($failed) { exit 1 }
