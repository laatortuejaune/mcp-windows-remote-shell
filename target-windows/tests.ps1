#requires -version 5.1
# Safe, isolated checks: no relay process, tunnel, DELETE request or cleanup runs.
param([switch]$Http)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'relay-common.ps1')
$script:checks = 0
function Assert-Test([bool]$Condition, [string]$Message) {
  if (-not $Condition) { throw "FAILED: $Message" }
  $script:checks++
}
function Assert-Rejected([scriptblock]$Operation, [string]$Message) {
  $rejected = $false
  try { $null = & $Operation } catch { $rejected = $true }
  Assert-Test $rejected $Message
}

# Parse all scripts without running launchers or cleaners.
Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' | ForEach-Object {
  $tokens = $null; $parseErrors = $null
  $null = [Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$parseErrors)
  Assert-Test ($parseErrors.Count -eq 0) ('Parse ' + $_.Name)
}
Assert-Test ((New-RelayRandomHex 16) -cmatch '^[a-f0-9]{32}$') 'Session ID size'
Assert-Test ((New-RelayRandomHex 32) -cmatch '^[a-f0-9]{64}$') 'Delete capability size'
Assert-Test ((ConvertTo-RelayArgument 'C:\Example Directory\relay\') -ceq '"C:\Example Directory\relay\\"') 'Spaces and trailing slash are quoted'
Assert-Test ((ConvertTo-RelayArgument 'one"two') -ceq '"one\"two"') 'Embedded quotes are escaped'
Assert-Test ((Get-RelayRendezvousOrigin 'https://example.test/') -ceq 'https://example.test') 'Canonical HTTPS origin'
foreach ($badUrl in @('http://example.test', 'https://!@example.test', 'https://example.test/path', 'https://example.test/?x=1', 'https://example.test/#x', 'https://example.test:8443')) {
  Assert-Rejected { Get-RelayRendezvousOrigin $badUrl } 'Reject unsafe rendezvous origin'
}

# Ticket fixtures contain only synthetic capabilities and fixed UTC dates.
$ticketNow = [DateTimeOffset]::Parse('2026-09-05T00:00:00Z')
function New-TestTicket {
  return [pscustomobject]@{version=3; url='https://fixture.example'; ticket_id=('a' * 32); ticket_secret=('b' * 64); expires_at=$null}
}
$validTicket = Get-RelayTicketConfig (New-TestTicket) $ticketNow
Assert-Test ($validTicket.version -eq 3 -and $validTicket.ticket_id -ceq ('a' * 32)) 'Accept persistent credential'
$jsonTicket = ConvertFrom-RelayTicketJson ((New-TestTicket) | ConvertTo-Json -Compress)
Assert-Test ($null -eq $jsonTicket.expires_at) 'Persistent expiration is JSON null'
$null = Get-RelayTicketConfig $jsonTicket $ticketNow
$null = Get-RelayTicketConfig $jsonTicket ($ticketNow.AddYears(20))
Assert-Test $true 'Persistent credential has no expiry'
Assert-Test $true 'Validate ticket after real JSON parsing'
Assert-Rejected { Get-RelayTicketConfig ([pscustomobject]@{url='https://fixture.example';write_key='old-synthetic-key'}) $ticketNow } 'Reject legacy permanent write key'
Assert-Rejected { Get-RelayTicketConfig $null $ticketNow } 'Reject null ticket'
Assert-Rejected { Get-RelayTicketConfig @('x') $ticketNow } 'Reject array ticket'
foreach ($badVersion in @('3', 1, 2, 3.0)) {
  $ticket = New-TestTicket; $ticket.version = $badVersion
  Assert-Rejected { Get-RelayTicketConfig $ticket $ticketNow } 'Reject noninteger or obsolete version'
}
foreach ($badExpiry in @('2026-09-05T00:00:00.000Z', '2026-09-12T00:00:00.001Z', '2026-09-06T00:00:00+00:00', '2026-09-06', 'invalid')) {
  $ticket = New-TestTicket; $ticket.expires_at = $badExpiry
  Assert-Rejected { Get-RelayTicketConfig $ticket $ticketNow } 'Reject expired or malformed ticket date'
}
foreach ($field in @('ticket_id', 'ticket_secret')) {
  foreach ($bad in @(('A' * 64), ('g' * 32), 'x', $null, @(('a' * 32)))) {
    $ticket = New-TestTicket; $ticket.$field = $bad
    Assert-Rejected { Get-RelayTicketConfig $ticket $ticketNow } 'Reject malformed ticket capability'
  }
}
$ticket = New-TestTicket; $ticket | Add-Member NoteProperty write_key 'unexpected-synthetic-key'
Assert-Rejected { Get-RelayTicketConfig $ticket $ticketNow } 'Reject permanent key alongside ticket'

# Simulate retries without network requests or live processes.
& {
  $fixture = @{calls=0; requests=(New-Object Collections.ArrayList); mode='lost-response'}
  function Start-Sleep {param($Milliseconds)}
  function Invoke-RelayHttp {
    param($Uri, $Method, $Headers, $Body, $TimeoutMs)
    $fixture.calls++
    $null = $fixture.requests.Add(@{uri=$Uri; method=$Method; authorization=$Headers.Authorization; body=$Body})
    if ($fixture.mode -eq 'lost-response' -and $fixture.calls -eq 1) { throw (New-RelayFailure 'Synthetic timeout.' -Retryable) }
    if ($fixture.mode -eq 'lost-response') { return @{status=200;body=''} }
    if ($fixture.mode -eq 'oversized') { throw (New-RelayFailure 'Synthetic oversized body.') }
    return @{status=[int]$fixture.mode;body='SYNTHETIC_UNTRUSTED_BODY'}
  }
  $secret = 'b' * 64; $payload = '{"ticket_id":"synthetic","session_id":"same-every-time","token":"synthetic"}'
  Publish-RelaySession 'https://fixture.example' $secret $payload
  Assert-Test ($fixture.calls -eq 2) 'Retry when acknowledgement is lost'
  foreach ($request in $fixture.requests) {
    Assert-Test ($request.body -ceq $payload -and $request.authorization -ceq "Bearer $secret" -and $request.method -ceq 'POST') 'Retry preserves exact request'
  }
  foreach ($status in @(400, 401, 403, 409, 410, 302, 429)) {
    $fixture.calls=0; $fixture.mode="$status"
    Assert-Rejected { Publish-RelaySession 'https://fixture.example' $secret $payload } 'Reject permanent HTTP failure'
    Assert-Test ($fixture.calls -eq 1) "Never retry HTTP $status"
  }
  $fixture.calls=0; $fixture.mode='503'
  Assert-Rejected { Publish-RelaySession 'https://fixture.example' $secret $payload } 'Server failures are bounded'
  Assert-Test ($fixture.calls -eq 3) 'At most three publication attempts'
  $fixture.calls=0; $fixture.mode='oversized'
  Assert-Rejected { Publish-RelaySession 'https://fixture.example' $secret $payload } 'Oversized responses are terminal'
  Assert-Test ($fixture.calls -eq 1) 'Never retry response validation failure'
  $fixture.calls=0; $fixture.mode='409'
  try { Publish-RelaySession 'https://fixture.example' $secret $payload } catch {
    Assert-Test ($_.Exception.Message -notmatch 'SYNTHETIC_UNTRUSTED_BODY' -and -not $_.Exception.Message.Contains($secret) -and -not $_.Exception.Message.Contains($payload)) 'Errors never echo HTTP body or secrets'
  }
}

# Simulated WMI: only positively identified fixed storage allows deletion.
& {
  function Get-CimInstance { param($ClassName, $Filter, $ErrorAction); return $fixtureDisks }
  foreach ($type in @(0, 1, 2, 4, 5, 6)) {
    $fixtureDisks = @([pscustomobject]@{DriveType=$type})
    Assert-Rejected { Assert-RelayFixedVolume 'E:' } "Reject DriveType $type"
  }
  $fixtureDisks = @()
  Assert-Rejected { Assert-RelayFixedVolume 'E:' } 'Reject absent CIM result'
  $fixtureDisks = @([pscustomobject]@{DriveType=3}, [pscustomobject]@{DriveType=3})
  Assert-Rejected { Assert-RelayFixedVolume 'E:' } 'Reject ambiguous CIM result'
  $fixtureDisks = @([pscustomobject]@{DriveType=3})
  Assert-RelayFixedVolume 'C:'
  Assert-Test $true 'Allow positively identified fixed volume'
  function Get-CimInstance { throw 'Fixture CIM unavailable' }
  Assert-Rejected { Assert-RelayFixedVolume 'E:' } 'Reject CIM error'
}
Assert-Rejected { Assert-RelayCleanupFolder '\\server\share\relay' } 'Reject network folder'

# Process fixtures never call the OS to stop a real process.
& {
  $fixtureProcess = [pscustomobject]@{Kills=0; Disposed=0}
  $fixtureProcess | Add-Member ScriptMethod Kill { $this.Kills++ }
  $fixtureProcess | Add-Member ScriptMethod WaitForExit { param($Milliseconds); return $true }
  $fixtureProcess | Add-Member ScriptMethod Dispose { $this.Disposed++ }
  $expected = @{pid=424242; started_ticks='100'; executable=(Join-Path $PSScriptRoot 'fixture.exe')}
  $actual = @{pid=424242; started_ticks='101'; executable=$expected.executable}
  function Get-Process { param($Id, $ErrorAction); return $fixtureProcess }
  function Get-RelayProcessIdentity { param($Process); return $actual }
  Assert-Rejected { Stop-RelayOwnedProcess $expected } 'Reject reused PID'
  Assert-Test ($fixtureProcess.Kills -eq 0) 'Reused PID was not killed'
  $actual.started_ticks = '100'; $actual.executable = Join-Path $PSScriptRoot 'unrelated.exe'
  Assert-Rejected { Stop-RelayOwnedProcess $expected } 'Reject other executable'
  Assert-Test ($fixtureProcess.Kills -eq 0) 'Other executable was not killed'
  $actual.executable = $expected.executable
  Stop-RelayOwnedProcess $expected
  Assert-Test ($fixtureProcess.Kills -eq 1) 'Only matching identity was killed'
  $fixtureProcess = $null
  Stop-RelayOwnedProcess $expected
  Assert-Test $true 'Already exited process needs no kill'
}

$parseTokens = $null; $parseErrors = $null
$launcherAst = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'start-relay.ps1'), [ref]$parseTokens, [ref]$parseErrors)
$healthFunction = $launcherAst.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-LocalAgent'}, $false)
& {
  . ([scriptblock]::Create($healthFunction.Extent.Text))
  $agent = [pscustomobject]@{Id=424242; HasExited=$false}
  $Port = 47600; $Token = 'synthetic-test-token'
  $fixtureStatus = 200; $fixtureHealth = @{status='ok'; agent='relay-agent'; pid=424242}
  $fixtureListener = [pscustomobject]@{OwningProcess=424242}
  function Invoke-RelayHttp { param($Uri, $Method, $Headers, $TimeoutMs); return @{status=$fixtureStatus; body=($fixtureHealth | ConvertTo-Json -Compress)} }
  function Get-NetTCPConnection { param($LocalAddress, $LocalPort, $State, $ErrorAction); return $fixtureListener }
  Assert-LocalAgent
  Assert-Test $true 'Accept authenticated own health and socket'
  $fixtureHealth.pid = 424243
  Assert-Rejected { Assert-LocalAgent } 'Reject health from other PID'
  $fixtureHealth.pid = 424242; $fixtureListener.OwningProcess = 424243
  Assert-Rejected { Assert-LocalAgent } 'Reject socket owned by other PID'
  $fixtureListener.OwningProcess = 424242; $fixtureStatus = 401
  Assert-Rejected { Assert-LocalAgent } 'Reject unauthenticated health'
  $fixtureStatus = 200; $agent.HasExited = $true
  Assert-Rejected { Assert-LocalAgent } 'Reject exited agent'
}

# Exercise the launcher try/finally with simulated Start-Process and filesystem.
# This specifically covers a process created BEFORE its identity is saved.
$mainTry = $launcherAst.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.TryStatementAst]} | Select-Object -First 1
foreach ($fault in @('identity', 'persist')) {
  & {
    $here = $PSScriptRoot; $exe = Join-Path $here 'fixture-agent.exe'
    $stateDirectory = Join-Path $here 'fixture-state'
    $Token = 'a' * 64; $RevealToken = $false; $Port=47600; $Timeout=30
    $state=$null; $agent=$null; $cf=$null; $ownsState=$false; $failed=$false
    $fixtureProcess = [pscustomobject]@{HasExited=$false; Kills=0}
    $fixtureProcess | Add-Member ScriptMethod Kill {$this.Kills++; $this.HasExited=$true}
    $fixtureProcess | Add-Member ScriptMethod WaitForExit {param($Milliseconds); return $true}
    function Test-Path {param($LiteralPath, $PathType); return $true}
    function Assert-RelayNoReparse {}
    function Get-Item {param($LiteralPath, $ErrorAction); return @{Length=512}}
    function Get-Content {param($LiteralPath, [switch]$Raw, $ErrorAction); return '{"fixture":true}'}
    function Get-RelayTicketConfig {param($Config); return @{url='https://fixture.example';ticket_id=('a' * 32);ticket_secret=('b' * 64)}}
    function New-RelayPrivateDirectory {}
    function Write-RelayState {if($fault -eq 'persist' -and $null -ne $agent){throw 'Fixture state write failed'}}
    function Resolve-Cloudflared {return 'fixture-cloudflared.exe'}
    function Unblock-File {param($LiteralPath, $ErrorAction)}
    function Start-Process {param($FilePath, $ArgumentList, $WindowStyle, [switch]$PassThru, $ErrorAction); return $fixtureProcess}
    function Get-RelayProcessIdentity {if($fault -eq 'identity'){throw 'Fixture identity failed'}; return @{pid=424242;started_ticks='100';executable=$exe}}
    function Remove-RelayRemoteSession {}
    function Start-RelayCleanup {param($Folder, [switch]$PauseOnFailure)}
    function Write-Host {}
    function Write-Warning {}
    . ([scriptblock]::Create($mainTry.Extent.Text))
    Assert-Test ($fixtureProcess.Kills -eq 1) "Finally closes handle after $fault failure"
    Assert-Test ([string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable('RELAY_TOKEN', 'Process'))) 'Launcher token environment was cleared'
  }
}
if ($Http) {
  # Optional loopback-only regression checks using real .NET HTTP transport.
  # Each fixture sends a terminal status with a deliberately incomplete body.
  foreach ($status in @(401, 409, 410, 302, 307)) {
    $hitFile = [IO.Path]::GetTempFileName()
    [IO.File]::WriteAllText($hitFile, '0')
    $job = Start-Job -ArgumentList $status, $hitFile -ScriptBlock {
      param($Status, $HitFile)
      $hitCount = 0
      $ErrorActionPreference='Stop'
      $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
      try {
        $listener.Start()
        Write-Output ([pscustomobject]@{kind='ready';port=$listener.LocalEndpoint.Port})
        while ($true) {
          $pending=$listener.AcceptTcpClientAsync()
          while (-not $pending.Wait(100)) {}
          $tcp=$pending.GetAwaiter().GetResult()
          try {
            $tcp.ReceiveTimeout=3000; $tcp.SendTimeout=3000
            $stream = $tcp.GetStream()
            $reader = New-Object IO.StreamReader($stream, [Text.Encoding]::ASCII)
            try {
              $length=0
              do {
                $line=$reader.ReadLine()
                if ($line -match '^Content-Length:\s*(\d+)$') { $length=[int]$Matches[1] }
              } while ($null -ne $line -and $line -ne '')
              # Consume the request before closing so TCP does not reset and
              # discard the response headers we are deliberately testing.
              $body=New-Object char[] $length; $received=0
              while ($received -lt $length) {
                $count=$reader.Read($body, $received, $length-$received)
                if ($count -eq 0) { throw 'Incomplete synthetic request.' }
                $received+=$count
              }
              $response = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 $Status Fixture`r`nContent-Length: 100`r`nConnection: close`r`n`r`n{")
              # Synchronous receipt barrier: job output can arrive after the
              # client already received the response and returned.
              $hitCount++
              [IO.File]::WriteAllText($HitFile, [string]$hitCount)
              $stream.Write($response, 0, $response.Length); $stream.Flush()
            } finally { $reader.Dispose() }
          } finally { $tcp.Dispose() }
        }
      } finally { $listener.Stop() }
    }
    try {
      $ready = $null
      for ($attempt=0; $attempt -lt 100; $attempt++) {
        $ready = Receive-Job $job -Keep | Where-Object {$_.kind -eq 'ready'} | Select-Object -First 1
        if ($null -ne $ready) { break }
        if ($job.State -eq 'Failed') { throw 'Loopback HTTP fixture failed to start.' }
        Start-Sleep -Milliseconds 100
      }
      if ($null -eq $ready) { throw 'Loopback HTTP fixture startup timeout.' }
      $origin = 'http://127.0.0.1:' + $ready.port
      Assert-Rejected { Publish-RelaySession $origin ('b' * 64) '{"synthetic":true}' } "Reject truncated HTTP $status"
      $hits = [int][IO.File]::ReadAllText($hitFile)
      Assert-Test ($hits -eq 1) "Truncated HTTP $status never retries"
    } finally { Stop-Job $job; Remove-Job $job -Force; Remove-Item -LiteralPath $hitFile -Force }
  }
}
Write-Output "Windows helper checks passed: $script:checks (no live relay or cleanup executed)."
