#requires -version 5.1
# Shared helpers. Never print a token, request body, or response body.
Set-StrictMode -Version 2
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

function New-RelayFailure([string]$Message, [switch]$Retryable) {
  $failureException = New-Object InvalidOperationException($Message)
  $failureException.Data['RelaySafeMessage'] = $Message
  if ($Retryable) { $failureException.Data['RelayRetryable'] = $true }
  return $failureException
}

function New-RelayRandomHex([int]$Bytes) {
  $buffer = New-Object byte[] $Bytes
  $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($buffer) } finally { $rng.Dispose() }
  return ([BitConverter]::ToString($buffer)).Replace('-', '').ToLowerInvariant()
}

function ConvertTo-RelayArgument([string]$Value) {
  # Start-Process joins ArgumentList; quote every Windows argument explicitly.
  $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
  $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
  return '"' + $escaped + '"'
}

function Get-RelayFullPath([string]$Path) {
  return [IO.Path]::GetFullPath($Path).TrimEnd([char[]]@('\', '/'))
}

function Test-RelaySamePath([string]$Left, [string]$Right) {
  return [string]::Equals((Get-RelayFullPath $Left), (Get-RelayFullPath $Right), [StringComparison]::OrdinalIgnoreCase)
}

function Assert-RelayNoReparse([string]$Path) {
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  while ($null -ne $item) {
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw (New-RelayFailure 'Paths containing junctions or symbolic links are not allowed.')
    }
    if ($item -is [IO.FileInfo]) { $item = $item.Directory } else { $item = $item.Parent }
  }
}

function New-RelayPrivateDirectory([string]$Path) {
  if (Test-Path -LiteralPath $Path) { throw (New-RelayFailure 'Private session state already exists. Run cleanup.cmd before starting again.') }
  Assert-RelayNoReparse (Split-Path -Parent $Path)
  $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $acl = New-Object Security.AccessControl.DirectorySecurity
  $acl.SetOwner($sid)
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($principal in @($sid, (New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))) {
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($principal, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
  }
  # Windows PowerShell 5.1 / .NET Framework: create with the restrictive ACL.
  [IO.Directory]::CreateDirectory($Path, $acl) | Out-Null
  Assert-RelayPrivateDirectory $Path
}

function Assert-RelayPrivateDirectory([string]$Path) {
  Assert-RelayNoReparse $Path
  $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
  $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  if (-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid) {
    throw (New-RelayFailure 'Invalid session state ownership or permissions.')
  }
  foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @($sid, 'S-1-5-18')) {
      throw (New-RelayFailure 'Session state is accessible to another account.')
    }
  }
}

function Write-RelayState([string]$Directory, $State) {
  Assert-RelayPrivateDirectory $Directory
  $pending = Join-Path $Directory 'state.pending.json'
  [IO.File]::WriteAllText($pending, ($State | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
  Move-Item -LiteralPath $pending -Destination (Join-Path $Directory 'state.json') -Force -ErrorAction Stop
}

function Get-RelayProcessIdentity([Diagnostics.Process]$Process) {
  if ($Process.HasExited) { throw (New-RelayFailure 'The process has already stopped.') }
  $null = $Process.Handle
  return @{
    pid = $Process.Id
    started_ticks = $Process.StartTime.ToUniversalTime().Ticks.ToString([Globalization.CultureInfo]::InvariantCulture)
    executable = $Process.MainModule.FileName
  }
}

function Stop-RelayOwnedProcess($Identity) {
  if ($null -eq $Identity) { return }
  if ([int]$Identity.pid -eq $PID -or [int]$Identity.pid -le 0) { throw (New-RelayFailure 'Invalid process identity.') }
  $process = Get-Process -Id ([int]$Identity.pid) -ErrorAction SilentlyContinue
  if ($null -eq $process) { return }
  try {
    $actual = Get-RelayProcessIdentity $process
    if ($actual.started_ticks -ne [string]$Identity.started_ticks -or -not (Test-RelaySamePath $actual.executable ([string]$Identity.executable))) {
      throw (New-RelayFailure 'The PID now belongs to a different process. Nothing was stopped.')
    }
    $process.Kill()
    if (-not $process.WaitForExit(5000)) { throw (New-RelayFailure 'The process did not stop.') }
  } finally { $process.Dispose() }
}

function Get-RelayRendezvousOrigin([string]$Value) {
  $uri = $null
  if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -ne 'https' -or
      $uri.UserInfo -or $uri.Query -or $uri.Fragment -or $uri.AbsolutePath -ne '/' -or -not $uri.IsDefaultPort) {
    throw (New-RelayFailure 'Invalid rendezvous URL: a plain HTTPS origin is required.')
  }
  return $uri.GetLeftPart([UriPartial]::Authority)
}

function ConvertFrom-RelayTicketJson([string]$Json) {
  $options = @{ErrorAction='Stop'}
  # PowerShell 7.5+ converts ISO dates automatically; 5.1 leaves them strings.
  # Preserve the same strict ticket schema on both supported parser behaviors.
  if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) { $options.DateKind = 'String' }
  return ConvertFrom-Json -InputObject $Json @options
}

function Get-RelayTicketConfig($Config, [DateTimeOffset]$Now = [DateTimeOffset]::UtcNow) {
  $fields = @('version', 'url', 'ticket_id', 'ticket_secret', 'expires_at')
  if ($null -eq $Config -or $Config -isnot [pscustomobject]) {
    throw (New-RelayFailure 'Invalid package configuration.')
  }
  $names = @($Config.PSObject.Properties.Name)
  if ($names.Count -ne $fields.Count -or @($names | Where-Object { $_ -cnotin $fields }).Count -ne 0 -or
      ($Config.version -isnot [int] -and $Config.version -isnot [long]) -or $Config.version -ne 3) {
    throw (New-RelayFailure 'Update the package to the persistent-credential format.')
  }
  foreach ($field in @('url', 'ticket_id', 'ticket_secret')) {
    if ($Config.$field -isnot [string]) { throw (New-RelayFailure 'Invalid package credential.') }
  }
  if ($Config.ticket_id -cnotmatch '^[0-9a-f]{32}$' -or $Config.ticket_secret -cnotmatch '^[0-9a-f]{64}$' -or $null -ne $Config.expires_at) {
    throw (New-RelayFailure 'Invalid persistent package credential.')
  }
  return @{
    version = 3; url = (Get-RelayRendezvousOrigin $Config.url)
    ticket_id = $Config.ticket_id; ticket_secret = $Config.ticket_secret; expires_at = $null
  }
}

function Publish-RelaySession([string]$Origin, [string]$TicketSecret, [string]$Payload) {
  # A lost response may hide a successful publication. Every retry MUST reuse
  # the exact same session, token, tunnel and serialized payload.
  for ($attempt = 1; $attempt -le 3; $attempt++) {
    $response = $null
    try { $response = Invoke-RelayHttp "$Origin/session" 'POST' @{ Authorization = "Bearer $TicketSecret" } $Payload -TimeoutMs 15000 }
    catch {
      if (-not $_.Exception.Data.Contains('RelayRetryable') -or -not $_.Exception.Data['RelayRetryable']) { throw }
      if ($attempt -eq 3) { throw (New-RelayFailure 'Publication was not confirmed after several attempts. The relay will stop.') }
    }
    if ($null -ne $response) {
      if ($response.status -in @(200, 201)) { return }
      if ($response.status -lt 500 -or $response.status -gt 599) {
        throw (New-RelayFailure 'Connection refused: another session is active or the package credential was revoked. Stop the previous relay and verify cleanup.')
      }
      if ($attempt -eq 3) { throw (New-RelayFailure 'The rendezvous is unavailable. The relay will stop.') }
    }
    Start-Sleep -Milliseconds (500 * $attempt)
  }
}

function Invoke-RelayHttp([string]$Uri, [string]$Method, [hashtable]$Headers, [string]$Body = '', [int]$TimeoutMs = 10000) {
  $clock = [Diagnostics.Stopwatch]::StartNew()
  $request = [Net.HttpWebRequest]::Create($Uri)
  $request.Method = $Method
  $request.AllowAutoRedirect = $false
  $request.Timeout = $TimeoutMs
  $request.ReadWriteTimeout = $TimeoutMs
  $request.UseDefaultCredentials = $false
  if (([Uri]$Uri).IsLoopback) { $request.Proxy = $null }
  foreach ($key in $Headers.Keys) { $request.Headers[$key] = [string]$Headers[$key] }
  $response = $null
  try {
    if ($Body) {
      $data = [Text.Encoding]::UTF8.GetBytes($Body)
      $request.ContentType = 'application/json'
      $request.ContentLength = $data.Length
      $stream = $request.GetRequestStream()
      try { $stream.Write($data, 0, $data.Length) } finally { $stream.Dispose() }
    }
    try { $response = $request.GetResponse() }
    catch [Net.WebException] {
      if ($null -eq $_.Exception.Response) { throw (New-RelayFailure 'HTTP request failed or timed out.' -Retryable) }
      $response = $_.Exception.Response
    }
    # Error and redirect bodies are untrusted and irrelevant to every caller.
    # Preserve the received status even if that body is truncated or never ends:
    # a denied publication must never turn into a retryable transport failure.
    $status = [int]$response.StatusCode
    if ($status -lt 200 -or $status -ge 300) { return @{status=$status; body=''} }
    $reader = New-Object IO.StreamReader($response.GetResponseStream())
    try {
      $buffer = New-Object char[] 16385
      $length = 0
      while ($length -lt $buffer.Length) {
        $remaining = $TimeoutMs - [int]$clock.ElapsedMilliseconds
        if ($remaining -le 0) { throw (New-RelayFailure 'HTTP deadline exceeded.' -Retryable) }
        $read = $reader.ReadAsync($buffer, $length, $buffer.Length - $length)
        if (-not $read.Wait($remaining)) { $request.Abort(); throw (New-RelayFailure 'HTTP deadline exceeded.' -Retryable) }
        $count = $read.GetAwaiter().GetResult()
        if ($count -eq 0) { break }
        $length += $count
      }
      if ($length -gt 16384) { throw (New-RelayFailure 'HTTP response exceeds the size limit.') }
      $text = if ($length -eq 0) { '' } else { -join $buffer[0..($length - 1)] }
      return @{ status = [int]$response.StatusCode; body = $text }
    } finally { $reader.Dispose() }
  } catch [Net.WebException] {
    throw (New-RelayFailure 'HTTP request failed or timed out.' -Retryable)
  } catch {
    # ReadAsync may wrap a mid-response disconnect in AggregateException.
    $cause = $_.Exception
    while ($null -ne $cause) {
      if ($cause -is [IO.IOException] -or $cause -is [Net.WebException]) {
        throw (New-RelayFailure 'HTTP response was interrupted.' -Retryable)
      }
      $cause = $cause.InnerException
    }
    throw
  } finally {
    if ($null -ne $response) { $response.Dispose() }
    $request.Abort()
  }
}

function Remove-RelayRemoteSession($State) {
  if (-not $State.rendezvous_url) { return }
  $origin = Get-RelayRendezvousOrigin ([string]$State.rendezvous_url)
  if ([string]$State.session_id -notmatch '^[0-9a-f]{32}$' -or [string]$State.delete_token -notmatch '^[0-9a-f]{64}$') {
    throw (New-RelayFailure 'Invalid session removal credentials.')
  }
  $response = Invoke-RelayHttp "$origin/session" 'DELETE' @{
    Authorization = "Bearer $($State.delete_token)"
    'X-Relay-Session-Id' = [string]$State.session_id
  }
  # Not found or replaced: never use publication rights to delete a session.
  if ($response.status -notin @(200, 204, 404, 409)) { throw (New-RelayFailure 'Remote session removal could not be confirmed.') }
}

function Assert-RelayCleanupFolder([string]$Folder) {
  $full = Get-RelayFullPath $Folder
  if ($full -notmatch '^[a-zA-Z]:\\.+') { throw (New-RelayFailure 'Cleanup refused: a full local path is required.') }
  $root = [IO.Path]::GetPathRoot($full)
  $protected = @($root, $env:USERPROFILE, $env:TEMP, [Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('MyDocuments'))
  foreach ($path in $protected) {
    if ($path -and (Test-RelaySamePath $full $path)) { throw (New-RelayFailure 'Cleanup refused: a protected user directory or drive root was selected.') }
  }
  Assert-RelayNoReparse $full
  $qualifier = $root.TrimEnd('\')
  Assert-RelayFixedVolume $qualifier
  return $full
}

function Assert-RelayFixedVolume([string]$Qualifier) {
  if ($Qualifier -notmatch '^[a-zA-Z]:$') { throw (New-RelayFailure 'Invalid drive identifier.') }
  $disks = @(Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$Qualifier'" -ErrorAction Stop)
  if ($disks.Count -ne 1 -or [int]$disks[0].DriveType -ne 3) {
    throw (New-RelayFailure 'Directory preserved: a fixed local drive could not be verified.')
  }
}

function Start-RelayCleanup([string]$Folder, [switch]$PauseOnFailure) {
  $temporary = Join-Path $env:TEMP ('relay-cleaner-' + [Guid]::NewGuid().ToString('N'))
  New-RelayPrivateDirectory $temporary
  foreach ($name in @('relay-cleaner.ps1', 'relay-common.ps1')) {
    Copy-Item -LiteralPath (Join-Path $Folder $name) -Destination (Join-Path $temporary $name) -ErrorAction Stop
  }
  $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  # EncodedCommand transports only paths, avoiding cmd.exe expansion of names.
  $retryCommand = "& '" + (Join-Path $temporary 'relay-cleaner.ps1').Replace("'", "''") + "' -Folder '" + $Folder.Replace("'", "''") + "' -Detached -PauseOnFailure"
  $encodedRetry = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($retryCommand))
  $retryBatch = "@echo off`r`nsetlocal DisableDelayedExpansion`r`n" + '"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -EncodedCommand ' + $encodedRetry + "`r`n"
  [IO.File]::WriteAllText((Join-Path $temporary 'retry-cleanup.cmd'), $retryBatch, [Text.Encoding]::ASCII)
  $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $temporary 'relay-cleaner.ps1'), '-Folder', $Folder, '-Detached')
  if ($PauseOnFailure) { $arguments += '-PauseOnFailure' }
  $commandLine = ($arguments | ForEach-Object { ConvertTo-RelayArgument $_ }) -join ' '
  $process = Start-Process -FilePath $powershell -WorkingDirectory $env:TEMP -ArgumentList $commandLine -WindowStyle Normal -PassThru -ErrorAction Stop
  $process.Dispose()
}
