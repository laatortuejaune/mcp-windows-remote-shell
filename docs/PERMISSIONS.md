# Permissions and platform validation

The intended target baseline is an ordinary interactive Windows user with a
writable package directory. There is no installer, Windows service registration,
firewall-rule change, scheduled task, or automatic UAC elevation in the launcher.

## What the code actually requests

- `Start-Process` starts the agent/cloudflared without `-Verb RunAs`.
- The agent listens on an unprivileged loopback port (47600 by default).
- The launcher creates a private session directory owned by the current user,
  granting access only to that user and SYSTEM.
- Authenticated `/health`, `Get-NetTCPConnection`, and process metadata are used
  to verify the new agent and its listening PID.
- `Get-CimInstance Win32_LogicalDisk` checks the cleanup volume type.
- Cleanup stops the processes it started and removes package-owned files.

The CIM queries and filesystem operations can be restricted by local or domain
policy. Failure to verify a process, listener, volume, or ACL blocks that step;
the code does not silently fall back to elevated or less-verified execution.

## PowerShell policy is separate from administrator rights

The `.cmd` entry points use `powershell.exe -ExecutionPolicy Bypass -File ...`.
This applies only to that PowerShell process. It does not change machine policy,
grant administrator rights, or override Group Policy precedence.

Microsoft documents [execution-policy scopes and precedence](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies).

## When additional rights may be required

- A requested troubleshooting command changes protected files, services,
  machine-wide registry settings, or other administrator-controlled resources.
- The chosen package directory is not writable by the launching user.
- Organization policy requires an administrator to permit the executable,
  PowerShell, CIM access, or required outbound connectivity.
- Development tools are installed using an installation method that requires
  elevated permissions. Runtime use does not itself install Go or Node.js.

If an operator intentionally launches the relay elevated, remote commands inherit
those higher privileges. Do not assume UAC prompts can be answered remotely by
this noninteractive command interface. Prefer standard-user operation.

## Validation status and release check

The repository contains cross-platform Go tests, native Windows test sources,
PowerShell helper checks, and local MCP/Worker integration tests. Cross-compiling
or passing mocked checks does not prove startup and cleanup under every Windows
standard-user policy. A live standard-user target was not available during the
English/publication preparation pass.

Before claiming standard-user support for a release, validate on a disposable
Windows 11 x64 machine from a non-elevated account:

1. Copy the package to that user's writable fixed-drive directory.
2. Start `start-relay.cmd` without selecting "Run as administrator".
3. Confirm successful port/PID validation, publication, and a harmless command.
4. Confirm a protected operation is denied rather than silently elevated.
5. Stop with Ctrl+C and verify the agent, tunnel, and expected package files are
   gone. Test `cleanup.cmd` and its retry behavior after an interrupted cleanup.

Record OS, PowerShell version, elevation state, and outcomes without publishing
usernames, credential values, tunnel URLs, or private paths.
