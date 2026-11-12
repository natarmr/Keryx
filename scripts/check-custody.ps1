#Requires -Version 5.1
<#
.SYNOPSIS
    Report who can reach idboard's trust root and its door.

.DESCRIPTION
    Two separate custody assumptions, and it is worth keeping them apart:

      1. config.toml - the trust root. It is the only thing that says which key
         belongs to which name, so a substituted key is *self-consistent*: the
         fingerprint is derived from the parsed key rather than read from the
         file, which means the wrapper/daemon fingerprint cross-check compares
         two readings of the same substituted key and agrees with it. The
         rotation warning is the only signal that anything moved.

      2. the daemon and relay sockets - the door. Every local process can reach
         a named pipe; a Unix socket path can be stat'd. Neither has a security
         descriptor set by idboard, so on Windows the listener inherits the
         creating token's default DACL. Every control behind the socket is a
         signature check, which anyone may attempt.

    This script READS. It starts nothing, stops nothing, and writes nothing. It
    cannot tell you whether the answer is good; it tells you what the answer is,
    so you can compare it against the intended list.

.EXAMPLE
    .\scripts\check-custody.ps1

.EXAMPLE
    # With a running daemon, so the live pipe can be inspected too.
    .\scripts\check-custody.ps1 -IncludeSocket
#>
[CmdletBinding()]
param(
    # Also inspect the live daemon pipe. Requires a running idboardd, and on
    # Windows a busy pipe may refuse inspection - that is reported, not hidden.
    [switch] $IncludeSocket
)

$ErrorActionPreference = 'Continue'
$root     = Split-Path -Parent $PSScriptRoot

function Section($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }
function Note($t)   { Write-Host "    $t" -ForegroundColor DarkGray }

# The intended list. Anything outside it that can WRITE is the finding.
$intended = @(
    "$env:COMPUTERNAME\$env:USERNAME"
    'NT AUTHORITY\SYSTEM'
    'BUILTIN\Administrators'
)

function Show-Acl([string] $Path, [string] $Label) {
    if (-not (Test-Path -LiteralPath $Path)) {
        Note "$Label : absent ($Path)"
        return
    }
    Write-Host "  $Label" -ForegroundColor White
    Note $Path
    $acl = Get-Acl -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $acl) { Note '  could not read the ACL'; return }
    Note "  owner: $($acl.Owner)"
    Note "  inheritance protected: $($acl.AreAccessRulesProtected)"
    foreach ($rule in $acl.Access) {
        $flag = switch ($rule.AccessControlType) {
            'Allow' { '+' } 'Deny' { '-' } default { '?' }
        }
        # Inherited-only rights are far less interesting than explicit ones.
        $how = if ($rule.IsInherited) { 'inherited' } else { 'EXPLICIT' }
        Note ("    {0} {1,-30} {2,-14} {3}" -f $flag, $rule.IdentityReference, $rule.FileSystemRights, $how)
    }
}

Section 'Environment'
Note "user:    $env:USERPROFILE"
Note "home:    $(if ($env:IDBOARD_HOME) { $env:IDBOARD_HOME } else { Join-Path $env:USERPROFILE '.idboard' })"
Note "daemon:  $(if ($env:IDBOARD_DAEMON) { $env:IDBOARD_DAEMON } else { '\\.\pipe\idboardd-' + $env:USERNAME })"

$home_ = if ($env:IDBOARD_HOME) { $env:IDBOARD_HOME } else { Join-Path $env:USERPROFILE '.idboard' }
$config = if ($env:IDBOARD_CONFIG) { $env:IDBOARD_CONFIG } else { Join-Path $home_ 'config.toml' }
$socket = if ($env:IDBOARD_DAEMON) { $env:IDBOARD_DAEMON } else { '\\.\pipe\idboardd-' + $env:USERNAME }

Section '1. The trust root'
Show-Acl $home_     'state root'
Show-Acl $config    'config.toml'
Show-Acl (Join-Path $home_ 'keys')   'keys/'
Show-Acl (Join-Path $home_ 'keys\eng-01.key') 'keys/eng-01.key (if present)'

Section '2. The door'
if ($IncludeSocket) {
    Show-Acl $socket 'daemon socket'
    Note 'a busy pipe may refuse inspection; that is a Win32 limitation, not a finding'
} else {
    Note "skipped. re-run with -IncludeSocket while a daemon is listening."
    Note "socket would be: $socket"
}

Section '3. Comparison'
Write-Host '  Intended principals:' -ForegroundColor White
foreach ($p in $intended) { Note "    $p" }
Write-Host '  Anything above with EXPLICIT write/modify that is not in that list is the finding.' -ForegroundColor Yellow
Note 'A second non-administrative local account is the only in-scope principal:'
Note 'README places same-user processes inside the boundary, and root/SYSTEM/Admins outside it.'
Note 'On a standard profile, BUILTIN\Users and Everyone are absent from both listings above.'

Section '4. What this cannot tell you'
Note 'idboard does not set a security descriptor on either listener, so the pipe'
Note "inherits the creating token's default DACL. This script cannot read a busy pipe."
Note 'The remaining in-boundary peer is a SAME-USER process, which is excluded from'
Note 'neither surface by design - see README "What idboard does not defend against".'
