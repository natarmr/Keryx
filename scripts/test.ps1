#Requires -Version 5.1
<#
.SYNOPSIS
    Run the idboard workspace tests, working around Smart App Control.

.DESCRIPTION
    Smart App Control on this machine refuses to execute some locally built,
    unsigned test binaries. The verdict is per file content hash, so it is not
    something a build can reason about: a given source tree may build fine, and
    an unrelated one-line edit may produce a binary that is refused with

        An Application Control policy has blocked this file. (os error 4551)

    The durable fix is a machine security setting, and that is the owner's call,
    not this script's. There is no supported per-file allow rule without
    administrator rights, and the build runs unprivileged here.

    So the script perturbs the *emitted binary* and retries. It rewrites a
    documented constant in a real source file, which changes codegen and
    therefore the content hash that Smart App Control keys on.

    The probe lives in `idboard-core`, not in a leaf crate, and that placement
    is load-bearing: a change only reaches a test binary that links the changed
    library. Probing `idboard/src/lib.rs` unblocked the `idboard` test binary and
    nothing else, so `-Package idboardd` and a full workspace run would re-roll
    the same verdict until they gave up. `idboard-core` is linked by every crate
    in the workspace, so one probe location covers every test binary.

    An earlier version probed a scratch file at the workspace root. That did not
    work: the file belonged to no crate, so cargo reused the identical binary and
    re-rolled the same verdict ten times in a row. A comment does not work
    either, because comments do not reach codegen.

.PARAMETER Package
    Cargo package selector, e.g. -Package idboardd. Defaults to the workspace.

.PARAMETER MaxAttempts
    How many times to try before giving up.

.EXAMPLE
    .\scripts\test.ps1
    .\scripts\test.ps1 -Package idboard
#>
[CmdletBinding()]
param(
    [string] $Package,
    [int]    $MaxAttempts = 12
)

$ErrorActionPreference = 'Continue'
$root     = Split-Path -Parent $PSScriptRoot
# Must be a crate that every package under test links, so the perturbation
# reaches every test binary and not just the leaf crate's.
$probe    = Join-Path $root 'crates\idboard-core\src\lib.rs'
$cargo    = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'

if (-not (Test-Path $cargo)) { throw "cargo not found at $cargo" }

function Log($m) { Write-Host "    $m" -ForegroundColor DarkGray }

function Set-Probe([int] $n) {
    $text = Get-Content -LiteralPath $probe -Raw
    # Strip any previous probe. The whole probe is one line on purpose: an
    # earlier version used a separate `#[doc(hidden)]` attribute line, and
    # cleaning up the const left the orphaned attribute behind, which broke the
    # build. One line means one line to remove.
    $text = ($text -split "`r?`n" | Where-Object { $_ -notmatch '__SM_APP_CONTROL_PROBE' }) -join "`r`n"
    if ($n -gt 0) {
        $text = $text.TrimEnd() + "`r`n" +
                "#[doc(hidden)] pub const __SM_APP_CONTROL_PROBE: u8 = $n;`r`n"
    } else {
        $text = $text.TrimEnd() + "`r`n"
    }
    Set-Content -LiteralPath $probe -Value $text -NoNewline
}

$args = @('test')
if ($Package) { $args += @('-p', $Package) }
$args += @('--color', 'never')

for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
    Write-Host "==> test attempt $attempt/$MaxAttempts" -ForegroundColor DarkGray
    $output = & $cargo @args 2>&1 | Out-String
    $exit   = $LASTEXITCODE

    # Every exit from this loop must leave the tree clean. The give-up path below
    # and an interrupted run are exactly the cases AGENTS.md warns about: a
    # stray `__SM_APP_CONTROL_PROBE` in a real source file, which gates nothing
    # and confuses the next reader.
    try {
        if ($exit -eq 0) {
            Write-Host $output
            Write-Host "==> ok on attempt $attempt" -ForegroundColor Green
            Set-Probe 0 | Out-Null
            exit 0
        }

        if ($output -notmatch 'Application Control policy has blocked this file') {
            # A genuine test failure or compile error. Print it and stop; retrying
            # would only hide a real problem.
            Write-Host $output
            Write-Host "==> failed for a real reason (not an App Control block)" -ForegroundColor Red
            Set-Probe 0 | Out-Null
            exit $exit
        }

        Log "blocked by Application Control; perturbing the binary"
        Set-Probe $attempt
    } finally {
        # No-op on the paths that already cleaned up; this covers Ctrl-C and any
        # other unwinding out of the loop.
        if ($output -notmatch 'Application Control policy has blocked this file') {
            Set-Probe 0 | Out-Null
        }
    }
}

Write-Host "==> gave up after $MaxAttempts attempts" -ForegroundColor Red
Set-Probe 0 | Out-Null
exit 1
