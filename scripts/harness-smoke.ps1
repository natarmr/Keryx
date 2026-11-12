#Requires -Version 5.1
<#
.SYNOPSIS
    Prove a real agent harness can post through `idboard run`.

.DESCRIPTION
    Runs one live conformance test: a scratch state root, two identities, a real
    daemon, and a real harness launched by the wrapper. The harness is given a
    prompt that tells it to call `idboard whoami` and then post a nonce. The test
    asserts on the *board*, not on the model's prose: the nonce must be stored,
    and it must be signed by the identity the wrapper was launched with.

    This spends model tokens and needs network access, which is why it is not
    part of `cargo test --workspace`. Nothing here writes to a real `~/.idboard`.

    Harness support is a property of the harness, not of idboard:

      opencode   `opencode run --auto --format json "<prompt>"`   works
      warm       `warm -p "<prompt>"`                             needs `warm login`
      freebuff   no headless mode                                 not automatable
      others     anything with a one-shot prompt mode             add an argv arm
                 in `live_harness_posts`

.PARAMETER Harness
    Which harness to drive. Only `opencode` is implemented today.

.PARAMETER TimeoutSeconds
    How long the harness may take before the test kills it.

.EXAMPLE
    .\scripts\harness-smoke.ps1
    .\scripts\harness-smoke.ps1 -Harness opencode -TimeoutSeconds 300
#>
[CmdletBinding()]
param(
    [ValidateSet('opencode')]
    [string] $Harness = 'opencode',
    # Path to the harness's real executable. Resolved automatically when the
    # harness is an npm shim, because CreateProcess cannot run a .cmd/.ps1.
    [string] $HarnessBin,
    # Model to run the harness with. Account-specific, and free models get
    # retired; override this rather than editing the test.
    [string] $Model = 'opencode/minimax-m3.1-flash-free',
    [int] $TimeoutSeconds = 240
)

$ErrorActionPreference = 'Stop'
$log = Join-Path ([System.IO.Path]::GetTempPath()) "idboard-harness-$Harness.log"

# Native tools write progress to stderr, and PowerShell turns a native stderr
# write into an error record. With `$ErrorActionPreference = 'Stop'` that aborts
# the script on a *successful* build, so native invocations get 'Continue' and
# are judged by `$LASTEXITCODE` instead.
function Invoke-Native([scriptblock] $Command) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Command } finally { $ErrorActionPreference = $previous }
}

# The e2e harness locates idboardd as a sibling binary, so a package-scoped build
# is not enough. Same rule as `cargo test --workspace`.
Write-Host "building the workspace (the e2e harness needs target\debug\idboardd.exe)"
Invoke-Native { & cargo build --workspace *> $log }
if ($LASTEXITCODE -ne 0) {
    Write-Host "cargo build --workspace failed:"
    Get-Content -LiteralPath $log | Select-Object -Last 30
    exit $LASTEXITCODE
}

# Check the harness is actually installed before spending a daemon on
# discovering that it is not, then resolve it to something CreateProcess can run.
if (-not $HarnessBin) {
    $cmd = Get-Command $Harness -ErrorAction SilentlyContinue
    if (-not $cmd) { throw "$Harness is not on PATH; nothing to test against" }

    if ($cmd.CommandType -eq 'Application') {
        $HarnessBin = $cmd.Source
    }
    else {
        # An npm shim is a .cmd that names a real .exe under node_modules.
        $shimDir = Split-Path $cmd.Source -Parent
        $found = Get-ChildItem -Path (Join-Path $shimDir 'node_modules') -Recurse -Depth 4 `
            -Filter "$Harness.exe" -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $found) {
            throw "$Harness resolves to $($cmd.Source), which is a $($cmd.CommandType) shim and " +
                  "not an executable CreateProcess can run. Pass -HarnessBin <path-to-exe>."
        }
        $HarnessBin = $found.FullName
    }
}
Write-Host "harness executable: $HarnessBin"

$env:IDBOARD_LIVE_HARNESS = $Harness
$env:IDBOARD_LIVE_HARNESS_BIN = $HarnessBin
$env:IDBOARD_LIVE_HARNESS_MODEL = $Model
try {
    Write-Host "driving $Harness under idboard run (timeout ${TimeoutSeconds}s), log: $log"
    # Redirect to a file and read $LASTEXITCODE. Piping cargo's stderr through
    # PowerShell turns native stderr into error records, which makes a passing
    # run look like a failure when the harness writes JSON-lines to stdout.
    Invoke-Native {
        & cargo test -p idboard --test e2e -- --ignored --exact --nocapture `
            opencode_posts_through_the_wrapper *> $log
    }
    $code = $LASTEXITCODE

    Get-Content -LiteralPath $log | Select-String -Pattern 'test result|panicked|skipping' | ForEach-Object { $_.Line }
    if ($code -ne 0) {
        Write-Host ""
        Write-Host "failed; last 40 lines of the log:"
        Get-Content -LiteralPath $log | Select-Object -Last 40
        exit $code
    }
    Write-Host "harness smoke passed: a real $Harness agent posted a signed message through the wrapper"
}
finally {
    Remove-Item Env:\IDBOARD_LIVE_HARNESS -ErrorAction SilentlyContinue
    Remove-Item Env:\IDBOARD_LIVE_HARNESS_BIN -ErrorAction SilentlyContinue
    Remove-Item Env:\IDBOARD_LIVE_HARNESS_MODEL -ErrorAction SilentlyContinue
}
