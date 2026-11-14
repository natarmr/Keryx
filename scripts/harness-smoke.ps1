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
      muse       `muse exec --yolo "<prompt>"`                    works when configured
      freebuff   no headless mode                                 not automatable
      others     anything with a one-shot prompt mode             add an argv arm

.PARAMETER Harness
    Which harness to drive.

.PARAMETER TimeoutSeconds
    How long the harness may take before the test kills it.

.PARAMETER List
    Print supported harnesses, whether they are on PATH, and the resolved
    executable. Does not build or run anything.

.EXAMPLE
    .\scripts\harness-smoke.ps1 -List
    .\scripts\harness-smoke.ps1
    .\scripts\harness-smoke.ps1 -Harness muse
    .\scripts\harness-smoke.ps1 -Harness opencode -TimeoutSeconds 300
#>
[CmdletBinding()]
param(
    [ValidateSet('opencode', 'muse')]
    [string] $Harness = 'opencode',
    # Path to the harness's real executable. Resolved automatically when the
    # harness is an npm shim or a launcher script.
    [string] $HarnessBin,
    # Model to run the harness with. Account-specific; leave empty to let the
    # harness choose its own default.
    [string] $Model,
    [int] $TimeoutSeconds = 240,
    [switch] $List
)

function Resolve-HarnessBin([string] $Name, [string] $Override) {
    if ($Override) { return $Override }
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $cmd) { return $null }
    if ($cmd.CommandType -eq 'Application' -and $cmd.Source -match '\.exe$') { return $cmd.Source }
    $shimDir = Split-Path $cmd.Source -Parent
    $found = Get-ChildItem -Path $shimDir -Filter "$Name*.exe" -File -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $found) {
        $nodeModules = Join-Path $shimDir 'node_modules'
        if (Test-Path $nodeModules) {
            $found = Get-ChildItem -Path $nodeModules -Recurse -Depth 4 `
                -Filter "$Name.exe" -File -ErrorAction SilentlyContinue | Select-Object -First 1
        }
    }
    if ($found) { return $found.FullName }
    return $cmd.Source
}

if ($List) {
    foreach ($h in @('opencode', 'muse')) {
        $cmd = Get-Command $h -ErrorAction SilentlyContinue
        $onPath = [bool]$cmd
        $path = if ($cmd) { $cmd.Source } else { '(not on PATH)' }
        $bin = Resolve-HarnessBin $h $null
        if (-not $bin) { $bin = '(unresolved)' }
        $test = "${h}_posts_through_the_wrapper"
        Write-Host ("{0,-10} test={1}" -f $h, $test)
        Write-Host ("           path: {0}" -f $path)
        Write-Host ("           exec: {0}" -f $bin)
    }
    exit 0
}

if (-not $Model -and $Harness -eq 'opencode') {
    $Model = 'opencode/minimax-m3.1-flash-free'
}

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
    $HarnessBin = Resolve-HarnessBin $Harness $null
    if (-not $HarnessBin -or $HarnessBin -notmatch '\.exe$') {
        $src = if ($cmd) { $cmd.Source } else { $Harness }
        throw "$Harness resolves to $src, which is not an executable CreateProcess can run. Pass -HarnessBin <path-to-exe>."
    }
} else {
    $HarnessBin = Resolve-HarnessBin $Harness $HarnessBin
}
Write-Host "harness executable: $HarnessBin"

$testName = "${Harness}_posts_through_the_wrapper"
$env:IDBOARD_LIVE_HARNESS = $Harness
$env:IDBOARD_LIVE_HARNESS_BIN = $HarnessBin
if ($Model) { $env:IDBOARD_LIVE_HARNESS_MODEL = $Model } else { Remove-Item Env:\IDBOARD_LIVE_HARNESS_MODEL -ErrorAction SilentlyContinue }
try {
    Write-Host "driving $Harness under idboard run (timeout ${TimeoutSeconds}s), log: $log"
    # Redirect to a file and read $LASTEXITCODE. Piping cargo's stderr through
    # PowerShell turns native stderr into error records, which makes a passing
    # run look like a failure when the harness writes JSON-lines to stdout.
    Invoke-Native {
        & cargo test -p idboard --test e2e -- --ignored --exact --nocapture $testName *> $log
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
