#Requires -Version 5.1
<#
.SYNOPSIS
    Mechanically check the substring assertions in the custody-statement tests.

.DESCRIPTION
    The two new tests assert on properties of two string constants
    (idboard_ipc::listener_custody_statement and idboard_acl::Config::
    custody_statement): that they name a way to verify, that they do not contain
    over-claiming language, and that they admit the residual.

    Those are substring assertions on hand-written literals, which is precisely
    the class of assertion a compiler cannot check. This script extracts the real
    literals from the source, applies Rust's line-continuation and escape rules,
    and evaluates each assertion against the resulting value.

    It is a partial check. It does not compile anything, does not run the test
    harness, and cannot catch a type or borrow error.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$failures = 0

function Get-RustStrings([string] $Path, [string] $FnMarker) {
    $text = Get-Content -LiteralPath $Path -Raw
    $start = $text.IndexOf($FnMarker)
    if ($start -lt 0) { throw "could not find $FnMarker in $Path" }

    # Find the function body by brace matching rather than by searching for a
    # closing brace at some indentation. An earlier version cut the body at the
    # first `\n}`, which silently truncated the function at the end of its first
    # `#[cfg]` arm whenever those arms close at column 0 - and then reported a
    # missing arm that was present in the file.
    $open = $text.IndexOf('{', $start)
    if ($open -lt 0) { throw "no body found for $FnMarker" }
    $depth = 0
    $i = $open
    while ($i -lt $text.Length) {
        switch ($text[$i]) {
            '{' { $depth++ }
            '}' { $depth--; if ($depth -eq 0) { break } }
        }
        if ($depth -eq 0) { break }
        $i++
    }
    if ($depth -ne 0) { throw "unbalanced braces in the body of $FnMarker" }
    $body = $text.Substring($start, $i - $start)

    # Arms, keyed by the cfg that guards them. The cfg body allows one level of
    # nesting so that `not(unix)` matches; a `[^)]+` character class cannot, and
    # would have reported a present arm as missing.
    $arms = @{}
    $cfgPattern = '#\[cfg\((?<cfg>\w+(?:\(\w+\))?)\)\]\s*\{\s*(?<lit>"(?:[^"\\]|\\.|`r?`n\s*\\)*")\s*\}'
    foreach ($m in [regex]::Matches($body, $cfgPattern, 'Singleline')) {
        $lit = $m.Groups['lit'].Value
        # Rust: a backslash immediately before a newline continues the line and
        # contributes nothing. Then \\ -> \ and \" -> ".
        $lit = $lit -replace "\\\r?\n\s*", ""
        $lit = $lit.Substring(1, $lit.Length - 2)
        $lit = $lit -replace '\\\\', '\'
        $lit = $lit -replace '\\"', '"'
        $arms[$m.Groups['cfg'].Value] = $lit
    }
    return $arms
}

function Check([string] $Label, [bool] $Ok, [string] $Detail) {
    if ($Ok) { Write-Host "  PASS  $Label" -ForegroundColor Green }
    else { Write-Host "  FAIL  $Label" -ForegroundColor DarkYellow; Write-Host "        $Detail" -ForegroundColor DarkGray; $script:failures++ }
}

$ipcArms  = Get-RustStrings "$root\crates\idboard-ipc\src\lib.rs" "pub fn listener_custody_statement()"
$aclArms  = Get-RustStrings "$root\crates\idboard-acl\src\lib.rs"   "pub fn custody_statement()"

Write-Host "`n=== idboard_ipc::listener_custody_statement ===" -ForegroundColor Cyan
foreach ($k in $ipcArms.Keys | Sort-Object) { Write-Host "  [$k arm] len=$($ipcArms[$k].Length)" -ForegroundColor DarkGray }

# Every arm is checked, not just the one this host can compile. The test these
# mirror asserts unconditionally, so an arm that omits a required phrase fails
# the suite on the other platform - which is precisely the case nobody runs.
if ($ipcArms.Count -eq 0) { Write-Host "  FAIL  no arms extracted" -ForegroundColor Red; $failures++ }
foreach ($k in $ipcArms.Keys | Sort-Object) {
    $s = $ipcArms[$k]
    Write-Host "  -- $k arm" -ForegroundColor White
    Check "names a way to verify" ($s.Contains('check-custody.ps1')) $s
    foreach ($bad in @('only you', 'denies Everyone', 'restricts access', 'enforced')) {
        Check "does NOT over-claim '$bad'" (-not $s.Contains($bad)) "found it in: $s"
    }
    Check "names the in-boundary peer ('same-user')" ($s.Contains('same-user')) $s
    Check "names what guards it ('signature')"      ($s.Contains('signature')) $s
}

Write-Host "`n=== idboard_acl::Config::custody_statement ===" -ForegroundColor Cyan
foreach ($k in $aclArms.Keys | Sort-Object) { Write-Host "  [$k arm] len=$($aclArms[$k].Length)" -ForegroundColor DarkGray }

# Shared assertion first: it runs on every platform.
if ($aclArms.Count -eq 0) { Write-Host "  FAIL  no arms extracted" -ForegroundColor Red; $failures++ }
foreach ($k in $aclArms.Keys | Sort-Object) {
    Check "[$k] names a way to verify" ($aclArms[$k].Contains('check-custody.ps1')) $aclArms[$k]
}
# Then the platform-specific claims.
$a = $aclArms['not(unix)']
if ($null -eq $a) { Write-Host "  FAIL  no not(unix) arm found" -ForegroundColor Red; $failures++ }
else {
    Check "admits the DACL is not checked ('NOT')" ($a.Contains('NOT')) $a
    Check "does NOT imply the DACL is enforced" (-not $a.Contains('enforced (DACL)')) $a
}
$u = $aclArms['unix']
if ($null -eq $u) { Write-Host "  FAIL  no unix arm found" -ForegroundColor Red; $failures++ }
else {
    Check "unix arm claims the owner check" ($u.Contains('owned by you')) $u
    Check "unix arm claims enforcement"      ($u.Contains('enforced')) $u
}

Write-Host "`n=== idboardd startup ordering ===" -ForegroundColor Cyan
$main = Get-Content -LiteralPath "$root\crates\idboardd\src\main.rs" -Raw
Check "prints Config::custody_statement"          ($main.Contains('Config::custody_statement()')) 'not called'
Check "prints listener_custody_statement"         ($main.Contains('idboard_ipc::listener_custody_statement()')) 'not called'
$i1 = $main.IndexOf('Config::custody_statement()')
$i2 = $main.IndexOf('idboard_ipc::listener_custody_statement()')
Check "config custody comes before socket custody" ($i1 -ge 0 -and $i2 -gt $i1) "i1=$i1 i2=$i2"
Check "both are printed before the identity summary" ($main.IndexOf('config.summary()') -gt $i2) 'summary printed first'

Write-Host ""
if ($failures -eq 0) { Write-Host "all substring assertions hold" -ForegroundColor Green; exit 0 }
else { Write-Host "$failures assertion(s) would FAIL" -ForegroundColor Red; exit 1 }
