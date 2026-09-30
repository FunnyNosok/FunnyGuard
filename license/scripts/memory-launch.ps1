param(
    [Parameter(Mandatory = $true)] [string] $Main,
    [Parameter(Mandatory = $true)] [string] $Token,
    [Parameter(Mandatory = $true)] [string] $Secret,
    [string] $Server = "http://127.0.0.1:8077",
    [string] $BuildJdk = "C:\Users\danil\classloader-tools\jdk\jdk-21.0.12.1+1",
    [string] $RunJdk = "C:\Users\danil\classloader-tools\jdk-src\build\windows-x86_64-server-release\jdk"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$classes = Join-Path $root "build\classes"

Write-Host "[memory-launch] fetching key from server (in memory)..."
$pass = & (Join-Path $BuildJdk "bin\java.exe") -cp $classes com.protectedclient.license.LicenseClient "$Server/license" $Token $Secret
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($pass)) { throw "could not obtain key" }
$pass = $pass.Trim()

Write-Host "[memory-launch] key in memory; pulling code from server and running (no jar on disk)..."
$env:PMCH_PASS = $pass
$env:PMCH_GUARD = "LOG"
try {
    & (Join-Path $RunJdk "bin\java.exe") -XX:+DisableAttachMechanism -XX:-EnableDynamicAgentLoading --add-exports java.base/jdk.internal.misc=ALL-UNNAMED `
        -cp $classes com.protectedclient.boot.MemoryLauncher $Server $Token $Secret $Main
    $code = $LASTEXITCODE
} finally {
    $env:PMCH_PASS = ""
    $pass = $null
}
Write-Host "[memory-launch] exit code: $code"
