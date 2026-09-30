param(
    [Parameter(Mandatory = $true)] [string] $Jar,
    [Parameter(Mandatory = $true)] [string] $Main,
    [Parameter(Mandatory = $true)] [string] $Token,
    [Parameter(Mandatory = $true)] [string] $Secret,
    [string] $Server = "http://127.0.0.1:8077/license",
    [string] $HwidOverride = "",
    [string] $BuildJdk = "C:\Users\danil\classloader-tools\jdk\jdk-21.0.12.1+1",
    [string] $RunJdk = "C:\Users\danil\classloader-tools\jdk-src\build\windows-x86_64-server-release\jdk"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$classes = Join-Path $root "build\classes"

Write-Host "[secure-launch] requesting key from server (no key stored on disk)..."
$clientArgs = @('-cp', $classes, 'com.protectedclient.license.LicenseClient', $Server, $Token, $Secret)
if ($HwidOverride -ne "") { $clientArgs += $HwidOverride }
$pass = & (Join-Path $BuildJdk "bin\java.exe") @clientArgs
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($pass)) {
    throw "could not obtain license key from server"
}
$pass = $pass.Trim()
Write-Host "[secure-launch] key received in memory, launching protected client..."

$env:PMCH_PASS = $pass
$env:PMCH_GUARD = "LOG"
try {
    & (Join-Path $RunJdk "bin\java.exe") -XX:+DisableAttachMechanism -XX:-EnableDynamicAgentLoading --add-exports java.base/jdk.internal.misc=ALL-UNNAMED -cp $Jar $Main
    $code = $LASTEXITCODE
} finally {
    $env:PMCH_PASS = ""
    $pass = $null
}
Write-Host "[secure-launch] exit code: $code"
