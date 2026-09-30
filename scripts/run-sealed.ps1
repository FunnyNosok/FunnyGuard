param(
    [Parameter(Mandatory = $true)] [string] $Jar,
    [Parameter(Mandatory = $true)] [string] $Main,
    [Parameter(Mandatory = $true)] [string] $Token,
    [Parameter(Mandatory = $true)] [string] $Secret,
    [string] $Server = "http://127.0.0.1:8077/seal",
    [string] $Guard = "LOG",
    [string] $JvmHash = "",
    [string] $BuildJdk = "C:\Users\danil\classloader-tools\jdk\jdk-21.0.12.1+1",
    [string] $RunJdk = "C:\Users\danil\classloader-tools\jdk-src\build\windows-x86_64-server-release\jdk"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$licenseRoot = Join-Path $root "license"
$classes = Join-Path $licenseRoot "build\classes"

if (-not (Test-Path (Join-Path $classes "com\protectedclient\boot\SealedLauncher.class"))) {
    & (Join-Path $licenseRoot "scripts\build.ps1") -Jdk $BuildJdk
}
if (-not (Test-Path $Jar)) {
    throw "sealed jar not found: $Jar (build it via scripts\seal-jar.ps1)"
}

$env:PMCH_JDK = $RunJdk
$env:PMCH_GUARD = $Guard
if ($JvmHash -ne "") { $env:PMCH_JVM_HASH = $JvmHash }
try {
    & (Join-Path $BuildJdk "bin\java.exe") -cp $classes com.protectedclient.boot.SealedLauncher `
        $Server $Token $Secret $Jar $Main
    $code = $LASTEXITCODE
} finally {
    $env:PMCH_JDK = ""
    $env:PMCH_GUARD = ""
    $env:PMCH_JVM_HASH = ""
}

Write-Host ""
Write-Host "Exit code: $code"
