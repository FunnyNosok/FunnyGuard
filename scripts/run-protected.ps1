param(
    [Parameter(Mandatory = $true)]
    [string] $Jar,

    [Parameter(Mandatory = $true)]
    [string] $Main,

    [Parameter(Mandatory = $true)]
    [string] $Pass,

    [Parameter(Mandatory = $true)]
    [string] $Core,

    [string] $McJar = "",

    [string] $Guard = "LOG",

    [string] $Jdk = "C:\Users\danil\classloader-tools\jdk-src\build\windows-x86_64-server-release\jdk"
)

$ErrorActionPreference = "Stop"
$java = Join-Path $Jdk "bin\java.exe"

if (-not (Test-Path $java)) {
    throw "protected JDK not found: $java (build it via jdk\README.md, then pass -Jdk <path>)"
}
if (-not (Test-Path $Jar)) {
    throw "jar not found: $Jar"
}
if (-not (Test-Path $Core)) {
    throw "nativecore.dll not found: $Core (build it via nativecore\scripts\build.ps1)"
}

$cp = $Jar
if ($McJar -ne "" -and (Test-Path $McJar)) {
    $cp = "$Jar;$McJar"
}

$env:PMCH_PASS = $Pass
$env:PMCH_CORE = (Resolve-Path $Core).Path
$env:PMCH_GUARD = $Guard
try {
    & $java -XX:+DisableAttachMechanism -XX:-EnableDynamicAgentLoading --add-exports java.base/jdk.internal.misc=ALL-UNNAMED -cp $cp $Main
    $code = $LASTEXITCODE
} finally {
    $env:PMCH_PASS = ""
    $env:PMCH_CORE = ""
}

Write-Host ""
Write-Host "Exit code: $code"
