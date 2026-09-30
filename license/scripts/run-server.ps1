param(
    [int] $Port = 8077,
    [string] $Payload = "",
    [string] $SealKey = "",
    [string] $Jdk = "C:\Users\danil\classloader-tools\jdk\jdk-21.0.12.1+1"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$java = Join-Path $Jdk "bin\java.exe"
$classes = Join-Path $root "build\classes"
if (-not (Test-Path (Join-Path $classes "com\protectedclient\license\LicenseServer.class"))) {
    & (Join-Path $PSScriptRoot "build.ps1") -Jdk $Jdk
}
$args = @('-cp', $classes, 'com.protectedclient.license.LicenseServer', "$Port")
if ($Payload -ne "") { $args += $Payload } elseif ($SealKey -ne "") { $args += "" }
if ($SealKey -ne "") { $args += $SealKey }
& $java @args
