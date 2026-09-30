param(
    [string] $Jdk = "C:\Users\danil\classloader-tools\jdk\jdk-21.0.12.1+1"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$java = Join-Path $Jdk "bin\java.exe"
$classes = Join-Path $root "build\classes"
$dll = Join-Path $root "build\nativecore.dll"

if (-not (Test-Path $dll)) { throw "nativecore.dll not built; run build.ps1 first" }

& $java -cp $classes com.protectedclient.nativecore.NativeDemo $dll
