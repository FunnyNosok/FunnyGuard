param(
    [Parameter(Mandatory = $true)]
    [string] $Text,

    [string] $Jdk = "C:\Users\danil\classloader-tools\jdk\jdk-21.0.12.1+1"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$java = Join-Path $Jdk "bin\java.exe"
$classes = Join-Path $root "build\packer-classes"

if (-not (Test-Path (Join-Path $classes "com\protectedclient\packer\Packer.class"))) {
    & (Join-Path $PSScriptRoot "build-packer.ps1") -Jdk $Jdk
}

& $java -cp $classes com.protectedclient.packer.Packer vault --text $Text
