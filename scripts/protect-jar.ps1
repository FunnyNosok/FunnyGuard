param(
    [Parameter(Mandatory = $true)]
    [string] $InJar,

    [Parameter(Mandatory = $true)]
    [string] $OutJar,

    [Parameter(Mandatory = $true)]
    [string] $Pass,

    [string] $Jdk = "C:\Users\danil\classloader-tools\jdk\jdk-21.0.12.1+1"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$java = Join-Path $Jdk "bin\java.exe"
$classes = Join-Path $root "build\packer-classes"

if (-not (Test-Path $InJar)) {
    throw "input jar not found: $InJar"
}
if (-not (Test-Path (Join-Path $classes "com\protectedclient\packer\Packer.class"))) {
    & (Join-Path $PSScriptRoot "build-packer.ps1") -Jdk $Jdk
}

& $java -cp $classes com.protectedclient.packer.Packer jarhook --in $InJar --out $OutJar --pass $Pass
if ($LASTEXITCODE -ne 0) { throw "jarhook packing failed" }

Write-Host ""
Write-Host "Protected jar written: $OutJar"
Write-Host "Run it with scripts\run-protected.ps1 and the same passphrase."
