param(
    [Parameter(Mandatory = $true)]
    [string] $InJar,

    [Parameter(Mandatory = $true)]
    [string] $OutJar,

    [Parameter(Mandatory = $true)]
    [string] $KeyOut,

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

& $java -cp $classes com.protectedclient.packer.Packer seal --in $InJar --out $OutJar --key-out $KeyOut
if ($LASTEXITCODE -ne 0) { throw "seal packing failed" }

Write-Host ""
Write-Host "Sealed jar written: $OutJar"
Write-Host "Seal key (KEEP ON SERVER, never ship to client): $KeyOut"
Write-Host "Serve it via: license\scripts\run-server.ps1 -SealKey $KeyOut"
