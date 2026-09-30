param(
    [string] $Jdk = "C:\Users\danil\classloader-tools\jdk\jdk-21.0.12.1+1"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$javac = Join-Path $Jdk "bin\javac.exe"

if (-not (Test-Path $javac)) {
    throw "javac not found: $javac (pass -Jdk <path to a full JDK 17+>)"
}

$out = Join-Path $root "build\packer-classes"
if (Test-Path $out) {
    Remove-Item -Recurse -Force $out
}
New-Item -ItemType Directory -Force -Path $out | Out-Null

$sources = @()
$sources += Get-ChildItem -Recurse -Filter *.java (Join-Path $root "src\loader") | ForEach-Object { $_.FullName }
$sources += Get-ChildItem -Recurse -Filter *.java (Join-Path $root "src\packer") | ForEach-Object { $_.FullName }

& $javac --release 17 -d $out @sources
if ($LASTEXITCODE -ne 0) { throw "packer compilation failed" }

Write-Host "Packer built: $out"
