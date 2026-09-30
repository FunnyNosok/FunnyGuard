param(
    [string] $Jdk = "C:\Users\danil\classloader-tools\jdk\jdk-21.0.12.1+1"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$fg = Split-Path -Parent $root
$javac = Join-Path $Jdk "bin\javac.exe"
if (-not (Test-Path $javac)) { throw "javac not found: $javac" }

$out = Join-Path $root "build\classes"
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory -Force $out | Out-Null

$sources = @()
$sources += Get-ChildItem -Recurse -Filter *.java (Join-Path $root "src") | ForEach-Object { $_.FullName }
$sources += Get-ChildItem -Filter *.java (Join-Path $fg "src\loader") | ForEach-Object { $_.FullName }
& $javac --release 17 -d $out @sources
if ($LASTEXITCODE -ne 0) { throw "license compilation failed" }

Write-Host "License built: $out"
