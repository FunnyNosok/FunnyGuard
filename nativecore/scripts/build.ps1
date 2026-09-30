param(
    [string] $Jdk = "C:\Users\danil\classloader-tools\jdk\jdk-21.0.12.1+1",
    [string] $Cmake = "C:\Users\danil\classloader-tools\cmake\cmake-3.30.5-windows-x86_64\bin\cmake.exe",
    [string] $Generator = "Visual Studio 17 2022"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$javac = Join-Path $Jdk "bin\javac.exe"
if (-not (Test-Path $javac)) { throw "javac not found: $javac" }

$classes = Join-Path $root "build\classes"
if (Test-Path $classes) { Remove-Item -Recurse -Force $classes }
New-Item -ItemType Directory -Force $classes | Out-Null

$sources = @()
$sources += Get-ChildItem -Recurse -Filter *.java (Join-Path $root "java") | ForEach-Object { $_.FullName }
$sources += Get-ChildItem -Recurse -Filter *.java (Join-Path $root "example") | ForEach-Object { $_.FullName }
& $javac --release 17 -d $classes @sources
if ($LASTEXITCODE -ne 0) { throw "java compilation failed" }

$build = Join-Path $root "build\cmake"
& $Cmake -S (Join-Path $root "native") -B $build -G $Generator -A x64 "-DJAVA_HOME=$Jdk"
if ($LASTEXITCODE -ne 0) { throw "cmake configure failed" }
& $Cmake --build $build --config Release
if ($LASTEXITCODE -ne 0) { throw "cmake build failed" }

Copy-Item (Join-Path $build "Release\nativecore.dll") (Join-Path $root "build\nativecore.dll") -Force
Write-Host ""
Write-Host "Built: $root\build\nativecore.dll and $classes"
