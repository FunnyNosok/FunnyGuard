param(
    [string] $Jvm = "C:\Users\danil\classloader-tools\jdk-src\build\windows-x86_64-server-release\jdk\bin\server\jvm.dll"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$src = Join-Path $root "native\nativecore.cpp"

if (-not (Test-Path $Jvm)) { throw "jvm.dll not found: $Jvm" }
if (-not (Test-Path $src)) { throw "nativecore.cpp not found: $src" }

$hash = (Get-FileHash -Algorithm SHA256 -Path $Jvm).Hash.ToLower()
Write-Host "jvm.dll SHA-256: $hash"

$bytes = for ($i = 0; $i -lt 64; $i += 2) { "0x" + $hash.Substring($i, 2).ToUpper() }
$lines = @()
for ($i = 0; $i -lt 32; $i += 8) {
    $lines += "    " + (($bytes[$i..($i + 7)]) -join ", ") + ","
}
$block = "static const unsigned char EXPECTED_JVM_SHA256[32] = {`n" + ($lines -join "`n").TrimEnd(",") + "`n};"

$text = Get-Content -Raw $src
$pattern = "static const unsigned char EXPECTED_JVM_SHA256\[32\] = \{[^}]*\};"
$updated = [System.Text.RegularExpressions.Regex]::Replace($text, $pattern, [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $block })
if ($updated -eq $text) { throw "EXPECTED_JVM_SHA256 block not found / unchanged in nativecore.cpp" }
Set-Content -Path $src -Value $updated -Encoding utf8 -NoNewline

Write-Host "Patched EXPECTED_JVM_SHA256 in nativecore.cpp. Now rebuild: scripts\build.ps1"
