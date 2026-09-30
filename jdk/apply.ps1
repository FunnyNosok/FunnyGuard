param(
    [Parameter(Mandatory = $true)]
    [string] $JdkSrc
)

$ErrorActionPreference = "Stop"
$here = $PSScriptRoot

if (-not (Test-Path (Join-Path $JdkSrc "src\hotspot\share\classfile\classFileParser.cpp"))) {
    throw "JdkSrc does not look like an OpenJDK checkout: $JdkSrc"
}

Copy-Item (Join-Path $here "new-files\hotspot\pmchDecrypt.cpp") (Join-Path $JdkSrc "src\hotspot\share\classfile\pmchDecrypt.cpp") -Force
Copy-Item (Join-Path $here "new-files\hotspot\pmchDecrypt.hpp") (Join-Path $JdkSrc "src\hotspot\share\classfile\pmchDecrypt.hpp") -Force
Copy-Item (Join-Path $here "new-files\java.base\PmchGuard.java") (Join-Path $JdkSrc "src\java.base\share\classes\jdk\internal\misc\PmchGuard.java") -Force
Copy-Item (Join-Path $here "new-files\java.base\PmchStrings.java") (Join-Path $JdkSrc "src\java.base\share\classes\jdk\internal\misc\PmchStrings.java") -Force
Copy-Item (Join-Path $here "new-files\libjava\PmchStrings_md.c") (Join-Path $JdkSrc "src\java.base\windows\native\libjava\PmchStrings_md.c") -Force

Push-Location $JdkSrc
try {
    & git apply --whitespace=nowarn (Join-Path $here "patches\classFileParser.cpp.patch")
    if ($LASTEXITCODE -ne 0) { throw "failed to apply classFileParser.cpp.patch" }
    & git apply --whitespace=nowarn (Join-Path $here "patches\System.java.patch")
    if ($LASTEXITCODE -ne 0) { throw "failed to apply System.java.patch" }
    & git apply --whitespace=nowarn (Join-Path $here "patches\arguments.cpp.patch")
    if ($LASTEXITCODE -ne 0) { throw "failed to apply arguments.cpp.patch" }
} finally {
    Pop-Location
}

Write-Host "Patches applied to $JdkSrc"
Write-Host "Next: bash configure --with-boot-jdk=<jdk> --disable-warnings-as-errors && make exploded-image"
