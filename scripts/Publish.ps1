param([string]$Target)
# Stage an unsigned local package; does not upload or publish a release.
$ErrorActionPreference = 'Stop'
Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    $packageArgs = @('xtask', 'package')
    $verifyArgs = @('xtask', 'verify')
    if ($Target) {
        $packageArgs += @('--target', $Target)
        $verifyArgs += @('--target', $Target)
    }
    & cargo @packageArgs
    if ($LASTEXITCODE) { throw 'Rust packaging failed' }
    & cargo @verifyArgs
    if ($LASTEXITCODE) { throw 'Rust package verification failed' }
} finally { Pop-Location }
