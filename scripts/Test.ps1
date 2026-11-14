$ErrorActionPreference = 'Stop'
Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    & cargo xtask test
    if ($LASTEXITCODE) { throw 'Rust verification failed' }
} finally { Pop-Location }
