$ErrorActionPreference = 'Stop'
Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    & cargo xtask assets
    if ($LASTEXITCODE) { throw 'Rust asset verification failed' }
} finally { Pop-Location }
