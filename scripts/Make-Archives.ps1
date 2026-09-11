param([ValidateSet('win-x64','linux-x64','both')][string]$Runtime = 'both', [string]$SevenZip = 'C:/Program Files/7-Zip/7z.exe')
$ErrorActionPreference = 'Stop'
$projectDir = Split-Path $PSScriptRoot -Parent
if ($Runtime -in @('win-x64', 'both')) {
    $packageDir = Join-Path $projectDir 'dist/win-x64'
    $lines = Get-ChildItem -LiteralPath $packageDir -Recurse -File | Where-Object Name -ne 'SHA256SUMS.txt' | Sort-Object FullName | ForEach-Object {
        $relative = [IO.Path]::GetRelativePath($packageDir, $_.FullName).Replace('\', '/')
        (Get-FileHash -LiteralPath $_.FullName).Hash.ToLowerInvariant() + '  ' + $relative
    }
    [IO.File]::WriteAllLines("$packageDir/SHA256SUMS.txt", $lines, [Text.UTF8Encoding]::new($false))
    # Build a new archive: updating an existing ZIP retains deleted/vulnerable DLLs.
    $stagedZip = Join-Path $projectDir ('dist/windows-' + [Guid]::NewGuid().ToString('N') + '.zip')
    & $SevenZip a -tzip -mx=5 -bso0 -bsp0 $stagedZip "$projectDir/dist/win-x64/*"
if ($LASTEXITCODE) { throw 'Windows archive failed' }
    Move-Item -LiteralPath $stagedZip -Destination "$projectDir/dist/PII-Explorer-Windows-x64.zip" -Force
    $windowsHash = (Get-FileHash -LiteralPath "$projectDir/dist/PII-Explorer-Windows-x64.zip").Hash.ToLowerInvariant()
    "$windowsHash  PII-Explorer-Windows-x64.zip" | Set-Content "$projectDir/dist/PII-Explorer-Windows-x64.zip.sha256"
}
if ($Runtime -in @('linux-x64', 'both')) {
$wslProject = (& wsl -d Ubuntu --exec wslpath -a ($projectDir.Replace('\', '/'))).Trim()
& wsl -d Ubuntu -- bash "$wslProject/scripts/make-linux-archive.sh" $wslProject
if ($LASTEXITCODE) { throw 'Linux archive failed' }
}
$archives = @('PII-Explorer-Windows-x64.zip', 'PII-Explorer-Linux-x64.tar.gz') | ForEach-Object { Join-Path $projectDir "dist/$_" } | Where-Object { Test-Path -LiteralPath $_ }
Get-FileHash -LiteralPath $archives | ForEach-Object {
    $_.Hash.ToLowerInvariant() + '  ' + [IO.Path]::GetFileName($_.Path)
} | Set-Content "$projectDir/dist/SHA256SUMS.txt"
Write-Output 'Portable archives and integrity manifests created.'
