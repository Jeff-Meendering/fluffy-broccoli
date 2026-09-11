param([ValidateSet('win-x64','linux-x64')][string]$Runtime = 'win-x64')
$ErrorActionPreference = 'Stop'
$env:AVALONIA_TELEMETRY_OPTOUT = '1'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$projectDir = Split-Path $PSScriptRoot -Parent
$destination = Join-Path $projectDir "dist/$Runtime"
$outputDir = Join-Path $projectDir (".build-tools/package-$Runtime-" + [Guid]::NewGuid().ToString('N'))
# Self-contained/single-file restore adds runtime and linker dependencies. Keep its
# lock separate so publishing cannot invalidate a normal locked solution restore.
$publishLock = "packages.publish-$Runtime.lock.json"
$restoreLocked = (Test-Path -LiteralPath "$projectDir/src/PiiExplorer.App/$publishLock").ToString().ToLowerInvariant()
& dotnet publish "$projectDir/src/PiiExplorer.App" -c Release -r $Runtime --self-contained true -p:PublishSingleFile=true "-p:NuGetLockFilePath=$publishLock" "-p:RestoreLockedMode=$restoreLocked" -o $outputDir
if ($LASTEXITCODE) { throw 'Publish failed' }
New-Item -ItemType Directory -Force "$outputDir/assets", "$outputDir/licenses" | Out-Null
foreach ($folder in @('models','worker')) {
    Copy-Item -LiteralPath "$projectDir/assets/$folder" -Destination "$outputDir/assets" -Recurse -Force
}
if (Test-Path "$projectDir/licenses") { Copy-Item "$projectDir/licenses/*" "$outputDir/licenses" -Recurse -Force }
foreach ($name in @('README.md', 'REVIEW.md', 'PILOT-GUIDE.md', 'CONTRIBUTING.md', 'THIRD-PARTY-NOTICES.md')) {
    if (Test-Path "$projectDir/$name") { Copy-Item -LiteralPath "$projectDir/$name" -Destination $outputDir -Force }
}
if ($Runtime -eq 'win-x64') {
    Copy-Item -LiteralPath "$projectDir/scripts/Verify-Package.ps1" -Destination $outputDir
    Copy-Item -LiteralPath "$projectDir/scripts/New-SandboxConfig.ps1" -Destination $outputDir
    Copy-Item -LiteralPath "$projectDir/tests/fixtures/accuracy-smoke.jsonl" -Destination $outputDir
    foreach ($folder in @('java','ocr')) { Copy-Item -LiteralPath "$projectDir/assets/$folder" -Destination "$outputDir/assets" -Recurse -Force }
    foreach ($dll in @('vcruntime140.dll','vcruntime140_1.dll','msvcp140.dll')) {
        Copy-Item -LiteralPath "$env:WINDIR/System32/$dll" -Destination $outputDir -Force
    }
} else {
    Write-Output 'Run scripts/prepare-linux.sh inside Ubuntu, passing the desktop project path, to bundle the Linux Java/OCR runtime.'
}
$backup = Join-Path $projectDir (".build-tools/previous-package-$Runtime-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force (Join-Path $projectDir 'dist') | Out-Null
foreach ($path in @($outputDir, $destination, $backup, (Join-Path $projectDir 'dist'), (Join-Path $projectDir '.build-tools'))) {
    $full = [IO.Path]::GetFullPath($path)
    if (!$full.StartsWith([IO.Path]::GetFullPath($projectDir) + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Publish path is outside the project' }
    if ((Test-Path -LiteralPath $full) -and ((Get-Item -LiteralPath $full).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Publish paths must not be links' }
}
# Debug symbols and linker import libraries are build artifacts, not runtime files.
Get-ChildItem -LiteralPath $outputDir -Recurse -File | Where-Object Extension -in @('.pdb', '.lib') | ForEach-Object { Remove-Item -LiteralPath $_.FullName }
# A fresh directory prevents obsolete DLLs and licenses surviving a runtime upgrade.
if (Test-Path -LiteralPath $destination) { Move-Item -LiteralPath $destination -Destination $backup }
try { Move-Item -LiteralPath $outputDir -Destination $destination }
catch {
    if ((Test-Path -LiteralPath $backup) -and !(Test-Path -LiteralPath $destination)) { Move-Item -LiteralPath $backup -Destination $destination }
    throw
}
Write-Output "Published $destination"
