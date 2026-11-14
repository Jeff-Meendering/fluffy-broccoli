param([string]$SevenZip = 'C:/Program Files/7-Zip/7z.exe')
$ErrorActionPreference = 'Stop'
$projectDir = Split-Path $PSScriptRoot -Parent
$assetsDir = Join-Path $projectDir 'assets'
$jdkDir = Join-Path $projectDir '.build-tools/jdk-21.0.12.1+1'
if (!(Test-Path "$assetsDir/java/bin/java.exe")) {
    & "$jdkDir/bin/jlink.exe" --add-modules java.base,java.desktop,java.xml,java.sql,java.naming,java.management,java.logging,java.net.http,jdk.charsets,jdk.crypto.ec,java.security.jgss,java.prefs,jdk.unsupported --strip-debug --no-man-pages --no-header-files --output "$assetsDir/java"
    if ($LASTEXITCODE) { throw 'Runtime bundling failed' }
}
$installer = Join-Path $projectDir '.build-tools/tesseract-ocr-w64-setup-5.5.3.20260724.exe'
if (!(Test-Path -LiteralPath $installer)) { throw 'Run Get-Assets.ps1 to download the pinned OCR release first.' }
if ((Get-FileHash -LiteralPath $installer).Hash -ne 'bee9e3434bd94fd65387d9be28cd467a41f61b1275383b55b0f59a1331270ae4') { throw 'OCR installer checksum mismatch' }
if (!(Test-Path -LiteralPath $SevenZip)) { throw '7-Zip is required to extract the OCR release without installing it. Pass -SevenZip with its executable path.' }
$extracted = Join-Path $projectDir ('.build-tools/ocr-extracted-' + [Guid]::NewGuid().ToString('N'))
& $SevenZip x -y -bso0 -bsp0 "-o$extracted" $installer
if ($LASTEXITCODE) { throw 'OCR release extraction failed' }
$ocrDir = Join-Path $assetsDir 'ocr'
# Validate the staged release before replacing the generated runtime. Keep the old
# directory as a backup; copying over it would leave obsolete DLLs in the package.
foreach ($name in @('tesseract.exe')) {
    if (!(Test-Path -LiteralPath "$extracted/$name")) { throw "OCR release is missing $name" }
}
$dataDir = Join-Path $projectDir '.build-tools/tessdata-fast-4.1.0'
$dataHashes = @{ eng = '7d4322bd2a7749724879683fc3912cb542f19906c83bcc1a52132556427170b2'; osd = '9cf5d576fcc47564f11265841e5ca839001e7e6f38ff7f7aacf46d15a96b00ff' }
foreach ($language in $dataHashes.Keys) {
    if ((Get-FileHash -LiteralPath "$dataDir/$language.traineddata").Hash -ne $dataHashes[$language]) { throw "OCR model checksum mismatch: $language" }
}
$staged = Join-Path $assetsDir ('ocr-staged-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force "$staged/tessdata" | Out-Null
Copy-Item -LiteralPath "$extracted/tesseract.exe" -Destination $staged
Get-ChildItem -LiteralPath $extracted -Filter '*.dll' | Copy-Item -Destination $staged
Copy-Item -LiteralPath "$dataDir/eng.traineddata", "$dataDir/osd.traineddata" -Destination "$staged/tessdata"
if (Test-Path -LiteralPath "$extracted/tessdata/configs") { Copy-Item -LiteralPath "$extracted/tessdata/configs" -Destination "$staged/tessdata" -Recurse }
& "$staged/tesseract.exe" --version
if ($LASTEXITCODE) { throw 'Staged OCR runtime could not start' }
$backup = Join-Path $assetsDir ('ocr-backup-' + [Guid]::NewGuid().ToString('N'))
foreach ($path in @($assetsDir, $ocrDir, $staged, $backup)) {
    $full = [IO.Path]::GetFullPath($path)
    if (!$full.StartsWith([IO.Path]::GetFullPath($projectDir) + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Runtime path is outside the project' }
    if ((Test-Path -LiteralPath $full) -and ((Get-Item -LiteralPath $full).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Runtime paths must not be links' }
}
if (Test-Path -LiteralPath $ocrDir) {
    Move-Item -LiteralPath $ocrDir -Destination $backup
}
Move-Item -LiteralPath $staged -Destination $ocrDir
if (Test-Path -LiteralPath "$extracted/doc") {
    New-Item -ItemType Directory -Force "$projectDir/licenses/tesseract" | Out-Null
    Copy-Item "$extracted/doc/*" "$projectDir/licenses/tesseract" -Recurse -Force
}
Write-Output 'Windows Java and OCR runtime bundled.'
