$ErrorActionPreference = 'Stop'
$projectDir = Split-Path $PSScriptRoot -Parent
$licenseDir = Join-Path $projectDir 'licenses'
New-Item -ItemType Directory -Force $licenseDir, "$licenseDir/nuget", "$licenseDir/tesseract", "$licenseDir/tika" | Out-Null
$assets = Get-Content "$projectDir/src/PiiExplorer.App/obj/project.assets.json" -Raw | ConvertFrom-Json
$packageRoot = $assets.packageFolders.PSObject.Properties.Name | Select-Object -First 1
$inventory = foreach ($library in $assets.libraries.PSObject.Properties) {
    if ($library.Value.type -ne 'package') { continue }
    $directory = Join-Path $packageRoot $library.Value.path
    $destination = Join-Path "$licenseDir/nuget" ($library.Name.Replace('/', '-'))
    New-Item -ItemType Directory -Force $destination | Out-Null
    foreach ($file in $library.Value.files) {
        if ($file -match '(?i)(license|notice|copying|\.nuspec$)' -and (Test-Path -LiteralPath "$directory/$file" -PathType Leaf)) {
            Copy-Item -LiteralPath "$directory/$file" -Destination (Join-Path $destination ($file.Replace('/', '_'))) -Force
        }
    }
    [pscustomobject]@{Package=$library.Name;Sha512=$library.Value.sha512}
}
$inventory | ConvertTo-Json | Set-Content "$licenseDir/nuget-packages.json"
# Prepare-WindowsRuntime.ps1 collects documentation from the pinned OCR package.
# Never replace it with notices from an unrelated system-wide installation.
Add-Type -AssemblyName System.IO.Compression.FileSystem
$jar = [IO.Compression.ZipFile]::OpenRead("$projectDir/assets/worker/tika-app.jar")
try {
    foreach ($entry in $jar.Entries) {
        if ($entry.Name -match '(?i)^(licen[sc]e|notices?|copying)(\.(txt|md|html?|rtf))?$' -and $entry.Length -gt 0) {
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, "$licenseDir/tika/$($entry.FullName.Replace('/', '_'))", $true)
        }
    }
} finally { $jar.Dispose() }
Copy-Item -LiteralPath "$projectDir/assets/models/README.md" -Destination "$licenseDir/model-card.md" -Force
Write-Output 'Packaged dependency licenses and pinned package inventory collected.'
