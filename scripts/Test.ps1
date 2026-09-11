$ErrorActionPreference = 'Stop'
$env:AVALONIA_TELEMETRY_OPTOUT = '1'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$projectDir = Split-Path $PSScriptRoot -Parent
foreach ($asset in @('java/bin/java.exe', 'ocr/tesseract.exe', 'worker/ExtractionWorker.class', 'models/model_quantized.onnx')) {
    if (!(Test-Path -LiteralPath (Join-Path "$projectDir/assets" $asset))) {
        throw 'Test assets are missing. Run Get-Assets.ps1, Build-Worker.ps1 and Prepare-WindowsRuntime.ps1 first.'
    }
}
& dotnet restore "$projectDir/PiiExplorer.slnx" --locked-mode -p:NuGetAudit=true -p:NuGetAuditMode=all
if ($LASTEXITCODE) { throw 'Locked restore or dependency audit failed' }
& dotnet restore "$projectDir/tools/PiiExplorer.Benchmarks" --locked-mode
if ($LASTEXITCODE) { throw 'Benchmark lock file is stale' }
& dotnet build "$projectDir/tools/PiiExplorer.Benchmarks" -c Release --no-restore
if ($LASTEXITCODE) { throw 'Benchmark build failed' }
& dotnet test "$projectDir/PiiExplorer.slnx" -c Release --no-restore --logger 'trx;LogFileName=release.trx' --results-directory "$projectDir/test-results"
if ($LASTEXITCODE) { throw 'Release tests failed' }
