param(
    [Parameter(Mandatory)][string]$InputFolder,
    [string]$PackageFolder = (Join-Path (Split-Path $PSScriptRoot -Parent) 'dist/win-x64'),
    [string]$OutputFile = (Join-Path (Get-Location) 'PII-Explorer-Pilot.wsb')
)
$ErrorActionPreference = 'Stop'
# This script generates configuration only; it never installs or starts Sandbox.
# Requires Windows Sandbox already enabled on a supported Windows edition.
$inputPath = (Resolve-Path -LiteralPath $InputFolder).ProviderPath
$packagePath = (Resolve-Path -LiteralPath $PackageFolder).ProviderPath
if (!(Test-Path -LiteralPath $inputPath -PathType Container)) { throw 'InputFolder must be a directory' }
if (!(Test-Path -LiteralPath (Join-Path $packagePath 'PiiExplorer.exe') -PathType Leaf)) { throw 'PackageFolder must contain PiiExplorer.exe' }
$outputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputFile)
if ([IO.Path]::GetExtension($outputPath) -ne '.wsb') { throw 'OutputFile must end in .wsb' }
$xml = [xml]@'
<Configuration>
  <vGPU>Disable</vGPU>
  <Networking>Disable</Networking>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <PrinterRedirection>Disable</PrinterRedirection>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <ProtectedClient>Enable</ProtectedClient>
  <MemoryInMB>8192</MemoryInMB>
  <MappedFolders>
    <MappedFolder><HostFolder/><SandboxFolder>C:\PiiExplorer</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
    <MappedFolder><HostFolder/><SandboxFolder>C:\Input</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
  </MappedFolders>
  <LogonCommand><Command>C:\PiiExplorer\PiiExplorer.exe</Command></LogonCommand>
</Configuration>
'@
# XML APIs escape ampersands and other characters in user-selected paths.
$xml.Configuration.MappedFolders.MappedFolder[0].HostFolder = $packagePath
$xml.Configuration.MappedFolders.MappedFolder[1].HostFolder = $inputPath
$stream = [IO.File]::Open($outputPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try { $xml.Save($stream) } finally { $stream.Dispose() }
Write-Output "Created $outputPath. Open it, then select C:\Input inside PII Explorer."
Write-Output 'Only the package and input folder are shared, both read-only. Network and clipboard sharing are disabled. Results disappear when Sandbox closes.'
