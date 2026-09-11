param([string]$PackageFolder = $PSScriptRoot)
$ErrorActionPreference = 'Stop'
$packagePath = (Resolve-Path -LiteralPath $PackageFolder).ProviderPath
$prefix = $packagePath.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
$manifest = Join-Path $packagePath 'SHA256SUMS.txt'
$expected = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$count = 0
foreach ($line in [IO.File]::ReadLines($manifest)) {
    if ($line -notmatch '^([0-9a-fA-F]{64})  (.+)$') { throw 'Invalid checksum manifest record' }
    $hash = $Matches[1]; $relative = $Matches[2].Replace('/', [IO.Path]::DirectorySeparatorChar)
    if ([IO.Path]::IsPathRooted($relative) -or $relative.Contains(':')) { throw 'Manifest contains an unsafe path' }
    $full = [IO.Path]::GetFullPath((Join-Path $packagePath $relative))
    if (!$full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or !$expected.Add($full)) { throw 'Manifest contains a duplicate or unsafe path' }
    $entry = Get-Item -LiteralPath $full -Force
    while ($null -ne $entry -and ($entry.FullName -eq $packagePath -or $entry.FullName.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase))) {
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Package must not contain links' }
        if ($entry -is [IO.FileInfo]) { $entry = $entry.Directory } else { $entry = $entry.Parent }
    }
    if ((Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash -ne $hash) { throw "Integrity check failed: $relative" }
    $count++
}
if ($count -eq 0) { throw 'Empty checksum manifest' }
foreach ($file in Get-ChildItem -LiteralPath $packagePath -File -Recurse -Force) {
    if ($file.FullName -ne $manifest -and !$expected.Contains($file.FullName)) { throw 'Package contains an unlisted file; extract the ZIP into a new empty folder' }
}
Write-Output "Verified $count files. Checksums detect changes, but do not authenticate the publisher; compare the ZIP hash through a trusted channel."
