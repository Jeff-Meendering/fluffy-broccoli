$ErrorActionPreference = 'Stop'
$projectDir = Split-Path $PSScriptRoot -Parent
New-Item -ItemType Directory -Force "$projectDir/test-results" | Out-Null
$start = [Diagnostics.ProcessStartInfo]::new("$projectDir/dist/win-x64/PiiExplorer.exe")
$start.WorkingDirectory = $projectDir
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$start.Environment['PATH'] = "$env:WINDIR/System32"
$start.Environment['DOTNET_ROOT'] = "$projectDir/.build-tools/no-installed-runtime"
$start.ArgumentList.Add('--scan-test')
$start.ArgumentList.Add([IO.Path]::GetFullPath("$projectDir/tests/fixtures/corpus"))
$process = [Diagnostics.Process]::Start($start)
$output = $process.StandardOutput.ReadToEndAsync()
$errors = $process.StandardError.ReadToEndAsync()
if (!$process.WaitForExit(180000)) {
    $process.Kill($true)
    $process.Dispose()
    throw 'Packaged scan exceeded the three-minute smoke-test deadline'
}
$json = $output.GetAwaiter().GetResult()
[IO.File]::WriteAllText("$projectDir/test-results/windows-isolated-package.jsonl", $json)
[IO.File]::WriteAllText("$projectDir/test-results/windows-isolated-package.stderr", $errors.GetAwaiter().GetResult())
if ($process.ExitCode -notin @(0,3)) { throw "Packaged scan failed: $($process.ExitCode)" }
$records = @($json -split '\r?\n' | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
$summary = ($records | Where-Object kind -eq summary).result
$findings = @($records | Where-Object kind -eq finding | ForEach-Object { $_.finding })
$issues = @($records | Where-Object kind -eq issue | ForEach-Object { $_.issue })
$expectedFiles = @(Get-ChildItem -LiteralPath "$projectDir/tests/fixtures/corpus" -File -Recurse).Count
if ($null -eq $summary -or $summary.Files -ne $expectedFiles -or $summary.Completed -ne $expectedFiles -or $summary.Cancelled) { throw 'Packaged scan did not complete the corpus' }
if ($summary.Findings -ne $findings.Count -or $summary.Issues -ne $issues.Count) { throw 'Packaged scan lost result records' }
if (!($findings | Where-Object { $_.Type -eq 'Email' -and $_.FilePath.EndsWith('badge.png') -and $_.Value -eq 'maria.hernandez@example.com' -and $_.Location.StartsWith('OCR') })) { throw 'Packaged OCR did not recover the planted email' }
if (!($findings | Where-Object { $_.Type -eq 'Person' -and $_.Value -eq 'Maria Hernandez' -and $_.Method -eq 'Local model' })) { throw 'Packaged local name inference failed' }
if (!($findings | Where-Object { $_.Type -eq 'Email' -and $_.FilePath.EndsWith('invoice.pdf') -and $_.Location.StartsWith('document text') })) { throw 'Packaged PDF extraction failed' }
if (!($findings | Where-Object { $_.Type -eq 'Email' -and $_.FilePath.EndsWith('.docx') -and $_.Location.StartsWith('document text') })) { throw 'Packaged Office extraction failed' }
if (!($findings | Where-Object { $_.Type -eq 'Email' -and $_.Source -ne '' -and $_.FilePath.EndsWith('.rar') })) { throw 'Packaged archive extraction/provenance failed' }
if ($issues.Count -eq 0 -or ($issues | Where-Object { $_.Message -match 'timeout|worker stopped unexpectedly|Source changed' })) { throw 'Packaged scan omitted expected attention items or encountered a runtime failure' }
Write-Output "Packaged app completed $($summary.Completed) files with only the Windows system directory on PATH; no installed Python/Java/.NET was used."
$process.Dispose()
# Exercise the new diagnostic mode through the same self-contained executable.
$evaluationPath = Join-Path $projectDir ('test-results/package-accuracy-' + [Guid]::NewGuid().ToString('N') + '.json')
$start.ArgumentList.Clear()
foreach ($arg in @('--evaluate', "$projectDir/dist/win-x64/accuracy-smoke.jsonl", $evaluationPath)) { $start.ArgumentList.Add($arg) }
$process = [Diagnostics.Process]::Start($start)
try {
    $output = $process.StandardOutput.ReadToEndAsync(); $errors = $process.StandardError.ReadToEndAsync()
    if (!$process.WaitForExit(30000)) { $process.Kill($true); throw 'Packaged evaluation timed out' }
    if ($process.ExitCode -ne 0) { throw ('Packaged evaluation failed: ' + $errors.GetAwaiter().GetResult()) }
    $report = Get-Content -LiteralPath $evaluationPath -Raw | ConvertFrom-Json
    $cases = @(Get-Content -LiteralPath "$projectDir/dist/win-x64/accuracy-smoke.jsonl" | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json })
    $goldCount = ($cases | ForEach-Object { $_.entities.Count } | Measure-Object -Sum).Sum
    if (!$report.NamesEnabled -or $goldCount -le 0 -or $report.Cases -ne $cases.Count -or $report.Micro.TruePositive -ne $goldCount -or $report.Micro.FalsePositive -ne 0 -or $report.Micro.FalseNegative -ne 0) { throw 'Packaged accuracy smoke test regressed' }
    Write-Output "Packaged evaluation passed all $($cases.Count) synthetic cases ($goldCount planted entities), with names enabled."
} finally { $process.Dispose() }
