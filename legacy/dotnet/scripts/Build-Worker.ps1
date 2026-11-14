$ErrorActionPreference = 'Stop'
$projectDir = Split-Path $PSScriptRoot -Parent
$jdkDir = Join-Path $projectDir '.build-tools/jdk-21.0.12.1+1'
$workerDir = Join-Path $projectDir 'assets/worker'
& "$jdkDir/bin/javac.exe" -proc:none -encoding UTF-8 -cp "$workerDir/tika-app.jar" -d $workerDir "$projectDir/worker/ExtractionWorker.java"
if ($LASTEXITCODE) { throw 'Java worker compilation failed' }
