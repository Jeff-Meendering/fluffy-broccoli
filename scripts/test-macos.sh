#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export DOTNET_ROOT="${DOTNET_ROOT:-$HOME/.dotnet}"
export PATH="$DOTNET_ROOT:$PATH"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 AVALONIA_TELEMETRY_OPTOUT=1
for asset in java/bin/java ocr/tesseract worker/ExtractionWorker.class models/model_quantized.onnx; do
    [[ -f "assets/$asset" ]] || { echo 'Run scripts/setup-macos.sh first.' >&2; exit 1; }
done
dotnet restore PiiExplorer.slnx --locked-mode -p:NuGetAudit=true -p:NuGetAuditMode=all
dotnet restore tools/PiiExplorer.Benchmarks --locked-mode
dotnet build tools/PiiExplorer.Benchmarks -c Release --no-restore
dotnet test PiiExplorer.slnx -c Release --no-restore --logger 'trx;LogFileName=macos.trx' --results-directory test-results
