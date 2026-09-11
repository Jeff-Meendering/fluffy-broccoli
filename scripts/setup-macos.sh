#!/usr/bin/env bash
# Native, local macOS setup. Homebrew supplies Java and OCR; no administrator access needed.
set -euo pipefail
[[ "$(uname -s)" == Darwin ]] || { echo 'This script requires macOS.' >&2; exit 1; }
project_dir="$(cd "$(dirname "$0")/.." && pwd)"
cd "$project_dir"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 AVALONIA_TELEMETRY_OPTOUT=1
command -v brew >/dev/null || { echo 'Install Homebrew from https://brew.sh, then rerun.' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'Python 3 is required for asset verification.' >&2; exit 1; }
brew install openjdk@21 tesseract
mkdir -p .build-tools assets/ocr
sdk_version="$(python3 -c 'import json; print(json.load(open("global.json"))["sdk"]["version"])')"
export DOTNET_ROOT="${DOTNET_ROOT:-$HOME/.dotnet}"
export PATH="$DOTNET_ROOT:$PATH"
if ! dotnet --list-sdks 2>/dev/null | awk '{print $1}' | grep -qx "$sdk_version"; then
    curl -fsSL https://dot.net/v1/dotnet-install.sh -o .build-tools/dotnet-install.sh
    bash .build-tools/dotnet-install.sh --version "$sdk_version" --install-dir "$DOTNET_ROOT"
fi
python3 scripts/get-assets.py
java_home="$(brew --prefix openjdk@21)/libexec/openjdk.jdk/Contents/Home"
# Refuse to replace a real bundled runtime; the Windows preparation uses these same paths.
for target in assets/java assets/ocr/tesseract; do
    if [[ -e "$target" && ! -L "$target" ]]; then
        echo "Move $target aside before preparing Mac assets; it is not a managed symlink." >&2
        exit 1
    fi
done
ln -sfn "$java_home" assets/java
ln -sfn "$(brew --prefix tesseract)/bin/tesseract" assets/ocr/tesseract
"$java_home/bin/javac" --release 21 -proc:none -encoding UTF-8 -cp assets/worker/tika-app.jar -d assets/worker worker/ExtractionWorker.java
dotnet restore PiiExplorer.slnx --locked-mode
echo 'Mac setup complete. Run scripts/test-macos.sh, then scripts/publish-macos.sh.'
