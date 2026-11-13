#!/usr/bin/env bash
# Builds a local .app. Java/Tesseract remain managed by Homebrew on this Mac.
set -euo pipefail
[[ "$(uname -s)" == Darwin ]] || { echo 'Build the Mac app on macOS.' >&2; exit 1; }
cd "$(dirname "$0")/.."
project_dir="$PWD"
export DOTNET_ROOT="${DOTNET_ROOT:-$HOME/.dotnet}"
export PATH="$DOTNET_ROOT:$PATH"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 AVALONIA_TELEMETRY_OPTOUT=1
case "$(uname -m)" in arm64) runtime=osx-arm64 ;; x86_64) runtime=osx-x64 ;; *) exit 1 ;; esac
for asset in java/bin/java ocr/tesseract worker/ExtractionWorker.class models/model_quantized.onnx; do
    [[ -f "assets/$asset" ]] || { echo 'Run scripts/setup-macos.sh first.' >&2; exit 1; }
done
mkdir -p .build-tools "dist/$runtime"
stage="$(mktemp -d "$project_dir/.build-tools/macos-package.XXXXXX")"
trap 'rm -rf "$stage"' EXIT
app="$stage/PII Explorer.app"
binary_dir="$app/Contents/MacOS"
lock="packages.publish-$runtime.lock.json"
locked=false
[[ ! -f "src/PiiExplorer.App/$lock" ]] || locked=true
dotnet publish src/PiiExplorer.App -c Release -r "$runtime" --self-contained true \
    -p:PublishSingleFile=true "-p:NuGetLockFilePath=$lock" "-p:RestoreLockedMode=$locked" -o "$binary_dir"
cp -R assets "$binary_dir/assets"
cp -R licenses "$app/Contents/licenses"
cp README.md THIRD-PARTY-NOTICES.md LICENSE NOTICE SECURITY.md "$app/Contents/"
brew list --versions > "$app/Contents/homebrew-versions.txt"
cat > "$app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>PiiExplorer</string>
<key>CFBundleIdentifier</key><string>local.piiexplorer.desktop</string>
<key>CFBundleName</key><string>PII Explorer</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.3.0</string>
<key>CFBundleVersion</key><string>0.3.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
plutil -lint "$app/Contents/Info.plist"
destination="$project_dir/dist/$runtime/PII Explorer.app"
if [[ -e "$destination" ]]; then
    mv "$destination" "$project_dir/.build-tools/previous-macos-app-$(date +%s)-$$.app"
fi
mv "$app" "$destination"
echo "Built $destination"
echo 'This local app requires the Homebrew Java and Tesseract installed by setup-macos.sh.'
echo "Launch: open \"$destination\""
