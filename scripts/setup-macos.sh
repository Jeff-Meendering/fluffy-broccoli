#!/usr/bin/env bash
set -euo pipefail
[[ "$(uname -s)" == Darwin ]] || { echo 'This script requires macOS.' >&2; exit 1; }
cd "$(dirname "$0")/.."
command -v cargo >/dev/null || { echo 'Install the Rust toolchain in rust-toolchain.toml first.' >&2; exit 1; }
command -v brew >/dev/null || { echo 'Install Tesseract, or use --no-ocr. Homebrew is required by this setup helper.' >&2; exit 1; }
brew install tesseract
cargo fetch --locked
cargo xtask assets
echo 'Rust assets ready. Run cargo xtask test, then cargo xtask package.'
