#!/usr/bin/env bash
# Build on Linux after installing Rust, native desktop prerequisites and optional Tesseract.
set -euo pipefail
[[ "$(uname -s)" == Linux ]] || { echo 'This script requires Linux.' >&2; exit 1; }
cd "$(dirname "$0")/.."
cargo xtask assets
cargo xtask package "$@"
cargo xtask verify "$@"
