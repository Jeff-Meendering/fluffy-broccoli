#!/usr/bin/env bash
# Stage an unsigned local Rust app and CLI. Does not upload or publish a release.
set -euo pipefail
[[ "$(uname -s)" == Darwin ]] || { echo 'Build the Mac app on macOS.' >&2; exit 1; }
cd "$(dirname "$0")/.."
cargo xtask package "$@"
cargo xtask verify "$@"
