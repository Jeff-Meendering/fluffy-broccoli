#!/usr/bin/env bash
set -euo pipefail
project_dir="$(realpath "${1:?Pass the desktop directory}")"
test -f "$project_dir/PiiExplorer.slnx"
cd "$project_dir/dist/linux-x64"
find . -type f ! -name SHA256SUMS.txt -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS.txt
tar -czf "$project_dir/dist/PII-Explorer-Linux-x64.tar.gz" -C "$project_dir/dist" linux-x64
