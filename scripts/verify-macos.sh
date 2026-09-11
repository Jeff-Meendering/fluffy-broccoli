#!/usr/bin/env bash
# Exercise the published app from outside the checkout, without a development PATH.
set -euo pipefail
project_dir="$(cd "$(dirname "$0")/.." && pwd)"
case "$(uname -m)" in arm64) runtime=osx-arm64 ;; x86_64) runtime=osx-x64 ;; *) exit 1 ;; esac
binary="$project_dir/dist/$runtime/PII Explorer.app/Contents/MacOS/PiiExplorer"
[[ -x "$binary" ]] || { echo 'Run scripts/publish-macos.sh first.' >&2; exit 1; }
mkdir -p "$project_dir/test-results"
output="$project_dir/test-results/macos-package.jsonl"
cd /tmp
status=0
PATH=/usr/bin:/bin "$binary" --scan-test "$project_dir/tests/fixtures/corpus" > "$output" || status=$?
# The corpus intentionally includes malformed, encrypted, and unsupported files.
[[ "$status" == 3 ]] || { echo "Expected attention exit 3, received $status" >&2; exit 1; }
python3 - "$output" <<'PY'
import json
import sys
from pathlib import Path
records = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
summary = next(row['result'] for row in records if row['kind'] == 'summary')
assert summary['Files'] > 0 and summary['Files'] == summary['Completed'], summary
assert not summary['Cancelled'], summary
findings = [row['finding'] for row in records if row['kind'] == 'finding']
for filename in ('contacts.txt', 'badge.png', 'invoice.pdf', 'scanned-memo.pdf', 'payroll.xlsx', 'staff-handbook.docx', 'records.rar'):
    assert any(Path(f['FilePath']).name == filename and f['Type'] == 'Email' for f in findings), filename
assert any(f['Type'] == 'Person' and f['Method'].startswith('Local model') for f in findings), 'Name model did not run'
print('Published Mac package verified:', summary)
PY
