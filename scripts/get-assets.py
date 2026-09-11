#!/usr/bin/env python3
"""Download platform-independent assets, verifying pins before atomic replacement."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest() if hasattr(hashlib, 'file_digest') else hashlib.sha256(stream.read()).hexdigest()


def main():
    for asset in json.loads((ROOT / 'scripts/assets.json').read_text()):
        target = ROOT / 'assets' / asset['path']
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if digest(target) != asset['sha256']:
                raise RuntimeError(f'Checksum mismatch: {target}')
            continue
        print(f"Downloading {asset['path']}", flush=True)
        descriptor, name = tempfile.mkstemp(dir=target.parent, suffix='.download')
        os.close(descriptor)
        partial = Path(name)
        try:
            subprocess.run(['curl', '--fail', '--location', '--silent', '--show-error',
                            '--retry', '3', asset['url'], '--output', str(partial)], check=True)
            if digest(partial) != asset['sha256']:
                raise RuntimeError(f'Checksum mismatch: {target}')
            partial.replace(target)
        finally:
            partial.unlink(missing_ok=True)
    print('Build assets downloaded and checked.')


if __name__ == '__main__':
    main()
