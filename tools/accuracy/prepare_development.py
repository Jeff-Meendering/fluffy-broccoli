#!/usr/bin/env python3
"""Prepare train/validation development corpora without opening the held-out split."""
import argparse
import ast
import json
import os
from pathlib import Path

import benchmark


def prepare(source, destination, train_limit, validation_limit):
    import pyarrow.parquet as parquet
    os.umask(0o077)
    pins = json.loads((benchmark.HERE / 'dataset.json').read_text())
    destination.mkdir(parents=True, exist_ok=False, mode=0o700)
    seen = set()
    for split, limit in [('train', train_limit), ('validation', validation_limit)]:
        path = source / (split + '.parquet')
        if benchmark.digest(path.read_bytes()) != pins['sha256'][split]:
            raise ValueError(f'{split} source checksum mismatch')
        rows = parquet.read_table(path).to_pylist()
        accepted, rejected, unsupported = [], {}, {}
        # Stable hash order prevents source ordering from selecting a single domain/template.
        rows.sort(key=lambda row: benchmark.text_hash(row['uid']))
        for row in rows:
            fingerprint = benchmark.normalized_hash(row['text'])
            duplicate = fingerprint in seen
            # Check validation against the entire source train split, not just its sample.
            seen.add(fingerprint)
            if duplicate:
                rejected['duplicate_development_document'] = rejected.get('duplicate_development_document', 0) + 1
                continue
            try:
                entities, excluded = benchmark.align(row['text'], ast.literal_eval(row['entities']))
            except (ValueError, SyntaxError, KeyError, TypeError):
                rejected['invalid_source_annotation'] = rejected.get('invalid_source_annotation', 0) + 1
                continue
            if len(accepted) >= limit:
                continue
            for kind, count in excluded.items():
                unsupported[kind] = unsupported.get(kind, 0) + count
            accepted.append({'Id': row['uid'], 'Text': row['text'], 'Entities': entities,
                             'Domain': row['domain'], 'TextSha256': benchmark.text_hash(row['text'])})
        if not accepted:
            raise ValueError(f'No eligible {split} documents')
        folder = destination / split
        folder.mkdir(mode=0o700)
        benchmark.write_jsonl(folder / 'gold.jsonl', accepted)
        benchmark.write_jsonl(folder / 'inputs.jsonl', ({'Id': row['Id'], 'Text': row['Text']} for row in accepted))
        benchmark.write_json(folder / 'manifest.json', {
            'schema': 1, 'purpose': 'development-only; do not report as held-out acceptance',
            'source': pins, 'source_split': split, 'source_documents': len(rows),
            'scope': benchmark.SCOPE, 'mapping': benchmark.GOLD_MAP,
            'projection': 'all-literal-occurrences-adjacent-person-parts-v1',
            'selection': 'first eligible documents in SHA-256(uid) order',
            'requested_limit': limit, 'documents': len(accepted), 'quarantined': rejected,
            'excluded_source_entities': unsupported,
            'gold_sha256': benchmark.digest((folder / 'gold.jsonl').read_bytes()),
            'input_sha256': benchmark.digest((folder / 'inputs.jsonl').read_bytes()),
            'leakage_check': 'normalized equality removed within development and between full source train and validation; no test file opened',
            'limitations': ['Synthetic projected labels, not independently adjudicated',
                            'No template or pretrained-model contamination guarantee',
                            'Source test predictions/errors must not guide development']})
        print(json.dumps({'split': split, 'documents': len(accepted), 'quarantined': rejected}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, help='directory containing checksum-pinned train.parquet and validation.parquet')
    parser.add_argument('destination', type=Path)
    parser.add_argument('--train-limit', type=int, default=10000)
    parser.add_argument('--validation-limit', type=int, default=2000)
    args = parser.parse_args()
    if args.train_limit < 1 or args.validation_limit < 1:
        parser.error('positive sample limits required')
    prepare(args.source, args.destination, args.train_limit, args.validation_limit)
