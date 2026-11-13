#!/usr/bin/env python3
"""Repeat identical-size findings workloads with different file-count dimensions."""
import argparse
from pathlib import Path
import statistics

import benchmark


def suite(executable, destination, repetitions, workers):
    destination.mkdir(parents=True, exist_ok=False, mode=0o700)
    dimensions = [(1000, 100), (10000, 10), (1, 100000)]
    reports = []
    for repetition in range(1, repetitions + 1):
        for files, per_file in dimensions:
            folder = destination / f'{files}x{per_file}-r{repetition}'
            benchmark.benchmark(executable, folder, files, per_file, workers, files >= 100)
            import json
            reports.append(json.loads((folder / 'report.json').read_text()))
    artifacts = reports[0]['artifacts']
    assert all(report['artifacts'] == artifacts for report in reports), 'Artifact/harness changed during suite'
    summary = {'schema_version': 1, 'artifacts': artifacts, 'workers': workers,
               'repetitions': repetitions, 'environment': reports[0]['environment'],
               'limits': reports[0]['limits'], 'dimensions': []}
    for files, per_file in dimensions:
        selected = [report for report in reports if report['expected']['files'] == files]
        measurements = {}
        for name in selected[0]['runs']:
            runs = [report['runs'][name] for report in selected]
            measurements[name] = {
                'seconds': {'min': min(run['elapsed_seconds'] for run in runs),
                            'median': statistics.median(run['elapsed_seconds'] for run in runs),
                            'max': max(run['elapsed_seconds'] for run in runs)},
                'observed_peak_tree_rss_bytes': max(run['observed_peak_tree_rss_bytes'] for run in runs),
                'observed_peak_coordinator_rss_bytes': max(run['observed_peak_coordinator_rss_bytes'] for run in runs),
                'samples': [run['sample_count'] for run in runs]}
        summary['dimensions'].append({'expected': selected[0]['expected'], 'runs': measurements})
    benchmark.write_json(destination / 'summary.json', summary)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('executable', type=Path)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--repetitions', type=int, default=3)
    parser.add_argument('--workers', type=int, choices=range(1, 9), default=2)
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error('positive repetition count required')
    suite(args.executable.resolve(strict=True), args.destination.resolve(), args.repetitions, args.workers)
