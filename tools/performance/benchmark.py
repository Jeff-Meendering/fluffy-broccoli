#!/usr/bin/env python3
"""Reproducible synthetic scale/recovery checks. Never scan real assessment data."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import sqlite3
import subprocess
import threading
import time

import psutil


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_json(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write('\n')


def alphabetic(number):
    result = ''
    while True:
        result = chr(97 + number % 26) + result
        number = number // 26 - 1
        if number < 0:
            return result


def prepare(root, files, per_file):
    root.mkdir(mode=0o700)
    total = 0
    for index in range(files):
        text = ''.join(f'contact{alphabetic(index * per_file + item)}@example.org\n'
                       for item in range(per_file))
        data = text.encode('utf-8')
        (root / f'source-{index:06}.txt').write_bytes(data)
        total += len(data)
    return {'files': files, 'email_occurrences': files * per_file,
            'unique_email_values': files * per_file, 'source_bytes': total}


class Measurement:
    def __init__(self, process):
        self.process = psutil.Process(process.pid)
        self.finished = threading.Event()
        self.error = None
        self.samples = 0
        self.peak_tree_rss = 0
        self.peak_coordinator_rss = 0
        self.peak_processes = 0
        self.thread = threading.Thread(target=self.monitor)
        self.thread.start()

    def monitor(self):
        try:
            while not self.finished.is_set():
                try:
                    processes = [self.process] + self.process.children(recursive=True)
                except psutil.NoSuchProcess:
                    break
                rss = 0
                for process in processes:
                    try:
                        resident = process.memory_info().rss
                    except psutil.NoSuchProcess:
                        continue
                    rss += resident
                    if process.pid == self.process.pid:
                        self.peak_coordinator_rss = max(self.peak_coordinator_rss, resident)
                self.peak_tree_rss = max(self.peak_tree_rss, rss)
                self.peak_processes = max(self.peak_processes, len(processes))
                self.samples += 1
                self.finished.wait(0.02)
        except BaseException as error:
            self.error = error

    def stop(self):
        self.finished.set()
        self.thread.join()
        if self.error:
            raise RuntimeError('Process-tree measurement unavailable; rerun with permission to inspect the benchmark processes') from self.error
        return {'sample_count': self.samples, 'sample_interval_ms': 20,
                'observed_peak_tree_rss_bytes': self.peak_tree_rss,
                'observed_peak_coordinator_rss_bytes': self.peak_coordinator_rss,
                'observed_peak_process_count': self.peak_processes}


def execute(arguments, destination, interrupt_after=None):
    started = time.perf_counter()
    stdout = destination.with_suffix('.stdout.json')
    stderr = destination.with_suffix('.stderr.txt')
    with stdout.open('xb') as output, stderr.open('xb') as errors:
        process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=output, stderr=errors)
        measurement = Measurement(process)
        killed = False
        try:
            if interrupt_after:
                case, completed = interrupt_after
                deadline = time.monotonic() + 30
                while process.poll() is None and time.monotonic() < deadline:
                    if case.exists():
                        try:
                            with sqlite3.connect(case.as_uri() + '?mode=ro', uri=True, timeout=0.1) as connection:
                                count = connection.execute("SELECT count(*) FROM run_resources WHERE status='complete'").fetchone()[0]
                            if count >= completed:
                                process.kill()
                                killed = True
                                break
                        except sqlite3.Error:
                            pass
                    time.sleep(0.02)
                if not killed:
                    process.kill()
                    raise AssertionError('Failed to interrupt a live capture after committed checkpoints')
            code = process.wait(timeout=600)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            metrics = measurement.stop()
    metrics.update({'elapsed_seconds': time.perf_counter() - started, 'exit_code': code,
                    'intentionally_killed': killed, 'arguments': [str(value) for value in arguments]})
    write_json(destination.with_suffix('.measurement.json'), metrics)
    if not killed and code != 0:
        raise AssertionError(f'Benchmark command failed ({code}); inspect {stderr}')
    text = stdout.read_text().strip()
    return metrics, None if killed or not text else json.loads(text)


def check_summary(summary, expected, reused):
    assert summary['status'] == 'complete', summary
    assert summary['discovered'] == expected['files'], summary
    assert summary['completed'] == expected['files'], summary
    assert summary['findings'] == expected['email_occurrences'], summary
    assert summary['attention'] == 0, summary
    assert summary['reused'] == reused, summary


def inspect_export(path, expected):
    counts = {}
    with path.open() as stream:
        for line in stream:
            record = json.loads(line)
            kind = record['kind']
            counts[kind] = counts.get(kind, 0) + 1
            if kind == 'finding':
                assert record['finding']['type'] == 'Email'
            elif kind == 'summary':
                assert record['summary']['findings'] == expected['email_occurrences']
                assert not record['summary']['cancelled']
    assert counts.get('finding') == expected['email_occurrences'], counts
    assert counts.get('source') == expected['files'], counts
    assert counts.get('attention', 0) == 0, counts
    assert counts.get('summary') == 1 and counts.get('settings') == 1, counts
    return counts


def benchmark(executable, destination, files, per_file, workers, crash):
    os.umask(0o077)
    # Fail before creating a corpus if the OS denies monitoring this process tree.
    psutil.Process().children(recursive=True)
    psutil.Process().memory_info()
    destination.mkdir(parents=True, exist_ok=False, mode=0o700)
    executable = executable.resolve(strict=True)
    helper = executable.with_name('pii-explorer-worker' + ('.exe' if os.name == 'nt' else ''))
    expected = prepare(destination / 'evidence', files, per_file)
    assert expected['email_occurrences'] <= 500_000, 'Regular stream check uses its default 500,000-finding cap'
    root = destination / 'evidence'
    case = destination / 'assessment.piicase'
    base = [str(executable), 'case', 'scan', str(root), '--case', str(case),
            '--no-names', '--no-ocr', '--no-context', '--jobs', str(workers)]
    report = {'schema_version': 1, 'expected': expected,
              'environment': {'platform': platform.platform(), 'machine': platform.machine(),
                              'logical_cpus': os.cpu_count(), 'psutil': psutil.__version__},
              'artifacts': {'cli_sha256': sha256(executable), 'helper_sha256': sha256(helper),
                            'harness_sha256': sha256(__file__)},
              'limits': 'Synthetic ASCII emails only; names/OCR disabled. RSS is sampled process-tree resident memory, can miss brief peaks and double-count shared pages. File cache is not flushed. No concurrent builds/scans should run. Not general detection accuracy or mixed-document performance.',
              'runs': {}}
    for name, arguments, reused in [('capture', base, 0), ('reuse', base + ['--resume'], files)]:
        metrics, summary = execute(arguments, destination / name)
        check_summary(summary, expected, reused)
        report['runs'][name] = metrics | {'summary': summary}
    metrics, page = execute([str(executable), 'case', 'show', str(case), '--limit', '100'], destination / 'page')
    assert len(page['findings']) == min(100, expected['email_occurrences'])
    report['runs']['page'] = metrics | {'page_rows': len(page['findings'])}
    exported = destination / 'export.jsonl'
    metrics, _ = execute([str(executable), 'case', 'export', str(case), str(exported)], destination / 'export')
    report['runs']['export'] = metrics | {'records': inspect_export(exported, expected), 'output_bytes': exported.stat().st_size}
    streamed = destination / 'stream.jsonl'
    metrics, _ = execute([str(executable), 'scan', str(root), '--no-names', '--no-ocr', '--no-context', '--jobs', str(workers), '--output', str(streamed)], destination / 'stream')
    report['runs']['stream'] = metrics | {'records': inspect_export(streamed, expected), 'output_bytes': streamed.stat().st_size}
    first = root / 'source-000000.txt'
    stat = first.stat()
    original = first.read_bytes()
    first.write_bytes(original.replace(b'contact', b'xontact', 1))
    os.utime(first, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    metrics, summary = execute(base + ['--resume'], destination / 'changed')
    check_summary(summary, expected, files - 1)
    report['runs']['same_size_mtime_change'] = metrics | {'summary': summary}
    if crash:
        crash_case = destination / 'recovery.piicase'
        command = base.copy()
        command[command.index(str(case))] = str(crash_case)
        metrics, _ = execute(command, destination / 'crash', (crash_case, 3))
        report['runs']['intentional_crash'] = metrics
        metrics, summary = execute(command + ['--resume'], destination / 'recovered')
        assert summary['reused'] >= 3 and summary['reused'] < files, summary
        check_summary(summary, expected, summary['reused'])
        with sqlite3.connect(crash_case.as_uri() + '?mode=ro', uri=True) as connection:
            assert connection.execute('SELECT status FROM runs ORDER BY id LIMIT 1').fetchone()[0] == 'interrupted'
        report['runs']['recovered'] = metrics | {'summary': summary}
    metrics, integrity = execute([str(executable), 'case', 'integrity', str(case)], destination / 'integrity')
    assert integrity['stored_findings'] >= expected['email_occurrences']
    report['runs']['integrity'] = metrics | {'result': integrity}
    write_json(destination / 'report.json', report)
    print(json.dumps({'report': str(destination / 'report.json'), 'expected': expected,
                      'seconds': {name: round(run['elapsed_seconds'], 3) for name, run in report['runs'].items()}}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('executable', type=Path)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--files', type=int, default=1_000)
    parser.add_argument('--per-file', type=int, default=100)
    parser.add_argument('--workers', type=int, choices=range(1, 9), default=2)
    parser.add_argument('--crash', action='store_true')
    args = parser.parse_args()
    if args.files < 1 or args.per_file < 1 or (args.crash and args.files < 100):
        parser.error('positive dimensions required; crash check requires at least 100 files')
    benchmark(args.executable, args.destination.resolve(), args.files, args.per_file, args.workers, args.crash)
