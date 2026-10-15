#!/usr/bin/env python3
"""Run the predetermined original-Rust grid, preserving every actual outcome."""
from __future__ import annotations
import argparse
from collections import Counter
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import sqlite3
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'benchmarks'))
from evidence import source_identity
from process_metrics import measured_child
from workloads import SEEDS, descriptors, write_case

WARMUPS, REPETITIONS = 5, 30
MODES = ('rust-on', 'rust-off', 'sqlite')
METRICS = ('wall_ns', 'cpu_user_ns', 'cpu_system_ns', 'peak_rss_bytes',
           'execution_only_ns', 'execution_call_wall_ns', 'load_ns',
           'compile_ns', 'serialization_ns', 'materialization_ns',
           'consumed_work', 'visible_work', 'peak_reserved_bytes')


def sha(path):
    hasher = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            hasher.update(block)
    return hasher.hexdigest()


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def canonical(result, ordered):
    # The oracle supplies schema independently. JSON scalars retain NULL/bool/i64 distinctions.
    rows = [encode(row) for row in result['rows']]
    return {'schema': result['schema'], 'rows': rows if ordered else sorted(rows)}


def semantic_digest(result, ordered):
    value = canonical(result, ordered) if result['status'] == 'ok' else {'error': result['error']['code']}
    return hashlib.sha256(encode(value).encode()).hexdigest()


def environment():
    result = {'system': platform.system(), 'release': platform.release(), 'version': platform.version(),
              'machine': platform.machine(), 'logical_processors': os.cpu_count(),
              'python': platform.python_version(), 'sqlite': sqlite3.sqlite_version,
              'cpu_model': None, 'physical_memory_bytes': None, 'available_memory_bytes': None,
              'cpu_governor': None, 'virtualization': None,
              'dedicated_reference_host': None, 'host_classification': 'dedication cannot be established by hardware inspection alone'}
    if os.name == 'nt':
        command = ['powershell', '-NoProfile', '-NonInteractive', '-Command',
                   '$rillCpu=Get-CimInstance Win32_Processor; $rillOs=Get-CimInstance Win32_OperatingSystem; '
                   '[pscustomobject]@{cpu_model=($rillCpu.Name -join "; "); '
                   'physical_cores=($rillCpu.NumberOfCores | Measure-Object -Sum).Sum; '
                   'physical_memory_bytes=([long]$rillOs.TotalVisibleMemorySize*1024); '
                   'available_memory_bytes=([long]$rillOs.FreePhysicalMemory*1024)} | ConvertTo-Json -Compress']
        inspected = subprocess.run(command, capture_output=True, timeout=30)
        if inspected.returncode == 0:
            result.update(json.loads(inspected.stdout))
        else:
            result['hardware_metadata_status'] = 'NOT MEASURED: OS inspection failed'
    elif Path('/proc/cpuinfo').is_file():
        cpu = Path('/proc/cpuinfo').read_text()
        result['cpu_model'] = next((line.split(':', 1)[1].strip() for line in cpu.splitlines() if line.startswith('model name')), None)
        memory = {line.split(':')[0]: int(line.split()[1]) * 1024 for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith(('MemTotal:', 'MemAvailable:'))}
        result['physical_memory_bytes'] = memory.get('MemTotal')
        result['available_memory_bytes'] = memory.get('MemAvailable')
        governor = Path('/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor')
        if governor.is_file(): result['cpu_governor'] = governor.read_text().strip()
        result['virtualization'] = 'hypervisor flag present' if any('hypervisor' in line for line in cpu.splitlines() if line.startswith('flags')) else 'not established'
    return result


def distribution(values):
    if not values:
        return {'n': 0, 'status': 'NOT MEASURED'}
    ordered = sorted(values)
    percentile = lambda fraction: ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]
    return {'n': len(ordered), 'min': ordered[0], 'p50': statistics.median(ordered),
            'p95': percentile(.95), 'p99': percentile(.99), 'max': ordered[-1],
            'median_absolute_deviation': statistics.median(abs(value - statistics.median(ordered)) for value in ordered)}


def command_for(mode, binary, case, measurement, description):
    if mode == 'sqlite':
        return [sys.executable, str(ROOT / 'benchmarks/sqlite_worker.py'), '--case', str(case), '--measurement', str(measurement)]
    return [str(binary), '--synthetic', '--catalog', str(case / 'catalog.json'),
            '--context', str(case / 'context.json'), '--query', str(case / 'query.json'),
            '--optimize', 'on' if mode == 'rust-on' else 'off',
            '--batch-rows', str(description['batch_rows']),
            '--max-work', str(description.get('max_work', 10000000)),
            '--measurement', str(measurement)]


def sample(mode, binary, case, description, spec, output, phase, repetition, order_index, hashes):
    tag = f'{phase}-{repetition:02d}-{mode}'
    prefix = output / tag
    measurement = output / (tag + '.measurement.json')
    command = command_for(mode, binary, case, measurement, description)
    started_utc = dt.datetime.now(dt.timezone.utc).isoformat()
    usage, stdout, stderr = measured_child(command, cwd=ROOT, prefix=prefix)
    record = {'mode': mode, 'phase': phase, 'repetition': repetition, 'order_index': order_index,
              'started_utc': started_utc,
              'command_template': ['rillscope-measure' if mode != 'sqlite' else 'python',
                                   *[value.replace(str(ROOT), '<public-root>').replace(str(output.parent.parent), '<run-root>') for value in command[1:]]],
              'inputs': hashes, **usage, 'stdout_sha256': hashlib.sha256(stdout).hexdigest(),
              'stderr_sha256': hashlib.sha256(stderr).hexdigest(), 'measurement': None,
              'status': 'INVALID', 'problems': []}
    try:
        result = json.loads(stdout)
        if not isinstance(result, dict) or result.get('status') not in ('ok', 'error'):
            raise ValueError('not a terminal envelope')
        record['status'] = result['status'].upper()
        record['result_digest'] = semantic_digest(result, spec['ordered'])
        if result['status'] == 'error': record['error_code'] = result['error']['code']
        if result['status'] == 'ok' and result['schema'] != spec['schema']:
            record['problems'].append('independent expected schema mismatch')
        if stderr: record['problems'].append('unexpected stderr')
        if (usage['exit_code'] == 0) != (result['status'] == 'ok' or mode == 'sqlite'):
            record['problems'].append('exit code/envelope disagreement')
        if usage['timed_out']: record['problems'].append('process timeout')
        if usage['cpu_rss_status'] != 'MEASURED': record['problems'].append('CPU/RSS instrument unavailable')
        if not measurement.is_file():
            record['problems'].append('measurement artifact missing')
        else:
            data = json.loads(measurement.read_bytes())
            record['measurement'] = data
            record['measurement_sha256'] = sha(measurement)
            payload_hash = hashlib.sha256(stdout.rstrip(b'\r\n')).hexdigest()
            if data['result_sha256'] is not None and data['result_sha256'] != payload_hash:
                record['problems'].append('serialized result digest mismatch')
            if mode != 'sqlite':
                for field in ('catalog', 'context', 'query'):
                    if data[field + '_sha256'] != hashes[field + '.json']:
                        record['problems'].append(field + ' input hash mismatch')
                if data['consumed_work'] > description.get('max_work', 10000000):
                    record['problems'].append('work counter exceeds configured limit')
                if data['peak_reserved_bytes'] > 64 * 1024 * 1024:
                    record['problems'].append('logical memory reservation exceeds configured limit')
            for key in METRICS:
                if key in data: record[key] = data[key]
        if result['status'] == 'error' and mode != 'sqlite' and result['error']['code'] not in ('E_BUDGET', 'E_OUTPUT_LIMIT'):
            record['problems'].append('unexpected product rejection')
        return record, result
    except (ValueError, KeyError, TypeError) as error:
        record['problems'].append('invalid result/instrumentation: ' + type(error).__name__)
        return record, None


def summarize_case(records):
    measured = [record for record in records if record['phase'] == 'measured']
    summary = {}
    for mode in MODES:
        selected = [record for record in measured if record['mode'] == mode]
        summary[mode] = {'observations': len(selected), 'outcomes': dict(Counter(record.get('error_code', record['status']) for record in selected)),
                         'invalid_observations': sum(bool(record['problems']) for record in selected),
                         'all_outcome_metrics': {key: distribution([record[key] for record in selected if record.get(key) is not None]) for key in METRICS},
                         'success_only_execution_ns': distribution([record['execution_only_ns'] for record in selected if record['status'] == 'OK' and record.get('execution_only_ns') is not None])}
    # Explicit label prevents success-only distributions being confused with capacity or target proof.
    summary['pairing'] = {'pairs': REPETITIONS,
                          'wall_on_minus_off_ns': distribution([next(row['wall_ns'] for row in measured if row['mode'] == 'rust-on' and row['repetition'] == index) - next(row['wall_ns'] for row in measured if row['mode'] == 'rust-off' and row['repetition'] == index) for index in range(REPETITIONS)]),
                          'p99_interpretation': 'nearest-rank descriptive order statistic; 30 observations do not establish a tail guarantee'}
    return summary


def execute_case(binary, description, seed, directory, stream):
    case = directory / 'inputs'
    spec = write_case(case, description, seed)
    hashes = {name: sha(case / name) for name in ('catalog.json', 'context.json', 'query.json', 'case.json')}
    records, invalid = [], 0
    randomizer = random.Random(encode(description) + ':' + str(seed))
    for phase, repetitions in (('warmup', WARMUPS), ('measured', REPETITIONS)):
        for repetition in range(repetitions):
            order = list(MODES); randomizer.shuffle(order)
            triplet = []
            for index, mode in enumerate(order):
                record, result = sample(mode, binary, case, description, spec, directory / 'raw', phase, repetition, index, hashes)
                record.update(workload=description['id'], seed=seed)
                triplet.append((record, result))
            oracle = next(result for record, result in triplet if record['mode'] == 'sqlite')
            for record, result in triplet:
                if result is not None and result['status'] == 'ok' and record['mode'] != 'sqlite':
                    if oracle is None or oracle['status'] != 'ok':
                        record['problems'].append('successful Rust output has no successful independent oracle')
                    elif canonical(result, spec['ordered']) != canonical(oracle, spec['ordered']):
                        record['problems'].append('independent SQLite result mismatch')
                if description.get('expected_product_status') and record['mode'] != 'sqlite':
                    if record.get('error_code', record['status']) != description['expected_product_status']:
                        record['problems'].append('predetermined control outcome mismatch')
                # Legitimate finite-budget/output rejection remains a recorded outcome, never a successful query.
                record['oracle_comparison'] = 'EXACT' if result is not None and result['status'] == 'ok' and oracle is not None and oracle['status'] == 'ok' and canonical(result, spec['ordered']) == canonical(oracle, spec['ordered']) else 'NO SUCCESSFUL RESULT TO COMPARE'
                if record['problems']: invalid += 1
                stream.write(encode(record) + '\n'); stream.flush(); records.append(record)
    after = {name: sha(case / name) for name in hashes}
    summary = {'workload': description, 'seed': seed, 'inputs': hashes,
               'input_identity_stable': hashes == after, 'invalid_observations': invalid,
               'warmup_observations': WARMUPS * len(MODES), 'measured_observations': REPETITIONS * len(MODES),
               'metrics': summarize_case(records)}
    (directory / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    return summary


def batch_rejection(binary, out):
    case = out / 'batch-4096-control'
    description = {'id': 'batch-limit-control', 'family': 'filter', 'rows': 10,
                   'selectivity': 100, 'null_percent': 0, 'batch_rows': 4096}
    write_case(case, description, SEEDS[0])
    command = command_for('rust-on', binary, case, case / 'measurement.json', description)
    usage, stdout, stderr = measured_child(command, cwd=ROOT, prefix=case / 'actual')
    try:
        value = json.loads(stdout)
        passed = usage['exit_code'] != 0 and not stderr and value['status'] == 'error' and value['error']['code'] == 'E_CONTEXT' and 'rows' not in value
    except (ValueError, KeyError, TypeError):
        passed = False
    record = {'batch_rows': 4096, 'status': 'PASS' if passed else 'FAIL', **usage,
              'expected': 'E_CONTEXT; limits may only tighten',
              'stdout_sha256': hashlib.sha256(stdout).hexdigest(),
              'stderr_sha256': hashlib.sha256(stderr).hexdigest()}
    (case / 'control.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    return record


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--binary', type=Path, default=ROOT / 'target/release' / ('rillscope-measure.exe' if os.name == 'nt' else 'rillscope-measure'))
    parser.add_argument('--profile', choices=('full', 'instrumentation-pilot'), default='full')
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file(): raise SystemExit('FAIL: build the release rillscope-measure binary first')
    if args.out.exists(): raise SystemExit('FAIL: output must be a new directory; no overwrites or omitted original runs')
    args.out.mkdir(parents=True)
    identity = source_identity(ROOT)
    binary_hash = sha(binary)
    compiler = subprocess.run(['rustc', '--version', '--verbose'], capture_output=True, text=True, check=True).stdout
    commit = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    dirty = bool(subprocess.run(['git', 'status', '--porcelain'], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip())
    chosen = descriptors()
    seeds = SEEDS
    if args.profile == 'instrumentation-pilot':
        # Predetermined instrument verification, not a reduced full-grid claim.
        chosen = [dict(chosen[0], id='pilot-filter-empty'),
                  next(row for row in chosen if row['id'] == 'B01-n10000-s100-null10-b1024'),
                  next(row for row in chosen if row['id'] == 'B02-k1000-uniform-composite1'),
                  next(row for row in chosen if row['id'] == 'B03-all-null'),
                  next(row for row in chosen if row['id'] == 'B04-n10000-equal'),
                  chosen[-1]]
        chosen = [dict(row, expected_product_status='E_BUDGET' if row['family'] == 'budget' else 'OK') for row in chosen]
        seeds = SEEDS[:1]
    manifest = {'schema_version': 1, 'profile': args.profile, 'started_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
                'source': identity, 'commit': commit, 'dirty': dirty, 'binary_sha256': binary_hash,
                'cargo_lock_sha256': sha(ROOT / 'Cargo.lock'), 'compiler': compiler, 'build_profile': 'release',
                'environment': environment(), 'warmups': WARMUPS, 'repetitions': REPETITIONS, 'seeds': seeds,
                'chosen_workloads': chosen, 'expected_cases': len(chosen) * len(seeds),
                'expected_observations': len(chosen) * len(seeds) * (WARMUPS + REPETITIONS) * len(MODES),
                'timing_boundaries': {'wall_ns': 'entire owned process, including startup, input loading, binding/verification, execution, serialization, measurement I/O and exit',
                                     'rust_execution_only_ns': 'library executor operator evaluation/row collection; excludes catalog load, parse/bind/optimize/verify, output byte dry count, final serialization and measurement I/O',
                                     'sqlite_execution_only_ns': 'SQLite query execute and full row collection; excludes physically scoped input materialization and serialization',
                                     'cpu_rss': 'whole owned child process; logical reservations are separate and do not contain OS RSS'},
                'unavailable_experiments': [{'experiment': 'batch_rows=4096', 'status': 'PROHIBITED BY LOCKED LIMIT', 'reason': 'PRD limits trusted callers to tightening the maximum batch of 1024; execute a rejection control, not a relaxed performance run'},
                                            {'experiment': 'AC-022 reference target', 'status': 'NOT EVALUATED HERE', 'reason': 'separate dedicated reference Linux host preflight and target report required'},
                                            {'experiment': 'AC-023 cancellation reference target', 'status': 'NOT EVALUATED HERE', 'reason': 'separate actual Linux cancellation campaign and reference-host report required'}]}
    (args.out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    batch_control = batch_rejection(binary, args.out)
    summaries = []
    with (args.out / 'samples.jsonl').open('x', encoding='utf-8', newline='\n') as stream:
        for description in chosen:
            for seed in seeds:
                case = args.out / (description['id'] + '-seed' + str(seed))
                summary = execute_case(binary, description, seed, case, stream)
                summaries.append(summary)
                print(encode({'completed_cases': len(summaries), 'expected_cases': manifest['expected_cases'],
                              'workload': description['id'], 'seed': seed, 'invalid_observations': summary['invalid_observations']}), flush=True)
    stable = identity['sha256'] == source_identity(ROOT)['sha256'] and binary_hash == sha(binary)
    complete = len(summaries) == manifest['expected_cases'] and all(row['input_identity_stable'] for row in summaries)
    invalid = sum(row['invalid_observations'] for row in summaries) + int(batch_control['status'] != 'PASS')
    result = {'schema_version': 1, 'profile': args.profile, 'completed_cases': len(summaries),
              'expected_cases': manifest['expected_cases'], 'complete_grid': args.profile == 'full' and complete,
              'invalid_observations': invalid, 'source_binary_inputs_stable': stable and complete,
              'batch_limit_control': batch_control,
              'instrumentation_status': 'PASS' if stable and complete and invalid == 0 else 'FAIL',
              'release_status': 'NOT EVALUATED: reference host/cancellation and final release evidence are separate',
              'finished_utc': dt.datetime.now(dt.timezone.utc).isoformat(), 'samples_sha256': sha(args.out / 'samples.jsonl'),
              'summaries': summaries}
    (args.out / 'results.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(encode({key: value for key, value in result.items() if key != 'summaries'}))
    return 0 if result['instrumentation_status'] == 'PASS' else 1


if __name__ == '__main__': raise SystemExit(main())
