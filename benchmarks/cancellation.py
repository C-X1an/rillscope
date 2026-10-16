#!/usr/bin/env python3
"""Actual Linux SIGINT campaign at a real owned CLI hash-join checkpoint."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from workloads import SEEDS, write_case, make_catalog, context, query, validate_workload_catalog
from run import WARMUPS, REPETITIONS, distribution, environment, sha
from process_metrics import ENVIRONMENT_KEYS
from envelopes import terminal
from build import verify_build
sys.path.insert(0, str(ROOT / 'scripts'))
from evidence import source_identity


def cancellation_summary(rows, stable):
    measured = [row for row in rows if row['phase'] == 'measured']
    valid = all(not row['problems'] for row in rows) and stable and len(rows) == len(SEEDS) * (WARMUPS + REPETITIONS)
    values = [row['cancel_upper_bound_ns'] for row in measured if row['cancel_upper_bound_ns'] is not None]
    return {'status': 'PASS' if valid else 'FAIL', 'observations': len(rows),
            'measured_observations': len(measured), 'invalid_observations': sum(bool(row['problems']) for row in rows),
            'source_binary_input_identity_stable': stable, 'cancel_upper_bound_ns': distribution(values),
            'target_observations_over_100ms': sum(value > 100000000 for value in values),
            'reference_target_status': 'NOT ESTABLISHED by standalone campaign; verified reference wrapper supplies contextual verdict'}


def verify_cancellation(directory):
    from collections import Counter
    manifest = json.loads((directory / 'manifest.json').read_bytes())
    result = json.loads((directory / 'results.json').read_bytes())
    rows = [json.loads(line) for line in (directory / 'samples.jsonl').read_text().splitlines()]
    errors = []
    if (manifest.get('schema_version') != 2 or manifest.get('system') != 'Linux'
            or manifest.get('environment',{}).get('system') != 'Linux'
            or manifest.get('warmups') != WARMUPS or manifest.get('repetitions') != REPETITIONS
            or manifest.get('seeds') != list(SEEDS)):
        errors.append('cancellation requires the complete declared Linux campaign manifest')
    if result.get('source_binary_input_identity_stable') is not True:
        errors.append('cancellation source/binary/input identity unstable')
    expected = {(seed, phase, index) for seed in SEEDS for phase, count in (('warmup', WARMUPS), ('measured', REPETITIONS)) for index in range(count)}
    counts = Counter((row['seed'], row['phase'], row['repetition']) for row in rows)
    if set(counts) != expected or any(value != 1 for value in counts.values()): errors.append('missing/extra/duplicate cancellation observation')
    if result['samples_sha256'] != sha(directory / 'samples.jsonl'): errors.append('cancellation sample digest changed')
    build = json.loads((directory / 'build/build.json').read_bytes())
    if (build.get('schema_version') != 2 or build.get('exit_code') != 0 or build.get('profile') != 'release'
            or build.get('fresh_target_directory') is not True or build.get('problems') != []
            or build.get('compiler_selection') != 'explicit pinned sysroot executable passed as RUSTC'
            or sha(directory / 'build/build.json') != manifest.get('build_receipt_sha256')):
        errors.append('cancellation release/compiler/build receipt provenance incomplete')
    actual_profile = build.get('bins',{}).get('rillscope',{}).get('actual_profile',{})
    if (actual_profile.get('opt_level') != '3' or actual_profile.get('debug_assertions') is not False
            or actual_profile.get('test') is not False):
        errors.append('cancellation actual Cargo profile is not release')
    for stream in ('stdout','stderr'):
        path = directory / 'build' / ('compiler.' + stream)
        if not path.is_file() or sha(path) != build.get('raw_compiler_' + stream + '_sha256'):
            errors.append('cancellation raw compiler probe digest changed')
    compiler_stdout = directory / 'build/compiler.stdout'
    if not compiler_stdout.is_file() or compiler_stdout.read_text(encoding='utf-8') != build.get('compiler'):
        errors.append('cancellation actual compiler version differs from build receipt')
    # Incomplete historical/unit metadata cannot proceed as qualifying evidence.
    if errors:
        return {'status':'FAIL','observations_checked':0,'errors':errors,
                'scope':'manifest/build provenance rejected; no signal experiment performed'}
    if build != manifest['build'] or build['source']['sha256'] != manifest['source']['sha256'] or build['source_after_sha256'] != manifest['source']['sha256']:
        errors.append('cancellation source/build binding differs')
    if build['status'] != 'PASS' or build['bins']['rillscope']['sha256'] != manifest['binary_sha256']:
        errors.append('cancellation executable differs from actual release build')
    for name in ('stdout', 'stderr'):
        if sha(directory / 'build' / ('cargo.' + name)) != build['raw_' + name + '_sha256']: errors.append('cancellation raw build digest changed')
    input_hashes = {}
    description = cancellation_description()
    for seed in SEEDS:
        case = directory / ('seed-' + str(seed))
        input_hashes[seed] = {name:sha(case / name) for name in ('catalog.json','context.json','query.json')}
        catalog = json.loads((case / 'catalog.json').read_bytes())
        validate_workload_catalog(description,catalog)
        expected_catalog = json.dumps(make_catalog(description,seed),ensure_ascii=False,separators=(',',':')).encode()
        if hashlib.sha256(expected_catalog).hexdigest() != input_hashes[seed]['catalog.json']:
            errors.append('cancellation catalog differs from declared seeded workload')
        if (json.loads((case / 'context.json').read_bytes()) != context()
                or json.loads((case / 'query.json').read_bytes()) != query(description)[0]):
            errors.append('cancellation authority/query differs from declared experiment')
    for row in rows:
        case = directory / ('seed-' + str(row['seed']))
        tag = f'{row["phase"]}-{row["repetition"]:02d}'
        stdout = (case / (tag + '.stdout')).read_bytes(); stderr = (case / (tag + '.stderr')).read_bytes()
        if hashlib.sha256(stdout).hexdigest() != row['stdout_sha256'] or hashlib.sha256(stderr).hexdigest() != row['stderr_sha256']:
            errors.append('cancellation terminal artifact changed')
        value = terminal(stdout, stderr, row['exit_code'], 'rust')
        if value['status'] != 'error' or value['error']['code'] != 'E_CANCELLED': errors.append('cancellation did not return E_CANCELLED')
        times = [row[key] for key in ('started_ns', 'checkpoint_observed_ns', 'signal_sent_ns', 'terminal_and_exit_observed_ns')]
        if any(type(value) is not int for value in times) or times != sorted(times): errors.append('invalid cancellation event timestamps')
        elif row['cancel_upper_bound_ns'] != times[-1] - times[-2]: errors.append('cancellation latency differs from event timestamps')
        if (case / (tag + '.phase')).read_bytes() != b'join_inner\n': errors.append('real join checkpoint marker differs')
        if input_hashes[row['seed']] != row['inputs']: errors.append('cancellation input digest changed')
        if row['problems']: errors.append('invalid cancellation observation retained')
    expected_summary = cancellation_summary(rows, result['source_binary_input_identity_stable'])
    if expected_summary['status'] != 'PASS': errors.append('cancellation campaign did not pass')
    if any(result.get(key) != value for key, value in expected_summary.items()): errors.append('cancellation summary differs from retained observations')
    return {'status': 'FAIL' if errors else 'PASS', 'observations_checked': len(rows), 'errors': errors,
            'scope': 'retained cancellation events/artifacts only; this validator performed no signal experiment'}


def cancellation_description():
    return {'id':'cancel-join','family':'budget','rows':20000,'keys':1,'skew':'heavy',
            'null_percent':0,'batch_rows':1024}


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--binary', type=Path, default=ROOT / 'target/release/rillscope')
    parser.add_argument('--build-receipt', type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    if platform.system() != 'Linux':
        print(json.dumps({'status': 'BLOCKED', 'reason': 'actual Linux signal semantics required; no hard-kill substitute measured'}))
        return 77
    binary = args.binary.resolve()
    if not binary.is_file(): raise SystemExit('FAIL: release CLI binary not found')
    if args.build_receipt is None: raise ValueError('actual source-bound release build receipt required')
    build = verify_build(args.build_receipt, binary, name='rillscope')
    build_hash = sha(args.build_receipt)
    (args.out / 'build').mkdir()
    for name in ('build.json', 'cargo.stdout', 'cargo.stderr', 'compiler.stdout', 'compiler.stderr'):
        shutil.copyfile(args.build_receipt.parent / name, args.out / 'build' / name)
    binary_hash = sha(binary)
    identity = source_identity(ROOT)
    manifest = {'schema_version': 2, 'system': platform.system(), 'environment': environment(), 'binary_sha256': binary_hash, 'source': identity,
                'build': build, 'build_receipt_sha256': build_hash,
                'warmups': WARMUPS, 'repetitions': REPETITIONS, 'seeds': list(SEEDS),
                'timing': 'upper bound from actual SIGINT send through terminal envelope and process exit, after observed real join_inner checkpoint; input load excluded',
                'target': '<=100ms, reported descriptively; this command alone does not establish a dedicated reference host'}
    (args.out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    rows = []; input_stability = []
    with (args.out / 'samples.jsonl').open('x', encoding='utf-8', newline='\n') as stream:
        for seed in SEEDS:
            case = args.out / ('seed-' + str(seed))
            write_case(case, cancellation_description(), seed)
            inputs = {name: sha(case / name) for name in ('catalog.json', 'context.json', 'query.json')}
            for phase, count in (('warmup', WARMUPS), ('measured', REPETITIONS)):
                for repetition in range(count):
                    tag = f'{phase}-{repetition:02d}'
                    marker = case / (tag + '.phase')
                    env = {key: os.environ[key] for key in ENVIRONMENT_KEYS if key in os.environ}
                    env['RILLSCOPE_TEST_PHASE_FILE'] = str(marker.resolve())
                    command = [str(binary), 'run', '--catalog', str((case / 'catalog.json').resolve()),
                               '--context', str((case / 'context.json').resolve()), '--query', str((case / 'query.json').resolve())]
                    started = time.perf_counter_ns()
                    child = None; problems = []; sent = None; observed = None; stdout = b''; stderr = b''
                    try:
                        child = subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        deadline = time.monotonic() + 20
                        while not marker.is_file() and child.poll() is None and time.monotonic() < deadline:
                            time.sleep(.001)
                        if marker.is_file() and marker.read_bytes() == b'join_inner\n' and child.poll() is None:
                            observed = time.perf_counter_ns()
                            sent = time.perf_counter_ns()
                            child.send_signal(signal.SIGINT)
                        else: problems.append('live real join checkpoint unavailable')
                        stdout, stderr = child.communicate(timeout=20)
                    except subprocess.TimeoutExpired:
                        problems.append('timeout retained; own process hard-killed for cleanup, not a cancellation success')
                        child.kill(); stdout, stderr = child.communicate()
                    except OSError as error:
                        problems.append('launch/signal failure: ' + type(error).__name__)
                        if child is not None:
                            if child.poll() is None: child.kill()
                            stdout, stderr = child.communicate()
                    finished = time.perf_counter_ns()
                    try:
                        result = terminal(stdout, stderr, None if child is None else child.returncode, 'rust')
                        if result['status'] != 'error' or result['error']['code'] != 'E_CANCELLED':
                            problems.append('expected single E_CANCELLED terminal failure')
                    except (ValueError, TypeError): problems.append('invalid terminal envelope')
                    if stderr: problems.append('unexpected stderr')
                    (case / (tag + '.stdout')).write_bytes(stdout)
                    (case / (tag + '.stderr')).write_bytes(stderr)
                    row = {'seed': seed, 'phase': phase, 'repetition': repetition, 'pid': None if child is None else child.pid,
                           'started_ns': started, 'checkpoint_observed_ns': observed, 'signal_sent_ns': sent,
                           'terminal_and_exit_observed_ns': finished, 'cancel_upper_bound_ns': None if sent is None else finished - sent,
                           'exit_code': None if child is None else child.returncode, 'problems': problems, 'inputs': inputs,
                           'stdout_sha256': hashlib.sha256(stdout).hexdigest(), 'stderr_sha256': hashlib.sha256(stderr).hexdigest()}
                    stream.write(json.dumps(row, separators=(',', ':')) + '\n'); stream.flush(); rows.append(row)
            input_stability.append(inputs == {name: sha(case / name) for name in inputs})
    stable = all(input_stability) and binary_hash == sha(binary) and identity['sha256'] == source_identity(ROOT)['sha256'] and build_hash == sha(args.build_receipt)
    summary = {**cancellation_summary(rows, stable),
               'environment_after':environment(),
               'samples_sha256': sha(args.out / 'samples.jsonl'), 'finished_utc': dt.datetime.now(dt.timezone.utc).isoformat()}
    (args.out / 'results.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))
    return 0 if summary['status'] == 'PASS' else 1


if __name__ == '__main__': raise SystemExit(main())
