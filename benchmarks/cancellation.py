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
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from workloads import SEEDS, write_case
from run import WARMUPS, REPETITIONS, distribution, environment, sha
from process_metrics import ENVIRONMENT_KEYS
sys.path.insert(0, str(ROOT / 'scripts'))
from evidence import source_identity


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--binary', type=Path, default=ROOT / 'target/release/rillscope')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    if platform.system() != 'Linux':
        print(json.dumps({'status': 'BLOCKED', 'reason': 'actual Linux signal semantics required; no hard-kill substitute measured'}))
        return 77
    binary = args.binary.resolve()
    if not binary.is_file(): raise SystemExit('FAIL: release CLI binary not found')
    binary_hash = sha(binary)
    identity = source_identity(ROOT)
    manifest = {'system': platform.system(), 'environment': environment(), 'binary_sha256': binary_hash, 'source': identity,
                'warmups': WARMUPS, 'repetitions': REPETITIONS, 'seeds': list(SEEDS),
                'timing': 'upper bound from actual SIGINT send through terminal envelope and process exit, after observed real join_inner checkpoint; input load excluded',
                'target': '<=100ms, reported descriptively; this command alone does not establish a dedicated reference host'}
    (args.out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    rows = []; input_stability = []
    with (args.out / 'samples.jsonl').open('x', encoding='utf-8', newline='\n') as stream:
        for seed in SEEDS:
            case = args.out / ('seed-' + str(seed))
            write_case(case, {'id': 'cancel-join', 'family': 'budget', 'rows': 20000,
                             'keys': 1, 'skew': 'heavy', 'null_percent': 0, 'batch_rows': 1024}, seed)
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
                    child = subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    problems = []; sent = None; observed = None
                    try:
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
                    finished = time.perf_counter_ns()
                    try:
                        result = json.loads(stdout)
                        if child.returncode == 0 or result.get('status') != 'error' or result.get('error', {}).get('code') != 'E_CANCELLED' or 'rows' in result:
                            problems.append('expected single E_CANCELLED terminal failure')
                    except (ValueError, TypeError): problems.append('invalid terminal envelope')
                    if stderr: problems.append('unexpected stderr')
                    (case / (tag + '.stdout')).write_bytes(stdout)
                    (case / (tag + '.stderr')).write_bytes(stderr)
                    row = {'seed': seed, 'phase': phase, 'repetition': repetition, 'pid': child.pid,
                           'started_ns': started, 'checkpoint_observed_ns': observed, 'signal_sent_ns': sent,
                           'terminal_and_exit_observed_ns': finished, 'cancel_upper_bound_ns': None if sent is None else finished - sent,
                           'exit_code': child.returncode, 'problems': problems, 'inputs': inputs,
                           'stdout_sha256': hashlib.sha256(stdout).hexdigest(), 'stderr_sha256': hashlib.sha256(stderr).hexdigest()}
                    stream.write(json.dumps(row, separators=(',', ':')) + '\n'); stream.flush(); rows.append(row)
            input_stability.append(inputs == {name: sha(case / name) for name in inputs})
    measured = [row for row in rows if row['phase'] == 'measured']
    stable = all(input_stability) and binary_hash == sha(binary) and identity['sha256'] == source_identity(ROOT)['sha256']
    valid = all(not row['problems'] for row in rows) and stable
    values = [row['cancel_upper_bound_ns'] for row in measured if row['cancel_upper_bound_ns'] is not None]
    summary = {'status': 'PASS' if valid else 'FAIL', 'observations': len(rows),
               'measured_observations': len(measured), 'invalid_observations': sum(bool(row['problems']) for row in rows),
               'source_binary_input_identity_stable': stable,
               'cancel_upper_bound_ns': distribution(values), 'target_observations_over_100ms': sum(value > 100000000 for value in values),
               'reference_target_status': 'NOT ESTABLISHED without verified dedicated host allocation',
               'samples_sha256': sha(args.out / 'samples.jsonl'), 'finished_utc': dt.datetime.now(dt.timezone.utc).isoformat()}
    (args.out / 'results.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))
    return 0 if valid else 1


if __name__ == '__main__': raise SystemExit(main())
