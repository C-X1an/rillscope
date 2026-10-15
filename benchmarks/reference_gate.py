#!/usr/bin/env python3
"""Fail narrowly until an actual dedicated reference host has been established."""
import argparse
import json
import platform
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from run import environment


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--host-receipt', type=Path)
    args = parser.parse_args()
    actual = environment()
    reasons = []
    if platform.system() != 'Linux': reasons.append('actual Linux runtime unavailable on this host')
    if args.host_receipt is None: reasons.append('dedicated 4-core/8-GiB reference host allocation has not been evidenced')
    else:
        receipt = json.loads(args.host_receipt.read_bytes())
        if receipt.get('source') != 'actual host allocation and inspection' or receipt.get('dedicated') is not True:
            reasons.append('reference receipt does not establish dedicated allocation')
        if receipt.get('logical_processors') != 4 or actual['logical_processors'] != 4:
            reasons.append('actual/reference CPU count is not four')
        memory = actual.get('physical_memory_bytes')
        if memory is None or not 7.5 * 1024**3 <= memory <= 8.5 * 1024**3:
            reasons.append('actual/reference memory is not the documented 8-GiB configuration')
        if receipt.get('cpu_model') != actual.get('cpu_model'):
            reasons.append('reference receipt does not match actual CPU')
    args.out.mkdir(parents=True, exist_ok=False)
    record = {'gate': 'benchmark', 'status': 'BLOCKED' if reasons else 'READY', 'actual_environment': actual,
              'reasons': reasons, 'local_work': 'make benchmark-local executes the complete available grid without reference-target claims'}
    (args.out / 'reference-preflight.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(record, indent=2), flush=True)
    if reasons: return 77
    subprocess.run(['cargo', 'build', '--release', '--locked'], cwd=ROOT, check=True)
    code = subprocess.call([sys.executable, str(ROOT / 'benchmarks/run.py'), '--out', str(args.out / 'grid')], cwd=ROOT)
    if code: return code
    code = subprocess.call([sys.executable, str(ROOT / 'benchmarks/cancellation.py'), '--out', str(args.out / 'cancel')], cwd=ROOT)
    if code: return code
    code = subprocess.call([sys.executable, str(ROOT / 'benchmarks/verify.py'), str(args.out / 'grid')], cwd=ROOT)
    if code: return code
    grid = json.loads((args.out / 'grid/results.json').read_bytes())
    targets = []
    for row in grid['summaries']:
        if row['workload']['id'] != 'B01-n100000-s10-null10-b1024': continue
        measured = row['metrics']['rust-on']
        latency = measured['success_only_execution_ns']
        targets.append({'seed': row['seed'], 'execution_ns': latency,
                        'end_to_end_ns': measured['all_outcome_metrics']['wall_ns'],
                        'target_status': 'MET' if latency['n'] == 30 and latency['p95'] < 1000000000 else 'MISSED'})
    cancellation = json.loads((args.out / 'cancel/results.json').read_bytes())
    report = {'reference_host_preflight': record, 'filter_project_target_by_seed': targets,
              'cancellation': cancellation, 'status': 'PASS' if len(targets) == 5 else 'FAIL',
              'meaning': 'targets reported as met or missed; a speed target miss is retained, not a correctness waiver'}
    (args.out / 'reference-results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__': raise SystemExit(main())
