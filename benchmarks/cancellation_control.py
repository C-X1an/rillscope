#!/usr/bin/env python3
"""Corrupt a retained cancellation summary, without inventing a signal run."""
import argparse
import json
from pathlib import Path
import shutil
from cancellation import verify_cancellation


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('source', type=Path)
    parser.add_argument('--out', type=Path, required=True); args = parser.parse_args()
    shutil.copytree(args.source, args.out)
    before = verify_cancellation(args.out)
    target = args.out / 'results.json'; raw = target.read_bytes()
    value = json.loads(raw); value['cancel_upper_bound_ns']['p95'] = -123
    target.write_text(json.dumps(value))
    mutant = verify_cancellation(args.out)
    target.write_bytes(raw)
    restored = verify_cancellation(args.out)
    manifest_path = args.out / 'manifest.json'; manifest_raw = manifest_path.read_bytes()
    build_path = args.out / 'build/build.json'; build_raw = build_path.read_bytes()
    manifest = json.loads(manifest_raw); build = json.loads(build_raw)
    manifest['system'] = 'Windows'
    manifest.pop('environment', None)
    manifest['build_receipt_sha256'] = '0' * 64
    build['exit_code'] = 9
    build['profile'] = 'debug'
    build.pop('compiler_selection', None)
    manifest['build'] = build
    manifest_path.write_text(json.dumps(manifest)); build_path.write_text(json.dumps(build))
    provenance_mutant = verify_cancellation(args.out)
    manifest_path.write_bytes(manifest_raw); build_path.write_bytes(build_raw)
    final = verify_cancellation(args.out)
    passed = before['status'] == 'PASS' and mutant['status'] == 'FAIL' and 'cancellation summary differs from retained observations' in mutant['errors'] and restored['status'] == 'PASS'
    passed = passed and provenance_mutant['status'] == 'FAIL' and final['status'] == 'PASS'
    result = {'control': 'cancellation-summary-integrity', 'sequence': [before['status'], mutant['status'], restored['status']],
              'provenance_sequence':[restored['status'],provenance_mutant['status'],final['status']],
              'provenance_errors':provenance_mutant['errors'],
              'status': 'PASS' if passed else 'FAIL', 'scope': 'artifact validator only; no new signal/latency observations'}
    (args.out / 'negative-control.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if passed else 1


if __name__ == '__main__': raise SystemExit(main())
