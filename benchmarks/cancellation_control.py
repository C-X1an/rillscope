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
    passed = before['status'] == 'PASS' and mutant['status'] == 'FAIL' and 'cancellation summary differs from retained observations' in mutant['errors'] and restored['status'] == 'PASS'
    result = {'control': 'cancellation-summary-integrity', 'sequence': [before['status'], mutant['status'], restored['status']],
              'status': 'PASS' if passed else 'FAIL', 'scope': 'artifact validator only; no new signal/latency observations'}
    (args.out / 'negative-control.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if passed else 1


if __name__ == '__main__': raise SystemExit(main())
