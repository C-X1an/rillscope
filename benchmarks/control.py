#!/usr/bin/env python3
"""PASS-FAIL-PASS against a disposable copy of real benchmark artifacts."""
import argparse
import json
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify import verify
from run import sha


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('source', type=Path)
    parser.add_argument('--out', type=Path, required=True); args = parser.parse_args()
    original = sha(args.source / 'samples.jsonl')
    shutil.copytree(args.source, args.out)
    before = verify(args.out)
    sample_file = args.out / 'samples.jsonl'
    raw = sample_file.read_bytes()
    records = raw.decode().splitlines()
    first = json.loads(records[0]); first['wall_ns'] += 1
    records[0] = json.dumps(first, separators=(',', ':'))
    sample_file.write_text('\n'.join(records) + '\n', encoding='utf-8', newline='\n')
    mutant = verify(args.out)
    sample_file.write_bytes(raw)
    restored = verify(args.out)
    result_file = args.out / 'results.json'
    original_result = result_file.read_bytes()
    changed = json.loads(original_result)
    changed['summaries'][0]['metrics']['rust-on']['success_only_execution_ns']['p95'] = -123
    result_file.write_text(json.dumps(changed), encoding='utf-8')
    summary_mutant = verify(args.out)
    result_file.write_bytes(original_result)
    summary_restored = verify(args.out)
    unchanged = original == sha(args.source / 'samples.jsonl') == sha(sample_file)
    passed = before['status'] == 'PASS' and mutant['status'] == 'FAIL' and 'sample stream digest changed' in mutant['errors'] and restored['status'] == 'PASS' and unchanged
    passed = passed and summary_mutant['status'] == 'FAIL' and 'top-level summaries differ from verified case summaries' in summary_mutant['errors'] and summary_restored['status'] == 'PASS'
    result = {'control': 'benchmark-sample-integrity', 'sequence': [before['status'], mutant['status'], restored['status']],
              'original_source_unchanged': unchanged, 'mutant_errors': mutant['errors'],
              'top_summary_sequence': [restored['status'], summary_mutant['status'], summary_restored['status']],
              'top_summary_mutant_errors': summary_mutant['errors'],
              'status': 'PASS' if passed else 'FAIL', 'scope': 'evidence checker only; no new product query or performance observations'}
    (args.out / 'negative-control.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if passed else 1


if __name__ == '__main__': raise SystemExit(main())
