"""Finite seeded malformed-input campaign against real Rust subprocesses, not libFuzzer."""
import argparse
import hashlib
import json
from pathlib import Path
import random
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests/acceptance_locked'))
from product_helpers import Client, BINARY, fixture, scan

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists(): parser.error('preserve previous corpus evidence')
    args.out.mkdir(parents=True)
    rng = random.Random(61425)
    failures = 0
    with tempfile.TemporaryDirectory() as folder, (args.out / 'verdicts.jsonl').open('w') as output:
        client = Client(folder, fixture())
        for case in range(1000):
            if case % 5 == 0: data = json.dumps({'version': 1, 'plan': scan(), 'unknown' + str(case): rng.randrange(10000)}).encode()
            elif case % 5 == 1: data = b'{"version":1,"version":1,"plan":{"op":"scan","table":"sales","alias":"s"}}'
            elif case % 5 == 2: data = b'\xff\xfe' + rng.randbytes(rng.randrange(50))
            elif case % 5 == 3: data = b'{"version":1,"plan":{"op":"operator' + str(case).encode() + b'"}}'
            else: data = b'[' * 100 + b'0' + b']' * 100
            verdict = {'case': case, 'seed': 61425, 'input_sha256': hashlib.sha256(data).hexdigest(), 'status': 'FAIL'}
            try:
                code, value = client.call(data)
                if code not in (2, 3) or value.get('status') != 'error': raise AssertionError('invalid corpus did not return a typed error')
                if value['error']['code'] not in ('E_INPUT', 'E_UNSUPPORTED', 'E_LIMIT'): raise AssertionError('unexpected invalid-input error')
                verdict.update(status='PASS', code=value['error']['code'])
            except Exception as error: failures += 1; verdict['error'] = str(error)
            output.write(json.dumps(verdict) + '\n')
    result = {'campaign': 'finite seeded malformed JSON corpus', 'cases': 1000, 'seed': 61425, 'failures': failures,
              'status': 'PASS' if not failures else 'FAIL', 'binary_sha256': hashlib.sha256(BINARY.read_bytes()).hexdigest(),
              'verdicts_sha256': hashlib.sha256((args.out / 'verdicts.jsonl').read_bytes()).hexdigest(), 'libfuzzer_campaign': 'NOT RUN'}
    (args.out / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return int(bool(failures))

if __name__ == '__main__': raise SystemExit(main())
