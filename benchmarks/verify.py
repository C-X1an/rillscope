#!/usr/bin/env python3
"""Verify complete recorded observations and raw hashes, without inventing reruns."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from run import MODES, REPETITIONS, WARMUPS, canonical, sha, summarize_case
from workloads import SEEDS, descriptors


def verify(directory):
    errors = []
    manifest = json.loads((directory / 'manifest.json').read_bytes())
    results = json.loads((directory / 'results.json').read_bytes())
    rows = [json.loads(line) for line in (directory / 'samples.jsonl').read_text(encoding='utf-8').splitlines()]
    if results['samples_sha256'] != sha(directory / 'samples.jsonl'): errors.append('sample stream digest changed')
    if manifest['warmups'] != WARMUPS or manifest['repetitions'] != REPETITIONS: errors.append('warmup/repetition contract changed')
    if manifest['profile'] == 'full':
        if manifest['chosen_workloads'] != descriptors() or manifest['seeds'] != list(SEEDS): errors.append('full predetermined grid changed')
        if not results['complete_grid']: errors.append('full grid incomplete')
    if len(rows) != manifest['expected_observations']: errors.append('missing or extra observations')
    if not results['source_binary_inputs_stable']: errors.append('source/binary/input identity was not stable during execution')
    by_case = defaultdict(list)
    for row in rows: by_case[(row['workload'], row['seed'])].append(row)
    expected_cases = {(description['id'], seed) for description in manifest['chosen_workloads'] for seed in manifest['seeds']}
    if set(by_case) != expected_cases: errors.append('missing or extra cases')
    for description in manifest['chosen_workloads']:
        for seed in manifest['seeds']:
            case_rows = by_case[(description['id'], seed)]
            case = directory / (description['id'] + '-seed' + str(seed))
            counts = Counter((row['phase'], row['repetition'], row['mode']) for row in case_rows)
            expected = {(phase, number, mode) for phase, count in (('warmup', WARMUPS), ('measured', REPETITIONS)) for number in range(count) for mode in MODES}
            if set(counts) != expected or any(count != 1 for count in counts.values()):
                errors.append('missing/duplicate paired record: ' + description['id'])
                continue
            spec = json.loads((case / 'inputs/case.json').read_bytes())
            groups = defaultdict(dict)
            for row in case_rows:
                tag = f'{row["phase"]}-{row["repetition"]:02d}-{row["mode"]}'
                prefix = case / 'raw' / tag
                stdout = prefix.with_suffix('.stdout').read_bytes()
                stderr = prefix.with_suffix('.stderr').read_bytes()
                if hashlib.sha256(stdout).hexdigest() != row['stdout_sha256'] or hashlib.sha256(stderr).hexdigest() != row['stderr_sha256']:
                    errors.append('raw process output digest changed: ' + tag)
                for name, digest in row['inputs'].items():
                    if sha(case / 'inputs' / name) != digest: errors.append('input digest changed: ' + name)
                measurement = json.loads((case / 'raw' / (tag + '.measurement.json')).read_bytes())
                if measurement != row['measurement']: errors.append('instrumentation differs from captured record: ' + tag)
                if row['problems']: errors.append('invalid observation retained: ' + tag)
                if row['cpu_rss_status'] != 'MEASURED' or any(row.get(key) is None or row[key] < 0 for key in ('wall_ns', 'cpu_user_ns', 'cpu_system_ns', 'peak_rss_bytes')):
                    errors.append('missing/invalid owned process measurement: ' + tag)
                groups[(row['phase'], row['repetition'])][row['mode']] = json.loads(stdout)
            for triplet in groups.values():
                oracle = triplet['sqlite']
                for mode in ('rust-on', 'rust-off'):
                    result = triplet[mode]
                    if result['status'] == 'ok' and (oracle['status'] != 'ok' or canonical(result, spec['ordered']) != canonical(oracle, spec['ordered'])):
                        errors.append('successful product outcome differs from independent oracle')
            saved = json.loads((case / 'summary.json').read_bytes())
            if saved['metrics'] != summarize_case(case_rows): errors.append('summary omits/changes observations: ' + description['id'])
    control = directory / 'batch-4096-control'
    if not control.is_dir(): errors.append('batch bound rejection control missing')
    else:
        captured = json.loads((control / 'actual.stdout').read_bytes())
        if captured.get('status') != 'error' or captured.get('error', {}).get('code') != 'E_CONTEXT' or 'rows' in captured:
            errors.append('batch 4096 did not reject with E_CONTEXT')
        if results['batch_limit_control']['status'] != 'PASS': errors.append('batch bound control failed')
    return {'profile': manifest['profile'], 'observations_checked': len(rows), 'cases_checked': len(by_case),
            'status': 'FAIL' if errors else 'PASS', 'errors': errors,
            'scope': 'recorded observations and artifacts verified; this command executed no queries and establishes no reference-host target'}


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('directory', type=Path); args = parser.parse_args()
    try: result = verify(args.directory)
    except (OSError, ValueError, KeyError, TypeError) as error:
        result = {'status': 'FAIL', 'errors': ['missing/invalid evidence: ' + type(error).__name__]}
    print(json.dumps(result, indent=2))
    return int(result['status'] != 'PASS')


if __name__ == '__main__': raise SystemExit(main())
