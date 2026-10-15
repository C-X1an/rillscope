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
from run import MODES, REPETITIONS, WARMUPS, canonical, sha, summarize_case, pair_verdict
from workloads import SEEDS, descriptors
from envelopes import terminal


def verify(directory):
    errors = []
    manifest = json.loads((directory / 'manifest.json').read_bytes())
    results = json.loads((directory / 'results.json').read_bytes())
    rows = [json.loads(line) for line in (directory / 'samples.jsonl').read_text(encoding='utf-8').splitlines()]
    version = manifest.get('schema_version', 1)
    pair_rows = []
    if version >= 2:
        pair_rows = [json.loads(line) for line in (directory / 'pair-verdicts.jsonl').read_text(encoding='utf-8').splitlines()]
        if results['pair_verdicts_sha256'] != sha(directory / 'pair-verdicts.jsonl'): errors.append('pair verdict journal digest changed')
        build = json.loads((directory / 'build/build.json').read_bytes())
        if build != manifest['build'] or sha(directory / 'build/build.json') != manifest['build_receipt_sha256']:
            errors.append('retained build receipt changed')
        if build['status'] != 'PASS' or build['exit_code'] != 0 or build['source']['sha256'] != manifest['source']['sha256'] or build['source_after_sha256'] != manifest['source']['sha256']:
            errors.append('build/source identity mismatch')
        if build['bins']['rillscope-measure']['sha256'] != manifest['binary_sha256'] or build['profile'] != 'release':
            errors.append('source-bound release artifact mismatch')
        for item in build['bins'].values():
            if item['actual_profile']['opt_level'] != '3' or item['actual_profile']['debug_assertions'] or item['actual_profile']['test']:
                errors.append('actual Cargo build profile mismatch')
        for name in ('stdout', 'stderr'):
            if sha(directory / 'build' / ('cargo.' + name)) != build['raw_' + name + '_sha256']:
                errors.append('raw Cargo build digest changed')
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
    saved_summaries = []
    by_pair = defaultdict(list)
    for item in pair_rows: by_pair[(item['workload'], item['seed'], item['phase'], item['repetition'])].append(item)
    expected_pairs = set()
    total_invalid = 0
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
            groups = defaultdict(list)
            hashes = {name: sha(case / 'inputs' / name) for name in ('catalog.json', 'context.json', 'query.json', 'case.json')}
            for row in case_rows:
                tag = f'{row["phase"]}-{row["repetition"]:02d}-{row["mode"]}'
                prefix = case / 'raw' / tag
                stdout = prefix.with_suffix('.stdout').read_bytes()
                stderr = prefix.with_suffix('.stderr').read_bytes()
                if hashlib.sha256(stdout).hexdigest() != row['stdout_sha256'] or hashlib.sha256(stderr).hexdigest() != row['stderr_sha256']:
                    errors.append('raw process output digest changed: ' + tag)
                for name, digest in row['inputs'].items():
                    if hashes[name] != digest: errors.append('input digest changed: ' + name)
                measurement = json.loads((case / 'raw' / (tag + '.measurement.json')).read_bytes())
                if measurement != row['measurement']: errors.append('instrumentation differs from captured record: ' + tag)
                if row['problems']: errors.append('invalid observation retained: ' + tag)
                if row['cpu_rss_status'] != 'MEASURED' or any(row.get(key) is None or row[key] < 0 for key in ('wall_ns', 'cpu_user_ns', 'cpu_system_ns', 'peak_rss_bytes')):
                    errors.append('missing/invalid owned process measurement: ' + tag)
                value = terminal(stdout, stderr, row['exit_code'], row['mode'])
                groups[(row['phase'], row['repetition'])].append((row, value))
            case_invalid = 0
            for key, triplet in groups.items():
                verdict = pair_verdict(triplet, spec)
                verdict.update(workload=description['id'], seed=seed)
                pair_key = (description['id'], seed, *key)
                expected_pairs.add(pair_key)
                if version >= 2 and by_pair[pair_key] != [verdict]: errors.append('pair verdict mismatch or duplicate')
                case_invalid += sum(bool(row['problems'] or verdict['modes'][row['mode']]['problems']) for row, _ in triplet)
                if any(value['problems'] for value in verdict['modes'].values()): errors.append('independent oracle mismatch/unavailable')
            saved = json.loads((case / 'summary.json').read_bytes())
            if saved['metrics'] != summarize_case(case_rows): errors.append('summary omits/changes observations: ' + description['id'])
            if saved['invalid_observations'] != case_invalid: errors.append('case invalid count mismatch')
            total_invalid += case_invalid
            saved_summaries.append(saved)
    if version >= 2 and set(by_pair) != expected_pairs: errors.append('missing/extra pair verdicts')
    if results['summaries'] != saved_summaries: errors.append('top-level summaries differ from verified case summaries')
    control = directory / 'batch-4096-control'
    if not control.is_dir(): errors.append('batch bound rejection control missing')
    else:
        captured = terminal((control / 'actual.stdout').read_bytes(), (control / 'actual.stderr').read_bytes(), results['batch_limit_control']['exit_code'], 'rust-on')
        if captured.get('status') != 'error' or captured.get('error', {}).get('code') != 'E_CONTEXT' or 'rows' in captured:
            errors.append('batch 4096 did not reject with E_CONTEXT')
        if results['batch_limit_control']['status'] != 'PASS': errors.append('batch bound control failed')
        total_invalid += int(results['batch_limit_control']['status'] != 'PASS')
    if results['invalid_observations'] != total_invalid: errors.append('top-level invalid count differs from observations')
    if results['completed_cases'] != len(expected_cases) or results['expected_cases'] != len(expected_cases): errors.append('top-level case count differs from actual cases')
    return {'profile': manifest['profile'], 'observations_checked': len(rows), 'cases_checked': len(by_case),
            'status': 'FAIL' if errors else 'PASS', 'errors': errors,
            'build_provenance_status': 'RECORDED' if version >= 2 else 'NOT RECORDED: historical schema 1 instrument evidence only',
            'scope': 'recorded observations and artifacts verified; this command executed no queries and establishes no reference-host target'}


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('directory', type=Path); args = parser.parse_args()
    try: result = verify(args.directory)
    except (OSError, ValueError, KeyError, TypeError) as error:
        result = {'status': 'FAIL', 'errors': ['missing/invalid evidence: ' + type(error).__name__]}
    print(json.dumps(result, indent=2))
    return int(result['status'] != 'PASS')


if __name__ == '__main__': raise SystemExit(main())
