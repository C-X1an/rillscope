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
from run import METRICS, MODES, REPETITIONS, WARMUPS, semantic_digest, sha, summarize_case, pair_verdict
from workloads import SEEDS, descriptors, sort_null_descriptors, query, context, make_catalog, validate_workload_catalog, sort_input_characterization
from envelopes import terminal
from evidence import source_identity


def sample_problems(row, value, measurement, description, spec, hashes, stdout):
    errors = []
    if row.get('inputs') != hashes: errors.append('input identities differ')
    if row.get('status') != value['status'].upper(): errors.append('recorded terminal status differs')
    actual = value['error']['code'] if value['status'] == 'error' else 'OK'
    if row.get('error_code') != (actual if value['status'] == 'error' else None): errors.append('recorded error code differs')
    if row.get('result_digest') != semantic_digest(value, spec['ordered']): errors.append('semantic digest differs from terminal result')
    if value['status'] == 'ok' and value['schema'] != spec['schema']: errors.append('independent expected schema mismatch')
    if row['mode'] != 'sqlite' and description.get('expected_product_status') and actual != description['expected_product_status']:
        errors.append('predetermined control outcome mismatch')
    if row['mode'] != 'sqlite' and description.get('allowed_product_statuses') and actual not in description['allowed_product_statuses']:
        errors.append('predetermined capacity outcome mismatch')
    if not isinstance(measurement, dict): return errors + ['measurement artifact missing']
    for key in METRICS:
        if key not in ('wall_ns', 'cpu_user_ns', 'cpu_system_ns', 'peak_rss_bytes') and row.get(key) != measurement.get(key):
            errors.append('flattened metric differs: ' + key)
        number = measurement.get(key)
        if number is not None and (type(number) is not int or number < 0): errors.append('invalid instrumentation metric: ' + key)
    payload_hash = hashlib.sha256(stdout.rstrip(b'\r\n')).hexdigest()
    expected_payload = None if row['mode'] != 'sqlite' and value['status'] == 'error' else payload_hash
    if measurement.get('result_sha256') != expected_payload: errors.append('measurement result hash mismatch')
    if row['mode'] != 'sqlite':
        if value['status'] == 'ok':
            if any(type(measurement.get(key)) is not int or measurement[key] < 0 for key in ('execution_only_ns','serialization_ns')):
                errors.append('successful Rust execution/serialization timing missing')
            elif measurement['execution_only_ns'] > measurement['execution_call_wall_ns']:
                errors.append('execution timer exceeds enclosing call')
        for field in ('load_ns', 'compile_ns', 'execution_call_wall_ns', 'consumed_work', 'visible_work', 'peak_reserved_bytes'):
            if type(measurement.get(field)) is not int or measurement[field] < 0: errors.append('required Rust measurement missing: ' + field)
        for field in ('catalog', 'context', 'query'):
            if measurement.get(field + '_sha256') != hashes[field + '.json']: errors.append('measurement input hash mismatch: ' + field)
        if measurement.get('implementation') != 'rust-benchmark' or measurement.get('synthetic_only') is not True:
            errors.append('measurement implementation mismatch')
        if measurement.get('optimize') is not (row['mode'] == 'rust-on') or measurement.get('batch_rows') != description['batch_rows']:
            errors.append('measured optimization/batch parameters differ')
        if measurement.get('consumed_work', -1) > description.get('max_work', 10000000): errors.append('work counter exceeds configured limit')
        if measurement.get('peak_reserved_bytes', -1) > 64 * 1024 * 1024: errors.append('logical reservation exceeds configured limit')
        if measurement.get('error') != (value['error'] if value['status'] == 'error' else None): errors.append('measurement error differs')
    else:
        if measurement.get('implementation') != 'sqlite-baseline': errors.append('measurement implementation mismatch')
        for field in ('materialization_ns', 'execution_only_ns', 'serialization_ns'):
            if type(measurement.get(field)) is not int or measurement[field] < 0: errors.append('required SQLite measurement missing: ' + field)
    return errors


def verify(directory, require_current_product=False):
    errors = []
    manifest = json.loads((directory / 'manifest.json').read_bytes())
    results = json.loads((directory / 'results.json').read_bytes())
    rows = [json.loads(line) for line in (directory / 'samples.jsonl').read_text(encoding='utf-8').splitlines()]
    version = manifest.get('schema_version', 1)
    if type(version) is not int or version not in (1,2,3): errors.append('unsupported benchmark evidence schema')
    if results.get('schema_version',1) != version: errors.append('manifest/results evidence schema differs')
    if require_current_product and version != 3:
        errors.append('current release qualification requires schema-3 build/process evidence')
    product_file = lambda name: name.startswith('src/') or name in ('Cargo.toml','Cargo.lock','rust-toolchain.toml')
    captured_product = {name:digest for name,digest in manifest['source']['files'] if product_file(name)}
    current_product = {name:digest for name,digest in source_identity(ROOT)['files'] if product_file(name)}
    current_product_matches = captured_product == current_product
    if require_current_product and not current_product_matches: errors.append('current Rust product source differs from captured build')
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
        if version >= 3:
            if build.get('schema_version') != 2 or build.get('compiler_selection') != 'explicit pinned sysroot executable passed as RUSTC':
                errors.append('explicit actual compiler build binding missing')
            for name in ('stdout','stderr'):
                if sha(directory / 'build' / ('compiler.' + name)) != build.get('raw_compiler_' + name + '_sha256'):
                    errors.append('raw compiler probe digest changed')
            if (directory / 'build/compiler.stdout').read_text(encoding='utf-8') != build['compiler']:
                errors.append('compiler probe/receipt version differs')
    if results['samples_sha256'] != sha(directory / 'samples.jsonl'): errors.append('sample stream digest changed')
    if manifest['warmups'] != WARMUPS or manifest['repetitions'] != REPETITIONS: errors.append('warmup/repetition contract changed')
    if manifest['profile'] == 'full':
        dimensions = lambda row: {key:value for key,value in row.items() if key not in ('expected_product_status','allowed_product_statuses','expected_oracle_status')}
        if [dimensions(row) for row in manifest['chosen_workloads']] != [dimensions(row) for row in descriptors()] or manifest['seeds'] != list(SEEDS):
            errors.append('full predetermined grid changed')
        if not results['complete_grid']: errors.append('full grid incomplete')
    if manifest['profile'] == 'sort-null-supplement':
        if manifest['chosen_workloads'] != sort_null_descriptors() or manifest['seeds'] != list(SEEDS):
            errors.append('complete declared NULL-sort supplement changed')
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
    total_comparisons = 0
    required_success_cases = 0
    sort_conditions = []
    for description in manifest['chosen_workloads']:
        validation_description = next((row for row in descriptors() if row['id'] == description['id']), description) if manifest['profile'] == 'full' else description
        for seed in manifest['seeds']:
            case_rows = by_case[(description['id'], seed)]
            case = directory / (description['id'] + '-seed' + str(seed))
            counts = Counter((row['phase'], row['repetition'], row['mode']) for row in case_rows)
            expected = {(phase, number, mode) for phase, count in (('warmup', WARMUPS), ('measured', REPETITIONS)) for number in range(count) for mode in MODES}
            if set(counts) != expected or any(count != 1 for count in counts.values()):
                errors.append('missing/duplicate paired record: ' + description['id'])
                continue
            spec = json.loads((case / 'inputs/case.json').read_bytes())
            catalog_path = case / 'inputs/catalog.json'
            if catalog_path.stat().st_size > 256 * 1024 * 1024: raise ValueError('catalog evidence exceeds locked input bound')
            actual_shape = validate_workload_catalog(description,json.loads(catalog_path.read_bytes()))
            if description['family'] == 'sort':
                sort_conditions.append({'workload':description['id'],'seed':seed,
                                        **sort_input_characterization(json.loads(catalog_path.read_bytes()))})
            expected_catalog = json.dumps(make_catalog(description,seed),ensure_ascii=False,separators=(',',':')).encode()
            if hashlib.sha256(expected_catalog).hexdigest() != sha(catalog_path):
                errors.append('catalog differs from declared deterministic workload/seed recipe')
            del expected_catalog
            if spec['realized_shape'] != actual_shape or json.loads((case / 'inputs/context.json').read_bytes()) != context():
                errors.append('retained catalog dimensions/authority differ from declared case')
            expected_query, sql, schema, ordered = query(description)
            if (spec['description'] != description or spec['seed'] != seed or spec['sql'] != sql
                    or spec['schema'] != schema or spec['ordered'] != ordered
                    or json.loads((case / 'inputs/query.json').read_bytes()) != expected_query):
                errors.append('case specification differs from predetermined workload')
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
                if sha(case / 'raw' / (tag + '.measurement.json')) != row.get('measurement_sha256'):
                    errors.append('measurement artifact digest changed: ' + tag)
                if row['problems']: errors.append('invalid observation retained: ' + tag)
                if row['cpu_rss_status'] != 'MEASURED' or any(row.get(key) is None or row[key] < 0 for key in ('wall_ns', 'cpu_user_ns', 'cpu_system_ns', 'peak_rss_bytes')):
                    errors.append('missing/invalid owned process measurement: ' + tag)
                value = terminal(stdout, stderr, row['exit_code'], row['mode'])
                errors.extend(problem + ': ' + tag for problem in sample_problems(row, value, measurement, validation_description, spec, hashes, stdout))
                if version >= 3:
                    usage_path = case / 'raw' / (tag + '.process.json')
                    usage = json.loads(usage_path.read_bytes())
                    if sha(usage_path) != row.get('process_measurement_sha256') or any(row.get(key) != number for key, number in usage.items()):
                        errors.append('process measurement differs from recorded sample: ' + tag)
                groups[(row['phase'], row['repetition'])].append((row, value))
            case_invalid = 0
            comparisons = 0
            for key, triplet in groups.items():
                verdict = pair_verdict(triplet, dict(spec,description=validation_description))
                verdict.update(workload=description['id'], seed=seed)
                pair_key = (description['id'], seed, *key)
                expected_pairs.add(pair_key)
                if version >= 2 and by_pair[pair_key] != [verdict]: errors.append('pair verdict mismatch or duplicate')
                case_invalid += sum(bool(row['problems'] or verdict['modes'][row['mode']]['problems']) for row, _ in triplet)
                if any(value['problems'] for value in verdict['modes'].values()): errors.append('independent oracle mismatch/unavailable')
                if key[0] == 'measured': comparisons += sum(value['oracle_comparison'] == 'EXACT' for mode, value in verdict['modes'].items() if mode != 'sqlite')
            saved = json.loads((case / 'summary.json').read_bytes())
            expected_summary = {'workload':description,'seed':seed,'inputs':hashes,
                                'input_identity_stable':all(row['inputs'] == hashes for row in case_rows),
                                'invalid_observations':case_invalid,'independent_semantic_comparisons':comparisons,
                                'warmup_observations':WARMUPS * len(MODES),
                                'measured_observations':REPETITIONS * len(MODES),'metrics':summarize_case(case_rows)}
            if saved != expected_summary: errors.append('case summary identity/counts differ from verified case: ' + description['id'])
            if saved['metrics'] != summarize_case(case_rows): errors.append('summary omits/changes observations: ' + description['id'])
            if saved['invalid_observations'] != case_invalid: errors.append('case invalid count mismatch')
            total_invalid += case_invalid
            if version >= 3 and saved.get('independent_semantic_comparisons') != comparisons: errors.append('case independent comparison count mismatch')
            if validation_description.get('expected_product_status') == 'OK' and comparisons != REPETITIONS * 2:
                errors.append('required successful Rust/SQLite comparisons missing: ' + description['id'])
            if validation_description.get('expected_product_status') == 'OK' and comparisons == REPETITIONS * 2:
                required_success_cases += 1
            total_comparisons += comparisons
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
    if version >= 3 and (results.get('independent_semantic_comparisons') != total_comparisons or total_comparisons == 0):
        errors.append('independent semantic comparisons missing or misreported')
    if results['completed_cases'] != len(expected_cases) or results['expected_cases'] != len(expected_cases): errors.append('top-level case count differs from actual cases')
    return {'profile': manifest['profile'], 'observations_checked': len(rows), 'cases_checked': len(by_case),
            'status': 'FAIL' if errors else 'PASS', 'errors': errors,
            'current_product_source_matches_capture':current_product_matches,
            'evidence_schema_version':version,
            'current_release_evidence_qualified':not errors and version == 3 and current_product_matches,
            'sort_input_conditions':sort_conditions,
            'independent_semantic_comparisons':total_comparisons,'required_success_cases_checked':required_success_cases,
            'build_provenance_status': 'RECORDED' if version >= 2 else 'NOT RECORDED: historical schema 1 instrument evidence only',
            'scope': 'recorded observations and artifacts verified; this command executed no queries and establishes no reference-host target'}


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('directory', type=Path)
    parser.add_argument('--require-current-product',action='store_true'); args = parser.parse_args()
    try: result = verify(args.directory,args.require_current_product)
    except (OSError, ValueError, KeyError, TypeError) as error:
        result = {'status': 'FAIL', 'errors': ['missing/invalid evidence: ' + type(error).__name__]}
    print(json.dumps(result, indent=2))
    return int(result['status'] != 'PASS')


if __name__ == '__main__': raise SystemExit(main())
