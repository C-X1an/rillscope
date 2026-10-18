#!/usr/bin/env python3
"""Mutate copied real observations; never create substitute timing samples."""
import argparse
import copy
import json
from pathlib import Path
import shutil
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('source', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--checker-root',type=Path,help='Explicit frozen checker source for a before-fix reproduction')
    parser.add_argument('--single-case-control',action='store_true',help='Use the first complete recorded case, retaining all its warmups/repetitions/modes; never a performance claim')
    args = parser.parse_args()
    checker = args.checker_root.resolve() if args.checker_root else Path(__file__).resolve().parents[1]
    sys.path[:0] = [str(checker / 'benchmarks'),str(checker / 'scripts')]
    from verify import verify
    from run import sha
    from capture_paths import case_folders
    if args.out.exists(): raise ValueError('preserve earlier control artifacts; output must be new')
    source_identity = sha(args.source / 'samples.jsonl')
    shutil.copytree(args.source, args.out)
    if args.single_case_control:
        manifest_path = args.out / 'manifest.json'; manifest = json.loads(manifest_path.read_bytes())
        result_path = args.out / 'results.json'; results = json.loads(result_path.read_bytes())
        first = results['summaries'][0]
        for name, field in (('samples.jsonl','samples_sha256'),('pair-verdicts.jsonl','pair_verdicts_sha256')):
            path = args.out / name
            selected = [line for line in path.read_text().splitlines()
                        if json.loads(line)['workload'] == first['workload']['id'] and json.loads(line)['seed'] == first['seed']]
            path.write_text('\n'.join(selected)+'\n',encoding='utf-8',newline='\n')
            results[field] = sha(path)
        manifest.update(profile='instrumentation-pilot',chosen_workloads=[first['workload']],seeds=[first['seed']],
                        expected_cases=1,expected_observations=105,
                        derivation='first complete actual case for artifact negative controls only; no performance/grid qualification')
        results.update(profile='instrumentation-pilot',summaries=[first],completed_cases=1,expected_cases=1,complete_grid=False,
                       independent_semantic_comparisons=first['independent_semantic_comparisons'],invalid_observations=first['invalid_observations'])
        manifest_path.write_text(json.dumps(manifest)); result_path.write_text(json.dumps(results))
    control_samples = sha(args.out / 'samples.jsonl')
    baseline = verify(args.out, require_current_product=True)
    result_path = args.out / 'results.json'
    original_results = result_path.read_bytes()
    results = json.loads(original_results)
    first = results['summaries'][0]
    manifest=json.loads((args.out/'manifest.json').read_bytes())
    case_path = args.out / case_folders(manifest)[first['workload']['id'],first['seed']] / 'summary.json'
    original_case = case_path.read_bytes()
    changed = copy.deepcopy(first)
    changed['workload']['id'] = 'incorrect-workload-label'
    changed['seed'] += 99
    changed['inputs'] = {}
    changed['input_identity_stable'] = False
    changed['warmup_observations'] = 0
    changed['measured_observations'] = 0
    case_path.write_text(json.dumps(changed))
    results['summaries'][0] = changed
    result_path.write_text(json.dumps(results))
    identity_mutant = verify(args.out, require_current_product=True)
    case_path.write_bytes(original_case)
    result_path.write_bytes(original_results)
    restored = verify(args.out, require_current_product=True)
    manifest_path = args.out / 'manifest.json'
    original_manifest = manifest_path.read_bytes()
    manifest = json.loads(original_manifest)
    manifest['schema_version'] = 1
    manifest_path.write_text(json.dumps(manifest))
    legacy_mutant = verify(args.out, require_current_product=True)
    manifest_path.write_bytes(original_manifest)
    final = verify(args.out, require_current_product=True)
    stable = source_identity == sha(args.source / 'samples.jsonl') and control_samples == sha(args.out / 'samples.jsonl')
    passed = (all(value['status'] == 'PASS' for value in (baseline, restored, final))
              and identity_mutant['status'] == 'FAIL' and legacy_mutant['status'] == 'FAIL' and stable)
    result = {'control':'reviewed-summary-identity-and-schema', 'status':'PASS' if passed else 'FAIL',
              'summary_identity_sequence':[baseline['status'], identity_mutant['status'], restored['status']],
              'schema_sequence':[restored['status'], legacy_mutant['status'], final['status']],
              'summary_identity_errors':identity_mutant['errors'], 'schema_errors':legacy_mutant['errors'],
              'original_samples_unchanged':stable,
              'checker_source_sha256':sha(checker / 'benchmarks/verify.py'),
              'selected_complete_case_control':args.single_case_control,
              'scope':'copied actual artifacts only; this control executes no product query and measures no latency'}
    (args.out / 'review-control.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return int(not passed)


if __name__ == '__main__':
    raise SystemExit(main())
