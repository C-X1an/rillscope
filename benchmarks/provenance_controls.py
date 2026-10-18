#!/usr/bin/env python3
"""Negative controls on a complete recorded case; no timing generation/rerun."""
import argparse
import copy
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('source',type=Path)
    parser.add_argument('--out',type=Path,required=True); parser.add_argument('--checker-root',type=Path,required=True)
    args = parser.parse_args(); source = args.source.resolve(); out = args.out.resolve(); checker = args.checker_root.resolve()
    if out.exists(): raise ValueError('new control destination required')
    sys.path[:0] = [str(checker / 'benchmarks'),str(checker / 'scripts')]
    from verify import verify
    from run import sha, summarize_case
    from capture_paths import case_folders
    original_source_sha = sha(source / 'samples.jsonl')
    shutil.copytree(source,out)
    manifest_path = out / 'manifest.json'; result_path = out / 'results.json'
    manifest = json.loads(manifest_path.read_bytes()); result = json.loads(result_path.read_bytes())
    first = result['summaries'][0]
    for name,field in (('samples.jsonl','samples_sha256'),('pair-verdicts.jsonl','pair_verdicts_sha256')):
        target = out / name
        selected = [line for line in target.read_text().splitlines() if json.loads(line)['workload'] == first['workload']['id'] and json.loads(line)['seed'] == first['seed']]
        target.write_text('\n'.join(selected)+'\n',encoding='utf-8',newline='\n'); result[field] = sha(target)
    manifest.update(profile='instrumentation-pilot',chosen_workloads=[first['workload']],seeds=[first['seed']],
                    expected_cases=1,expected_observations=105,derivation='all105 actual observations of first complete case; artifact control only')
    result.update(profile='instrumentation-pilot',summaries=[first],completed_cases=1,expected_cases=1,complete_grid=False,
                  independent_semantic_comparisons=first['independent_semantic_comparisons'],invalid_observations=first['invalid_observations'])
    manifest_path.write_text(json.dumps(manifest)); result_path.write_text(json.dumps(result))
    baseline = verify(out,require_current_product=True)
    preserved = {}
    def save(path):
        if path not in preserved: preserved[path] = path.read_bytes()
    def restore():
        for path,data in preserved.items(): path.write_bytes(data)
    checks = []
    build_path = out / 'build/build.json'
    for field,wrong in (('fresh_target_directory',False),('problems',['deliberate copied-artifact negative control'])):
        save(build_path); save(manifest_path)
        build = json.loads(build_path.read_bytes()); build[field] = wrong
        build_path.write_text(json.dumps(build)); altered = copy.deepcopy(manifest)
        altered.update(build=build,build_receipt_sha256=sha(build_path)); manifest_path.write_text(json.dumps(altered))
        mutant = verify(out,require_current_product=True); restore(); after = verify(out,require_current_product=True)
        checks.append({'field':field,'sequence':[baseline['status'],mutant['status'],after['status']], 'errors':mutant['errors']})
    save(out / 'samples.jsonl'); save(result_path)
    case = out / case_folders(manifest)[first['workload']['id'],first['seed']]
    summary_path = case / 'summary.json'; save(summary_path)
    rows = [json.loads(line) for line in (out / 'samples.jsonl').read_text().splitlines()]
    for row in rows:
        path = case / 'raw' / (row['phase'] + '-' + str(row['repetition']).zfill(2) + '-' + row['mode'] + '.process.json')
        save(path); usage = json.loads(path.read_bytes()); usage['cpu_user_ns'] = False
        path.write_text(json.dumps(usage)); row.update(cpu_user_ns=False,process_measurement_sha256=sha(path))
    (out / 'samples.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in rows),encoding='utf-8',newline='\n')
    altered = copy.deepcopy(result); altered['samples_sha256'] = sha(out / 'samples.jsonl')
    altered['summaries'][0]['metrics'] = summarize_case(rows)
    summary_path.write_text(json.dumps(altered['summaries'][0])); result_path.write_text(json.dumps(altered))
    mutant = verify(out,require_current_product=True); restore(); after = verify(out,require_current_product=True)
    checks.append({'field':'cpu_user_ns=False consistent sample/process/summary','sequence':[baseline['status'],mutant['status'],after['status']], 'errors':mutant['errors']})
    stable = original_source_sha == sha(source / 'samples.jsonl')
    passed = stable and all(item['sequence'] == ['PASS','FAIL','PASS'] for item in checks)
    report = {'status':'PASS' if passed else 'FAIL','control':'e7-build-and-process-provenance','checks':checks,
              'original_samples_unchanged':stable,'selected_complete_case_control':True,
              'checker_source_sha256':sha(checker / 'benchmarks/verify.py'),
              'scope':'copied105 actual records; mutations are negative controls, never measured performance'}
    (out / 'provenance-control.json').write_text(json.dumps(report,indent=2)+'\n'); print(json.dumps(report,indent=2)); return int(not passed)


if __name__ == '__main__': raise SystemExit(main())
