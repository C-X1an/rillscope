#!/usr/bin/env python3
"""Fail narrowly until an actual dedicated reference host has been established."""
import argparse
import hashlib
import json
import platform
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'benchmarks'))
sys.path.insert(0, str(ROOT / 'scripts'))
from run import environment
from build import build_release
import archive_capture
import reference_capture_export
import reference_measurement_barrier as measurement
from verify_sequence import write_json


def retain_capture(out,stage,*,export_stage=None):
    """Retain every available raw file before starting the lengthy validator."""
    try:
        result=archive_capture.pack(out/stage,out/('capture-'+stage))
        if result['status']=='RECORDED':
            exported=reference_capture_export.export_capture(out/('capture-'+stage)/'capture.zip',
                stage if export_stage is None else export_stage)
            result['host_export']=exported
            if exported['status'] not in {'NOT REQUESTED','HOST ACKNOWLEDGED'}:
                result.update(pack_status='RECORDED',status='FAIL')
    except (OSError,ValueError,TypeError,KeyError) as error:
        result={'status':'FAIL','error':type(error).__name__,'reason':str(error)}
    write_json(out/('retention-'+stage+'.json'),result)
    print(json.dumps({'retained_stage':stage,**result}),flush=True)
    return 0 if result['status']=='RECORDED' else (77 if result['status']=='BLOCKED' else 1)


def host_reasons(actual, receipt):
    reasons = []
    if actual['system'] != 'Linux': reasons.append('actual Linux runtime unavailable on this host')
    if actual['machine'].lower() not in ('x86_64', 'amd64'): reasons.append('actual reference architecture is not x86_64')
    if actual['system'] == 'Linux':
        if actual.get('resource_inspection_status') != 'MEASURED': reasons.append('effective Linux CPU/memory restrictions have not been measured')
        elif actual.get('effective_cpu_capacity') != 4 or actual.get('process_affinity_cpu_count') != 4:
            reasons.append('effective Linux CPU capacity/affinity is not four')
        limit = actual.get('cgroup_memory_limit_bytes')
        if limit is not None and limit < 7.5 * 1024**3: reasons.append('effective cgroup memory is below the reference configuration')
        high = actual.get('cgroup_memory_high_bytes')
        if high is not None and high < 7.5 * 1024**3: reasons.append('effective cgroup memory throttle is below the reference configuration')
    if receipt is None: return reasons + ['dedicated 4-core/8-GiB reference host allocation has not been evidenced']
    if receipt.get('source') != 'actual host allocation and inspection' or receipt.get('dedicated') is not True:
        reasons.append('reference receipt does not establish dedicated allocation')
    if receipt.get('logical_processors') != 4 or actual['logical_processors'] != 4:
        reasons.append('actual/reference CPU count is not four')
    memory = actual.get('physical_memory_bytes')
    if memory is None or not 7.5 * 1024**3 <= memory <= 8.5 * 1024**3:
        reasons.append('actual/reference memory is not the documented 8-GiB configuration')
    if receipt.get('cpu_model') != actual.get('cpu_model'): reasons.append('reference receipt does not match actual CPU')
    if receipt.get('machine', '').lower() != actual['machine'].lower(): reasons.append('reference receipt architecture differs from actual host')
    return reasons


def allocation_binding_errors(actual, receipt):
    # Existing operator receipts retain their documented hardware checks.
    # New structured receipts must also satisfy their current identity/lease.
    structured = {'method', 'operator_allocation', 'actual_environment', 'actual_source',
        'actual_boot_id', 'preflight_monotonic_ns', 'operator_document_sha256',
        'allocation_evidence_sha256', 'allocation_evidence_bytes', 'inputs_and_source_stable'}
    if type(receipt) is not dict or not (structured & set(receipt)):
        return []
    from reference_allocation import binding_errors
    return binding_errors(receipt, actual)


def experiment_environment_errors(preflight, receipt, observations):
    expected = {'grid-start','grid-end','cancellation-start','cancellation-end','wrapper-end'}
    errors = []
    if set(observations) != expected: errors.append('complete experiment environment snapshots missing')
    fields = ('system','machine','logical_processors','cpu_model','physical_memory_bytes',
              'resource_inspection_status','effective_cpu_capacity','process_affinity_cpu_count',
              'cgroup_memory_limit_bytes','cgroup_memory_high_bytes')
    for name, actual in observations.items():
        if not isinstance(actual,dict):
            errors.append('actual experiment environment missing: ' + name); continue
        if any(key not in actual for key in fields):
            errors.append('actual experiment environment incomplete: ' + name); continue
        errors.extend(name + ': ' + reason for reason in host_reasons(actual,receipt))
        if any(actual.get(key) != preflight.get(key) for key in fields):
            errors.append('actual experiment allocation differs from preflight: ' + name)
    if isinstance(observations.get('wrapper-end'), dict):
        errors.extend(allocation_binding_errors(observations['wrapper-end'], receipt))
    return errors


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--host-receipt', type=Path)
    args = parser.parse_args()
    actual = environment()
    receipt_bytes = receipt = None
    parse_errors = []
    if args.host_receipt is not None:
        from reference_allocation import read_bounded, decode_document, DOCUMENT_LIMIT
        try:
            receipt_bytes = read_bounded(args.host_receipt, DOCUMENT_LIMIT)
            receipt = decode_document(receipt_bytes)
            if type(receipt) is not dict:
                raise ValueError('allocation receipt must be an object')
        except (OSError, ValueError, UnicodeError) as error:
            receipt = None
            parse_errors.append('invalid allocation receipt: ' + type(error).__name__ + ': ' + str(error)[:1024])
    reasons = host_reasons(actual, receipt) + parse_errors + allocation_binding_errors(actual, receipt)
    args.out.mkdir(parents=True, exist_ok=False)
    record = {'gate': 'benchmark', 'status': 'BLOCKED' if reasons else 'READY', 'actual_environment': actual,
              'allocation_receipt_sha256': None if receipt_bytes is None else hashlib.sha256(receipt_bytes).hexdigest(),
              'allocation_fields': None if receipt is None else {key: receipt.get(key) for key in ('source', 'dedicated', 'logical_processors', 'machine', 'cpu_model')},
              'reasons': reasons, 'local_work': 'make benchmark-local executes the complete available grid without reference-target claims'}
    (args.out / 'reference-preflight.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(record, indent=2), flush=True)
    if reasons: return 77
    build = build_release(args.out / 'build')
    proof = args.out / 'build/build.json'
    code = measurement.collect('grid', lambda: subprocess.call([sys.executable, str(ROOT / 'benchmarks/run.py'), '--binary', str(ROOT / build['bins']['rillscope-measure']['path']),
                            '--build-receipt', str(proof), '--out', str(args.out / 'grid')], cwd=ROOT))
    retained=retain_capture(args.out,'grid')
    if code: return code
    if retained: return retained
    code = measurement.collect('cancel', lambda: subprocess.call([sys.executable, str(ROOT / 'benchmarks/cancellation.py'), '--binary', str(ROOT / build['bins']['rillscope']['path']),
                            '--build-receipt', str(proof), '--out', str(args.out / 'cancel')], cwd=ROOT))
    retained=retain_capture(args.out,'cancel')
    if code: return code
    if retained: return retained
    code = subprocess.call([sys.executable, str(ROOT / 'benchmarks/verify.py'), str(args.out / 'grid'),'--require-current-product'], cwd=ROOT)
    if code: return code
    grid = json.loads((args.out / 'grid/results.json').read_bytes())
    targets = []
    for row in grid['summaries']:
        if row['workload']['id'] != 'B01-n100000-s10-null10-b1024': continue
        measured = row['metrics']['rust-on']
        latency = measured['success_only_execution_ns']
        if latency.get('n') != 30 or row.get('independent_semantic_comparisons') != 60:
            raise ValueError('reference target has no complete valid execution distribution; no speed target verdict exists')
        targets.append({'seed': row['seed'], 'execution_ns': latency,
                        'independent_semantic_comparisons':row['independent_semantic_comparisons'],
                        'end_to_end_ns': measured['all_outcome_metrics']['wall_ns'],
                        'target_status': 'MET' if latency['p95'] < 1000000000 else 'MISSED'})
    cancellation = json.loads((args.out / 'cancel/results.json').read_bytes())
    from cancellation import verify_cancellation
    cancellation_check = verify_cancellation(args.out / 'cancel')
    if cancellation_check['status'] != 'PASS': raise ValueError('cancellation artifacts do not validate')
    experiment_environments = {
        'grid-start':json.loads((args.out / 'grid/manifest.json').read_bytes()).get('environment'),
        'grid-end':grid.get('environment_after'),
        'cancellation-start':json.loads((args.out / 'cancel/manifest.json').read_bytes()).get('environment'),
        'cancellation-end':cancellation.get('environment_after'), 'wrapper-end':environment()}
    environment_errors = experiment_environment_errors(actual,receipt,experiment_environments)
    cancel_target = 'MET' if cancellation['measured_observations'] == 150 and cancellation['target_observations_over_100ms'] == 0 else 'MISSED'
    stable_receipt = args.host_receipt is not None and args.host_receipt.read_bytes() == receipt_bytes
    report = {'reference_host_preflight': record, 'filter_project_target_by_seed': targets,
              'cancellation': cancellation, 'cancellation_reference_target': {'status': cancel_target, 'definition': 'all 150 measured signal-to-exit upper bounds <=100ms; misses retained'},
              'allocation_receipt_stable': stable_receipt,
              'experiment_environment_errors':environment_errors,
              'experiment_environments':experiment_environments,
              'status': 'PASS' if len(targets) == 5 and stable_receipt and not environment_errors else 'FAIL',
              'meaning': 'targets reported as met or missed; a speed target miss is retained, not a correctness waiver'}
    (args.out / 'reference-results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__': raise SystemExit(main())
