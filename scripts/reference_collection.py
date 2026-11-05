"""Collect the original full campaigns once; validate all records separately.

This is a T-061 collection entry point. It does not run or replace the later
canonical fresh-checkout recipe. A successful byte export is never a semantic
or dedicated-reference verdict. Failed commands and partial raw bytes remain.
"""
import os
from pathlib import Path
import platform
import signal
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from inspect_reference_guest import TrialCommands, interrupted, TrialInterrupted
from owned_process import LinuxOwnedChildren
from kvm_pilot_common import require, read_json, write_json
from kvm_pilot_guest import probe_identity, failed
from kvm_reference_common import METHOD, STAGES
from kvm_reference_budget import PACKAGE_SECONDS, GUEST_FINISH_SECONDS
from reference_capture_export import export_capture
import reference_measurement_barrier as measurement

BASE = ROOT / '.local-runs/kvm-reference'
INPUT = ROOT / '.local-runs/kvm-input/payload.json'


def remaining(deadline_ns):
    value = (deadline_ns - time.monotonic_ns()) / 10**9
    require(value > 0, 'original full collection budget exhausted; no retry or reduced scope')
    return value


def command_for(stage, payload, raw):
    require(stage in STAGES, 'closed original full collection stage required')
    if stage == 'cancel':
        command = ['/usr/bin/python3', str(ROOT / 'benchmarks/cancellation.py'), '--binary',
                   str(ROOT / payload['bins']['rillscope']['path'])]
    else:
        command = ['/usr/bin/python3', str(ROOT / 'benchmarks/run.py'), '--binary',
                   str(ROOT / payload['bins']['rillscope-measure']['path']), '--profile',
                   'full' if stage == 'grid' else 'sort-null-supplement']
    return command + ['--build-receipt', str(ROOT / payload['build_receipt']['path']), '--out', str(raw)]


def collect_stage(stage, payload, base, checked, deadline_ns):
    raw = base / 'raw' / stage; receipt = base / 'raw-receipts' / stage
    row = {'stage': stage, 'status': 'FAIL', 'method': METHOD, 'command_attempted': False,
        'package_status': 'MISSING RAW', 'all_record_validation': 'NOT RUN', 'reference_qualified': False}
    try:
        seconds = remaining(deadline_ns)
        command = ['/usr/bin/python3', str(ROOT / 'scripts/evidence.py'), '--out', str(receipt),
            '--timeout', str(seconds), '--input', str(INPUT)]
        for key in (measurement.CONFIG_PATH, 'RILLSCOPE_REFERENCE_EXPORT_CONFIG'):
            if key in os.environ: command += ['--input', os.environ[key]]
        command += ['--', *command_for(stage, payload, raw)]
        def original():
            row['command_attempted'] = True
            checked('campaign-' + stage, command, timeout=remaining(deadline_ns) + 10, inputs=(INPUT,))
            return 0
        code = measurement.collect(stage, original)
        proof = read_json(receipt / 'receipt.json')
        row['collection_exit_code'] = proof['exit_code']
        require(code == 0 and proof['verification_status'] == 'PASS' and proof['exit_code'] == 0
            and proof['source_before']['sha256'] == proof['source_after_sha256'] == payload['source']['sha256']
            and proof['process_cleanup']['status'] == 'PASS'
            and proof['process_cleanup']['remaining_active_processes'] == 0,
            'original full collection receipt failed or source/cleanup differs')
        row['status'] = 'COLLECTED'
    except (Exception, KeyboardInterrupt) as error:
        failed(row, 'collection', error)
    finally:
        # This independent retention attempt is made even after upstream FAIL.
        # Its reserve cannot make the original collection successful.
        if raw.is_dir():
            package = base / 'exports/packages' / stage
            try:
                seconds = min(PACKAGE_SECONDS, remaining(deadline_ns + GUEST_FINISH_SECONDS * 10**9))
                checked('pack-' + stage, ['/usr/bin/python3', str(ROOT / 'scripts/archive_capture.py'),
                    'pack', '--source', str(raw), '--out', str(package)], timeout=seconds)
                row['package_status'] = 'PACKED'
                row['host_transfer'] = export_capture(package / 'capture.zip', stage)
                require(row['host_transfer']['status'] == 'HOST ACKNOWLEDGED', 'actual full capture host ACK missing')
                row['package_status'] = 'HOST ACKNOWLEDGED'
            except (Exception, KeyboardInterrupt) as error:
                failed(row, 'pack-or-transfer', error)
        if row['package_status'] != 'HOST ACKNOWLEDGED': row['status'] = 'FAIL'
        write_json(base / ('exports/stage-' + stage + '.json'), row)
    return row


def main():
    if (platform.system() != 'Linux' or not hasattr(os, 'geteuid') or os.geteuid() != 65534
        or ROOT != Path('/work/c') or not Path('/run/rillscope-owned-reference').is_file()
        or Path('/run/rillscope-owned-reference').read_text().strip() != 'owned-ephemeral-full-collection'):
        print('BLOCKED: requires the owned ephemeral full guest and existing nobody identity'); return 77
    config = measurement.configuration()
    require(config is not None, 'source-bound original measurement config required')
    payload = read_json(INPUT)
    require(payload.get('mode') == METHOD and payload.get('reference_qualified') is False,
            'original full payload required')
    probe_identity(payload)
    # Leave a real finish reserve inside the root owner's live deadline.
    deadline_ns = config['value']['deadline_monotonic_ns'] - GUEST_FINISH_SECONDS * 10**9
    remaining(deadline_ns)
    for number in (signal.SIGTERM, signal.SIGINT): signal.signal(number, interrupted)
    ownership = LinuxOwnedChildren(); checked = TrialCommands(BASE, ownership)
    result = {'status': 'FAIL', 'method': METHOD, 'campaigns': [], 'all_record_validation': 'NOT RUN',
        'reference_qualified': False, 'canonical_fresh': 'NOT RUN',
        'scope': 'Original full grid, cancellation and NULL supplement collection only; no implicit reruns, '
                 'dedicated reference or canonical fresh-checkout qualification'}
    try:
        for stage in STAGES:
            record = collect_stage(stage, payload, BASE, checked, deadline_ns)
            result['campaigns'].append(record)
            write_json(BASE / 'exports/collection-result.json', result)
            # Original semantic failures remain FAIL but permit later diagnostic
            # campaigns once. Interrupted ownership/retention stops the attempt.
            if record.get('interrupted') or record['package_status'] != 'HOST ACKNOWLEDGED': break
            remaining(deadline_ns)
        if [r['stage'] for r in result['campaigns']] == list(STAGES) and all(
                r['status'] == 'COLLECTED' for r in result['campaigns']): result['status'] = 'COLLECTED'
    except (Exception, KeyboardInterrupt) as error:
        failed(result, 'full-collection', error)
    finally:
        for number in (signal.SIGTERM, signal.SIGINT): signal.signal(number, signal.SIG_IGN)
        result['cleanup'] = ownership.finish(None)
        if result['cleanup']['status'] != 'PASS': result['status'] = 'FAIL'
        write_json(BASE / 'exports/collection-result.json', result)
    return 0 if result['status'] == 'COLLECTED' else 1


if __name__ == '__main__': raise SystemExit(main())
