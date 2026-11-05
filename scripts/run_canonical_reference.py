"""Collect one original native canonical attempt; qualification is a later gate.

Every required product command stays in the unchanged clean recipe. This owner
does not infer provider fit or turn retained/failed bytes into benchmark PASS.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import archive_capture
import canonical_reference_allocation as allocation
from canonical_reference_boot import parse_boot, validate_footer
from canonical_reference_host import run_vm
from canonical_reference_host_setup import actual_controller, prepare
from canonical_reference_recovery import recover
from canonical_reference_reservation import source_check, fsync_directory
from inspect_reference_guest import TrialCommands, interrupted, bounded_bytes, SERIAL_LIMIT
from kvm_pilot_common import write_json, sha
from kvm_reference_common import strict_json
from owned_process import LinuxOwnedChildren
from prepare_canonical_reference import provision

FIELDS = {'schema_version', 'method', 'mode', 'commit', 'source_sha256', 'provision_seconds',
    'prepare_seconds', 'vm_seconds', 'guest_setup_seconds', 'guest_tail_seconds',
    'guest_retention_seconds', 'recovery_seconds', 'cleanup_reserve_seconds', 'whole_seconds'}
MAX_CONFIG_BYTES = 16384


def validate_plan(plan):
    allocation.require(type(plan) is dict and set(plan) == FIELDS and type(plan['schema_version']) is int
        and plan['schema_version'] == 1 and plan['method'] == allocation.METHOD and plan['mode'] == 'canonical'
        and allocation.hex_value(plan['commit'], 40) and allocation.hex_value(plan['source_sha256'], 64),
        'closed source-bound canonical collection plan required')
    limits = {'provision_seconds': (1, 900), 'prepare_seconds': (1, 1800), 'vm_seconds': (18000, 21600),
        'guest_setup_seconds': (1, 3600), 'guest_tail_seconds': (1, 600), 'guest_retention_seconds': (1, 600),
        'recovery_seconds': (1, 1800), 'cleanup_reserve_seconds': (120, 600), 'whole_seconds': (1, 21600)}
    for name, (minimum, maximum) in limits.items():
        allocation.require(type(plan[name]) is int and minimum <= plan[name] <= maximum,
            'explicit finite canonical plan bound differs: ' + name)
    sequential = sum(plan[name] for name in ('provision_seconds', 'prepare_seconds', 'vm_seconds',
        'recovery_seconds', 'cleanup_reserve_seconds'))
    allocation.require(sequential + 60 <= plan['whole_seconds'], 'declared whole owner leaves no original control overhead')
    allocation.require(plan['guest_setup_seconds'] + plan['guest_tail_seconds']
        + plan['guest_retention_seconds'] + 660 < plan['vm_seconds'], 'original VM leaves no canonical command budget')
    return plan


def check_collected(root, result, recovery, seed):
    """Require actual producer completion; every raw/all-record check remains later."""
    allocation.require(type(result) is dict and result.get('status') == 'CAPTURED' and result.get('failure') is None
        and type(result.get('qemu_exit_observed_before_owned_stop')) is int
        and result['qemu_exit_observed_before_owned_stop'] == 0
        and type(result.get('qemu_exit_observed_monotonic_ns')) is int
        and type(result.get('started_monotonic_ns')) is int and type(result.get('deadline_monotonic_ns')) is int
        and result['started_monotonic_ns'] < result['qemu_exit_observed_monotonic_ns'] < result['deadline_monotonic_ns'],
        'original canonical VM producer did not complete inside its original cutoff')
    allocation.require(type(recovery) is dict and recovery.get('status') == 'RECOVERED INCLUDED BYTES'
        and recovery.get('disk_unchanged') is True and recovery.get('filesystem_clean') is True,
        'complete unchanged stopped canonical recovery required')
    footer = parse_boot(bounded_bytes(root / 'vm/artifact/serial.txt', SERIAL_LIMIT).decode('utf-8'))
    validate_footer(footer)
    allocation.require(footer['status'] == 'PASS' and footer['mode'] == 'canonical'
        and footer['commit'] == seed['commit'] and footer['source_sha256'] == seed['source_sha256']
        and footer['seed_sha256'] == sha(root / 'vm/preparation/seed.json')
        and footer['unmount_status'] == 'PASS' and type(footer['worker_exit']) is int and footer['worker_exit'] == 0,
        'actual final source-bound canonical boot/unmount footer required')
    owners = [row for row in recovery.get('trees', []) if row.get('name') == 'owner']
    allocation.require(len(owners) == 1 and owners[0].get('status') == 'RECOVERED INCLUDED BYTES',
        'one original recovered canonical owner required')
    owner_path = archive_capture.owned(root / 'vm/artifact' / owners[0]['host_path'] / 'owner-result.json')
    allocation.require(owner_path.is_relative_to(root / 'vm/artifact') and owner_path.stat().st_size <= 4 * 1024**2,
        'bounded original canonical owner record required')
    owner = strict_json(owner_path.read_bytes())
    allocation.require(owner.get('status') == 'PASS' and owner.get('commit') == seed['commit']
        and owner.get('source_sha256') == seed['source_sha256']
        and owner.get('canonical_records', {}).get('status') == 'RECORDED CANONICAL PASS'
        and owner['canonical_records'].get('gates') == 18
        and owner.get('native_retention', {}).get('status') == 'RETAINED'
        and owner.get('retention') == 'RETAINED',
        'original unchanged fresh recipe/native retention failed; diagnostics cannot replace it')
    return {'footer': footer, 'owner_sha256': sha(owner_path), 'scope':
        'Producer completion only; this does not revalidate every original fresh receipt, native binary, resource sample or benchmark observation.'}


def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True); parser.add_argument('--run-as', required=True)
    args = parser.parse_args(argv)
    try: actual_controller()
    except ValueError as error: print(str(error)); return 77
    config, out = map(archive_capture.owned, (args.config, args.out))
    allocation.require(config.is_file() and config.stat().st_size <= MAX_CONFIG_BYTES
        and not out.exists() and out.parent.is_dir() and not config.is_relative_to(out),
        'bounded original plan and new separate owned output required')
    raw = config.read_bytes(); plan = validate_plan(strict_json(raw))
    source_check(plan['commit'], plan['source_sha256'])
    started = time.monotonic(); deadline = started + plan['whole_seconds']; ownership = None
    out.mkdir(mode=0o755); (out / 'declared-plan.json').write_bytes(raw); fsync_directory(out)
    record = {'schema_version': 1, 'method': allocation.METHOD, 'mode': 'canonical', 'status': 'FAIL',
        'commit': plan['commit'], 'source_sha256': plan['source_sha256'], 'plan_sha256': hashlib.sha256(raw).hexdigest(),
        'started_monotonic_ns': int(started * 10**9), 'deadline_monotonic_ns': int(deadline * 10**9),
        'reference_qualified': False, 'all_record_validation': 'NOT RUN', 'provider_fit': 'NOT ESTABLISHED',
        'scope': 'One original unchanged native clean recipe/VM collection. Terminal owner/source/raw/all-record validation is mandatory after this process exits.'}
    def reserve(*names):
        allocation.require(time.monotonic() + sum(plan[name] for name in names) < deadline,
            'original whole owner cannot fit its remaining declared stages; no stage budget is shortened')
    previous = {number: signal.signal(number, interrupted) for number in (signal.SIGTERM, signal.SIGINT)}
    try:
        reserve('provision_seconds', 'prepare_seconds', 'vm_seconds', 'recovery_seconds', 'cleanup_reserve_seconds')
        record['host_utilities'] = provision(out / 'utilities', plan['provision_seconds'])
        allocation.require(record['host_utilities']['status'] == 'PREPARED HOST UTILITIES ONLY', 'host prerequisites failed')
        reserve('prepare_seconds', 'vm_seconds', 'recovery_seconds', 'cleanup_reserve_seconds')
        vm = out / 'vm'; vm.mkdir(mode=0o755); ownership = LinuxOwnedChildren()
        prepared = prepare(vm, commit=plan['commit'], source_sha256=plan['source_sha256'], run_as=args.run_as,
            host_seconds=plan['prepare_seconds'], guest_setup_seconds=plan['guest_setup_seconds'],
            tail_seconds=plan['guest_tail_seconds'], retention_seconds=plan['guest_retention_seconds'],
            mode='canonical', ownership=ownership)
        reserve('vm_seconds', 'recovery_seconds', 'cleanup_reserve_seconds')
        original = {}
        result = run_vm(vm, image=prepared['image'], run_as=args.run_as, port=prepared['port'],
            commit=plan['commit'], source_sha256=plan['source_sha256'], vm_seconds=plan['vm_seconds'],
            setup_seconds=plan['guest_setup_seconds'], ownership=ownership, execution=original)
        record['vm'] = result
        if original.get('process') is not None and result['cleanup']['status'] == 'PASS':
            direct = TrialCommands(vm / 'preparation', ownership)
            recovery_started = time.monotonic()
            declared_recovery_end = recovery_started + plan['recovery_seconds']
            preservation_end = min(deadline - plan['cleanup_reserve_seconds'], declared_recovery_end)
            full_recovery_budget = declared_recovery_end < deadline - plan['cleanup_reserve_seconds']
            record['recovery_budget'] = {'status': 'DECLARED BUDGET AVAILABLE' if full_recovery_budget else 'FAIL',
                'declared_seconds': plan['recovery_seconds'],
                'available_preservation_seconds': max(0, preservation_end - recovery_started),
                'started_monotonic_ns': int(recovery_started * 10**9),
                'declared_deadline_monotonic_ns': int(declared_recovery_end * 10**9),
                'actual_deadline_monotonic_ns': int(preservation_end * 10**9),
                'scope': 'A shorter remaining cutoff preserves failed-prefix bytes only; it cannot satisfy the declared collection budget.'}
            allocation.require(preservation_end > recovery_started, 'original failed-prefix preservation reserve exhausted')
            record['recovery'] = recover(vm, process=original['process'], command=original['command'],
                channel=original['channel'], cleanup=result['cleanup'], mode='canonical',
                deadline=preservation_end, checked=direct)
            record['recovery_budget']['completed_monotonic_ns'] = time.monotonic_ns()
            allocation.require(record['recovery_budget']['completed_monotonic_ns'] < int(preservation_end * 10**9),
                'original recovery cutoff exhausted before helper return; completed collection is unavailable')
            allocation.require(full_recovery_budget,
                'full declared recovery budget no longer fits; shorter failed-prefix preservation cannot qualify collection')
        record['collected'] = check_collected(out, result, record.get('recovery', {}), prepared['seed'])
        source_check(plan['commit'], plan['source_sha256'])
        allocation.require(config.read_bytes() == raw, 'original declared plan changed during execution')
        record['status'] = 'COLLECTED CANONICAL ATTEMPT'
    except (Exception, KeyboardInterrupt) as error:
        record.update(status='FAIL', error=type(error).__name__, reason=str(error)[:2048])
    finally:
        for number in previous: signal.signal(number, signal.SIG_IGN)
        try:
            if ownership is not None:
                record['cleanup'] = ownership.finish(None)
                if record['cleanup']['status'] != 'PASS': record['status'] = 'FAIL'
            record.update(finished_monotonic_ns=time.monotonic_ns(), elapsed_seconds=time.monotonic() - started)
            if time.monotonic() >= deadline: record.update(status='FAIL', reason='original whole canonical owner deadline exhausted')
            write_json(out / 'driver-result.json', record); fsync_directory(out)
            # Observe after actual result persistence, using the same original
            # cutoff. A failed-prefix preservation write can never repair it.
            record.update(result_persistence_completed_monotonic_ns=time.monotonic_ns(),
                finished_monotonic_ns=time.monotonic_ns(), elapsed_seconds=time.monotonic() - started)
            if time.monotonic() >= deadline:
                record.update(status='FAIL', reason='original whole canonical owner deadline exhausted during result persistence')
            write_json(out / 'driver-result.json', record); fsync_directory(out)
            if time.monotonic() >= deadline and record['status'] != 'FAIL':
                record.update(status='FAIL', finished_monotonic_ns=time.monotonic_ns(),
                    elapsed_seconds=time.monotonic() - started,
                    reason='original whole canonical owner deadline exhausted during terminal persistence')
                write_json(out / 'driver-result.json', record); fsync_directory(out)
        finally:
            for number, handler in previous.items(): signal.signal(number, handler)
    print(json.dumps({'status': record['status'], 'reference_qualified': False,
        'all_record_validation': 'NOT RUN', 'provider_fit': 'NOT ESTABLISHED'}, sort_keys=True))
    if time.monotonic() >= deadline and record['status'] != 'FAIL':
        record.update(status='FAIL', finished_monotonic_ns=time.monotonic_ns(),
            elapsed_seconds=time.monotonic() - started,
            reason='original whole canonical owner deadline exhausted before return')
        write_json(out / 'driver-result.json', record); fsync_directory(out)
    return 0 if record['status'] == 'COLLECTED CANONICAL ATTEMPT' else 1


if __name__ == '__main__': raise SystemExit(main())
