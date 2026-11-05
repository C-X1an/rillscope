"""Always-step recovery after the original root evidence owner has exited."""
import argparse
import json
import os
from pathlib import Path
import platform
import signal
import sys
import time

from evidence import source_identity
from kvm_pilot_common import RECOVERY_SECONDS, require, read_json, write_json
from kvm_benchmark_pilot import ROOT, owned_output, recover
from kvm_boot_recovery import recover_boot_logs
from inspect_reference_guest import TrialCommands, interrupted
from owned_process import LinuxOwnedChildren


def owner_stopped(receipt, out):
    require(receipt.get('cwd') == str(ROOT) and receipt.get('source_before') == source_identity(ROOT)
        and receipt.get('source_after_sha256') == receipt['source_before']['sha256'], 'original owner source/cwd differs')
    cleanup = receipt.get('process_cleanup', {})
    require(cleanup.get('status') == 'PASS' and cleanup.get('remaining_active_processes') == 0,
            'original root owner did not establish stopped descendants')
    command = receipt.get('command', [])
    require(len(command) >= 4 and (ROOT / command[1]).resolve() == ROOT / 'scripts/kvm_benchmark_pilot.py'
        and '--out' in command and owned_output(command[command.index('--out') + 1]) == out,
        'original owner command/output association differs')


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--owner-receipt', type=Path, required=True); args = parser.parse_args()
    if platform.system() != 'Linux' or not hasattr(os, 'geteuid') or os.geteuid() != 0:
        print(json.dumps({'status': 'BLOCKED', 'reason': 'requires existing Linux root permission',
            'reference_qualified': False})); return 77
    out = owned_output(args.out); owner_path = owned_output(args.owner_receipt)
    report = {'status': 'FAIL', 'reference_qualified': False, 'upstream_failure_preserved': True}
    ownership = None
    for number in (signal.SIGTERM, signal.SIGINT): signal.signal(number, interrupted)
    try:
        owner_stopped(read_json(owner_path, 8 * 1024**2), out)
        require((out / 'work.raw').is_file(), 'original owned work disk unavailable')
        original = out / 'artifact/recovery.json'
        if original.is_file() and read_json(original).get('status') == 'PASS':
            report.update(status='NOT NEEDED', reason='original stopped-disk recovery already passed')
        else:
            ownership = LinuxOwnedChildren()
            destination = out / 'artifact/after-owner-recovery'
            require(not destination.exists(), 'preserve earlier fallback recovery')
            destination.mkdir()
            deadline = time.monotonic() + RECOVERY_SECONDS
            original_boot = out / 'artifact/root-boot-recovery.json'
            if not original_boot.is_file() or read_json(original_boot).get('status') != 'COLLECTED':
                try:
                    report['boot_recovery'] = recover_boot_logs(out, TrialCommands(out / 'artifact', ownership),
                        min(deadline, time.monotonic() + 180), artifact=destination)
                except (Exception, KeyboardInterrupt) as error:
                    report['boot_recovery'] = {'status': 'FAIL', 'error': type(error).__name__, 'reason': str(error)[:1024]}
            result = recover(out, TrialCommands(out / 'artifact', ownership), deadline,
                             artifact=destination)
            report.update(status='RECORDED' if result['status'] == 'PASS' else 'FAIL', recovery=result)
    except (Exception, KeyboardInterrupt) as error:
        report.update(error=type(error).__name__, reason=str(error)[:2048])
    finally:
        for number in (signal.SIGTERM, signal.SIGINT): signal.signal(number, signal.SIG_IGN)
        cleanup = ownership.finish(None) if ownership else {'status': 'NOT LAUNCHED'}
        report['cleanup'] = cleanup
        if ownership and cleanup['status'] != 'PASS': report['status'] = 'FAIL'
    # Never rewrite original results or turn a failed owner receipt into PASS.
    write_json(out / 'artifact/always-recovery.json', report)
    print(json.dumps(report, indent=2)); return 0 if report['status'] in ('NOT NEEDED', 'RECORDED') else 1


if __name__ == '__main__': raise SystemExit(main())
