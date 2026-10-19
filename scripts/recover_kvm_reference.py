"""One finite fallback recovery after the exact original owner has stopped."""
import argparse
import json
import os
from pathlib import Path
import platform
import signal
import time

from evidence import source_identity
from kvm_pilot_common import require, read_json, write_json
from kvm_benchmark_pilot import ROOT, owned_output
from kvm_reference_common import METHOD
from kvm_reference_recovery import recover
from kvm_boot_recovery import recover_boot_logs
from inspect_reference_guest import TrialCommands, interrupted
from owned_process import LinuxOwnedChildren


def owner_stopped(receipt, out):
    require(receipt.get('cwd') == str(ROOT) and receipt.get('source_before') == source_identity(ROOT)
        and receipt.get('source_after_sha256') == receipt['source_before']['sha256'], 'original full owner source/cwd differs')
    cleanup = receipt.get('process_cleanup', {})
    require(cleanup.get('status') == 'PASS' and cleanup.get('remaining_active_processes') == 0,
            'original full owner did not establish stopped descendants')
    command = receipt.get('command', [])
    require(len(command) >= 4 and (ROOT / command[1]).resolve() == ROOT / 'scripts/kvm_reference_host.py'
        and command.count('--out') == 1 and owned_output(command[command.index('--out') + 1]) == out,
        'original full owner command/output association differs')


def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--owner-receipt', type=Path, required=True); args = parser.parse_args(argv)
    if platform.system() != 'Linux' or not hasattr(os, 'geteuid') or os.geteuid() != 0:
        print(json.dumps({'status': 'BLOCKED', 'reason': 'requires existing Linux root permission',
            'method': METHOD, 'reference_qualified': False})); return 77
    out = owned_output(args.out); owner = owned_output(args.owner_receipt)
    report = {'status': 'FAIL', 'method': METHOD, 'reference_qualified': False, 'upstream_failure_preserved': True}
    ownership = None
    for number in (signal.SIGTERM, signal.SIGINT): signal.signal(number, interrupted)
    try:
        owner_stopped(read_json(owner, 8 * 1024**2), out)
        require((out / 'work.raw').is_file(), 'original full work disk unavailable')
        original = out / 'artifact/recovery.json'
        if original.is_file() and read_json(original).get('status') == 'PASS':
            report.update(status='NOT NEEDED', reason='original stopped full recovery already passed')
        else:
            ownership = LinuxOwnedChildren(); destination = out / 'artifact/after-owner-recovery'
            destination.mkdir(exist_ok=False)
            deadline = time.monotonic() + 510  # inside the540s outer and10min action reserve
            checked = TrialCommands(destination, ownership)
            try: report['boot_recovery'] = recover_boot_logs(out, checked, min(deadline, time.monotonic() + 120), artifact=destination)
            except (Exception, KeyboardInterrupt) as error: report['boot_recovery'] = {'status': 'FAIL', 'error': type(error).__name__}
            report['recovery'] = recover(out, checked, deadline, artifact=destination)
            report['status'] = 'RECORDED' if report['recovery']['status'] == 'PASS' else 'FAIL'
    except (Exception, KeyboardInterrupt) as error:
        report.update(error=type(error).__name__, reason=str(error)[:2048])
    finally:
        for number in (signal.SIGTERM, signal.SIGINT): signal.signal(number, signal.SIG_IGN)
        report['cleanup'] = ownership.finish(None) if ownership else {'status': 'NOT LAUNCHED'}
        if ownership and report['cleanup']['status'] != 'PASS': report['status'] = 'FAIL'
    # Recovery never rewrites original collection, owner or receiver results.
    write_json(out / 'artifact/always-recovery.json', report)
    print(json.dumps(report, indent=2)); return 0 if report['status'] in {'NOT NEEDED', 'RECORDED'} else 1


if __name__ == '__main__': raise SystemExit(main())
