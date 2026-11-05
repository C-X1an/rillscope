"""Install only host utilities in the already authorized ephemeral Linux job."""
import argparse
import json
import os
from pathlib import Path
import signal
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import canonical_reference_allocation as allocation
from canonical_reference_host_setup import actual_controller
from canonical_reference_reservation import fsync_directory
from inspect_reference_guest import TrialCommands, interrupted
from kvm_pilot_common import write_json
from owned_process import LinuxOwnedChildren
import archive_capture

PACKAGES = ('qemu-system-x86', 'qemu-utils', 'cloud-image-utils', 'gpg', 'gpgv', 'e2fsprogs', 'git')


def provision(out, budget_seconds):
    actual_controller()
    allocation.require(type(budget_seconds) is int and 1 <= budget_seconds <= 1800,
        'explicit finite original host-utility provision budget required')
    out = archive_capture.owned(out)
    allocation.require(out.parent.is_dir(), 'existing owned utility-output parent required')
    out.mkdir(mode=0o700, exist_ok=False)
    started = time.monotonic(); deadline = started + budget_seconds
    record = {'schema_version': 1, 'method': allocation.METHOD, 'status': 'FAIL',
        'started_monotonic_ns': int(started * 10**9), 'deadline_monotonic_ns': int(deadline * 10**9),
        'reference_qualified': False, 'first_party_build': 'NOT RUN',
        'scope': 'Existing scoped ephemeral Linux job only; no account, device permission, host feature, service policy or billing change.'}
    ownership = LinuxOwnedChildren(); direct = TrialCommands(out, ownership)
    previous = {number: signal.signal(number, interrupted) for number in (signal.SIGTERM, signal.SIGINT)}
    os.environ.update(DEBIAN_FRONTEND='noninteractive', PYTHONDONTWRITEBYTECODE='1',
        GIT_OPTIONAL_LOCKS='0', GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='safe.directory', GIT_CONFIG_VALUE_0=str(ROOT))
    def checked(name, command, limit):
        remaining = deadline - time.monotonic()
        allocation.require(remaining > 0, 'original host-utility provision deadline exhausted')
        return direct(name, command, timeout=min(limit, remaining))
    try:
        checked('apt-update', ['/usr/bin/apt-get', 'update'], 300)
        checked('apt-install', ['/usr/bin/apt-get', 'install', '--yes', '--no-install-recommends', *PACKAGES], 900)
        checked('package-versions', ['/usr/bin/dpkg-query', '-W', '-f=${Package}\t${Version}\n', *PACKAGES], 15)
        allocation.require(time.monotonic() < deadline, 'original utility preparation deadline exhausted')
        record['status'] = 'PREPARED HOST UTILITIES ONLY'
    except (Exception, KeyboardInterrupt) as error:
        record.update(status='FAIL', error=type(error).__name__, reason=str(error)[:2048])
    finally:
        for number in previous: signal.signal(number, signal.SIG_IGN)
        try:
            record['cleanup'] = ownership.finish(None)
            if record['cleanup']['status'] != 'PASS' or time.monotonic() >= deadline: record['status'] = 'FAIL'
            record.update(finished_monotonic_ns=time.monotonic_ns(), elapsed_seconds=time.monotonic() - started)
            write_json(out / 'provision-result.json', record); fsync_directory(out)
        finally:
            for number, handler in previous.items(): signal.signal(number, handler)
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--budget-seconds', type=int, required=True); args = parser.parse_args(argv)
    try:
        actual_controller()
        row = provision(args.out, args.budget_seconds); print(json.dumps(row, sort_keys=True))
        return 0 if row['status'] == 'PREPARED HOST UTILITIES ONLY' else 1
    except (Exception, KeyboardInterrupt) as error:
        print(json.dumps({'status': 'FAIL', 'error': type(error).__name__, 'reason': str(error)[:2048]})); return 77 if 'BLOCKED:' in str(error) else 1


if __name__ == '__main__': raise SystemExit(main())
