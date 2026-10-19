"""Existing root owns preparation; Rust setup/build drop to the existing runner."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import signal
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
from kvm_pilot_common import require, write_json
from kvm_benchmark_pilot import owned_output
from kvm_reference_common import METHOD
from kvm_reference_budget import PROVISION_SECONDS
from inspect_reference_guest import TrialCommands, interrupted
from owned_process import LinuxOwnedChildren


def runner_prefix(account):
    home = PurePosixPath(account.pw_dir)
    require(type(account.pw_uid) is int and account.pw_uid > 0
        and type(account.pw_gid) is int and account.pw_gid > 0
        and home.is_absolute() and '..' not in home.parts
        and re.fullmatch('/[A-Za-z0-9_./-]+', str(home)), 'closed existing non-root runner identity/home required')
    return ['/usr/bin/setpriv', '--reuid=' + str(account.pw_uid), '--regid=' + str(account.pw_gid),
        '--clear-groups', '--', '/usr/bin/env', 'HOME=' + str(home), 'CARGO_HOME=' + str(home / '.cargo'),
        'RUSTUP_HOME=' + str(home / '.rustup'),
        'PATH=' + str(home / '.cargo/bin') + ':/usr/local/bin:/usr/bin:/bin']


def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--run-as', required=True)
    args = parser.parse_args(argv)
    if platform.system() != 'Linux' or not hasattr(os, 'geteuid') or os.geteuid() != 0:
        print(json.dumps({'status': 'BLOCKED', 'reason': 'requires existing Linux root lifecycle permission',
            'method': METHOD, 'reference_qualified': False})); return 77
    require(re.fullmatch('[a-z_][a-z0-9_-]{0,31}', args.run_as), 'closed existing runner name required')
    import pwd
    prefix = runner_prefix(pwd.getpwnam(args.run_as))
    os.environ.update(GIT_OPTIONAL_LOCKS='0', GIT_CONFIG_COUNT='1',
        GIT_CONFIG_KEY_0='safe.directory', GIT_CONFIG_VALUE_0=str(ROOT))
    out = owned_output(args.out); out.mkdir(exist_ok=False)
    started = time.monotonic(); deadline = started + PROVISION_SECONDS - 60
    ownership = LinuxOwnedChildren(); direct = TrialCommands(out, ownership)
    result = {'status': 'FAIL', 'method': METHOD, 'reference_qualified': False,
        'scope': 'Existing allocated runner only. No accounts, permissions, policy, purchases or billing are changed.'}
    for number in (signal.SIGTERM, signal.SIGINT): signal.signal(number, interrupted)
    def checked(name, command):
        remaining = deadline - time.monotonic(); require(remaining > 20, 'whole full-route preparation deadline exhausted')
        return direct(name, command, timeout=remaining)
    def budget():
        remaining = deadline - time.monotonic() - 15
        require(remaining > 0, 'no nested preparation budget remains'); return str(remaining)
    try:
        checked('system', ['/usr/bin/python3', str(ROOT / 'scripts/evidence.py'),
            '--out', str(ROOT / '.local-runs/kfull-system'), '--timeout', budget(), '--',
            'sh', '-eu', '-c', 'apt-get update && apt-get install --yes --no-install-recommends '
            'qemu-system-x86 qemu-utils cloud-image-utils gpg gpgv e2fsprogs'])
        checked('pinned-rust', [*prefix, '/usr/bin/python3', str(ROOT / 'scripts/evidence.py'),
            '--out', str(ROOT / '.local-runs/kfull-rust'), '--timeout', budget(), '--', 'make', 'bootstrap'])
        checked('release-build', [*prefix, '/usr/bin/python3', str(ROOT / 'scripts/evidence.py'),
            '--out', str(ROOT / '.local-runs/kfull-build-command'), '--timeout', budget(), '--',
            '/usr/bin/python3', str(ROOT / 'benchmarks/build.py'), '--out', str(ROOT / '.local-runs/kfull-build')])
        checked('owned-lifecycle', ['/usr/bin/python3', str(ROOT / 'scripts/evidence.py'),
            '--out', str(ROOT / '.local-runs/kfull-lifecycle-command'), '--timeout', budget(), '--',
            '/usr/bin/python3', str(ROOT / 'scripts/guest_trial_controls.py'), '--out', str(ROOT / '.local-runs/kfull-lifecycle')])
        require(time.monotonic() < deadline, 'full-route preparation overran its finite bound')
        result['status'] = 'PREPARED'
    except (Exception, KeyboardInterrupt) as error:
        result['failure'] = {'error': type(error).__name__, 'reason': str(error)[:2048]}
    finally:
        for number in (signal.SIGTERM, signal.SIGINT): signal.signal(number, signal.SIG_IGN)
        result['cleanup'] = ownership.finish(None)
        if result['cleanup']['status'] != 'PASS': result['status'] = 'FAIL'
        result['elapsed_seconds'] = time.monotonic() - started
        write_json(out / 'results.json', result)
    print(json.dumps(result)); return 0 if result['status'] == 'PREPARED' else 1


if __name__ == '__main__': raise SystemExit(main())
