"""Measure actual native setup separately; never run or qualify canonical work."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import archive_capture
import canonical_reference_allocation as allocation
from canonical_reference_boot import parse_boot, validate_footer, BOOT_PREFIX
from canonical_reference_host import snapshot_before_cutoff
from canonical_reference_host_setup import actual_controller, prepare
from canonical_reference_recovery import recover
from canonical_reference_reservation import source_check, fsync_directory
from canonical_reference_seed import validate_seed
from canonical_reference_guest_setup import check_rust_versions
from evidence import source_identity, verify_receipt
from inspect_reference_guest import BoundedCapture, TrialCommands, interrupted, SERIAL_LIMIT, bounded_bytes
from kvm_pilot_common import write_json, append_json, sha
from kvm_reference_common import strict_json
from kvm_reference_host import check_sample, stop_vm
from owned_process import LinuxOwnedChildren
from prepare_canonical_reference import provision

PROVISION_SECONDS = 900
HOST_PREP_SECONDS = 600
GUEST_SETUP_SECONDS = 3000
VM_SECONDS = GUEST_SETUP_SECONDS + 180
RECOVERY_SECONDS = 600
CLEANUP_RESERVE_SECONDS = 120
TOTAL_SECONDS = 6000


def version_observations(setup_tree, *, commit, source_sha256, seed_sha256):
    home = '/work/c/.local-runs/canonical-home'
    prefix = ['/usr/bin/setpriv', '--reuid=65534', '--regid=65534', '--clear-groups', '--',
        '/usr/bin/env', 'HOME=' + home, 'CARGO_HOME=' + home + '/.cargo', 'RUSTUP_HOME=' + home + '/.rustup',
        'CARGO_INCREMENTAL=0', 'PATH=' + home + '/.cargo/bin:/usr/bin:/bin', 'GIT_OPTIONAL_LOCKS=0',
        'GIT_CONFIG_COUNT=1', 'GIT_CONFIG_KEY_0=safe.directory', 'GIT_CONFIG_VALUE_0=/work/c', 'PYTHONDONTWRITEBYTECODE=1']
    outputs = []
    for name, command in [('rustup-version', ['rustup', '--version']), ('rustc-version', ['rustc', '-vV']),
        ('cargo-version', ['cargo', '--version']), ('audit-version', ['cargo', 'audit', '--version']),
        ('deny-version', ['cargo', 'deny', '--version'])]:
        directory = archive_capture.owned(Path(setup_tree) / 'commands' / name)
        receipt = directory / 'receipt.json'
        allocation.require(receipt.is_file() and receipt.stat().st_size <= 1024**2,
            'bounded actual native version receipt required')
        row = strict_json(receipt.read_bytes())
        allocation.require(row.get('command') == prefix + command and row.get('cwd') == '/work/c'
            and row.get('verification_status') == 'PASS' and type(row.get('exit_code')) is int and row['exit_code'] == 0
            and row.get('execution_outcome') == 'EXECUTED'
            and row.get('source_before', {}).get('sha256') == source_sha256
            and row.get('source_after_sha256') == source_sha256
            and row.get('git', {}).get('commit') == commit and row['git'].get('dirty') is False
            and row.get('process_cleanup', {}).get('status') == 'PASS'
            and type(row['process_cleanup'].get('remaining_active_processes')) is int
            and row['process_cleanup']['remaining_active_processes'] == 0,
            'actual original native command/source/nonroot identity or cleanup differs')
        inputs = row.get('inputs_before')
        allocation.require(type(inputs) is list and len(inputs) == 1 and row.get('inputs_after') == inputs
            and inputs[0].get('path') == '/work/c/.local-runs/canonical-seed/seed.json'
            and inputs[0].get('sha256') == seed_sha256, 'original native version seed binding differs')
        for stream in ('stdout', 'stderr'):
            allocation.require(row.get(stream, {}).get('file') == stream + '.txt'
                and (directory / (stream + '.txt')).is_file()
                and (directory / (stream + '.txt')).stat().st_size <= 16384,
                'bounded original native version raw stream required')
        allocation.require(verify_receipt(receipt), 'original native version receipt/raw digest differs')
        outputs.append((directory / 'stdout.txt').read_bytes())
    return check_rust_versions(*outputs)


def check_setup_metadata(artifact, recovered, footer, seed):
    """Correlate actual disk progress/final serial and native setup observations."""
    validate_seed(seed)
    validate_footer(footer)
    allocation.require(seed['mode'] == 'native-setup-diagnostic'
        and recovered.get('status') == 'RECOVERED INCLUDED BYTES' and recovered.get('disk_unchanged') is True
        and recovered.get('filesystem_clean') is True, 'actual complete unchanged diagnostic metadata recovery required')
    trees = recovered.get('trees')
    allocation.require(type(trees) is list and [row.get('name') for row in trees] == ['boot', 'setup', 'start'],
        'exact setup-only recovered metadata scopes required')
    values, paths = {}, {}
    for row, filename in zip(trees, ('boot-result.json', 'setup-result.json', 'start-result.json')):
        allocation.require(row['status'] == 'RECOVERED INCLUDED BYTES' and type(row.get('host_path')) is str,
            'actual complete diagnostic metadata tree required')
        path = archive_capture.owned(Path(artifact) / row['host_path'] / filename)
        allocation.require(path.is_relative_to(Path(artifact)) and path.is_file()
            and not path.is_symlink() and path.stat().st_size <= 4 * 1024**2, 'bounded original diagnostic metadata required')
        values[row['name']] = strict_json(path.read_bytes()); paths[row['name']] = path.parent
    progress, setup, start = (values[name] for name in ('boot', 'setup', 'start'))
    allocation.require(footer['status'] == 'PASS' and footer['mode'] == 'native-setup-diagnostic'
        and footer['commit'] == seed['commit'] and footer['source_sha256'] == seed['source_sha256'],
        'actual complete source-bound diagnostic boot footer required')
    # The original disk record is written before unmount. Keep its unfinished
    # state intact; only the separately retained serial footer can observe final
    # unmount. Never relabel the disk progress snapshot as a completed PASS.
    mutable = {'unmount_status', 'finished_monotonic_ns', 'utc_ns', 'status'}
    allocation.require(set(progress) == set(footer)
        and all(progress[key] == footer[key] for key in set(footer) - mutable)
        and progress['unmount_status'] == 'PENDING' and progress['status'] == 'FAIL'
        and progress['finished_monotonic_ns'] is None and progress['utc_ns'] is None,
        'original pre-unmount progress and final footer do not correlate')
    for row in (setup, start):
        allocation.require(row.get('method') == allocation.METHOD and row.get('commit') == seed['commit']
            and row.get('source_sha256') == seed['source_sha256'] and row.get('reference_qualified') is False
            and row.get('status') == 'PREPARED NATIVE TOOLS ONLY' and row.get('canonical') == 'NOT RUN',
            'actual native-setup-only original result required')
    allocation.require(setup.get('first_party_build_transported') is False
        and setup.get('cleanup', {}).get('status') == 'PASS'
        and type(setup.get('elapsed_seconds')) in (int, float) and math.isfinite(setup['elapsed_seconds'])
        and setup['elapsed_seconds'] > 0 and start.get('native_setup_elapsed_seconds') == setup['elapsed_seconds']
        and start.get('mode') == 'native-setup-diagnostic' and 'owner_result' not in start,
        'actual stopped native prerequisite timing required')
    allocation.validate_environment({key: setup['environment'][key] for key in allocation.ENV_KEYS})
    original_seed = archive_capture.owned(Path(artifact).parent / 'preparation/seed.json')
    allocation.require(original_seed.is_file() and original_seed.stat().st_size <= 4 * 1024**2
        and strict_json(original_seed.read_bytes()) == seed and sha(original_seed) == footer['seed_sha256'],
        'original diagnostic seed bytes differ from guest boot')
    versions = version_observations(paths['setup'], commit=seed['commit'], source_sha256=seed['source_sha256'],
        seed_sha256=footer['seed_sha256'])
    allocation.require(versions == setup['versions'], 'actual version raw outputs differ from setup result')
    return {'status': 'OBSERVED NATIVE SETUP ONLY', 'elapsed_seconds': setup['elapsed_seconds'],
        'versions': versions, 'boot_id': footer['boot_id'], 'reference_qualified': False,
        'canonical': 'NOT RUN', 'provider_fit': 'NOT MEASURED',
        'scope': 'Actual source-bound prerequisite observation on sampled4CPU/8GiB guest with five checked original version commands; no canonical/provider fit result.'}


def run_vm(out, prepared, run_as, ownership, deadline):
    """One diagnostic VM, with actual exit observed before subreaper cleanup."""
    allocation.require(prepared['seed']['mode'] == 'native-setup-diagnostic', 'diagnostic never accepts canonical mode')
    artifact = out / 'artifact'
    allocation.require(artifact.is_dir() and not any(artifact.iterdir()), 'new empty diagnostic artifact root required')
    started = time.monotonic_ns(); vm_end = min(int(deadline * 10**9), started + VM_SECONDS * 10**9)
    process = None; captures = []; failure = None; footer = None; observed_exit = None
    count = valid = 0
    record = {'schema_version': 1, 'method': allocation.METHOD, 'status': 'FAIL',
        'mode': 'native-setup-diagnostic', 'started_monotonic_ns': started, 'deadline_monotonic_ns': vm_end,
        'reference_qualified': False, 'canonical': 'NOT RUN', 'allocation': 'NOT REQUESTED'}
    write_json(artifact / 'vm-lifetime.json', record)
    try:
        process = subprocess.Popen(prepared['command'], cwd=ROOT, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0, start_new_session=True)
        write_json(artifact / 'original-process.json', {'pid': process.pid, 'command': prepared['command'],
            'started_monotonic_ns': started, 'deadline_monotonic_ns': vm_end})
        captures = [BoundedCapture(process.stdout, artifact / 'serial.txt', SERIAL_LIMIT),
            BoundedCapture(process.stderr, artifact / 'qemu.stderr', 256 * 1024)]
        while process.poll() is None:
            allocation.require(time.monotonic_ns() < vm_end, 'original native diagnostic VM deadline exhausted')
            for capture in captures: capture.drain()
            serial = bounded_bytes(artifact / 'serial.txt', SERIAL_LIMIT).decode('utf-8')
            complete = serial[:serial.rfind('\n') + 1]
            if BOOT_PREFIX in complete: footer = parse_boot(complete)
            if footer is None:
                allocation.require(count < 2 * VM_SECONDS + 4, 'native diagnostic sample count exceeded')
                try:
                    sample = snapshot_before_cutoff(process.pid, prepared['port'], vm_end)
                    check_sample(sample, prepared['uid']); valid += 1
                    sample.update(observation_status='OBSERVED', reference_qualified=False)
                    append_json(artifact / 'host-samples.jsonl', sample, limit=(2 * VM_SECONDS + 4) * 16384)
                except (OSError, ValueError, KeyError, TypeError) as error:
                    append_json(artifact / 'host-observation-errors.jsonl', {'monotonic_ns': time.monotonic_ns(),
                        'error': type(error).__name__, 'reason': str(error)[:1024], 'reference_qualified': False})
                count += 1
            time.sleep(.5)
        observed_exit = process.returncode
        allocation.require(type(observed_exit) is int and observed_exit == 0, 'actual diagnostic QEMU exit failed')
    except (Exception, KeyboardInterrupt) as error:
        failure = {'error': type(error).__name__, 'reason': str(error)[:2048]}
    finally:
        stopped = stop_vm(out, process, None, [], prepared['port'], ownership, failure)
        for capture in captures:
            try:
                capture.drain()
                allocation.require(capture.eof and not capture.exceeded, 'diagnostic VM capture incomplete')
            except Exception as error: failure = failure or {'error': type(error).__name__, 'reason': str(error)[:1024]}
            finally: capture.close()
        if process is not None:
            process.wait(timeout=5); process.stdout.close(); process.stderr.close()
        write_json(artifact / 'capture.json', [capture.record() for capture in captures])
        write_json(artifact / 'vm-stop.json', stopped)
    if failure is None:
        try:
            footer = parse_boot(bounded_bytes(artifact / 'serial.txt', SERIAL_LIMIT).decode('utf-8'))
            allocation.require(footer['status'] == 'PASS' and footer['mode'] == 'native-setup-diagnostic'
                and footer['commit'] == prepared['seed']['commit']
                and footer['source_sha256'] == prepared['seed']['source_sha256']
                and footer['seed_sha256'] == sha(out / 'preparation/seed.json')
                and stopped['cleanup']['status'] == 'PASS' and not stopped['errors'] and valid > 0,
                'actual complete diagnostic boot, sampled resources or cleanup failed')
            record['status'] = 'CAPTURED SETUP DIAGNOSTIC ONLY'
        except Exception as error: failure = {'error': type(error).__name__, 'reason': str(error)[:2048]}
    record.update(failure=failure, footer=footer, qemu_exit_observed_before_owned_stop=observed_exit,
        host_sample_attempts=count, valid_resource_samples=valid, cleanup=stopped['cleanup'],
        finished_monotonic_ns=time.monotonic_ns(),
        scope='Actual native setup diagnostic only; no prior allocation, canonical, reference or whole-provider fit result.')
    if failure is not None: record['status'] = 'FAIL'
    write_json(artifact / 'vm-result.json', record); fsync_directory(artifact)
    return record, process


def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--run-as', required=True); args = parser.parse_args(argv)
    try: actual_controller()
    except ValueError as error: print(str(error)); return 77
    allocation.require(re.fullmatch('[a-z_][a-z0-9_-]{0,31}', args.run_as), 'existing nonroot diagnostic account required')
    out = archive_capture.owned(args.out); allocation.require(out.parent.is_dir(), 'existing owned diagnostic parent required')
    allocation.require(not out.exists(), 'one new diagnostic output required')
    source = source_identity(ROOT)['sha256']
    commit = subprocess.check_output(['git', '-c', 'safe.directory=' + str(ROOT), 'rev-parse', 'HEAD'],
        cwd=ROOT, timeout=15).decode().strip()
    source_check(commit, source)
    started = time.monotonic(); deadline = started + TOTAL_SECONDS
    out.mkdir(mode=0o755)
    record = {'schema_version': 1, 'method': allocation.METHOD, 'status': 'FAIL',
        'mode': 'native-setup-diagnostic', 'commit': commit, 'source_sha256': source,
        'started_monotonic_ns': int(started * 10**9), 'deadline_monotonic_ns': int(deadline * 10**9),
        'reference_qualified': False, 'canonical': 'NOT RUN', 'allocation': 'NOT REQUESTED',
        'provider_fit': 'NOT MEASURED'}
    ownership = None
    previous = {number: signal.signal(number, interrupted) for number in (signal.SIGTERM, signal.SIGINT)}
    try:
        record['host_utilities'] = provision(out / 'utilities', PROVISION_SECONDS)
        allocation.require(record['host_utilities']['status'] == 'PREPARED HOST UTILITIES ONLY', 'host utilities did not pass')
        vm = out / 'vm'; vm.mkdir(mode=0o755); ownership = LinuxOwnedChildren()
        prepared = prepare(vm, commit=commit, source_sha256=source, run_as=args.run_as,
            host_seconds=HOST_PREP_SECONDS, guest_setup_seconds=GUEST_SETUP_SECONDS,
            tail_seconds=60, retention_seconds=180, mode='native-setup-diagnostic', ownership=ownership)
        result, process = run_vm(vm, prepared, args.run_as, ownership,
            min(deadline - RECOVERY_SECONDS - CLEANUP_RESERVE_SECONDS, time.monotonic() + VM_SECONDS))
        record['vm'] = result
        if process is not None and result['cleanup']['status'] == 'PASS':
            direct = TrialCommands(vm / 'preparation', ownership)
            record['recovery'] = recover(vm, process=process, command=prepared['command'], channel=None,
                cleanup=result['cleanup'], mode='native-setup-diagnostic',
                deadline=min(deadline - CLEANUP_RESERVE_SECONDS, time.monotonic() + RECOVERY_SECONDS), checked=direct)
        allocation.require(result['status'] == 'CAPTURED SETUP DIAGNOSTIC ONLY', 'actual native diagnostic VM failed')
        record['native_setup'] = check_setup_metadata(vm / 'artifact', record['recovery'],
            result['footer'], prepared['seed'])
        source_check(commit, source)
        allocation.require(time.monotonic() < deadline, 'original whole diagnostic deadline exhausted')
        record['status'] = 'OBSERVED NATIVE SETUP ONLY'
    except (Exception, KeyboardInterrupt) as error:
        record.update(status='FAIL', error=type(error).__name__, reason=str(error)[:2048])
    finally:
        for number in previous: signal.signal(number, signal.SIG_IGN)
        try:
            if ownership is not None:
                record['cleanup'] = ownership.finish(None)
                if record['cleanup']['status'] != 'PASS': record['status'] = 'FAIL'
            record.update(finished_monotonic_ns=time.monotonic_ns(), elapsed_seconds=time.monotonic() - started)
            if time.monotonic() >= deadline: record['status'] = 'FAIL'
            write_json(out / 'diagnostic-result.json', record); fsync_directory(out)
        finally:
            for number, handler in previous.items(): signal.signal(number, handler)
    print(json.dumps({'status': record['status'], 'out': str(out), 'canonical': 'NOT RUN',
        'reference_qualified': False, 'provider_fit': 'NOT MEASURED'}, sort_keys=True))
    return 0 if record['status'] == 'OBSERVED NATIVE SETUP ONLY' else 1


if __name__ == '__main__': raise SystemExit(main())
