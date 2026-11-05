"""Own one full KVM collection with finite observation/recovery budgets.

The pilot's closed bootstrap and pure setup helpers are reused explicitly;
its stages, time limits, protocol, receiver and result claims are unchanged.
The new route collects complete campaigns, not a canonical fresh checkout.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts')); sys.path.insert(0, str(ROOT / 'benchmarks'))
import kvm_benchmark_pilot as pilot
from kvm_pilot_common import require, sha, read_json, write_json, append_json
from kvm_reference_common import METHOD, STAGES, identity, strict_json
from kvm_reference_channel import PORT_NAME
from kvm_reference_events import parse as parse_events
from kvm_reference_budget import (HOST_PREP_SECONDS, GUEST_SETUP_SECONDS, VM_SECONDS,
    RECOVERY_SECONDS, CLEANUP_SECONDS, OWNER_RESERVE_SECONDS, OWNER_SECONDS,
    HOST_PERIOD_SECONDS, MAX_HOST_SAMPLES, MAX_SAMPLE_BYTES, MAX_HOST_LOG_BYTES, MAX_GAP_NS, declaration)
from inspect_reference_guest import (TrialCommands, BoundedCapture, interrupted, bounded_bytes,
    host_snapshot, IMAGE_SHA, FINGERPRINT, SERIAL_LIMIT)
from owned_process import LinuxOwnedChildren
from kvm_capture_channel import fsync_directory
from kvm_boot_recovery import recover_boot_logs
from run import environment

DISK_BYTES = pilot.DISK_BYTES
MIN_FREE_BYTES = 60 * 1024**3
BOOT_PREFIX = 'RILLSCOPE_FULL_BOOT_V1 '


def cloud_config():
    config = pilot.cloud_config()
    source = pilot.BOOTSTRAP
    replacements = {'RILLSCOPE_PILOT_BOOT_STAGE_V1 ': 'RILLSCOPE_FULL_BOOT_STAGE_V1 ',
        'RILLSCOPE_PILOT_BOOT_V1 ': BOOT_PREFIX, 'kvm-pilot': 'kvm-reference',
        'rillscope-owned-pilot': 'rillscope-owned-reference',
        'owned-ephemeral-kvm-pilot': 'owned-ephemeral-full-collection',
        'kvm_pilot_guest.py': 'kvm_reference_guest.py'}
    # Apply longer phrases first: the marker contains the directory token.
    for old in sorted(replacements, key=len, reverse=True):
        require(old in source, 'closed reviewed boot template no longer matches: ' + old)
        source = source.replace(old, replacements[old])
    require('pilot' not in source, 'pilot bootstrap identity leaked into full route')
    config['write_files'] = [{'path': '/opt/rillscope-full-boot.py', 'permissions': '0644',
        'encoding': 'b64', 'content': base64.b64encode(source.encode()).decode()}]
    config['runcmd'] = [['/bin/sh', '-c', '/usr/bin/python3 /opt/rillscope-full-boot.py > /dev/ttyS0 2>&1']]
    return config


def parse_boot(serial):
    rows = []
    for line in serial.splitlines():
        if BOOT_PREFIX not in line: continue
        value = line.split(BOOT_PREFIX, 1)[1].strip()
        require(len(value) <= 90000, 'full boot result exceeds bound')
        decoded = base64.b64decode(value, validate=True)
        require(len(decoded) <= 65536, 'decoded full boot result exceeds bound')
        row = strict_json(decoded)
        require(type(row) is dict and row.get('reference_qualified') is False, 'invalid full boot result')
        rows.append(row)
    require(len(rows) <= 1, 'duplicate full boot result')
    return rows[0] if rows else None


def storage(out):
    total, used, free = shutil.disk_usage(out)
    row = {'total_bytes': total, 'used_bytes': used, 'free_bytes': free,
        'required_headroom_bytes': MIN_FREE_BYTES, 'full_fit_established': False,
        'accounting': '16GiB work +20GiB root +16GiB recovered raw +1GiB captures '
                      '+3GiB image/staging/logs +4GiB reserve; actual disk/time exhaustion remains FAIL'}
    require(free >= MIN_FREE_BYTES, 'actual full-route storage headroom insufficient: ' + json.dumps(row))
    return row


def qemu_command(out, image, run_as, port):
    command = pilot.qemu_command(out, image, run_as, port)
    name = command.index('-name') + 1
    require(command[name] == 'RillScope-unqualified-feasibility-pilot', 'closed QEMU name differs')
    command[name] = 'RillScope-full-collection-unqualified'
    old = 'virtserialport,chardev=capture,name=' + pilot.PORT_NAME
    require(command.count(old) == 1, 'closed pilot capture device differs')
    command[command.index(old)] = 'virtserialport,chardev=capture,name=' + PORT_NAME
    return command


def prepare_host(out, build_path, commit, run_as, ownership):
    import fcntl
    import pwd
    started = time.monotonic(); deadline = started + HOST_PREP_SECONDS
    account = pwd.getpwnam(run_as); require(account.pw_uid > 0, 'existing non-root QEMU identity required')
    write_json(out / 'artifact/storage-before.json', storage(out))
    initial = environment(); write_json(out / 'artifact/host-before.json', initial)
    require(initial.get('effective_cpu_capacity') == 4 and initial.get('process_affinity_cpu_count') == 4,
            'actual four-CPU host capacity required')
    require(type(initial.get('available_memory_bytes')) is int and initial['available_memory_bytes'] >= 10 * 1024**3,
            'actual host memory headroom insufficient')
    with Path('/dev/kvm').open('r+b', buffering=0) as device:
        require(fcntl.ioctl(device.fileno(), 0xae00, 0) == 12, 'existing KVM API12 required')
    for tool in ('qemu-system-x86_64', 'qemu-img', 'cloud-localds', 'gpg', 'gpgv', 'mkfs.ext4', 'debugfs', 'dumpe2fs'):
        require(shutil.which(tool) is not None, 'required installed tool missing: ' + tool)
    direct = TrialCommands(out, ownership)
    def checked(name, command, timeout=60, **keywords):
        remaining = deadline - time.monotonic(); require(remaining > 0, 'full host preparation deadline exhausted')
        return direct(name, command, timeout=min(timeout, remaining), **keywords)
    qemu = Path(shutil.which('qemu-system-x86_64')).resolve()
    version = checked('qemu-version', [str(qemu), '--version'], inputs=(qemu,)).decode()
    help_text = checked('qemu-help', [str(qemu), '-help'], inputs=(qemu,))
    require(b'-runas' in help_text and b'strict=on|off' in help_text, 'QEMU lacks privilege drop or strict boot')
    image = pilot.signed_image(out, checked, deadline)
    stage, payload = pilot.prepare_payload(out, build_path, commit, checked)
    payload.update(mode=METHOD, stage_budgets={'whole_collection_seconds': declaration()['guest_seconds']['collection']},
        stages=list(STAGES), canonical_fresh='NOT RUN', reference_qualified=False)
    # The excluded manifest does not alter the exact incoming file map.
    write_json(stage / 'c/.local-runs/kvm-input/payload.json', payload)
    write_json(out / 'payload.json', payload)
    shutil.copy2(out / 'payload.json', out / 'artifact/payload.json')
    binaries = out / 'artifact/binaries'; binaries.mkdir()
    for name, item in payload['bins'].items():
        shutil.copy2(ROOT / item['path'], binaries / name)
        require(sha(binaries / name, 64 * 1024**2) == item['sha256'], 'retained host executable bytes differ')
    with (out / 'work.raw').open('xb') as stream: stream.truncate(DISK_BYTES)
    checked('work-format', ['mkfs.ext4', '-F', '-m', '0', '-L', 'rillwork', '-d', str(stage), str(out / 'work.raw')], timeout=120)
    (out / 'user-data').write_text('#cloud-config\n' + json.dumps(cloud_config()) + '\n', encoding='utf-8')
    (out / 'meta-data').write_text('instance-id: rillscope-full-collection\nlocal-hostname: rillscope-full-collection\n')
    checked('seed-create', ['cloud-localds', str(out / 'seed.iso'), str(out / 'user-data'), str(out / 'meta-data')],
        inputs=(out / 'user-data', out / 'meta-data'))
    checked('overlay-create', ['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(image),
        str(out / 'disk.qcow2'), '20G'], large_inputs=(image,))
    runtime = out / 'runtime'; runtime.mkdir(mode=0o700); os.chown(runtime, account.pw_uid, account.pw_gid)
    for name in ('work.raw', 'disk.qcow2'):
        os.chown(out / name, account.pw_uid, account.pw_gid); os.chmod(out / name, 0o600)
    with socket.socket() as available:
        available.bind(('127.0.0.1', 0)); port = available.getsockname()[1]
    command = qemu_command(out, image, run_as, port)
    write_json(out / 'artifact/configuration.json', {'method': METHOD, 'command': command, 'qemu_sha256': sha(qemu),
        'original_root': str(ROOT), 'original_output': out.relative_to(ROOT).as_posix(),
        'qemu_version': version, 'image_sha256': IMAGE_SHA, 'signing_primary': FINGERPRINT,
        'qemu_run_as_uid': account.pw_uid, 'payload': payload, 'setup_elapsed_seconds': time.monotonic() - started,
        'budget': declaration(), 'canonical_fresh': 'NOT RUN', 'reference_qualified': False})
    return command, port, payload, account.pw_uid


def check_sample(sample, uid):
    require(sample['kvm'].get('return', {}).get('enabled') is True
        and sample['memory'].get('return', {}).get('base-memory') == 8 * 1024**3
        and sample['hotplug_memory'].get('return') == []
        and sample['run_status'].get('return', {}).get('status') == 'running'
        and len(sample['vcpu_threads']) == 4 and all(len(row['affinity']) == 4 for row in sample['vcpu_threads'])
        and sample['environment'].get('effective_cpu_capacity') == 4
        and sample['environment'].get('process_affinity_cpu_count') == 4
        and int(sample['process_status'].get('VmRSS', '0 kB').split()[0]) * 1024 >= 7.5 * 1024**3
        and sample['process_status'].get('Uid', '').split() == [str(uid)] * 4
        and sample['process_status'].get('VmSwap') == '0 kB', 'actual full host allocation/lifecycle differs')


def stop_vm(out, process, receiver, receiver_captures, port, ownership, failure):
    record = {'errors': [], 'cleanup': {'status': 'FAIL'}, 'receiver_exit_observed_before_stop': None}
    try:
        if process is not None and process.poll() is None:
            if failure is not None:
                try: pilot.collect_boot_diagnostics(out, port)
                except Exception as error: record['errors'].append('boot diagnostics: ' + type(error).__name__)
            try: pilot.qmp(port, 'system_powerdown'); process.wait(timeout=15)
            except (OSError, ValueError, subprocess.SubprocessError):
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
        if receiver is not None:
            until = time.monotonic() + 5
            while receiver.poll() is None and time.monotonic() < until:
                for capture in receiver_captures: capture.drain()
                time.sleep(.01)
            record['receiver_exit_observed_before_stop'] = receiver.poll()
            if record['receiver_exit_observed_before_stop'] is None:
                record['errors'].append('receiver did not exit before owned stop; eventual Popen ECHILD cannot establish an exit code')
    except (Exception, KeyboardInterrupt) as error:
        record['errors'].append('polite stop: ' + type(error).__name__ + ': ' + str(error)[:1024])
    finally:
        # No stream, diagnostic, signal or wait failure may skip the owned
        # pidfd/subreaper stop. Disk recovery is forbidden unless it passes.
        try: record['cleanup'] = ownership.terminate(process.pid if process is not None else None)
        except (Exception, KeyboardInterrupt) as error:
            record['cleanup'] = {'status': 'FAIL', 'error': type(error).__name__, 'reason': str(error)[:1024]}
    return record


def receiver_command(out, payload, started_ns):
    require(type(started_ns) is int and started_ns > 0, 'exact original VM clock required for receiver')
    return [sys.executable, str(ROOT / 'scripts/kvm_reference_receiver.py'),
        '--socket', str(out / 'runtime/capture.sock'), '--out', str(out / 'artifact/packages'),
        '--timeout', str(VM_SECONDS), '--vm-started-monotonic-ns', str(started_ns),
        '--commit', payload['commit'], '--source-sha256', payload['source']['sha256']]


def run_vm(out, command, port, payload, uid, ownership):
    artifact = out / 'artifact'; started_ns = time.monotonic_ns(); started = started_ns / 10**9
    deadline_ns = started_ns + VM_SECONDS * 10**9
    write_json(artifact / 'vm-lifetime.json', {'schema_version': 1, 'method': METHOD,
        'commit': payload['commit'], 'source_sha256': payload['source']['sha256'],
        'started_monotonic_ns': started_ns, 'deadline_monotonic_ns': deadline_ns,
        'reference_qualified': False})
    process = None; captures = []
    receiver = None; receiver_captures = []; events = []; ready_at = None; exit_at = None; final_observed = False
    receiver_argv = None
    count = 0; last_required = None; failure = None; link_ack = None
    append_cost = {'calls': 0, 'wall_ns': 0, 'cpu_ns': 0, 'maximum_wall_ns': 0}
    def observe(required):
        nonlocal count, last_required
        require(count < MAX_HOST_SAMPLES, 'full host sample count exceeds bound before write')
        begin = time.monotonic_ns(); cpu = time.thread_time_ns()
        sample = host_snapshot(process.pid, port)
        sample.update(balloon=pilot.qmp(port, 'query-balloon'), qemu_version=pilot.qmp(port, 'query-version'),
            ready=ready_at is not None, required_interval=required, method=METHOD,
            observer_wall_ns=time.monotonic_ns() - begin, observer_cpu_ns=time.thread_time_ns() - cpu,
            observation_status='OBSERVED')
        if required:
            try:
                check_sample(sample, uid)
                if last_required is not None:
                    require(0 < sample['monotonic_ns'] - last_required <= MAX_GAP_NS, 'full host sampling gap exceeded')
            except Exception as error:
                sample.update(observation_status='FAIL', observation_error=type(error).__name__, observation_reason=str(error)[:2048])
        require(len(json.dumps(sample, separators=(',', ':'), allow_nan=False).encode()) + 1 <= MAX_SAMPLE_BYTES,
                'full host sample exceeds byte bound')
        begin = time.monotonic_ns(); cpu = time.thread_time_ns()
        append_json(artifact / 'host-samples.jsonl', sample, limit=MAX_HOST_LOG_BYTES)
        elapsed = time.monotonic_ns() - begin
        append_cost['calls'] += 1; append_cost['wall_ns'] += elapsed
        append_cost['cpu_ns'] += time.thread_time_ns() - cpu
        append_cost['maximum_wall_ns'] = max(append_cost['maximum_wall_ns'], elapsed)
        count += 1
        if required: last_required = sample['monotonic_ns']
        require(sample['observation_status'] == 'OBSERVED', sample.get('observation_reason', 'full host sample failed'))
        return sample
    try:
        process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, bufsize=0, start_new_session=True)
        write_json(artifact / 'process.json', {'status': 'RUNNING', 'pid': process.pid, 'utc_ns': time.time_ns()})
        captures = [BoundedCapture(process.stdout, artifact / 'serial.txt', SERIAL_LIMIT),
                    BoundedCapture(process.stderr, artifact / 'qemu.stderr', 256 * 1024)]
        while process.poll() is None:
            require(time.monotonic_ns() < deadline_ns, 'full VM deadline exhausted; available partial bytes retained')
            for capture in captures + receiver_captures: capture.drain()
            if receiver is None and (out / 'runtime/capture.sock').exists():
                path = out / 'runtime/capture.sock'; require(stat.S_ISSOCK(path.lstat().st_mode), 'owned capture socket differs')
                os.chmod(path, 0o600)
                receiver_argv = receiver_command(out, payload, started_ns)
                receiver = subprocess.Popen(receiver_argv, cwd=ROOT,
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    bufsize=0, start_new_session=True)
                receiver_captures = [BoundedCapture(receiver.stdout, artifact / 'receiver.stdout', 4 * 1024**2),
                    BoundedCapture(receiver.stderr, artifact / 'receiver.stderr', 4 * 1024**2)]
            if receiver is not None and receiver.poll() is not None:
                require(receiver.returncode == 0, 'actual full capture receiver failed')
            serial = bounded_bytes(artifact / 'serial.txt', SERIAL_LIMIT).decode('utf-8', errors='replace')
            current = parse_events(serial[:serial.rfind('\n') + 1])
            require(current[:len(events)] == events, 'full serial lifecycle prefix changed')
            for row in current[len(events):]:
                received = {'received_utc_ns': time.time_ns(), 'received_monotonic_ns': time.monotonic_ns(), 'guest': row}
                append_json(artifact / 'received-events.jsonl', received)
                if row['phase'] == 'ready':
                    require(ready_at is None and row['commit'] == payload['commit']
                        and row['source_sha256'] == payload['source']['sha256']
                        and row['binary_sha256'] == {name: item['sha256'] for name, item in payload['bins'].items()},
                        'full guest readiness differs from original payload')
                    ready_at = received['received_monotonic_ns']
                    require(time.monotonic() - started < GUEST_SETUP_SECONDS, 'full guest setup deadline exhausted')
                    # This real validated observation precedes link-down. The
                    # child cannot start measurements until it sees that cut.
                    observe(True)
                    request = {'utc_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns()}
                    response = pilot.qmp(port, 'set_link', {'name': 'pilot-nic', 'up': False})
                    link_ack = {'requested': request, 'response': response, 'finished_utc_ns': time.time_ns(),
                        'finished_monotonic_ns': time.monotonic_ns()}
                    write_json(artifact / 'host-link-down.json', link_ack)
                    require('return' in response, 'full owned NIC link-down failed')
                if row['phase'] == 'guest-exit': exit_at = received['received_monotonic_ns']
                if row['phase'] == 'guest-failure': raise ValueError('actual full guest reported a failure')
            events = current
            require(ready_at is not None or time.monotonic() - started < GUEST_SETUP_SECONDS, 'full guest never became ready')
            required = ready_at is not None and not final_observed
            try:
                observe(required)
                if required and exit_at is not None:
                    require(last_required >= exit_at, 'actual final host sample precedes received guest exit')
                    final_observed = True
            except (OSError, ValueError, KeyError, TypeError) as error:
                append_json(artifact / 'host-observation-errors.jsonl', {'utc_ns': time.time_ns(),
                    'monotonic_ns': time.monotonic_ns(), 'required_interval': required,
                    'error': type(error).__name__, 'reason': str(error)[:2048]})
                if required: raise
            time.sleep(HOST_PERIOD_SECONDS)
        require(process.returncode == 0, 'actual full QEMU exit failed')
    except (Exception, KeyboardInterrupt) as error:
        failure = {'error': type(error).__name__, 'reason': str(error)[:2048]}
    finally:
        stopped = stop_vm(out, process, receiver, receiver_captures, port, ownership, failure)
        cleanup = stopped['cleanup']
        if stopped['errors']: failure = failure or {'error': 'StopError', 'reason': '; '.join(stopped['errors'])[:2048]}
        write_json(artifact / 'vm-stop.json', stopped)
        write_json(artifact / 'vm-cleanup.json', cleanup)
        if cleanup['status'] != 'PASS': failure = failure or {'error': 'CleanupError', 'reason': 'full VM ownership cleanup failed'}
        for capture in captures + receiver_captures:
            try: capture.drain()
            except (OSError, ValueError) as error: failure = failure or {'error': type(error).__name__, 'reason': str(error)[:2048]}
            capture.close()
            if not capture.eof or capture.exceeded:
                failure = failure or {'error': 'CaptureError', 'reason': 'full raw stream did not reach EOF within its bound'}
        if process is not None:
            write_json(artifact / 'process.json', {'status': 'EXITED', 'pid': process.pid,
                'exit_code': process.wait(timeout=5), 'utc_ns': time.time_ns(), 'cleanup': cleanup})
            process.stdout.close(); process.stderr.close()
        if receiver is not None:
            receiver.wait(timeout=5); receiver.stdout.close(); receiver.stderr.close()
        write_json(artifact / 'capture.json', [capture.record() for capture in captures + receiver_captures])
    fsync_ns = None
    if (artifact / 'host-samples.jsonl').is_file():
        before = time.monotonic_ns()
        try:
            with (artifact / 'host-samples.jsonl').open('ab') as stream: stream.flush(); os.fsync(stream.fileno())
            fsync_ns = time.monotonic_ns() - before
        except OSError as error: failure = failure or {'error': type(error).__name__, 'reason': str(error)[:2048]}
    serial = bounded_bytes(artifact / 'serial.txt', SERIAL_LIMIT).decode('utf-8', errors='replace') if captures else ''
    final_events = parse_events(serial[:serial.rfind('\n') + 1]); boot = parse_boot(serial)
    require(final_events[:len(events)] == events, 'terminal full lifecycle prefix changed')
    for row in final_events[len(events):]:
        append_json(artifact / 'received-events.jsonl', {'received_utc_ns': time.time_ns(),
            'received_monotonic_ns': time.monotonic_ns(), 'terminal_capture': True, 'guest': row})
    received = read_json(artifact / 'reference-receiver-result.json') if (artifact / 'reference-receiver-result.json').is_file() else {}
    result = {'status': 'FAIL', 'method': METHOD, 'events': final_events, 'boot_result': boot,
        'started_monotonic_ns': started_ns, 'deadline_monotonic_ns': deadline_ns,
        'receiver_command': receiver_argv,
        'host_samples': count, 'host_append_cost': append_cost, 'host_final_fsync_ns': fsync_ns,
        'final_host_observed': final_observed,
        'host_transfers': received.get('transfers', []), 'receiver_exit': stopped['receiver_exit_observed_before_stop'],
        'failure': failure, 'elapsed_seconds': time.monotonic() - started,
        'all_record_validation': 'NOT RUN', 'canonical_fresh': 'NOT RUN', 'reference_qualified': False}
    if (failure is None and final_observed and link_ack is not None and received.get('status') == 'PASS'
        and receiver is not None and result['receiver_exit'] == 0 and fsync_ns is not None and boot and boot.get('worker_exit') == 0
        and boot.get('unmount_status') == 'PASS' and boot.get('console_errors') == []
        and 'error' not in boot and 'retention_error' not in boot
        and any(row['phase'] == 'guest-exit' and row.get('status') == 'COLLECTED' for row in final_events)):
        result['status'] = 'COLLECTED'
    write_json(artifact / 'vm-result.json', result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--run-as', required=True); parser.add_argument('--build-receipt', type=Path, required=True)
    parser.add_argument('--commit', required=True); args = parser.parse_args(argv)
    if platform.system() != 'Linux' or not hasattr(os, 'geteuid') or os.geteuid() != 0:
        print(json.dumps({'status': 'BLOCKED', 'reason': 'requires existing Linux root permission',
            'method': METHOD, 'reference_qualified': False})); return 77
    require(re.fullmatch('[a-z_][a-z0-9_-]{0,31}', args.run_as), 'closed existing QEMU user required')
    identity(args.commit, '0' * 64)
    out = pilot.owned_output(args.out); build_path = pilot.owned_output(args.build_receipt)
    require(out.parent.is_dir(), 'existing owned output parent required')
    out.mkdir(exist_ok=False); fsync_directory(out.parent); (out / 'artifact').mkdir(); fsync_directory(out)
    started = time.monotonic(); ownership = None
    result = {'status': 'FAIL', 'method': METHOD, 'reference_qualified': False, 'canonical_fresh': 'NOT RUN',
        'all_record_validation': 'NOT RUN', 'upstream_failure_preserved': True}
    for number in (signal.SIGTERM, signal.SIGINT): signal.signal(number, interrupted)
    try:
        ownership = LinuxOwnedChildren()
        command, port, payload, uid = prepare_host(out, build_path, args.commit, args.run_as, ownership)
        result['vm'] = run_vm(out, command, port, payload, uid, ownership)
    except (Exception, KeyboardInterrupt) as error:
        result['failure'] = {'error': type(error).__name__, 'reason': str(error)[:2048]}
    finally:
        for number in (signal.SIGTERM, signal.SIGINT): signal.signal(number, signal.SIG_IGN)
        cleanup = ownership.terminate(None) if ownership else {'status': 'NOT LAUNCHED'}
        write_json(out / 'artifact/pre-recovery-cleanup.json', cleanup)
        if cleanup['status'] == 'PASS' and (out / 'work.raw').is_file():
            try:
                from kvm_reference_recovery import recover
                remaining = min(RECOVERY_SECONDS, OWNER_SECONDS - CLEANUP_SECONDS - OWNER_RESERVE_SECONDS
                    - (time.monotonic() - started))
                require(remaining > 0, 'no full recovery reserve remains')
                deadline = time.monotonic() + remaining
                try: result['boot_recovery'] = recover_boot_logs(out, TrialCommands(out, ownership), min(deadline, time.monotonic() + 180))
                except (Exception, KeyboardInterrupt) as error: result['boot_recovery'] = {'status': 'FAIL', 'error': type(error).__name__}
                result['recovery'] = recover(out, TrialCommands(out, ownership), deadline)
            except (Exception, KeyboardInterrupt) as error:
                result['recovery'] = {'status': 'FAIL', 'error': type(error).__name__, 'reason': str(error)[:2048]}
        result['cleanup'] = ownership.finish(None) if ownership else cleanup
        write_json(out / 'artifact/cleanup.json', result['cleanup'])
    if (result.get('vm', {}).get('status') == 'COLLECTED' and result.get('recovery', {}).get('status') == 'PASS'
        and result['cleanup']['status'] == 'PASS' and 'failure' not in result): result['status'] = 'COLLECTED'
    result.update(elapsed_seconds=time.monotonic() - started, budget=declaration(),
        work_disk_policy='Owned stopped disk retained until runner cleanup. Available failed/pending bytes retained; hard host loss or unsuccessful upload can lose unexported bytes.')
    write_json(out / 'artifact/results.json', result)
    print(json.dumps({'status': result['status'], 'method': METHOD, 'elapsed_seconds': result['elapsed_seconds'],
        'reference_qualified': False, 'all_record_validation': 'NOT RUN', 'canonical_fresh': 'NOT RUN'}))
    return 0 if result['status'] == 'COLLECTED' else 1


if __name__ == '__main__': raise SystemExit(main())
