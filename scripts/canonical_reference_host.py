"""Bounded new-method VM owner component with a real prior guest allocator.

The caller must first prepare the signed image/disks/native guest tools and
declare an honest whole-job envelope from measured overhead. This component
does not establish that fit or recover/qualify stopped disks. It preserves the
old method and its budgets, cases, frames and deadlines unchanged.
"""
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import stat
import subprocess
import time

import canonical_reference_allocation as allocation
from canonical_reference_channel import CanonicalChannel
from canonical_reference_process import ProcessReadiness
from canonical_reference_deadline import AllocationDeadline
from canonical_reference_events import parse, bind
from canonical_reference_reservation import (source_check, validate_qmp_binding,
    observed_membership, fsync_directory)
import kvm_benchmark_pilot as pilot
from kvm_reference_channel import PORT_NAME
from kvm_reference_host import check_sample, stop_vm
from kvm_pilot_common import write_json, append_json, sha
from inspect_reference_guest import (BoundedCapture, bounded_bytes, host_snapshot,
    IMAGE_SHA, IMAGE_LIMIT, SERIAL_LIMIT)

ROOT = Path(__file__).resolve().parents[1]
HOST_PERIOD_SECONDS = .5
MAX_GAP_NS = 15_000_000_000
MAX_SAMPLE_BYTES = 16 * 1024
MAX_HOST_SAMPLES = allocation.MAX_LEASE_NS // 500_000_000 + 4
MAX_HOST_LOG_BYTES = MAX_HOST_SAMPLES * MAX_SAMPLE_BYTES


def finite_lifetime(started_ns, vm_seconds, setup_seconds):
    allocation.require(all(allocation.integer(value) for value in (started_ns, vm_seconds, setup_seconds))
        and 0 < setup_seconds < vm_seconds <= allocation.MAX_LEASE_NS // 10**9,
        'explicit finite new-method VM/setup bounds required; no job-fit inference')
    return started_ns + vm_seconds * 10**9


def qemu_command(out, image, run_as, port):
    command = pilot.qemu_command(out, image, run_as, port)
    old_name = 'RillScope-unqualified-feasibility-pilot'
    old_port = 'virtserialport,chardev=capture,name=' + pilot.PORT_NAME
    allocation.require(command.count(old_name) == command.count(old_port) == 1,
        'unchanged reviewed QEMU template required')
    command[command.index(old_name)] = 'RillScope-controller-owned-canonical-reference'
    command[command.index(old_port)] = 'virtserialport,chardev=capture,name=' + PORT_NAME
    return command


def snapshot_before_cutoff(pid, port, vm_deadline_ns):
    allocation.require(allocation.integer(vm_deadline_ns), 'original VM observation cutoff required')
    return AllocationDeadline(min(vm_deadline_ns, time.monotonic_ns() + 5 * 10**9),
        lambda: False).snapshot(pid, port)


def run_vm(out, *, image, run_as, port, commit, source_sha256, vm_seconds, setup_seconds, ownership,
        execution=None):
    allocation.require(platform.system() == 'Linux' and hasattr(os, 'geteuid') and os.geteuid() == 0,
        'BLOCKED: actual existing scoped Linux root controller required')
    allocation.require(os.environ.get('GITHUB_REPOSITORY') == 'C-X1an/rillscope'
        and re.fullmatch('[1-9][0-9]{0,18}', os.environ.get('GITHUB_RUN_ID', ''))
        and re.fullmatch('[1-9][0-9]{0,8}', os.environ.get('GITHUB_RUN_ATTEMPT', '')),
        'actual scoped workflow identity required before VM launch')
    allocation.require(execution is None or type(execution) is dict and not execution,
        'new empty in-process execution slot required; never hydrate original processes from JSON')
    allocation.require(type(run_as) is str and re.fullmatch('[a-z_][a-z0-9_-]{0,31}', run_as)
        and type(port) is int and 0 < port < 65536, 'existing QEMU identity and loopback QMP endpoint required')
    import archive_capture
    import pwd
    out = archive_capture.owned(out); image = archive_capture.owned(image)
    account = pwd.getpwnam(run_as)
    allocation.require(account.pw_uid > 0, 'existing nonroot QEMU identity required')
    source_check(commit, source_sha256)
    allocation.require(sha(image, IMAGE_LIMIT) == IMAGE_SHA, 'actual pinned signed-image bytes differ')
    allocation.require(shutil.which('qemu-system-x86_64') is not None, 'actual installed QEMU required')
    artifact = out / 'artifact'
    allocation.require(artifact.is_dir() and not any(artifact.iterdir()), 'new prepared empty artifact directory required')
    for name in ('seed.iso', 'disk.qcow2', 'work.raw'):
        path = out / name
        allocation.require(path.is_file() and not path.is_symlink(), 'actual prepared owned VM disk/seed required')
    # This is the one original pre-Popen clock. No receiver/guest start may
    # renew its end. The caller still must fit this bound in its provider job.
    started_ns = time.monotonic_ns()
    deadline_ns = finite_lifetime(started_ns, vm_seconds, setup_seconds)
    command = qemu_command(out, image, run_as, port)
    write_json(artifact / 'vm-lifetime.json', {'method': allocation.METHOD, 'commit': commit,
        'source_sha256': source_sha256, 'started_monotonic_ns': started_ns,
        'deadline_monotonic_ns': deadline_ns, 'setup_seconds': setup_seconds,
        'whole_job_fit': 'NOT ESTABLISHED BY THIS COMPONENT', 'reference_qualified': False})
    fsync_directory(artifact)
    process = channel = readiness = None; captures = []; failure = None; events = []
    observed_exit = observed_exit_ns = None
    prefix_at = ready_at = end_at = None; final_observed = False; link_ack = None
    count = 0; last_required = None
    append_cost = {'calls': 0, 'wall_ns': 0, 'cpu_ns': 0}

    def observe(required):
        nonlocal count, last_required
        allocation.require(count < MAX_HOST_SAMPLES, 'new-method host sample count exhausted')
        begin, cpu = time.monotonic_ns(), time.thread_time_ns()
        sample = snapshot_before_cutoff(process.pid, port, deadline_ns)
        sample.update(method=allocation.METHOD, required_interval=required,
            observer_wall_ns=time.monotonic_ns() - begin, observer_cpu_ns=time.thread_time_ns() - cpu,
            observation_status='OBSERVED')
        if required:
            try:
                check_sample(sample, account.pw_uid)
                sample, members = observed_membership(sample, process.pid)
                validate_qmp_binding(command, port, sample, process.pid, members)
                if last_required is not None:
                    allocation.require(0 < sample['monotonic_ns'] - last_required <= MAX_GAP_NS,
                        'required canonical host sample gap exceeded')
            except Exception as error:
                sample.update(observation_status='FAIL', observation_error=type(error).__name__,
                    observation_reason=str(error)[:2048])
        raw = json.dumps(sample, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'
        allocation.require(len(raw) <= MAX_SAMPLE_BYTES, 'canonical host sample exceeds record bound')
        begin, cpu = time.monotonic_ns(), time.thread_time_ns()
        append_json(artifact / 'host-samples.jsonl', sample, limit=MAX_HOST_LOG_BYTES)
        append_cost['calls'] += 1; append_cost['wall_ns'] += time.monotonic_ns() - begin
        append_cost['cpu_ns'] += time.thread_time_ns() - cpu; count += 1
        if required: last_required = sample['monotonic_ns']
        allocation.require(sample['observation_status'] == 'OBSERVED', sample.get('observation_reason', 'host sample failed'))

    try:
        process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0, start_new_session=True)
        if execution is not None:
            execution.update(process=process, command=list(command), channel=None,
                method=allocation.METHOD, commit=commit, source_sha256=source_sha256,
                started_monotonic_ns=started_ns, deadline_monotonic_ns=deadline_ns)
        write_json(artifact / 'original-process.json', {'pid': process.pid, 'command': command,
            'started_monotonic_ns': started_ns, 'deadline_monotonic_ns': deadline_ns})
        captures = [BoundedCapture(process.stdout, artifact / 'serial.txt', SERIAL_LIMIT),
            BoundedCapture(process.stderr, artifact / 'qemu.stderr', 256 * 1024)]
        readiness = ProcessReadiness(process, command, account.pw_uid,
            out=artifact / 'process-identity', commit=commit, source_sha256=source_sha256,
            started_ns=started_ns, setup_deadline_ns=min(deadline_ns, started_ns + setup_seconds * 10**9),
            vm_deadline_ns=deadline_ns)
        while process.poll() is None:
            allocation.require(time.monotonic_ns() < deadline_ns, 'original canonical VM lease exhausted')
            for capture in captures: capture.drain()
            path = out / 'runtime/capture.sock'
            if channel is None and path.exists():
                allocation.require(stat.S_ISSOCK(path.lstat().st_mode), 'actual owned QEMU capture socket required')
                os.chmod(path, 0o600)
                if readiness.poll():
                    channel = CanonicalChannel(path, artifact / 'channel', process=process, command=command,
                        uid=account.pw_uid, qmp_port=port, commit=commit, source_sha256=source_sha256,
                        vm_started_ns=started_ns, vm_deadline_ns=deadline_ns, allocation_id=secrets.token_hex(16),
                        identity=readiness)
                    if execution is not None: execution['channel'] = channel
                    channel.thread.start()
            if channel is not None and channel.done.is_set():
                allocation.require(channel.report['status'] == 'VERIFIED HOST BYTES', 'actual canonical channel failed')
            serial = bounded_bytes(artifact / 'serial.txt', SERIAL_LIMIT).decode('utf-8', errors='replace')
            current = parse(serial[:serial.rfind('\n') + 1])
            allocation.require(current[:len(events)] == events, 'canonical serial lifecycle prefix changed')
            # A valid guest can emit immediately after receiving the grant;
            # allow its controller thread to finish publishing the same object.
            if current and channel is not None and channel.exchange_record is not None:
                grant = channel.exchange_record['grant']
                for row in current[len(events):]:
                    bind(row, grant)
                    received = {'received_utc_ns': time.time_ns(), 'received_monotonic_ns': time.monotonic_ns(), 'guest': row}
                    append_json(artifact / 'received-events.jsonl', received)
                    if row['phase'] == 'prefix-start': prefix_at = received['received_monotonic_ns']
                    if row['phase'] == 'ready':
                        ready_at = received['received_monotonic_ns']; observe(True)
                        requested = time.monotonic_ns()
                        response = pilot.qmp(port, 'set_link', {'name': 'pilot-nic', 'up': False},
                            deadline=deadline_ns / 10**9)
                        link_ack = {'requested_monotonic_ns': requested, 'response': response,
                            'finished_monotonic_ns': time.monotonic_ns(), 'grant_sha256': channel.exchange_record['grant_sha256']}
                        write_json(artifact / 'host-link-down.json', link_ack)
                        allocation.require('return' in response, 'actual canonical NIC link-down failed')
                    if row['phase'] == 'attempt-end':
                        end_at = received['received_monotonic_ns']
                        allocation.require(row['status'] == 'PASS', 'actual canonical guest retained a failed attempt')
                events = current
            allocation.require(prefix_at is not None or time.monotonic_ns() < started_ns + setup_seconds * 10**9,
                'new native guest setup exhausted its explicit bound')
            required = prefix_at is not None and not final_observed
            try:
                observe(required)
                if required and end_at is not None:
                    allocation.require(last_required >= end_at, 'final actual host sample precedes guest-end reception')
                    final_observed = True
            except (OSError, ValueError, KeyError, TypeError) as error:
                append_json(artifact / 'host-observation-errors.jsonl', {'monotonic_ns': time.monotonic_ns(),
                    'required_interval': required, 'error': type(error).__name__, 'reason': str(error)[:2048]})
                if required: raise
            time.sleep(HOST_PERIOD_SECONDS)
        observed_exit, observed_exit_ns = process.returncode, time.monotonic_ns()
        allocation.require(type(observed_exit) is int and observed_exit == 0, 'actual canonical QEMU exit failed')
        allocation.require(observed_exit_ns < deadline_ns, 'original canonical VM cutoff exhausted before terminal observation')
    except (Exception, KeyboardInterrupt) as error:
        failure = {'error': type(error).__name__, 'reason': str(error)[:2048]}
        if readiness is not None:
            try: readiness.fail(error)
            except Exception as retention_error:
                failure['identity_retention_error'] = type(retention_error).__name__
    finally:
        # Join the allocator before the subreaper cleanup endpoint. Its exact
        # exchange deadline and stop flag also constrain inspections and writes.
        if channel is not None:
            channel.upstream_failure = failure
            try: channel.close()
            except Exception as error: failure = failure or {'error': type(error).__name__, 'reason': str(error)[:2048]}
        receiver = channel.receiver_process if channel is not None else None
        # The channel alone writes its receiver capture paths. The existing
        # stop helper observes the child exit before pidfd/subreaper cleanup.
        stopped = stop_vm(out, process, receiver, [], port, ownership, failure)
        if stopped['errors']: failure = failure or {'error': 'StopError', 'reason': '; '.join(stopped['errors'])[:2048]}
        if channel is not None and channel.thread.is_alive():
            stopped['cleanup'].update(status='FAIL',
                allocator_thread='original allocator did not stop; no successful cleanup endpoint')
        if stopped['cleanup']['status'] != 'PASS': failure = failure or {'error': 'CleanupError', 'reason': 'owned VM cleanup failed'}
        write_json(artifact / 'vm-stop.json', stopped)
        if execution is not None and process is not None:
            execution.update(cleanup=dict(stopped['cleanup']),
                qemu_exit_observed_before_owned_stop=observed_exit,
                qemu_exit_observed_monotonic_ns=observed_exit_ns)
        for capture in captures:
            try:
                capture.drain()
                allocation.require(capture.eof and not capture.exceeded, 'canonical QEMU capture did not finish')
            except Exception as error: failure = failure or {'error': type(error).__name__, 'reason': str(error)[:2048]}
            finally: capture.close()
        if process is not None:
            process.wait(timeout=5); process.stdout.close(); process.stderr.close()
        write_json(artifact / 'capture.json', [capture.record() for capture in captures])
    final_fsync = None
    if (artifact / 'host-samples.jsonl').is_file():
        begin = time.monotonic_ns()
        try:
            with (artifact / 'host-samples.jsonl').open('rb') as stream: os.fsync(stream.fileno())
            fsync_directory(artifact); final_fsync = time.monotonic_ns() - begin
        except OSError as error: failure = failure or {'error': type(error).__name__, 'reason': 'host observation final fsync failed'}
    report = {'status': 'FAIL', 'method': allocation.METHOD, 'reference_qualified': False,
        'commit': commit, 'source_sha256': source_sha256, 'started_monotonic_ns': started_ns,
        'deadline_monotonic_ns': deadline_ns, 'prefix_received_monotonic_ns': prefix_at,
        'ready_received_monotonic_ns': ready_at, 'end_received_monotonic_ns': end_at,
        'events': events, 'host_samples': count, 'host_append_cost': append_cost,
        'host_final_fsync_ns': final_fsync, 'final_host_observed': final_observed,
        'channel': channel.report if channel is not None else None,
        'channel_thread_stopped': channel is None or not channel.thread.is_alive(),
        'receiver_exit_before_owned_cleanup': stopped['receiver_exit_observed_before_stop'],
        'qemu_exit_observed_before_owned_stop': observed_exit,
        'qemu_exit_observed_monotonic_ns': observed_exit_ns,
        'cleanup': stopped['cleanup'], 'failure': failure,
        'scope': 'New-method VM ownership, prior grant, sampled resources, serial events and retained capture bytes only; guest boot/unmount, stopped-disk recovery, complete canonical/all-record validation and provider fit remain separate.'}
    if (failure is None and observed_exit == 0 and observed_exit_ns < deadline_ns
        and final_observed and final_fsync is not None and link_ack is not None
        and channel is not None and not channel.thread.is_alive()
        and channel.report['status'] == 'VERIFIED HOST BYTES'
        and stopped['receiver_exit_observed_before_stop'] == 0
        and [row['phase'] for row in events] == ['prefix-start', 'ready', 'attempt-end']):
        report['status'] = 'CAPTURED'
    write_json(artifact / 'vm-result.json', report); fsync_directory(artifact)
    return report
