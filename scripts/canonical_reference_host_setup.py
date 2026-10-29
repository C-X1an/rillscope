"""Prepare new owned source-only disks; do not infer campaign/provider fit."""
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import time

import canonical_reference_allocation as allocation
from canonical_reference_boot import cloud_config
from canonical_reference_host import qemu_command
from canonical_reference_reservation import source_check, fsync_directory
from canonical_reference_seed import prepare_seed, INSTALLER_URL, INSTALLER_SHA256, INSTALLER_LIMIT
from inspect_reference_guest import TrialCommands, IMAGE_SHA, IMAGE_LIMIT, FINGERPRINT
import kvm_benchmark_pilot as pilot
from kvm_pilot_common import write_json, sha
from run import environment

ROOT = Path(__file__).resolve().parents[1]
MIN_FREE_BYTES = 60 * 1024**3
WORK_BYTES = 16 * 1024**3
HOST_TOOLS = ('git', 'qemu-system-x86_64', 'qemu-img', 'cloud-localds', 'gpg', 'gpgv', 'mkfs.ext4', 'debugfs', 'dumpe2fs')


def actual_controller():
    allocation.require(platform.system() == 'Linux' and hasattr(os, 'geteuid') and os.geteuid() == 0,
        'BLOCKED: actual existing scoped Linux root controller required')
    allocation.require(os.environ.get('GITHUB_REPOSITORY') == 'C-X1an/rillscope'
        and re.fullmatch('[1-9][0-9]{0,18}', os.environ.get('GITHUB_RUN_ID', ''))
        and re.fullmatch('[1-9][0-9]{0,8}', os.environ.get('GITHUB_RUN_ATTEMPT', '')),
        'actual authorized scoped workflow identity required')


def storage(out):
    total, used, free = shutil.disk_usage(out)
    allocation.require(all(type(value) is int and value >= 0 for value in (total, used, free))
        and total > 0 and used <= total and free <= total, 'actual complete host storage observation required')
    record = {'total_bytes': total, 'used_bytes': used, 'free_bytes': free,
        'required_headroom_bytes': MIN_FREE_BYTES, 'whole_campaign_fit': 'NOT MEASURED',
        'scope': 'Remote ephemeral execution headroom only; this is separate from the local package10GB cap.',
        'accounting': '16GiB work including native tools +20GiB root +16GiB bounded stopped recovery '
            '+1GiB captures +3GiB signed image/staging/logs +4GiB reserve; actual disk exhaustion remains failure.'}
    allocation.require(free >= MIN_FREE_BYTES, 'actual new-method remote storage headroom insufficient')
    return record


def parameters(*, commit, source_sha256, run_as, host_seconds, guest_setup_seconds,
        tail_seconds, retention_seconds, mode):
    allocation.require(allocation.hex_value(commit, 40) and allocation.hex_value(source_sha256, 64)
        and type(run_as) is str and re.fullmatch('[a-z_][a-z0-9_-]{0,31}', run_as)
        and type(host_seconds) is int and 1 <= host_seconds <= 1800
        and type(guest_setup_seconds) is int and 1 <= guest_setup_seconds <= 3600
        and type(tail_seconds) is int and 1 <= tail_seconds <= 600
        and type(retention_seconds) is int and 1 <= retention_seconds <= 600
        and type(mode) is str and mode in ('canonical', 'native-setup-diagnostic'),
        'exact source/existing nonroot identity and finite new-method preparation bounds required')
    return {'commit': commit, 'source_sha256': source_sha256, 'run_as': run_as,
        'host_seconds': host_seconds, 'guest_setup_seconds': guest_setup_seconds,
        'tail_seconds': tail_seconds, 'retention_seconds': retention_seconds, 'mode': mode}


def prepare(out, *, commit, source_sha256, run_as, host_seconds, guest_setup_seconds,
        tail_seconds, retention_seconds, mode, ownership):
    actual_controller()
    parameters(commit=commit, source_sha256=source_sha256, run_as=run_as, host_seconds=host_seconds,
        guest_setup_seconds=guest_setup_seconds, tail_seconds=tail_seconds,
        retention_seconds=retention_seconds, mode=mode)
    import archive_capture
    import fcntl
    import pwd
    out = archive_capture.owned(out)
    allocation.require(out.is_dir() and not any(out.iterdir()), 'new existing empty owned preparation root required')
    account = pwd.getpwnam(run_as)
    allocation.require(account.pw_uid > 0 and account.pw_gid > 0, 'existing nonroot QEMU account required')
    source_check(commit, source_sha256)
    started = time.monotonic(); deadline = started + host_seconds
    prep = out / 'preparation'; prep.mkdir(mode=0o700)
    # VM ownership requires this directory to remain empty until actual launch;
    # preparation inputs, failures and command receipts live separately.
    (out / 'artifact').mkdir(mode=0o700)
    write_json(prep / 'storage-before.json', storage(out))
    observed = environment(); write_json(prep / 'host-before.json', observed)
    allocation.require(observed.get('effective_cpu_capacity') == 4
        and observed.get('process_affinity_cpu_count') == 4
        and type(observed.get('available_memory_bytes')) is int
        and observed['available_memory_bytes'] >= 10 * 1024**3,
        'actual four-CPU host capacity and memory headroom required')
    with Path('/dev/kvm').open('r+b', buffering=0) as descriptor:
        allocation.require(fcntl.ioctl(descriptor.fileno(), 0xae00, 0) == 12,
            'actual existing KVM API12 permission required')
    for name in HOST_TOOLS:
        allocation.require(shutil.which(name) is not None, 'required installed host tool missing: ' + name)
    direct = TrialCommands(prep, ownership)
    def checked(name, command, timeout=60, **keywords):
        remaining = deadline - time.monotonic()
        allocation.require(remaining > 0, 'original new-method host preparation deadline exhausted')
        return direct(name, command, timeout=min(timeout, remaining), **keywords)
    record = {'schema_version': 1, 'method': allocation.METHOD, 'status': 'FAIL',
        'commit': commit, 'source_sha256': source_sha256, 'mode': mode,
        'started_monotonic_ns': int(started * 10**9), 'deadline_monotonic_ns': int(deadline * 10**9),
        'first_party_build_transported': False, 'reference_qualified': False,
        'whole_provider_fit': 'NOT MEASURED', 'scope': 'Actual owned disk/source/tool prerequisites only; VM execution and validation remain separate.'}
    write_json(prep / 'preparation-result.json', record)
    prepared = None
    try:
        qemu = Path(shutil.which('qemu-system-x86_64')).resolve(strict=True)
        record['qemu_version'] = checked('qemu-version', [str(qemu), '--version'], inputs=(qemu,)).decode()
        help_text = checked('qemu-help', [str(qemu), '-help'], inputs=(qemu,))
        allocation.require(b'-runas' in help_text and b'strict=on|off' in help_text,
            'actual installed QEMU lacks privilege drop or strict boot')
        image = pilot.signed_image(out, checked, deadline)
        installer = out / 'rustup-init'
        pilot.download_bounded(INSTALLER_URL, installer, INSTALLER_LIMIT, deadline)
        allocation.require(sha(installer, INSTALLER_LIMIT) == INSTALLER_SHA256,
            'actual complete pinned archived native installer digest differs')
        stage, seed = prepare_seed(out, installer, commit=commit, source_sha256=source_sha256,
            setup_seconds=guest_setup_seconds, tail_seconds=tail_seconds,
            retention_seconds=retention_seconds, mode=mode, checked=checked)
        write_json(prep / 'seed.json', seed)
        with (out / 'work.raw').open('xb') as stream: stream.truncate(WORK_BYTES)
        checked('work-format', ['mkfs.ext4', '-F', '-m', '0', '-L', 'rillwork', '-d',
            str(stage), str(out / 'work.raw')], timeout=120)
        (out / 'user-data').write_text('#cloud-config\n' + json.dumps(cloud_config()) + '\n', encoding='utf-8')
        (out / 'meta-data').write_text('instance-id: rillscope-controller-canonical\n'
            'local-hostname: rillscope-controller-canonical\n', encoding='utf-8')
        checked('seed-create', ['cloud-localds', str(out / 'seed.iso'), str(out / 'user-data'), str(out / 'meta-data')],
            inputs=(out / 'user-data', out / 'meta-data'))
        checked('overlay-create', ['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2',
            '-b', str(image), str(out / 'disk.qcow2'), '20G'], large_inputs=(image,))
        runtime = out / 'runtime'; runtime.mkdir(mode=0o700); os.chown(runtime, account.pw_uid, account.pw_gid)
        for name in ('work.raw', 'disk.qcow2'):
            os.chown(out / name, account.pw_uid, account.pw_gid); os.chmod(out / name, 0o600)
        with socket.socket() as available:
            available.bind(('127.0.0.1', 0)); port = available.getsockname()[1]
        command = qemu_command(out, image, run_as, port)
        record.update(status='PREPARED SOURCE ONLY', seed=seed, command=command, qmp_port=port,
            qemu_run_as_uid=account.pw_uid, qemu_sha256=sha(qemu), image_sha256=IMAGE_SHA,
            image_signing_primary=FINGERPRINT, installer_sha256=sha(installer, INSTALLER_LIMIT),
            original_root=str(ROOT), original_output=out.relative_to(ROOT).as_posix())
        allocation.require(time.monotonic() < deadline and not any((out / 'artifact').iterdir()),
            'original preparation deadline or empty VM artifact invariant failed')
        source_check(commit, source_sha256)
        allocation.require(time.monotonic() < deadline, 'original source recheck consumed host preparation deadline')
        prepared = {'image': image, 'port': port, 'seed': seed, 'uid': account.pw_uid, 'command': command}
    except (Exception, KeyboardInterrupt) as error:
        record.update(status='FAIL', error=type(error).__name__, reason=str(error)[:2048]); raise
    finally:
        record.update(finished_monotonic_ns=time.monotonic_ns(), elapsed_seconds=time.monotonic() - started)
        if time.monotonic() >= deadline: record['status'] = 'FAIL'
        write_json(prep / 'preparation-result.json', record); fsync_directory(prep)
        if time.monotonic() >= deadline:
            record.update(status='FAIL', reason='original preparation deadline exhausted while retaining metadata')
            write_json(prep / 'preparation-result.json', record); fsync_directory(prep)
    allocation.require(record['status'] == 'PREPARED SOURCE ONLY' and prepared is not None,
        'original source-only preparation failed; retained metadata is authoritative')
    return prepared
