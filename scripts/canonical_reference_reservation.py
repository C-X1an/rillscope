"""Actual root controller action reserving its one new QEMU guest before a grant.

This is a component for the new canonical owner, not a runnable VM campaign or a
qualification verdict. It requires existing Linux root, the live original Popen
child, a clean source, and actual QMP resources. It never obtains privileges or
reuses/relabels an old guest. A failed/existing slot is not retried or overwritten.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import canonical_reference_allocation as protocol
from evidence import source_identity
from inspect_reference_guest import host_snapshot
from kvm_reference_host import check_sample
from reference_allocation import read_bounded, observed_boot_id
from canonical_reference_deadline import AllocationDeadline

MAX_PROCESS_BYTES = 65536
MAX_EXECUTABLE_BYTES = 256 * 1024**2
MAX_SUPPORT_BYTES = 2 * 1024**2


def parse_stat(raw, expected_pid):
    """Linux comm may contain spaces/parentheses; fields start after its last )."""
    protocol.require(protocol.integer(expected_pid) and type(raw) is bytes and 0 < len(raw) <= MAX_PROCESS_BYTES,
        'bounded original Linux process stat required')
    prefix, separator, fields = raw.rpartition(b') ')
    protocol.require(separator and prefix.startswith(str(expected_pid).encode('ascii') + b' ('),
        'actual process stat identity differs')
    parts = fields.split()
    protocol.require(len(parts) >= 20 and parts[1].isdigit() and parts[19].isdigit(),
        'actual process parent/start fields missing')
    return {'pid': expected_pid, 'ppid': int(parts[1]), 'start_ticks': int(parts[19])}


def parse_uids(raw):
    protocol.require(type(raw) is bytes and len(raw) <= MAX_PROCESS_BYTES,
        'bounded original Linux status required')
    rows = [line.split()[1:] for line in raw.splitlines() if line.startswith(b'Uid:')]
    protocol.require(len(rows) == 1 and len(rows[0]) == 4 and all(value.isdigit() for value in rows[0]),
        'complete actual Linux UID tuple required')
    return [int(value) for value in rows[0]]


def canonical_bytes(row, limit=MAX_SUPPORT_BYTES):
    raw = json.dumps(row, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')
    protocol.require(0 < len(raw) <= limit, 'original reservation record exceeds fixed bound')
    return raw


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def durable_mkdir(path, *, mode, exist_ok=False):
    """Persist this entry in its existing parent; failures leave a closed slot."""
    protocol.require(path.parent.is_dir() and not path.parent.is_symlink(),
        'existing link-free reservation parent required')
    path.mkdir(mode=mode, exist_ok=exist_ok)
    fsync_directory(path.parent)


def write_original(path, raw, *, budget=None):
    protocol.require(type(raw) is bytes and 0 < len(raw) <= MAX_SUPPORT_BYTES,
        'bounded original reservation bytes required')
    if budget is not None: budget.check()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, 'wb', closefd=False) as stream:
            protocol.require(stream.write(raw) == len(raw), 'incomplete original reservation write')
            stream.flush()
            if budget is not None: budget.check()
            os.fsync(stream.fileno())
            if budget is not None: budget.check()
        protocol.require(read_bounded(path, MAX_SUPPORT_BYTES) == raw,
            'original reservation bytes differ after write')
    finally:
        os.close(descriptor)
    fsync_directory(path.parent)
    if budget is not None: budget.check()
    return hashlib.sha256(raw).hexdigest()


def source_check(commit, source_sha256, *, budget=None):
    protocol.require(protocol.hex_value(commit, 40) and protocol.hex_value(source_sha256, 64),
        'exact expected canonical source required')
    def git(*args):
        command = ['git', '--no-optional-locks', '-c', 'core.fsmonitor=false',
            '-c', 'core.untrackedCache=false', '-c', 'safe.directory=' + str(ROOT), *args]
        if budget is not None: return budget.command(command, ROOT)
        return subprocess.check_output(command, cwd=ROOT, stdin=subprocess.DEVNULL, timeout=15)
    protocol.require(git('rev-parse', 'HEAD').decode().strip() == commit
        and not git('status', '--porcelain').strip()
        and (source_identity(ROOT) if budget is None else budget.source_identity(ROOT))['sha256'] == source_sha256,
        'actual clean controller source differs from expected canonical commit')
    if budget is not None: budget.check()


def live_child(process, command, uid, *, budget=None):
    if budget is not None: budget.check()
    protocol.require(type(process) is subprocess.Popen and process.poll() is None,
        'original live owned QEMU Popen child required')
    protocol.require(type(command) is list and 0 < len(command) <= 256
        and all(protocol.text(item, 4096) for item in command)
        and sum(len(item.encode('utf-8')) + 1 for item in command) <= MAX_PROCESS_BYTES,
        'bounded original QEMU command required')
    protocol.require(process.args == command and protocol.integer(uid),
        'original command and existing nonroot QEMU identity required')
    pid = process.pid
    row = parse_stat(read_bounded(Path('/proc') / str(pid) / 'stat', MAX_PROCESS_BYTES), pid)
    actual_uids = parse_uids(read_bounded(Path('/proc') / str(pid) / 'status', MAX_PROCESS_BYTES))
    actual_command = read_bounded(Path('/proc') / str(pid) / 'cmdline', MAX_PROCESS_BYTES)
    expected_command = b'\0'.join(os.fsencode(item) for item in command) + b'\0'
    # /proc/<pid>/exe is the kernel identity link. Resolve this specific kernel
    # interface intentionally; normal input paths still never traverse links.
    executable = (Path('/proc') / str(pid) / 'exe').resolve(strict=True)
    selected_executable = shutil.which(command[0])
    protocol.require(row['ppid'] == os.getpid() and row['start_ticks'] > 0
        and actual_uids == [uid] * 4 and actual_command == expected_command
        and selected_executable is not None and Path(selected_executable).resolve(strict=True) == executable
        and executable.name == 'qemu-system-x86_64',
        'live QEMU parent/start/UID/command/executable differs')
    digest = (hashlib.sha256(read_bounded(executable, MAX_EXECUTABLE_BYTES)).hexdigest()
        if budget is None else budget.digest(executable, MAX_EXECUTABLE_BYTES))
    row.update(uid=uid, command_sha256=hashlib.sha256(actual_command).hexdigest(),
        executable_sha256=digest)
    protocol.require(process.poll() is None, 'owned QEMU exited during original identity inspection')
    if budget is not None: budget.check()
    return row


def validate_qmp_binding(command, port, sample, qemu_pid, task_ids):
    """The observed QMP endpoint and every reported vCPU belong to this child."""
    protocol.require(type(port) is int and 0 < port < 65536
        and type(command) is list and command.count('-qmp') == 1
        and command.index('-qmp') + 1 < len(command)
        and command[command.index('-qmp') + 1] == 'tcp:127.0.0.1:' + str(port) + ',server=on,wait=off',
        'QMP endpoint differs from the original owned QEMU command')
    protocol.require(protocol.integer(qemu_pid) and type(task_ids) is set
        and 0 < len(task_ids) <= 256 and all(protocol.integer(value) for value in task_ids)
        and qemu_pid in task_ids and type(sample) is dict
        and type(sample.get('qemu_pid')) is int and sample['qemu_pid'] == qemu_pid,
        'actual QMP process/task identities differ')
    threads = sample.get('vcpu_threads')
    protocol.require(type(threads) is list and len(threads) == 4
        and all(type(row) is dict and protocol.integer(row.get('thread_id')) for row in threads)
        and len({row['thread_id'] for row in threads}) == 4
        and all(row['thread_id'] in task_ids for row in threads),
        'every unique reported vCPU must be an actual task of this QEMU child')


def actual_tasks(pid):
    result = set()
    for number, path in enumerate((Path('/proc') / str(pid) / 'task').iterdir()):
        protocol.require(number < 256 and path.name.isdigit() and path.is_dir() and not path.is_symlink(),
            'bounded actual QEMU task membership required')
        result.add(int(path.name))
    return result


def observed_membership(sample, pid):
    """Retain the actual procfs set; never derive it from QMP's claimed IDs."""
    protocol.require(type(sample) is dict and protocol.integer(pid)
        and type(sample.get('qemu_pid')) is int and sample['qemu_pid'] == pid,
        'original QMP process required before task membership observation')
    members = actual_tasks(pid)
    protocol.require(type(members) is set and 0 < len(members) <= 256 and pid in members
        and all(protocol.integer(value) for value in members), 'bounded actual QEMU task membership required')
    return {**sample, 'actual_qemu_task_ids': sorted(members)}, members


def create_grant(process, command, uid, port, request_raw, *, commit, source_sha256,
        vm_started_ns, vm_deadline_ns, allocation_id, exchange_deadline_ns=None, cancelled=None, identity=None):
    """Reserve the actual owned guest once; return only the original prior grant.

    The outer canonical owner must launch no competing guest workload, retain
    this directory with its complete attempt, enforce the returned lease and
    cleanup, and validate actual fresh/measurement records separately. The guest
    uses the exact grant bytes as original operator supporting evidence; full
    launch/QMP/reservation originals are retained here and hash-bound by the grant.
    """
    protocol.require(platform.system() == 'Linux' and hasattr(os, 'geteuid') and os.geteuid() == 0,
        'BLOCKED: actual existing Linux root controller required; no privilege acquisition')
    protocol.require(protocol.integer(exchange_deadline_ns) and protocol.integer(vm_deadline_ns)
        and exchange_deadline_ns <= vm_deadline_ns,
        'original exchange deadline must spend the existing VM lease')
    budget = AllocationDeadline(exchange_deadline_ns, cancelled)
    source_check(commit, source_sha256, budget=budget)
    def inspect(stage):
        if identity is None:return live_child(process, command, uid, budget=budget)
        from canonical_reference_process import ProcessReadiness
        protocol.require(type(identity) is ProcessReadiness, 'original in-process readiness identity required')
        identity.bind(process, command, uid, commit, source_sha256, vm_started_ns, vm_deadline_ns)
        return identity.verify(stage, budget=budget)
    qemu = inspect('grant-before')
    now = time.monotonic_ns()
    protocol.require(all(protocol.integer(value) for value in (vm_started_ns, vm_deadline_ns))
        and vm_started_ns <= now < vm_deadline_ns
        and 0 < vm_deadline_ns - vm_started_ns <= protocol.MAX_LEASE_NS,
        'original actual finite new-method VM lifetime required')
    protocol.require(protocol.hex_value(allocation_id, 32), 'original unpredictable allocation identity required')
    run_id, run_attempt = os.environ.get('GITHUB_RUN_ID', ''), os.environ.get('GITHUB_RUN_ATTEMPT', '')
    protocol.require(os.environ.get('GITHUB_REPOSITORY') == 'C-X1an/rillscope'
        and re.fullmatch('[1-9][0-9]{0,18}', run_id)
        and re.fullmatch('[1-9][0-9]{0,8}', run_attempt), 'actual authorized workflow run/attempt identity required')
    own = parse_stat(read_bounded(Path('/proc') / str(os.getpid()) / 'stat', MAX_PROCESS_BYTES), os.getpid())
    controller = {'pid': os.getpid(), 'start_ticks': own['start_ticks'], 'euid': os.geteuid(),
        'boot_id': observed_boot_id(), 'repository': os.environ['GITHUB_REPOSITORY'],
        'run_id': int(run_id), 'run_attempt': int(run_attempt)}
    base = ROOT / '.local-runs/canonical-reservations'
    for component in (base, *base.parents):
        protocol.require(not component.is_symlink(), 'link-free actual reservation root required')
        if component == ROOT: break
    budget.check(); durable_mkdir(base, mode=0o700, exist_ok=True); budget.check()
    info = base.lstat()
    protocol.require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
        'existing reservation root must be exclusively owned by actual root')
    # One durable identity per actual PID/start. mkdir is exclusive across
    # controllers/processes; failures, replays and abandoned slots remain closed.
    slot = base / ('vm-' + str(qemu['pid']) + '-' + str(qemu['start_ticks']))
    budget.check(); durable_mkdir(slot, mode=0o700); budget.check()
    result = {'status': 'FAIL', 'method': protocol.METHOD, 'reference_qualified': False}
    try:
        claim = {'method': protocol.METHOD, 'status': 'RESERVED ONE CAMPAIGN SLOT',
            'controller': controller, 'qemu': qemu, 'commit': commit, 'source_sha256': source_sha256,
            'allocation_id': allocation_id, 'monotonic_ns': time.monotonic_ns(),
            'scope': protocol.PHYSICAL_SCOPE, 'reference_qualified': False}
        write_original(slot / 'claim-created.json', canonical_bytes(claim), budget=budget)
        protocol.require(type(request_raw) is bytes and 0 < len(request_raw) < protocol.FRAME_LIMIT,
            'bounded original guest allocation request required')
        write_original(slot / 'request.json.raw', request_raw, budget=budget)
        request = protocol.decode(request_raw)
        protocol.validate_request(request, commit=commit, source_sha256=source_sha256)
        # This call inspects the actual owned VM and its host allocation now.
        # It establishes sampled resources; the root slot action above grants
        # guest assignment. Hardware alone never produces a positive statement.
        sample = budget.snapshot(process.pid, port)
        write_original(slot / 'qmp-observation-before-membership.json', canonical_bytes(sample), budget=budget)
        sample, members = observed_membership(sample, qemu['pid'])
        write_original(slot / 'qmp-and-resource-inspection.json', canonical_bytes(sample), budget=budget)
        validate_qmp_binding(command, port, sample, qemu['pid'], members)
        check_sample(sample, uid)
        launch = {'method': protocol.METHOD, 'controller': controller, 'qemu': qemu,
            'command': command, 'vm_started_monotonic_ns': vm_started_ns,
            'vm_deadline_monotonic_ns': vm_deadline_ns, 'commit': commit,
            'source_sha256': source_sha256, 'observed_monotonic_ns': time.monotonic_ns()}
        budget.check()
        launch_sha = write_original(slot / 'original-launch-inspection.json', canonical_bytes(launch), budget=budget)
        reserved = time.monotonic_ns()
        reservation = {'method': protocol.METHOD, 'status': 'ALLOCATED TO ONE CANONICAL CAMPAIGN',
            'allocation_id': allocation_id, 'commit': commit, 'source_sha256': source_sha256,
            'boot_id': request['boot_id'], 'nonce': request['nonce'], 'controller': controller,
            'qemu': qemu, 'reserved_monotonic_ns': reserved,
            'dedication': protocol.DEDICATION, 'physical_scope': protocol.PHYSICAL_SCOPE,
            'claim_created_sha256': hashlib.sha256(read_bounded(slot / 'claim-created.json', MAX_SUPPORT_BYTES)).hexdigest(),
            'reference_qualified': False}
        reservation_sha = write_original(slot / 'positive-reservation.json', canonical_bytes(reservation), budget=budget)
        authority = {'operator': 'scoped workflow root controller ' + run_id + '/' + run_attempt,
            'controller': controller, 'qemu': qemu, 'launch_sha256': launch_sha,
            'qmp_sha256': hashlib.sha256(read_bounded(slot / 'qmp-and-resource-inspection.json', MAX_SUPPORT_BYTES)).hexdigest(),
            'reservation_sha256': reservation_sha, 'reservation_id': allocation_id,
            'reserved_monotonic_ns': reserved, 'commit': commit, 'source_sha256': source_sha256,
            'boot_id': request['boot_id'], 'nonce': request['nonce'],
            'dedication': protocol.DEDICATION, 'physical_scope': protocol.PHYSICAL_SCOPE}
        protocol.require(inspect('grant-after') == qemu, 'actual QEMU identity changed before grant')
        source_check(commit, source_sha256, budget=budget)
        budget.check()
        grant = protocol.GrantSession(commit=commit, source_sha256=source_sha256).grant(request,
            authority, allocation_id=allocation_id, host_started_ns=vm_started_ns,
            host_deadline_ns=vm_deadline_ns, host_issued_ns=time.monotonic_ns())
        raw = protocol.encode(grant)
        budget.check()
        grant_sha = write_original(slot / 'grant.json.raw', raw, budget=budget)
        result.update(status='PRIOR GUEST ASSIGNMENT GRANTED', grant_sha256=grant_sha,
            slot=slot.relative_to(ROOT).as_posix(), completed_monotonic_ns=time.monotonic_ns(),
            scope='Actual exclusive guest assignment by this live controller; canonical execution, lease continuity and benchmark verdicts remain separate.')
        write_original(slot / 'reservation-result.json', canonical_bytes(result), budget=budget)
        budget.check()
        return raw, slot
    except BaseException as error:
        result.update(error=type(error).__name__, reason=str(error)[:2048], failed_monotonic_ns=time.monotonic_ns())
        write_original(slot / 'reservation-failure.json', canonical_bytes(result))
        raise
