"""Replay bounded stopped-disk inventories and native boot/setup originals.

This checks included bytes and recorded execution. It neither reconstructs a
stopped VM nor grants allocation, continuous residency or reference qualification.
"""
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import time

import archive_capture
import canonical_reference_allocation as protocol
from canonical_reference_boot import validate_footer, parse_boot
from canonical_reference_guest_setup import check_rust_versions
from canonical_reference_host_setup import WORK_BYTES, IMAGE_SHA, FINGERPRINT
from canonical_reference_recovery import layout
from canonical_reference_retained_fresh import read_bounded_file, receipt, relative, instant
from canonical_reference_seed import validate_seed, INSTALLER_RELATIVE
from inspect_reference_guest import SERIAL_LIMIT
from kvm_reference_common import strict_json

MAX_FILES = 20000
MAX_DEPTH = 32
MAX_BYTES = 8 * 1024**3
MAX_FILE = 1024**3
MAX_INVENTORY = 8 * 1024**2
require = protocol.require


def span(row, seconds, *, lower, upper):
    values = [row.get(key) for key in ('started_monotonic_ns', 'finished_monotonic_ns', 'deadline_monotonic_ns')]
    require(all(protocol.integer(value) for value in values) and lower <= values[0] <= values[1] < values[2]
        and values[1] <= upper and abs(values[2] - values[0] - seconds * 10**9) <= 1000,
        'original stage clocks differ from its declared budget or enclosing interval')
    elapsed = row.get('elapsed_seconds')
    require(type(elapsed) in (int, float) and math.isfinite(elapsed) and elapsed >= 0
        and abs(elapsed - (values[1] - values[0]) / 10**9) <= .010,
        'original stage elapsed and recorded monotonic span differ')
    return values[0], values[1]


class OriginalRecords:
    """Hash held descriptors; retain every read identity for final rechecking."""
    def __init__(self, root, deadline):
        self.root = archive_capture.owned(root); self.deadline = deadline; self.identities = {}

    def remaining(self): require(time.monotonic() < self.deadline, 'original offline validation cutoff exhausted')

    def path(self, name):
        name = relative(name).as_posix(); archive_capture.member(name)
        require(len(PurePosixPath(name).parts) <= MAX_DEPTH, 'original metadata path depth exceeds bound')
        path = archive_capture.owned(self.root / name)
        require(path.is_relative_to(self.root), 'original evidence path left its declared root')
        return path

    def digest(self, name):
        self.remaining(); path = self.path(name); before = path.lstat()
        require(path.is_file() and not path.is_symlink() and 0 <= before.st_size <= MAX_FILE,
            'bounded original regular file required')
        identity = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns)
        value = hashlib.sha256(); count = 0
        with path.open('rb') as stream:
            require(identity(before) == identity(os.fstat(stream.fileno())), 'original descriptor changed before hashing')
            while block := stream.read(1024**2):
                self.remaining(); count += len(block); require(count <= before.st_size, 'original evidence grew while hashing')
                value.update(block)
            require(identity(before) == identity(os.fstat(stream.fileno())), 'original descriptor changed during hashing')
        digest = value.hexdigest()
        require(count == before.st_size and identity(before) == identity(path.lstat()), 'original file changed while hashing')
        require(name not in self.identities or self.identities[name] == (count, digest), 'previously read original bytes changed')
        self.identities[name] = (count, digest); return count, digest

    def raw(self, name, limit=16 * 1024**2):
        name = relative(name).as_posix(); self.remaining()
        raw = read_bounded_file(self.path(name), limit)
        value = (len(raw), hashlib.sha256(raw).hexdigest())
        require(name not in self.identities or self.identities[name] == value, 'original metadata snapshot changed')
        self.identities[name] = value; return raw

    def document(self, name, limit=16 * 1024**2):
        row = strict_json(self.raw(name, limit)); require(type(row) is dict, 'original metadata object required'); return row

    def scan(self, name):
        root = self.path(name); require(root.is_dir(), 'original recovered tree missing')
        pending = [root]; result = {}; entries = 0; spellings = {}
        while pending:
            self.remaining(); directory = pending.pop()
            for path in directory.iterdir():
                self.remaining(); entries += 1; require(entries <= 2 * MAX_FILES, 'original recovered entry bound exceeded')
                logical = path.relative_to(root).as_posix(); member = archive_capture.member(logical)
                require(len(member.parts) <= MAX_DEPTH and not path.is_symlink()
                    and not (hasattr(path, 'is_junction') and path.is_junction()), 'bounded link-free recovered paths required')
                directory = path.is_dir()
                for length in range(1, len(member.parts) + 1):
                    prefix = '/'.join(member.parts[:length]); key = prefix.casefold()
                    spelling = (prefix, length < len(member.parts) or directory)
                    require(key not in spellings or spellings[key] == spelling, 'recovered path case or file/directory alias')
                    spellings[key] = spelling
                if directory:
                    require(len(pending) < MAX_FILES, 'recovered directory frontier bound exceeded'); pending.append(path)
                else:
                    require(path.is_file() and len(result) < MAX_FILES, 'bounded regular recovered members required')
                    result[logical] = path.relative_to(self.root).as_posix()
        return result

    def unchanged(self):
        for name in tuple(self.identities): self.digest(name)


class RecoveryRecords(OriginalRecords):
    def __init__(self, artifact, expected, budget, *, deadline):
        super().__init__(artifact, deadline)
        self.record = self.document('recovery/recovery-result.json', 4 * 1024**2); row = self.record
        require(row == expected and row.get('schema_version') == 1 and type(row['schema_version']) is int
            and row.get('method') == protocol.METHOD and row.get('mode') == 'canonical'
            and row.get('status') == 'RECOVERED INCLUDED BYTES' and row.get('read_only') is True
            and row.get('disk_unchanged') is True and row.get('filesystem_clean') is True
            and row.get('reference_qualified') is False and row.get('errors') == [],
            'complete exact original stopped canonical recovery required')
        before = row.get('disk_before')
        require(type(before) is dict and set(before) == {'bytes', 'sha256'} and type(before['bytes']) is int
            and before['bytes'] == WORK_BYTES and protocol.hex_value(before['sha256'], 64) and row.get('disk_after') == before,
            'original stopped work-disk identity differs')
        finished = row.get('finished_monotonic_ns')
        require(protocol.integer(finished) and budget['started_monotonic_ns'] < finished <= budget['completed_monotonic_ns']
            < budget['actual_deadline_monotonic_ns'], 'recovery inventory finished outside original recovery interval')
        filesystem = self.raw('recovery/filesystem-state.txt', 65536).decode('utf-8')
        require(re.search(r'(?m)^Filesystem state:\s+clean\s*$', filesystem) is not None, 'original clean filesystem observation missing')
        trees = row.get('trees'); plan = layout('canonical')
        require(type(trees) is list and len(trees) == len(plan), 'all seven original recovery scopes required')
        self.trees = {}; self.members = {}; self.scans = {}; count = total = 0
        fields = {'name', 'guest_path', 'status', 'host_path', 'files', 'bytes', 'inventory', 'inventory_sha256'}
        for item, (name, guest_path, required) in zip(trees, plan):
            require(type(item) is dict and set(item) == fields and item['name'] == name and item['guest_path'] == guest_path
                and item['status'] == 'RECOVERED INCLUDED BYTES' and type(item['files']) is int and 0 < item['files'] <= MAX_FILES
                and type(item['bytes']) is int and 0 <= item['bytes'] <= MAX_BYTES
                and item['host_path'] in ('recovery/' + name, 'recovery/' + name + '/' + PurePosixPath(guest_path).name)
                and item['inventory'] == 'recovery/' + name + '-files.jsonl'
                and protocol.hex_value(item['inventory_sha256'], 64), 'closed original fixed recovered scope required')
            raw = self.raw(item['inventory'], MAX_INVENTORY)
            require(hashlib.sha256(raw).hexdigest() == item['inventory_sha256'], 'original recovered inventory digest differs')
            inventory = {}; size = 0
            stream = io.BytesIO(raw)
            while line := stream.readline(16385):
                require(len(inventory) < MAX_FILES and len(line) <= 16384 and line.endswith(b'\n'),
                    'bounded complete original recovered inventory lines required')
                entry = strict_json(line)
                require(type(entry) is dict and set(entry) == {'path', 'bytes', 'sha256'} and type(entry['bytes']) is int
                    and 0 <= entry['bytes'] <= MAX_FILE and protocol.hex_value(entry['sha256'], 64), 'closed recovered file identity required')
                path = relative(entry['path']).as_posix(); archive_capture.member(path)
                require(path not in inventory, 'duplicate recovered inventory member')
                logical = item['host_path'] + '/' + path
                require(self.digest(logical) == (entry['bytes'], entry['sha256']), 'included recovered file differs from original inventory')
                inventory[path] = logical; size += entry['bytes']
            actual = self.scan(item['host_path'])
            require(list(inventory) == sorted(inventory) and actual == inventory and required in inventory
                and len(inventory) == item['files'] and size == item['bytes'], 'recovered inventory omitted, added or reordered original files')
            count += len(inventory); total += size
            require(count <= MAX_FILES and total <= MAX_BYTES, 'aggregate recovered bound exceeded')
            self.trees[name] = item['host_path']; self.members[name] = inventory; self.scans[item['host_path']] = actual
        require(type(row.get('files')) is int and type(row.get('bytes')) is int and row['files'] == count and row['bytes'] == total,
            'original aggregate recovery inventory differs')

    def tree_document(self, tree, path, limit=4 * 1024**2):
        require(tree in self.members and path in self.members[tree], 'required included recovered metadata missing')
        return self.document(self.members[tree][path], limit)

    def unchanged(self):
        super().unchanged()
        require(all(self.scan(root) == scan for root, scan in self.scans.items()), 'recovered file set changed during validation')


def correlate_boot_progress(progress, footer, seed):
    validate_footer(footer)
    require(footer['status'] == 'PASS' and footer['mode'] == 'canonical' and footer['commit'] == seed['commit']
        and footer['source_sha256'] == seed['source_sha256'], 'complete exact-source canonical boot footer required')
    mutable = {'unmount_status', 'finished_monotonic_ns', 'utc_ns', 'status'}
    require(type(progress) is dict and set(progress) == set(footer)
        and all(progress[key] == footer[key] for key in set(footer) - mutable)
        and progress['unmount_status'] == 'PENDING' and progress['status'] == 'FAIL'
        and progress['finished_monotonic_ns'] is None and progress['utc_ns'] is None,
        'original pre-unmount progress differs from final serial observation')


def check_seed_source(seed, source):
    validate_seed(seed); expected = dict(source['files'])
    actual = {row['path']: row['sha256'] for row in seed['files']
        if not row['path'].startswith('.git/') and row['path'] != INSTALLER_RELATIVE}
    require(seed['source_sha256'] == source['sha256'] and actual == expected,
        'original source-only seed public file inventory differs from exact validator source')


class SetupCommands:
    def __init__(self, recovered): self.recovered = recovered
    def raw(self, path, limit=16 * 1024**2):
        name = relative(str(path)).as_posix()
        require(name.startswith('original-setup/'), 'unrelated native setup record')
        name = name[len('original-setup/'):]
        require(name in self.recovered.members['setup'], 'original native setup raw member missing')
        return self.recovered.raw(self.recovered.members['setup'][name], limit)
    def document(self, path, limit=16 * 1024**2):
        value = strict_json(self.raw(path, limit)); require(type(value) is dict, 'native setup object required'); return value


def native_versions(recovered, seed, seed_raw, source):
    home = '/work/c/.local-runs/canonical-home'
    prefix = ['/usr/bin/setpriv', '--reuid=65534', '--regid=65534', '--clear-groups', '--', '/usr/bin/env',
        'HOME=' + home, 'CARGO_HOME=' + home + '/.cargo', 'RUSTUP_HOME=' + home + '/.rustup', 'CARGO_INCREMENTAL=0',
        'PATH=' + home + '/.cargo/bin:/usr/bin:/bin', 'GIT_OPTIONAL_LOCKS=0', 'GIT_CONFIG_COUNT=2',
        'GIT_CONFIG_KEY_0=safe.directory', 'GIT_CONFIG_VALUE_0=/work/c',
        'GIT_CONFIG_KEY_1=safe.directory', 'GIT_CONFIG_VALUE_1=/work/c/.git', 'PYTHONDONTWRITEBYTECODE=1']
    metadata = SetupCommands(recovered); outputs = []; proofs = []
    commands = [('rustup-version', ['rustup', '--version']), ('rustc-version', ['rustc', '-vV']),
        ('cargo-version', ['cargo', '--version']), ('audit-version', ['cargo', 'audit', '--version']),
        ('deny-version', ['cargo', 'deny', '--version'])]
    expected = [{'path': '/work/c/.local-runs/canonical-seed/seed.json', 'bytes': len(seed_raw),
        'sha256': hashlib.sha256(seed_raw).hexdigest()}]
    for name, command in commands:
        directory = PurePosixPath('original-setup/commands') / name
        proof = receipt(metadata, directory, source=source, commit=seed['commit'], command=prefix + command, cwd=PurePosixPath('/work/c'))
        require(proof['inputs_before'] == proof['inputs_after'] == expected, 'native version original seed input differs')
        outputs.append(metadata.raw(directory / 'stdout.txt', 16384)); proofs.append(proof)
    return check_rust_versions(*outputs), proofs


def cleanup(row):
    require(type(row) is dict and row.get('status') == 'PASS'
        and type(row.get('remaining_active_processes')) is int and row['remaining_active_processes'] == 0,
        'actual terminal original process cleanup required')


def validate_prerequisites(attempt, terminal, *, source, deadline):
    """Check all seven stopped trees and original host/native prerequisite data."""
    attempt = archive_capture.owned(attempt); outer = OriginalRecords(attempt, deadline)
    plan, collector = terminal['plan'], terminal['collector']; commit = plan['commit']
    host = outer.document('utilities/provision-result.json', 4 * 1024**2)
    require(host == collector['host_utilities'] and host.get('method') == protocol.METHOD
        and host.get('status') == 'PREPARED HOST UTILITIES ONLY' and host.get('reference_qualified') is False
        and host.get('first_party_build') == 'NOT RUN', 'original host utility stage differs')
    host_start, host_end = span(host, plan['provision_seconds'], lower=collector['started_monotonic_ns'],
        upper=collector['finished_monotonic_ns']); cleanup(host.get('cleanup'))
    prepared = outer.document('vm/preparation/preparation-result.json', 4 * 1024**2)
    require(prepared.get('method') == protocol.METHOD and prepared.get('mode') == 'canonical'
        and prepared.get('status') == 'PREPARED SOURCE ONLY' and prepared.get('commit') == commit
        and prepared.get('source_sha256') == source['sha256'] and prepared.get('reference_qualified') is False
        and prepared.get('first_party_build_transported') is False and prepared.get('original_root') == terminal['original_root']
        and prepared.get('original_output') == (PurePosixPath(terminal['original_output']) / 'vm').relative_to(
            PurePosixPath(terminal['original_root'])).as_posix()
        and prepared.get('image_sha256') == IMAGE_SHA and prepared.get('image_signing_primary') == FINGERPRINT
        and protocol.hex_value(prepared.get('qemu_sha256'), 64)
        and protocol.integer(prepared.get('qemu_run_as_uid')) and type(prepared.get('qmp_port')) is int
        and 0 < prepared['qmp_port'] < 65536, 'original exact source-only host preparation differs')
    _prepare_start, prepare_end = span(prepared, plan['prepare_seconds'], lower=host_end, upper=collector['finished_monotonic_ns'])
    seed_raw = outer.raw('vm/preparation/seed.json', 4 * 1024**2); seed = strict_json(seed_raw)
    check_seed_source(seed, source)
    require(seed == prepared.get('seed') and seed['mode'] == 'canonical' and seed['commit'] == commit
        and seed['setup_seconds'] == plan['guest_setup_seconds'] and seed['tail_seconds'] == plan['guest_tail_seconds']
        and seed['retention_seconds'] == plan['guest_retention_seconds']
        and prepared.get('installer_sha256') == seed['installer_sha256'], 'original declared guest setup/finish/retention plan differs')
    artifact = attempt / 'vm/artifact'; recovered = RecoveryRecords(artifact, collector['recovery'],
        collector['recovery_budget'], deadline=deadline)
    vm = recovered.document('vm-result.json', 4 * 1024**2)
    require(vm == collector['vm'] and vm.get('status') == 'CAPTURED' and vm.get('method') == protocol.METHOD
        and vm.get('commit') == commit and vm.get('source_sha256') == source['sha256']
        and vm.get('failure') is None and vm.get('channel_thread_stopped') is True
        and vm.get('final_host_observed') is True and vm.get('reference_qualified') is False
        and type(vm.get('receiver_exit_before_owned_cleanup')) is int and vm['receiver_exit_before_owned_cleanup'] == 0
        and type(vm.get('qemu_exit_observed_before_owned_stop')) is int and vm['qemu_exit_observed_before_owned_stop'] == 0,
        'original complete source-bound canonical VM result differs')
    cleanup(vm.get('cleanup'))
    vm_start, vm_end, exited = (vm.get(key) for key in ('started_monotonic_ns', 'deadline_monotonic_ns', 'qemu_exit_observed_monotonic_ns'))
    require(all(protocol.integer(value) for value in (vm_start, vm_end, exited)) and prepare_end <= vm_start < exited < vm_end
        and vm_end - vm_start == plan['vm_seconds'] * 10**9
        and exited < collector['recovery_budget']['started_monotonic_ns'], 'original VM lease/terminal/recovery interval differs')
    process = recovered.document('original-process.json', 4 * 1024**2)
    require(process.get('command') == prepared['command'] and process.get('started_monotonic_ns') == vm_start
        and process.get('deadline_monotonic_ns') == vm_end and protocol.integer(process.get('pid')),
        'original owned QEMU launch differs from prepared command/lease')
    stopped = recovered.record.get('stopped_original')
    require(type(stopped) is dict and stopped.get('pid') == process['pid']
        and type(stopped.get('observed_returncode_after_owned_stop')) is int
        and stopped.get('command_sha256') == hashlib.sha256(json.dumps(process['command'], separators=(',', ':')).encode()).hexdigest(),
        'stopped recovery belongs to another original process/command')
    serial = recovered.raw('serial.txt', SERIAL_LIMIT).decode('utf-8')
    footer = parse_boot(serial)
    require(footer['seed_sha256'] == hashlib.sha256(seed_raw).hexdigest(), 'boot used different original seed bytes')
    correlate_boot_progress(recovered.tree_document('boot', 'boot-result.json'), footer, seed)
    require(footer['finished_monotonic_ns'] - footer['started_monotonic_ns']
        <= exited - vm_start + 10_000_000, 'recorded guest boot duration cannot fit actual enclosing VM lifetime')
    setup = recovered.tree_document('setup', 'setup-result.json')
    require(setup.get('method') == protocol.METHOD and setup.get('status') == 'PREPARED NATIVE TOOLS ONLY'
        and setup.get('commit') == commit and setup.get('source_sha256') == source['sha256']
        and setup.get('boot_id') == footer['boot_id'] and setup.get('first_party_build_transported') is False
        and setup.get('reference_qualified') is False and setup.get('canonical') == 'NOT RUN', 'original native prerequisite result differs')
    _setup_start, setup_end = span(setup, seed['setup_seconds'], lower=footer['started_monotonic_ns'], upper=footer['finished_monotonic_ns'])
    cleanup(setup.get('cleanup'))
    protocol.validate_environment({key: setup['environment'][key] for key in protocol.ENV_KEYS})
    retirement = setup.get('tool_target_retirement')
    require(type(retirement) is dict and retirement.get('status') in ('RETIRED', 'ABSENT'),
        'original stopped third-party setup cache disposition required')
    versions, version_proofs = native_versions(recovered, seed, seed_raw, source)
    require(versions == setup.get('versions'), 'original five native version outputs differ from result')
    previous_end = None; first_start = None; elapsed_total = 0
    for proof in version_proofs:
        start_utc, end_utc = instant(proof['started_utc']), instant(proof['finished_utc'])
        require(previous_end is None or previous_end <= start_utc, 'original native version receipt intervals overlap or reverse')
        require(proof['elapsed_seconds'] <= (end_utc - start_utc).total_seconds() + .010,
            'original native version elapsed exceeds its recorded UTC interval')
        if first_start is None: first_start = start_utc
        previous_end = end_utc; elapsed_total += proof['elapsed_seconds']
    require(elapsed_total <= setup['elapsed_seconds'] + .010
        and (previous_end - first_start).total_seconds() <= setup['elapsed_seconds'] + .010,
        'sequential original native version receipt intervals cannot fit actual setup duration')
    start = recovered.tree_document('start', 'start-result.json'); owner = recovered.tree_document('owner', 'owner-result.json')
    require(start.get('method') == protocol.METHOD and start.get('mode') == 'canonical' and start.get('status') == 'PASS'
        and start.get('commit') == commit and start.get('source_sha256') == source['sha256']
        and start.get('reference_qualified') is False and start.get('canonical') == 'ATTEMPTED'
        and start.get('native_setup_elapsed_seconds') == setup['elapsed_seconds'] and start.get('owner_result') == owner,
        'original native guest start is incomplete or substituted')
    require(owner.get('schema_version') == 1 and type(owner['schema_version']) is int and owner.get('method') == protocol.METHOD
        and owner.get('status') == 'PASS' and owner.get('commit') == commit and owner.get('source_sha256') == source['sha256']
        and owner.get('boot_id') == footer['boot_id'] and owner.get('reference_qualified') is False
        and owner.get('retention') == 'RETAINED', 'original canonical native owner failed')
    times = [owner.get(key) for key in ('started_monotonic_ns', 'canonical_started_monotonic_ns', 'canonical_finished_monotonic_ns',
        'finished_monotonic_ns', 'cutoff_monotonic_ns')]
    require(all(protocol.integer(value) for value in times) and setup_end <= times[0] <= times[1] < times[2] < times[3] < times[4]
        and protocol.integer(start.get('finished_monotonic_ns')) and times[3] <= start['finished_monotonic_ns'] < footer['finished_monotonic_ns'],
        'original setup/canonical/native-owner/final-boot chronology differs')
    cleanup(owner.get('cleanup'))
    retention = owner.get('native_retention')
    require(type(retention) is dict and retention.get('status') == 'RETAINED' and retention.get('errors') == []
        and retention.get('native_binaries') == retention.get('release_metadata') == 'RETAINED'
        and all(protocol.integer(retention.get(key)) for key in ('started_monotonic_ns', 'finished_monotonic_ns', 'cutoff_monotonic_ns'))
        and times[2] < retention['started_monotonic_ns'] <= retention['finished_monotonic_ns'] < retention['cutoff_monotonic_ns'] <= times[4]
        and retention['cutoff_monotonic_ns'] == min(times[4], retention['started_monotonic_ns'] + seed['retention_seconds'] * 10**9)
        and retention['finished_monotonic_ns'] <= times[3]
        and owner.get('retention_reserve_seconds') == seed['retention_seconds'], 'original shared native retention reserve failed')
    outer.unchanged(); recovered.unchanged()
    return {'status': 'CHECKED ORIGINAL RECOVERY AND NATIVE PREREQUISITES', 'outer': outer, 'recovered': recovered,
        'seed': seed, 'seed_raw': seed_raw, 'prepared': prepared, 'vm': vm, 'process': process,
        'footer': footer, 'serial': serial, 'setup': setup, 'start': start, 'owner': owner,
        'version_proofs': version_proofs, 'reference_qualified': False}
