"""Literal tiny inventory/clock controls; never a native VM or execution proof."""
import copy
import datetime as dt
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import archive_capture
import canonical_reference_recovered_records as records
from . import test_canonical_reference_boot as boot_fixtures
from . import test_canonical_reference_seed as seed_fixtures
from . import test_canonical_reference_allocation as allocation_fixtures
from . import test_canonical_reference_guest_setup as setup_fixtures
from .test_canonical_git_permissions import actual_nonroot_fixture_prefix
from .test_canonical_git_guest import literal_guest_proof
from .test_canonical_git_trust import literal_setup_trust
from . import test_canonical_reference_native_apt as apt_fixtures


def raw(row): return (json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n').encode()
def digest(value): return hashlib.sha256(value).hexdigest()


def literal_apt_acquisition(folder, setup, seed, seed_raw, source):
    """Literal tiny metadata only. No APT process or file role is exercised."""
    policy, _ = apt_fixtures.fixture()
    observation = {'nodes': policy['nodes'], 'ancestors': policy['ancestors']}
    setup['apt_acquisition'] = {'policy': policy, 'checks': [{'stage': name,
        'before': copy.deepcopy(observation), 'after': copy.deepcopy(observation)} for name in ('apt-update', 'apt-install')]}
    inputs = [{'path': apt_fixtures.KEY, 'bytes': len(apt_fixtures.PUBLIC_KEY_FIXTURE), 'sha256': digest(apt_fixtures.PUBLIC_KEY_FIXTURE)},
        {'path': apt_fixtures.DIR + '/native.sources', 'bytes': len(apt_fixtures.SOURCE), 'sha256': digest(apt_fixtures.SOURCE)},
        {'path': '/work/c/.local-runs/canonical-seed/seed.json', 'bytes': len(seed_raw), 'sha256': digest(seed_raw)}]
    prefix = ['/usr/bin/apt-get', '-o', 'Dir::Etc::sourcelist=' + apt_fixtures.DIR + '/native.sources',
        '-o', 'Dir::Etc::sourceparts=' + apt_fixtures.DIR + '/empty-sources.d', '-o', 'Acquire::Languages=none',
        '-o', 'Acquire::AllowInsecureRepositories=false', '-o', 'Acquire::AllowWeakRepositories=false',
        '-o', 'Acquire::AllowDowngradeToInsecureRepositories=false', '-o', 'Acquire::Check-Valid-Until=true',
        '-o', 'APT::Get::AllowUnauthenticated=false']
    for index, (name, suffix) in enumerate([('apt-update', ['--error-on=any', 'update']),
            ('apt-install', ['install', '--yes', '--no-install-recommends', *apt_fixtures.PACKAGES])]):
        directory = folder / 'commands' / name; directory.mkdir(parents=True)
        value = b'SYNTHETIC successful command output; no command executed\n'
        proof = {'schema_version': 1, 'command': prefix + suffix, 'cwd': '/work/c', 'source_before': source,
            'source_after_sha256': source['sha256'], 'verification_status': 'PASS', 'execution_outcome': 'EXECUTED', 'exit_code': 0,
            'process_cleanup': {'status': 'PASS', 'remaining_active_processes': 0}, 'environment': {'system': 'Linux'},
            'git': {'commit': seed['commit'], 'dirty': False},
            'started_utc': '2026-10-24T23:59:5' + str(4 + index * 2) + '+00:00',
            'finished_utc': '2026-10-24T23:59:5' + str(5 + index * 2) + '+00:00', 'elapsed_seconds': 1,
            'stdout': {'file': 'stdout.txt', 'sha256': digest(value)}, 'stderr': {'file': 'stderr.txt', 'sha256': digest(b'')},
            'inputs_before': inputs, 'inputs_after': inputs, 'stdin': None, 'fixture': 'No command executed'}
        (directory / 'receipt.json').write_bytes(raw(proof)); (directory / 'stdout.txt').write_bytes(value); (directory / 'stderr.txt').write_bytes(b'')


def fixture(root, *, canonical_path=False):
    artifact = root / ('.local-runs/capture/vm/artifact' if canonical_path else '.local-runs/capture/artifact')
    (artifact / 'recovery').mkdir(parents=True)
    scopes = [('boot', '/c/.local-runs/canonical-boot', 'boot-result.json'),
        ('setup', '/c/.local-runs/canonical-setup', 'setup-result.json'),
        ('start', '/c/.local-runs/canonical-start', 'start-result.json'),
        ('allocation', '/c/.local-runs/canonical-allocation', 'reference-host-receipt.json'),
        ('owner', '/c/.local-runs/canonical-attempt', 'owner-result.json'),
        ('control', '/c/.local-runs/kvm-reference/control', 'grid-request.json'),
        ('observer', '/c/.local-runs/kvm-reference/exports', 'canonical-guest-samples.jsonl')]
    row = {'schema_version': 1, 'method': records.protocol.METHOD, 'mode': 'canonical',
        'status': 'RECOVERED INCLUDED BYTES', 'read_only': True, 'disk_unchanged': True,
        'filesystem_clean': True, 'reference_qualified': False, 'errors': [],
        'disk_before': {'bytes': 17179869184, 'sha256': 'c' * 64},
        'disk_after': {'bytes': 17179869184, 'sha256': 'c' * 64}, 'finished_monotonic_ns': 150,
        'files': 7, 'bytes': 21, 'trees': []}
    (artifact / 'recovery/filesystem-state.txt').write_bytes(b'Filesystem state:         clean\n')
    for name, guest, required in scopes:
        folder = artifact / 'recovery' / name; folder.mkdir(); (folder / required).write_bytes(b'{}\n')
        listing = raw({'path': required, 'bytes': 3, 'sha256': digest(b'{}\n')})
        inventory = 'recovery/' + name + '-files.jsonl'; (artifact / inventory).write_bytes(listing)
        row['trees'].append({'name': name, 'guest_path': guest, 'status': 'RECOVERED INCLUDED BYTES',
            'host_path': 'recovery/' + name, 'files': 1, 'bytes': 3,
            'inventory': inventory, 'inventory_sha256': digest(listing)})
    (artifact / 'recovery/recovery-result.json').write_bytes(raw(row))
    budget = {'started_monotonic_ns': 100, 'completed_monotonic_ns': 200, 'actual_deadline_monotonic_ns': 300}
    return artifact, row, budget


def reindex(artifact, recovery):
    recovery['files'] = recovery['bytes'] = 0
    for item in recovery['trees']:
        folder = artifact / item['host_path']; entries = []
        for path in sorted(folder.rglob('*')):
            if path.is_file():
                value = path.read_bytes(); entries.append({'path': path.relative_to(folder).as_posix(), 'bytes': len(value), 'sha256': digest(value)})
        inventory = b''.join(raw(entry) for entry in entries)
        (artifact / item['inventory']).write_bytes(inventory)
        item.update(files=len(entries), bytes=sum(row['bytes'] for row in entries), inventory_sha256=digest(inventory))
        recovery['files'] += item['files']; recovery['bytes'] += item['bytes']
    (artifact / 'recovery/recovery-result.json').write_bytes(raw(recovery))


def prerequisite_fixture(root):
    """Explicitly synthetic clocks, source and receipts; no command is executed."""
    artifact, recovery, budget = fixture(root, canonical_path=True); attempt = artifact.parent.parent; second = 10**9
    seed = seed_fixtures.literal_seed(); seed.update(setup_seconds=900, tail_seconds=60, retention_seconds=180)
    seed['files'].append({'path': 'scripts/canonical_reference_guest_owner.py', 'bytes': 1, 'mode': 0o644, 'sha256': 'c' * 64})
    seed['files'].sort(key=lambda row: row['path'])
    source = {'sha256': seed['source_sha256'], 'files': [[row['path'], row['sha256']] for row in seed['files']
        if not row['path'].startswith('.git/') and row['path'] != records.INSTALLER_RELATIVE]}
    seed_raw = raw(seed); preparation = attempt / 'vm/preparation'; preparation.mkdir(parents=True)
    (preparation / 'seed.json').write_bytes(seed_raw)
    footer = boot_fixtures.NativeBootControls().fixture()
    footer.update(seed_sha256=digest(seed_raw), started_monotonic_ns=10 * second, finished_monotonic_ns=18000 * second)
    progress = copy.deepcopy(footer); progress.update(unmount_status='PENDING', status='FAIL', finished_monotonic_ns=None, utc_ns=None)
    (artifact / 'recovery/boot/boot-result.json').write_bytes(raw(progress))
    common = {'method': records.protocol.METHOD, 'commit': seed['commit'], 'source_sha256': source['sha256'], 'reference_qualified': False}
    complete = {'status': 'PASS', 'remaining_active_processes': 0}
    environment = allocation_fixtures.CanonicalAllocationTests(); environment.setUp()
    outputs = setup_fixtures.NativeSetupControls().outputs()
    setup = {**common, 'status': 'PREPARED NATIVE TOOLS ONLY', 'boot_id': footer['boot_id'], 'canonical': 'NOT RUN',
        'first_party_build_transported': False, 'started_monotonic_ns': 12 * second, 'finished_monotonic_ns': 112 * second,
        'deadline_monotonic_ns': 912 * second, 'elapsed_seconds': 100.0, 'cleanup': complete,
        'environment': environment.request['environment'], 'versions': records.check_rust_versions(*outputs),
        'tool_target_retirement': {'status': 'RETIRED', 'fixture': 'No cache existed; literal expected shape only'}}
    setup['started_utc_ns'] = int(dt.datetime(2026, 10, 24, 23, 59, 53, tzinfo=dt.timezone.utc).timestamp()) * second
    setup['finished_utc_ns'] = setup['started_utc_ns'] + 100 * second
    (artifact / 'recovery/setup/setup-result.json').write_bytes(raw(setup))
    trust_input = literal_setup_trust(artifact / 'recovery/setup', setup)
    home = '/work/c/.local-runs/canonical-home'
    prefix = ['/usr/bin/setpriv', '--reuid=65534', '--regid=65534', '--clear-groups', '--', '/usr/bin/env',
        'HOME=' + home, 'CARGO_HOME=' + home + '/.cargo', 'RUSTUP_HOME=' + home + '/.rustup', 'CARGO_INCREMENTAL=0',
        'PATH=' + home + '/.cargo/bin:/usr/bin:/bin', 'GIT_OPTIONAL_LOCKS=0',
        'GIT_CONFIG_GLOBAL=/work/canonical-git-trust/config', 'GIT_CONFIG_COUNT=2',
        'GIT_CONFIG_KEY_0=safe.directory', 'GIT_CONFIG_VALUE_0=/work/c',
        'GIT_CONFIG_KEY_1=safe.directory', 'GIT_CONFIG_VALUE_1=/work/c/.git', 'PYTHONDONTWRITEBYTECODE=1']
    commands = [('rustup-version', ['rustup', '--version']), ('rustc-version', ['rustc', '-vV']),
        ('cargo-version', ['cargo', '--version']), ('audit-version', ['cargo', 'audit', '--version']),
        ('deny-version', ['cargo', 'deny', '--version'])]
    inputs = [{'path': '/work/c/.local-runs/canonical-seed/seed.json', 'bytes': len(seed_raw), 'sha256': digest(seed_raw)}, trust_input]
    for index, ((name, command), value) in enumerate(zip(commands, outputs)):
        directory = artifact / 'recovery/setup/commands' / name; directory.mkdir(parents=True)
        proof = {'schema_version': 1, 'command': prefix + command, 'cwd': '/work/c', 'source_before': source,
            'source_after_sha256': source['sha256'], 'verification_status': 'PASS', 'execution_outcome': 'EXECUTED', 'exit_code': 0,
            'process_cleanup': complete, 'environment': {'system': 'Linux'}, 'git': {'commit': seed['commit'], 'dirty': False},
            'started_utc': '2026-10-25T00:00:0' + str(index) + '+00:00',
            'finished_utc': '2026-10-25T00:00:0' + str(index + 1) + '+00:00', 'elapsed_seconds': 1,
            'stdout': {'file': 'stdout.txt', 'sha256': digest(value)}, 'stderr': {'file': 'stderr.txt', 'sha256': digest(b'')},
            'inputs_before': inputs, 'inputs_after': inputs, 'stdin': None, 'fixture': 'No command executed'}
        (directory / 'receipt.json').write_bytes(raw(proof)); (directory / 'stdout.txt').write_bytes(value); (directory / 'stderr.txt').write_bytes(b'')
    literal_guest_proof(artifact / 'recovery/setup/commands/guest-git-ownership', seed, seed_raw, source, setup)
    literal_apt_acquisition(artifact / 'recovery/setup', setup, seed, seed_raw, source)
    # Explicitly synthetic same-boot monotonic observations; never execution evidence.
    starts = {'apt-update': 13, 'apt-install': 15, 'guest-git-ownership': 17,
        'rustup-version': 19, 'rustc-version': 20, 'cargo-version': 21, 'audit-version': 22, 'deny-version': 23}
    for name, begin in starts.items():
        path = artifact / 'recovery/setup/commands' / name / 'receipt.json'; proof = json.loads(path.read_bytes())
        proof['monotonic'] = {'schema_version': 1, 'clock': 'time.monotonic_ns', 'started_ns': begin * second,
            'finished_ns': begin * second + int(proof['elapsed_seconds'] * second)}
        path.write_bytes(raw(proof))
    (artifact / 'recovery/setup/setup-result.json').write_bytes(raw(setup))
    owner = {**common, 'schema_version': 1, 'status': 'PASS', 'boot_id': footer['boot_id'], 'retention': 'RETAINED',
        'cleanup': complete, 'started_monotonic_ns': 120 * second, 'canonical_started_monotonic_ns': 121 * second,
        'canonical_finished_monotonic_ns': 17000 * second, 'finished_monotonic_ns': 17010 * second,
        'cutoff_monotonic_ns': 19000 * second, 'retention_reserve_seconds': 180,
        'native_retention': {'status': 'RETAINED', 'errors': [], 'native_binaries': 'RETAINED', 'release_metadata': 'RETAINED',
            'started_monotonic_ns': 17001 * second, 'finished_monotonic_ns': 17009 * second, 'cutoff_monotonic_ns': 17181 * second}}
    (artifact / 'recovery/owner/owner-result.json').write_bytes(raw(owner))
    start = {**common, 'mode': 'canonical', 'status': 'PASS', 'canonical': 'ATTEMPTED',
        'native_setup_elapsed_seconds': 100.0, 'owner_result': owner, 'finished_monotonic_ns': 17011 * second}
    (artifact / 'recovery/start/start-result.json').write_bytes(raw(start))
    command = ['qemu-system-x86_64', '-qmp', 'tcp:127.0.0.1:1234,server=on,wait=off']
    vm = {**common, 'status': 'CAPTURED', 'failure': None, 'channel_thread_stopped': True, 'final_host_observed': True,
        'receiver_exit_before_owned_cleanup': 0, 'qemu_exit_observed_before_owned_stop': 0, 'cleanup': complete,
        'started_monotonic_ns': 126 * second, 'deadline_monotonic_ns': 20166 * second, 'qemu_exit_observed_monotonic_ns': 19000 * second}
    (artifact / 'vm-result.json').write_bytes(raw(vm))
    (artifact / 'original-process.json').write_bytes(raw({'pid': 202, 'command': command,
        'started_monotonic_ns': vm['started_monotonic_ns'], 'deadline_monotonic_ns': vm['deadline_monotonic_ns']}))
    (artifact / 'serial.txt').write_bytes(b'RILLSCOPE_CANONICAL_BOOT_V1 ' + base64.b64encode(raw(footer)) + b'\n')
    prepared = {**common, 'mode': 'canonical', 'status': 'PREPARED SOURCE ONLY', 'first_party_build_transported': False,
        'original_root': '/repo', 'original_output': '.local-runs/attempt/vm', 'image_sha256': records.IMAGE_SHA,
        'image_signing_primary': records.FINGERPRINT, 'qemu_sha256': 'd' * 64, 'qemu_run_as_uid': 1001, 'qmp_port': 1234,
        'started_monotonic_ns': 121 * second, 'finished_monotonic_ns': 125 * second,
        'deadline_monotonic_ns': 301 * second, 'elapsed_seconds': 4.0, 'seed': seed, 'installer_sha256': seed['installer_sha256'], 'command': command}
    (preparation / 'preparation-result.json').write_bytes(raw(prepared))
    (attempt / 'utilities').mkdir()
    utilities = {'method': records.protocol.METHOD, 'status': 'PREPARED HOST UTILITIES ONLY', 'reference_qualified': False,
        'first_party_build': 'NOT RUN', 'started_monotonic_ns': 110 * second, 'finished_monotonic_ns': 120 * second,
        'deadline_monotonic_ns': 230 * second, 'elapsed_seconds': 10.0, 'cleanup': complete}
    (attempt / 'utilities/provision-result.json').write_bytes(raw(utilities))
    budget.update(started_monotonic_ns=19005 * second, completed_monotonic_ns=19015 * second, actual_deadline_monotonic_ns=19305 * second)
    recovery.update(finished_monotonic_ns=19010 * second, stopped_original={'pid': 202, 'observed_returncode_after_owned_stop': 0,
        'command_sha256': digest(json.dumps(command, separators=(',', ':')).encode())})
    reindex(artifact, recovery)
    terminal = {'plan': {'commit': seed['commit'], 'provision_seconds': 120, 'prepare_seconds': 180, 'vm_seconds': 20040,
        'guest_setup_seconds': 900, 'guest_tail_seconds': 60, 'guest_retention_seconds': 180},
        'collector': {'started_monotonic_ns': 100 * second, 'finished_monotonic_ns': 19016 * second,
            'host_utilities': utilities, 'vm': vm, 'recovery': recovery, 'recovery_budget': budget},
        'original_root': '/repo', 'original_output': '/repo/.local-runs/attempt'}
    return attempt, artifact, terminal, source


class RecoveredRecordControls(unittest.TestCase):
    def test_protected_trust_role_and_raw_custody_cannot_be_reindexed_away(self):
        for kind in ('uid', 'raw', 'missing'):
            with self.subTest(kind=kind):
                local = ROOT / '.local-runs'; local.mkdir(exist_ok=True)
                with tempfile.TemporaryDirectory(prefix='g29-', dir=local) as directory:
                    root = Path(directory).resolve()
                    if sys.platform == 'win32': root = Path('\\\\?\\' + str(root))
                    attempt, artifact, terminal, source = prerequisite_fixture(root)
                    setup_dir = artifact / 'recovery/setup'; observation = setup_dir / 'git-trust-observation.json'
                    if kind == 'missing': observation.unlink()
                    elif kind == 'raw': (setup_dir / 'git-trust-config.raw').write_bytes(b'changed original')
                    else:
                        row = json.loads(observation.read_bytes()); row['uid'] = 65534; observation.write_bytes(raw(row))
                        path = setup_dir / 'setup-result.json'; setup = json.loads(path.read_bytes())
                        setup['git_trust_before'] = dict(row); setup['git_trust_after'] = dict(row); path.write_bytes(raw(setup))
                    reindex(artifact, terminal['collector']['recovery'])
                    with patch.object(archive_capture, 'ROOT', root), self.assertRaises((ValueError, FileNotFoundError)):
                        records.validate_prerequisites(attempt, terminal, source=source, deadline=time.monotonic() + 30)

    def test_prerequisite_fixture_constructs_final_path_without_directory_rename(self):
        local = ROOT / '.local-runs'; local.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='g26-', dir=local) as directory:
            root = Path(directory).resolve()
            if sys.platform == 'win32': root = Path('\\\\?\\' + str(root))
            with patch.object(Path, 'rename', side_effect=AssertionError('synthetic directory rename forbidden')):
                try: attempt, artifact, terminal, source = prerequisite_fixture(root)
                except AssertionError as error: self.fail(str(error))
            self.assertEqual(artifact, attempt / 'vm/artifact')
            with patch.object(archive_capture, 'ROOT', root):
                result = records.validate_prerequisites(attempt, terminal, source=source, deadline=time.monotonic() + 30)
            self.assertEqual(result['status'], 'CHECKED ORIGINAL RECOVERY AND NATIVE PREREQUISITES')

    def test_original_guest_transport_proof_is_mandatory_after_reindexing(self):
        for kind in ('missing', 'command', 'seed', 'duration', 'old-success'):
            with self.subTest(kind=kind):
                local = ROOT / '.local-runs'; local.mkdir(exist_ok=True)
                with tempfile.TemporaryDirectory(prefix='g25-', dir=local) as directory:
                    root = Path(directory).resolve()
                    if sys.platform == 'win32': root = Path('\\\\?\\' + str(root))
                    attempt, artifact, terminal, source = prerequisite_fixture(root)
                    proof_dir = artifact / 'recovery/setup/commands/guest-git-ownership'
                    path = proof_dir / 'receipt.json'; row = json.loads(path.read_bytes())
                    if kind == 'missing': path.unlink()
                    else:
                        if kind == 'command': row['command'] = ['/usr/bin/true']
                        if kind == 'seed': row['inputs_before'][0]['sha256'] = 'd' * 64
                        if kind == 'duration': row['elapsed_seconds'] = 31
                        if kind == 'old-success':
                            stdout = proof_dir / 'stdout.txt'
                            events = [json.loads(line) for line in stdout.read_bytes().splitlines()]
                            events[11]['canonical_git_child_observation']['returncode'] = 0
                            data = b''.join(json.dumps(event).encode() + b'\n' for event in events)
                            stdout.write_bytes(data); row['stdout']['sha256'] = digest(data)
                        path.write_bytes(raw(row))
                    reindex(artifact, terminal['collector']['recovery'])
                    with patch.object(archive_capture, 'ROOT', root), self.assertRaises((ValueError, FileNotFoundError)):
                        records.validate_prerequisites(attempt, terminal, source=source, deadline=time.monotonic() + 30)

    def native_commands(self, transform):
        local = ROOT / '.local-runs'; local.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='n19-', dir=local) as directory:
            root = Path(directory).resolve()
            if sys.platform == 'win32': root = Path('\\\\?\\' + str(root))
            attempt, artifact, terminal, source = prerequisite_fixture(root)
            paths = {path.parent.name: path for path in (artifact / 'recovery/setup/commands').glob('*/receipt.json')}
            versions = {'rustup-version', 'rustc-version', 'cargo-version', 'audit-version', 'deny-version'}
            self.assertEqual(set(paths), versions | {'guest-git-ownership', 'apt-update', 'apt-install'})
            # This synthetic transformer changes only the five original
            # nonroot version commands. Root APT has separate exact bindings.
            for name in sorted(versions):
                path = paths[name]
                row = json.loads(path.read_bytes()); row['command'] = transform(row['command']); path.write_bytes(raw(row))
            reindex(artifact, terminal['collector']['recovery'])
            with patch.object(archive_capture, 'ROOT', root):
                return records.validate_prerequisites(attempt, terminal, source=source, deadline=time.monotonic() + 30)

    def test_actual_current_producer_version_commands_are_accepted(self):
        def actual(command):
            end = command.index('PYTHONDONTWRITEBYTECODE=1') + 1
            return actual_nonroot_fixture_prefix(PurePosixPath('/work/c'),
                PurePosixPath('/work/c/.local-runs/canonical-home'), command[end:])
        try: result = self.native_commands(actual)
        except ValueError as error: self.fail('Current actual producer command rejected: ' + str(error))
        self.assertEqual(result['status'], 'CHECKED ORIGINAL RECOVERY AND NATIVE PREREQUISITES')
        self.assertIs(result['reference_qualified'], False)

    def test_old_extra_wildcard_and_foreign_git_trust_entries_are_rejected(self):
        def changed(command, kind):
            if kind == 'old':
                return ['GIT_CONFIG_COUNT=1' if value == 'GIT_CONFIG_COUNT=2' else value
                    for value in command if value not in {'GIT_CONFIG_KEY_1=safe.directory', 'GIT_CONFIG_VALUE_1=/work/c/.git'}]
            if kind == 'extra':
                command = ['GIT_CONFIG_COUNT=3' if value == 'GIT_CONFIG_COUNT=2' else value for value in command]
                index = command.index('PYTHONDONTWRITEBYTECODE=1')
                return command[:index] + ['GIT_CONFIG_KEY_2=safe.directory', 'GIT_CONFIG_VALUE_2=/foreign'] + command[index:]
            return ['GIT_CONFIG_VALUE_1=' + ('*' if kind == 'wildcard' else '/foreign/.git')
                if value == 'GIT_CONFIG_VALUE_1=/work/c/.git' else value for value in command]
        for kind in ('old', 'extra', 'wildcard', 'foreign'):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.native_commands(lambda command: changed(command, kind))

    def check(self, change=None):
        with tempfile.TemporaryDirectory(prefix='rill-recovered-unit-') as name:
            root = Path(name).resolve(); artifact, row, budget = fixture(root)
            if change: change(artifact, row, budget)
            (artifact / 'recovery/recovery-result.json').write_bytes(raw(row))
            with patch.object(archive_capture, 'ROOT', root):
                value = records.RecoveryRecords(artifact, row, budget, deadline=time.monotonic() + 30)
                self.assertEqual(list(value.trees), ['boot', 'setup', 'start', 'allocation', 'owner', 'control', 'observer'])
                self.assertEqual(sum(len(rows) for rows in value.members.values()), 7)
                self.assertEqual(value.tree_document('boot', 'boot-result.json'), {})
                value.unchanged()
                return value.record

    def test_exact_original_seven_inventory_scopes_and_every_included_file(self):
        self.assertEqual(self.check()['bytes'], 21)

    def test_changed_omitted_and_added_files_are_rejected(self):
        mutations = [lambda a, r, b: (a / 'recovery/boot/boot-result.json').write_bytes(b'changed'),
            lambda a, r, b: (a / 'recovery/boot/boot-result.json').unlink(),
            lambda a, r, b: (a / 'recovery/boot/added.json').write_bytes(b'{}')]
        for mutate in mutations:
            with self.subTest(mutation=mutate), self.assertRaises((ValueError, FileNotFoundError)): self.check(mutate)

    def test_changed_disk_and_late_recovery_or_missing_scope_stay_failed(self):
        for mutate in [lambda a, r, b: r['disk_after'].update(sha256='d' * 64),
            lambda a, r, b: r.update(finished_monotonic_ns=301),
            lambda a, r, b: r['trees'].pop(), lambda a, r, b: r.update(files=True),
            lambda a, r, b: r.update(read_only=False)]:
            with self.subTest(mutation=mutate), self.assertRaises(ValueError): self.check(mutate)

    def test_inventory_traversal_duplicate_unterminated_and_wrong_hash_rejected(self):
        values = [raw({'path': '../outside', 'bytes': 3, 'sha256': digest(b'{}\n')}),
            raw({'path': 'boot-result.json', 'bytes': 3, 'sha256': digest(b'{}\n')}) * 2,
            raw({'path': 'boot-result.json', 'bytes': 3, 'sha256': digest(b'{}\n')}).rstrip(b'\n'),
            raw({'path': 'boot-result.json', 'bytes': True, 'sha256': digest(b'{}\n')})]
        for value in values:
            def mutate(artifact, row, budget):
                item = row['trees'][0]; (artifact / item['inventory']).write_bytes(value); item['inventory_sha256'] = digest(value)
            with self.subTest(value=value), self.assertRaises(ValueError): self.check(mutate)

    def test_original_clock_span_cannot_be_shortened_or_shifted_outside_parent(self):
        row = {'started_monotonic_ns': 1000000000, 'finished_monotonic_ns': 2500000000,
            'deadline_monotonic_ns': 4000000000, 'elapsed_seconds': 1.5}
        self.assertEqual(records.span(row, 3, lower=1, upper=3000000000), (1000000000, 2500000000))
        for changed in [{**row, 'elapsed_seconds': .1}, {**row, 'finished_monotonic_ns': 5000000000},
            {**row, 'started_monotonic_ns': True}]:
            with self.subTest(changed=changed), self.assertRaises(ValueError): records.span(changed, 3, lower=1, upper=3000000000)

    def test_pre_unmount_failed_progress_is_not_relabelled_as_final_pass(self):
        seed = seed_fixtures.literal_seed(); footer = boot_fixtures.NativeBootControls().fixture()
        progress = copy.deepcopy(footer); progress.update(unmount_status='PENDING', status='FAIL', finished_monotonic_ns=None, utc_ns=None)
        records.correlate_boot_progress(progress, footer, seed)
        self.assertEqual(progress['status'], 'FAIL'); self.assertEqual(footer['status'], 'PASS')
        for changed in [{**progress, 'status': 'PASS'}, {**progress, 'worker_pid': 999}]:
            with self.subTest(changed=changed), self.assertRaises(ValueError): records.correlate_boot_progress(changed, footer, seed)

    def test_seed_must_include_exact_public_source_without_unlisted_extra_payload(self):
        seed = seed_fixtures.literal_seed()
        public = [[row['path'], row['sha256']] for row in seed['files']
            if not row['path'].startswith('.git/') and row['path'] != records.INSTALLER_RELATIVE]
        source = {'sha256': seed['source_sha256'], 'files': public}; records.check_seed_source(seed, source)
        changed = copy.deepcopy(seed); changed['files'].append({'path': 'unknown.rs', 'bytes': 1, 'mode': 0o644, 'sha256': 'c' * 64})
        changed['files'].sort(key=lambda item: item['path'])
        with self.assertRaises(ValueError): records.check_seed_source(changed, source)

    def test_expired_offline_cutoff_rejects_before_reading_records(self):
        with tempfile.TemporaryDirectory(prefix='rill-recovered-unit-') as name:
            root = Path(name).resolve(); artifact, row, budget = fixture(root)
            with patch.object(archive_capture, 'ROOT', root):
                with self.assertRaisesRegex(ValueError, 'cutoff'): records.RecoveryRecords(artifact, row, budget, deadline=time.monotonic() - 1)

    def test_complete_literal_prerequisites_bind_native_versions_and_keep_scope_unqualified(self):
        with tempfile.TemporaryDirectory(prefix='rill-recovered-unit-') as name:
            root = Path(name).resolve(); attempt, artifact, terminal, source = prerequisite_fixture(root)
            with patch.object(archive_capture, 'ROOT', root):
                result = records.validate_prerequisites(attempt, terminal, source=source, deadline=time.monotonic() + 30)
                self.assertEqual(result['status'], 'CHECKED ORIGINAL RECOVERY AND NATIVE PREREQUISITES')
                self.assertEqual(len(result['version_proofs']), 5)
                self.assertEqual(result['setup']['elapsed_seconds'], 100.0)
                self.assertIs(result['reference_qualified'], False)

    def test_native_setup_original_seed_input_and_raw_version_changes_are_rejected(self):
        for mutate in [lambda row: row['inputs_before'][0].update(bytes=1), lambda row: row.update(command=['invented', '--version']),
            lambda row: row.update(source_after_sha256='e' * 64), lambda row: row.update(exit_code=1)]:
            with self.subTest(mutation=mutate), tempfile.TemporaryDirectory(prefix='rill-recovered-unit-') as name:
                root = Path(name).resolve(); attempt, artifact, terminal, source = prerequisite_fixture(root)
                path = artifact / 'recovery/setup/commands/rustup-version/receipt.json'
                row = json.loads(path.read_bytes()); mutate(row); path.write_bytes(raw(row)); reindex(artifact, terminal['collector']['recovery'])
                with patch.object(archive_capture, 'ROOT', root), self.assertRaises(ValueError):
                    records.validate_prerequisites(attempt, terminal, source=source, deadline=time.monotonic() + 30)

    def test_native_apt_original_arguments_inputs_roles_and_intervals_are_required(self):
        for kind in ('missing-stage', 'writable-after', 'broad-sources', 'allow-unauthenticated',
                'unchecked-update', 'coherent-wrong-input', 'ancient-clock', 'over-budget'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix='rill-apt-record-unit-') as name:
                root = Path(name).resolve(); attempt, artifact, terminal, source = prerequisite_fixture(root)
                path = artifact / 'recovery/setup/setup-result.json'
                if kind in ('missing-stage', 'writable-after'):
                    value = json.loads(path.read_bytes())
                    if kind == 'missing-stage': value['apt_acquisition']['checks'].pop()
                    else: value['apt_acquisition']['checks'][1]['after']['nodes'][1]['mode'] = 0o666
                else:
                    path = artifact / 'recovery/setup/commands/apt-update/receipt.json'
                    value = json.loads(path.read_bytes())
                    if kind == 'broad-sources':
                        value['command'] = ['Dir::Etc::sourceparts=/etc/apt/sources.list.d' if arg.startswith('Dir::Etc::sourceparts=') else arg for arg in value['command']]
                    elif kind == 'allow-unauthenticated': value['command'].insert(1, '--allow-unauthenticated')
                    elif kind == 'unchecked-update': value['command'].remove('--error-on=any')
                    elif kind == 'coherent-wrong-input':
                        for field in ('inputs_before', 'inputs_after'): value[field][1]['sha256'] = 'f' * 64
                    elif kind == 'ancient-clock':
                        value.update(started_utc='2000-01-01T00:00:00+00:00', finished_utc='2000-01-01T00:00:01+00:00')
                    else: value.update(elapsed_seconds=301)
                path.write_bytes(raw(value)); reindex(artifact, terminal['collector']['recovery'])
                with patch.object(archive_capture, 'ROOT', root), self.assertRaises(ValueError):
                    records.validate_prerequisites(attempt, terminal, source=source, deadline=time.monotonic() + 30)

    def test_preparation_identity_and_native_owner_deadline_cannot_be_substituted(self):
        for relative, field, value in [('vm/preparation/preparation-result.json', 'image_sha256', 'e' * 64),
            ('vm/artifact/recovery/owner/owner-result.json', 'cutoff_monotonic_ns', 16900 * 10**9),
            ('vm/artifact/recovery/setup/setup-result.json', 'boot_id', 'ffffffff-ffff-ffff-ffff-ffffffffffff')]:
            with self.subTest(field=field), tempfile.TemporaryDirectory(prefix='rill-recovered-unit-') as name:
                root = Path(name).resolve(); attempt, artifact, terminal, source = prerequisite_fixture(root)
                path = attempt / relative; row = json.loads(path.read_bytes()); row[field] = value; path.write_bytes(raw(row))
                reindex(artifact, terminal['collector']['recovery'])
                with patch.object(archive_capture, 'ROOT', root), self.assertRaises(ValueError):
                    records.validate_prerequisites(attempt, terminal, source=source, deadline=time.monotonic() + 30)

    def test_shared_retention_cutoff_cannot_exceed_exact_recorded_original_reserve(self):
        with tempfile.TemporaryDirectory(prefix='rill-recovered-unit-') as name:
            root = Path(name).resolve(); attempt, artifact, terminal, source = prerequisite_fixture(root)
            path = artifact / 'recovery/owner/owner-result.json'; owner = json.loads(path.read_bytes())
            owner['native_retention']['cutoff_monotonic_ns'] = owner['cutoff_monotonic_ns']; path.write_bytes(raw(owner))
            path = artifact / 'recovery/start/start-result.json'; start = json.loads(path.read_bytes())
            start['owner_result'] = owner; path.write_bytes(raw(start)); reindex(artifact, terminal['collector']['recovery'])
            with patch.object(archive_capture, 'ROOT', root), self.assertRaisesRegex(ValueError, 'retention reserve'):
                records.validate_prerequisites(attempt, terminal, source=source, deadline=time.monotonic() + 30)

    def test_native_version_durations_must_fit_the_original_setup_interval(self):
        with tempfile.TemporaryDirectory(prefix='rill-recovered-unit-') as name:
            root = Path(name).resolve(); attempt, artifact, terminal, source = prerequisite_fixture(root)
            for path in (artifact / 'recovery/setup/commands').glob('*/receipt.json'):
                row = json.loads(path.read_bytes()); row['elapsed_seconds'] = 40; path.write_bytes(raw(row))
            reindex(artifact, terminal['collector']['recovery'])
            with patch.object(archive_capture, 'ROOT', root), self.assertRaisesRegex(ValueError, 'native version'):
                records.validate_prerequisites(attempt, terminal, source=source, deadline=time.monotonic() + 30)


if __name__ == '__main__': unittest.main()
