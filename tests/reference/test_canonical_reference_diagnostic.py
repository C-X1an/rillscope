"""Actual small-file correlation with literal fixtures; no native/VM result."""
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import canonical_reference_diagnostic as diagnostic
from .test_canonical_reference_seed import literal_seed
from . import test_canonical_reference_boot as boot_fixtures
from . import test_canonical_reference_allocation as allocation_fixtures
from . import test_canonical_reference_guest_setup as setup_fixtures
from .test_canonical_git_permissions import actual_nonroot_fixture_prefix
from .test_canonical_git_guest import literal_guest_proof
from .test_canonical_git_trust import literal_setup_trust


class DiagnosticControls(unittest.TestCase):
    def test_guest_git_interval_must_fit_the_entire_native_setup_sequence(self):
        def stale(directory):
            path = directory / 'receipt.json'; row = json.loads(path.read_bytes())
            row.update(started_utc='2000-01-01T00:00:00+00:00', finished_utc='2000-01-01T00:00:01+00:00')
            path.write_text(json.dumps(row), encoding='utf-8')
        with self.assertRaises(ValueError): self.check(git_transform=stale)

    def records(self):
        seed = literal_seed(); seed['mode'] = 'native-setup-diagnostic'
        seed['files'].append({'path': 'scripts/canonical_reference_guest_owner.py', 'bytes': 1, 'mode': 0o644, 'sha256': 'c' * 64})
        seed['files'].sort(key=lambda row: row['path'])
        footer = boot_fixtures.NativeBootControls().fixture(); footer['mode'] = seed['mode']
        progress = copy.deepcopy(footer)
        progress.update(unmount_status='PENDING', status='FAIL', finished_monotonic_ns=None, utc_ns=None)
        fixture = allocation_fixtures.CanonicalAllocationTests(); fixture.setUp()
        common = {'method': diagnostic.allocation.METHOD, 'commit': seed['commit'],
            'source_sha256': seed['source_sha256'], 'reference_qualified': False,
            'canonical': 'NOT RUN', 'status': 'PREPARED NATIVE TOOLS ONLY'}
        setup = {**common, 'first_party_build_transported': False, 'cleanup': {'status': 'PASS'},
            'elapsed_seconds': 123.5, 'environment': fixture.request['environment'],
            'versions': diagnostic.check_rust_versions(*setup_fixtures.NativeSetupControls().outputs())}
        start = {**common, 'mode': seed['mode'], 'native_setup_elapsed_seconds': 123.5}
        recovered = {'status': 'RECOVERED INCLUDED BYTES', 'disk_unchanged': True,
            'filesystem_clean': True, 'trees': [
                {'name': name, 'host_path': name, 'status': 'RECOVERED INCLUDED BYTES'}
                for name in ('boot', 'setup', 'start')]}
        return seed, footer, recovered, {'boot': progress, 'setup': setup, 'start': start}

    def check(self, change=None, command_transform=None, git_transform=None, trust_transform=None):
        seed, footer, recovered, values = self.records()
        if change: change(seed, footer, recovered, values)
        local = ROOT / '.local-runs'; local.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='diag-meta-', dir=local) as directory:
            base = Path(directory); artifact = base / 'artifact'; artifact.mkdir()
            (base / 'preparation').mkdir()
            seed_raw = json.dumps(seed).encode(); (base / 'preparation/seed.json').write_bytes(seed_raw)
            footer['seed_sha256'] = hashlib.sha256(seed_raw).hexdigest()
            values['boot']['seed_sha256'] = footer['seed_sha256']
            for name, filename in [('boot', 'boot-result.json'), ('setup', 'setup-result.json'), ('start', 'start-result.json')]:
                (artifact / name).mkdir(); (artifact / name / filename).write_text(json.dumps(values[name]), encoding='utf-8')
            trust_input = literal_setup_trust(artifact / 'setup', values['setup'])
            home = '/work/c/.local-runs/canonical-home'
            prefix = ['/usr/bin/setpriv', '--reuid=65534', '--regid=65534', '--clear-groups', '--',
                '/usr/bin/env', 'HOME=' + home, 'CARGO_HOME=' + home + '/.cargo', 'RUSTUP_HOME=' + home + '/.rustup',
                'CARGO_INCREMENTAL=0', 'PATH=' + home + '/.cargo/bin:/usr/bin:/bin', 'GIT_OPTIONAL_LOCKS=0',
                'GIT_CONFIG_GLOBAL=/work/canonical-git-trust/config',
                'GIT_CONFIG_COUNT=2', 'GIT_CONFIG_KEY_0=safe.directory', 'GIT_CONFIG_VALUE_0=/work/c',
                'GIT_CONFIG_KEY_1=safe.directory', 'GIT_CONFIG_VALUE_1=/work/c/.git', 'PYTHONDONTWRITEBYTECODE=1']
            commands = [('rustup-version', ['rustup', '--version']), ('rustc-version', ['rustc', '-vV']),
                ('cargo-version', ['cargo', '--version']), ('audit-version', ['cargo', 'audit', '--version']),
                ('deny-version', ['cargo', 'deny', '--version'])]
            for index, ((name, command), raw) in enumerate(zip(commands, setup_fixtures.NativeSetupControls().outputs())):
                path = artifact / 'setup/commands' / name; path.mkdir(parents=True)
                (path / 'stdout.txt').write_bytes(raw); (path / 'stderr.txt').write_bytes(b'')
                inputs = [{'path': '/work/c/.local-runs/canonical-seed/seed.json',
                    'bytes': len(seed_raw), 'sha256': footer['seed_sha256']}, trust_input]
                receipt = {'command': prefix + command, 'cwd': '/work/c', 'verification_status': 'PASS',
                    'started_utc': '2026-10-25T00:00:0' + str(index + 1) + '+00:00',
                    'finished_utc': '2026-10-25T00:00:0' + str(index + 2) + '+00:00', 'elapsed_seconds': 1,
                    'exit_code': 0, 'execution_outcome': 'EXECUTED', 'source_before': {'sha256': seed['source_sha256']},
                    'source_after_sha256': seed['source_sha256'], 'git': {'commit': seed['commit'], 'dirty': False},
                    'process_cleanup': {'status': 'PASS', 'remaining_active_processes': 0},
                    'inputs_before': inputs, 'inputs_after': inputs,
                    'stdout': {'file': 'stdout.txt', 'sha256': hashlib.sha256(raw).hexdigest()},
                    'stderr': {'file': 'stderr.txt', 'sha256': hashlib.sha256(b'').hexdigest()}}
                if command_transform is not None: receipt['command'] = command_transform(receipt['command'])
                (path / 'receipt.json').write_text(json.dumps(receipt), encoding='utf-8')
            literal_guest_proof(artifact / 'setup/commands/guest-git-ownership', seed, seed_raw,
                {'sha256': seed['source_sha256']}, values['setup'])
            if git_transform is not None: git_transform(artifact / 'setup/commands/guest-git-ownership')
            if trust_transform is not None: trust_transform(artifact / 'setup', values['setup'])
            (artifact / 'setup/setup-result.json').write_text(json.dumps(values['setup']), encoding='utf-8')
            return diagnostic.check_setup_metadata(artifact, recovered, footer, seed)

    def test_protected_trust_original_role_and_captured_bytes_are_mandatory(self):
        def alter(directory, setup, kind):
            path = directory / 'git-trust-observation.json'
            if kind == 'missing': path.unlink(); return
            if kind == 'raw': (directory / 'git-trust-config.raw').write_bytes(b'changed original'); return
            row = json.loads(path.read_bytes()); row['uid'] = 65534
            setup['git_trust_before'] = dict(row); setup['git_trust_after'] = dict(row)
            path.write_text(json.dumps(row), encoding='utf-8')
        for kind in ('uid', 'raw', 'missing'):
            with self.subTest(kind=kind), self.assertRaises((ValueError, FileNotFoundError)):
                self.check(trust_transform=lambda directory, setup: alter(directory, setup, kind))

    def test_guest_original_command_raw_seed_and_deadline_are_required(self):
        def alter(directory, kind):
            path = directory / 'receipt.json'; row = json.loads(path.read_bytes())
            if kind == 'missing': path.unlink(); return
            if kind == 'command': row['command'] = ['/usr/bin/true']
            if kind == 'seed': row['inputs_before'][0]['sha256'] = 'd' * 64
            if kind == 'duration': row['elapsed_seconds'] = 31
            if kind == 'old-success':
                stdout = directory / 'stdout.txt'
                events = [json.loads(line) for line in stdout.read_bytes().splitlines()]
                events[11]['canonical_git_child_observation']['returncode'] = 0
                data = b''.join(json.dumps(event).encode() + b'\n' for event in events)
                stdout.write_bytes(data); row['stdout']['sha256'] = hashlib.sha256(data).hexdigest()
            path.write_text(json.dumps(row), encoding='utf-8')
        for kind in ('missing', 'command', 'seed', 'duration', 'old-success'):
            with self.subTest(kind=kind), self.assertRaises((ValueError, FileNotFoundError)):
                self.check(git_transform=lambda directory: alter(directory, kind))

    def test_actual_current_producer_version_commands_are_accepted(self):
        def actual(command):
            end = command.index('PYTHONDONTWRITEBYTECODE=1') + 1
            return actual_nonroot_fixture_prefix(PurePosixPath('/work/c'),
                PurePosixPath('/work/c/.local-runs/canonical-home'), command[end:])
        try: result = self.check(command_transform=actual)
        except ValueError as error: self.fail('Current actual producer command rejected: ' + str(error))
        self.assertEqual(result['elapsed_seconds'], 123.5)
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
                self.check(command_transform=lambda command: changed(command, kind))

    def test_correlated_progress_remains_unqualified_and_separate_from_final_footer(self):
        row = self.check()
        self.assertEqual(row['elapsed_seconds'], 123.5)
        self.assertIs(row['reference_qualified'], False)
        self.assertEqual(row['canonical'], 'NOT RUN'); self.assertEqual(row['provider_fit'], 'NOT MEASURED')

    def test_changed_boot_progress_source_or_final_unmount_cannot_be_accepted(self):
        for mutate in [lambda s, f, r, v: v['boot'].update(worker_pid=202),
            lambda s, f, r, v: v['boot'].update(status='PASS'),
            lambda s, f, r, v: f.update(unmount_status='FAIL'),
            lambda s, f, r, v: v['setup'].update(source_sha256='0' * 64),
            lambda s, f, r, v: r.update(disk_unchanged=False)]:
            with self.subTest(mutation=mutate):
                with self.assertRaises(ValueError): self.check(mutate)

    def test_canonical_activity_failed_setup_or_nonfinite_timing_is_not_diagnostic_success(self):
        for mutate in [lambda s, f, r, v: v['start'].update(owner_result={}),
            lambda s, f, r, v: v['start'].update(canonical='ATTEMPTED'),
            lambda s, f, r, v: v['setup'].update(status='FAIL'),
            lambda s, f, r, v: v['setup'].update(elapsed_seconds=float('inf')),
            lambda s, f, r, v: v['start'].update(native_setup_elapsed_seconds=1),
            lambda s, f, r, v: v['setup'].update(first_party_build_transported=True)]:
            with self.subTest(mutation=mutate):
                with self.assertRaises(ValueError): self.check(mutate)

    def test_missing_actual_controller_precedes_any_diagnostic_path_or_process(self):
        with patch.object(diagnostic, 'actual_controller', side_effect=ValueError('BLOCKED: actual scoped controller')):
            self.assertEqual(diagnostic.main(['--out', 'missing', '--run-as', 'runner']), 77)


if __name__ == '__main__': unittest.main()
