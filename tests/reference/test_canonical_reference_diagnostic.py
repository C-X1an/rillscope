"""Actual small-file correlation with literal fixtures; no native/VM result."""
import copy
import hashlib
import json
from pathlib import Path
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


class DiagnosticControls(unittest.TestCase):
    def records(self):
        seed = literal_seed(); seed['mode'] = 'native-setup-diagnostic'
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

    def check(self, change=None):
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
            home = '/work/c/.local-runs/canonical-home'
            prefix = ['/usr/bin/setpriv', '--reuid=65534', '--regid=65534', '--clear-groups', '--',
                '/usr/bin/env', 'HOME=' + home, 'CARGO_HOME=' + home + '/.cargo', 'RUSTUP_HOME=' + home + '/.rustup',
                'CARGO_INCREMENTAL=0', 'PATH=' + home + '/.cargo/bin:/usr/bin:/bin', 'GIT_OPTIONAL_LOCKS=0',
                'GIT_CONFIG_COUNT=1', 'GIT_CONFIG_KEY_0=safe.directory', 'GIT_CONFIG_VALUE_0=/work/c', 'PYTHONDONTWRITEBYTECODE=1']
            commands = [('rustup-version', ['rustup', '--version']), ('rustc-version', ['rustc', '-vV']),
                ('cargo-version', ['cargo', '--version']), ('audit-version', ['cargo', 'audit', '--version']),
                ('deny-version', ['cargo', 'deny', '--version'])]
            for (name, command), raw in zip(commands, setup_fixtures.NativeSetupControls().outputs()):
                path = artifact / 'setup/commands' / name; path.mkdir(parents=True)
                (path / 'stdout.txt').write_bytes(raw); (path / 'stderr.txt').write_bytes(b'')
                inputs = [{'path': '/work/c/.local-runs/canonical-seed/seed.json', 'sha256': footer['seed_sha256']}]
                receipt = {'command': prefix + command, 'cwd': '/work/c', 'verification_status': 'PASS',
                    'exit_code': 0, 'execution_outcome': 'EXECUTED', 'source_before': {'sha256': seed['source_sha256']},
                    'source_after_sha256': seed['source_sha256'], 'git': {'commit': seed['commit'], 'dirty': False},
                    'process_cleanup': {'status': 'PASS', 'remaining_active_processes': 0},
                    'inputs_before': inputs, 'inputs_after': inputs,
                    'stdout': {'file': 'stdout.txt', 'sha256': hashlib.sha256(raw).hexdigest()},
                    'stderr': {'file': 'stderr.txt', 'sha256': hashlib.sha256(b'').hexdigest()}}
                (path / 'receipt.json').write_text(json.dumps(receipt), encoding='utf-8')
            return diagnostic.check_setup_metadata(artifact, recovered, footer, seed)

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
