"""Fixed scope and failure propagation controls; validators are stubbed only here."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import archive_capture
import verify_kvm_pilot as checker
from feasibility_profile import expectations


class OfflineContract(unittest.TestCase):
    def test_instrument_header_is_exact_and_typed(self):
        manifest = {'profile': 'instrumentation-pilot', 'chosen_workloads': copy.deepcopy(checker.INSTRUMENT),
            'seeds': [20261014], 'warmups': 5, 'repetitions': 30, 'expected_cases': 6, 'expected_observations': 630}
        result = {'profile': 'instrumentation-pilot', 'completed_cases': 6, 'expected_cases': 6, 'complete_grid': False}
        self.assertEqual(checker.scope_header('instrument', manifest, result), [])
        for field, value in (('seeds', [20261015]), ('expected_cases', True), ('warmups', 0)):
            changed = copy.deepcopy(manifest); changed[field] = value
            self.assertTrue(checker.scope_header('instrument', changed, result))
        changed = copy.deepcopy(manifest); changed['chosen_workloads'][0]['rows'] += 1
        self.assertTrue(checker.scope_header('instrument', changed, result))

    def test_sampling_reports_all_costs_and_rejects_clock_gaps(self):
        rows = [{'utc_ns': 1, 'monotonic_ns': 10, 'observer_wall_ns': 2, 'observer_cpu_ns': 1},
                {'utc_ns': 2, 'monotonic_ns': 20, 'observer_wall_ns': 3, 'observer_cpu_ns': 2}]
        self.assertEqual(checker.sampling(rows)['observer_wall_total_ns'], 5)
        for changed in (dict(rows[1], monotonic_ns=9), dict(rows[1], monotonic_ns=checker.MAX_GAP_NS + 11)):
            with self.assertRaises(ValueError): checker.sampling([rows[0], changed])

    def test_failed_upstream_remains_failed_after_all_stubbed_validators_pass(self):
        self.exercise(False)

    def test_missing_middle_package_does_not_suppress_other_validator_attempts(self):
        self.exercise(True)

    def test_failed_enclosing_owner_cannot_be_overridden_by_collected_child(self):
        self.exercise(False, child_status='COLLECTED', owner_status='FAIL')

    def test_complete_stubbed_campaigns_require_passing_original_owner(self):
        self.exercise(False, child_status='COLLECTED', owner_status='PASS')

    def test_supplied_sibling_receipt_cannot_borrow_canonical_owner_validation(self):
        self.exercise(False, child_status='COLLECTED', owner_status='PASS', supplied_name='sibling.json')

    def exercise(self, missing, child_status='FAIL', owner_status='PASS', supplied_name='receipt.json'):
        (ROOT / '.local-runs').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='ko-', dir=ROOT / '.local-runs') as temporary:
            base = Path(temporary); artifact = base / 'kp/artifact'; artifact.mkdir(parents=True)
            source = checker.source_identity(ROOT)
            payload = {'source': source, 'commit': '1' * 40, 'build_receipt': {'path': '.local-runs/kvm-build/build.json'}}
            checker.write_json(artifact / 'configuration.json', {'payload': payload, 'original_root': '/fixture/root',
                'original_output': '.local-runs/kp', 'command': ['qemu', '-runas', 'runner']})
            checker.write_json(artifact / 'results.json', {'status': child_status})
            owner = base / 'kvm-command'; owner.mkdir()
            (owner / 'stdout.txt').write_bytes(b'original owner stdout'); (owner / 'stderr.txt').write_bytes(b'')
            checker.write_json(owner / 'receipt.json', {'verification_status': owner_status,
                'exit_code': 0 if owner_status == 'PASS' else 124,
                'execution_outcome': 'EXECUTED' if owner_status == 'PASS' else 'TIMEOUT',
                'cwd': '/fixture/root', 'source_before': source, 'source_after_sha256': source['sha256'],
                'git': {'commit': payload['commit'], 'dirty': False},
                'environment': {'system': 'Linux'}, 'process_cleanup': {'status': 'PASS', 'remaining_active_processes': 0},
                'command': ['python3', 'scripts/kvm_benchmark_pilot.py', '--out', '.local-runs/kp', '--run-as', 'runner',
                    '--build-receipt', payload['build_receipt']['path'], '--commit', payload['commit']],
                'stdout': {'file': 'stdout.txt', 'sha256': checker.sha(owner / 'stdout.txt')},
                'stderr': {'file': 'stderr.txt', 'sha256': checker.sha(owner / 'stderr.txt')}})
            if supplied_name != 'receipt.json': checker.write_json(owner / supplied_name, {'not': 'an owner receipt'})
            checker.write_json(artifact / 'recovery.json', {'status': 'PASS'})
            for label, profile, _ in checker.STAGES:
                if missing and label == 'tail': continue
                raw = base / ('fixture-' + label); raw.mkdir()
                manifest = {'source': source, 'profile': profile, 'chosen_workloads':
                    copy.deepcopy(checker.INSTRUMENT) if label == 'instrument' else expectations(),
                    'seeds': [20261014], 'warmups': 5, 'repetitions': 30,
                    'expected_cases': 6 if label == 'instrument' else 3,
                    'expected_observations': 630 if label == 'instrument' else 315}
                result = {'profile': profile, 'completed_cases': manifest['expected_cases'],
                    'expected_cases': manifest['expected_cases'], 'complete_grid': False}
                checker.write_json(raw / 'manifest.json', manifest); checker.write_json(raw / 'results.json', result)
                packed = artifact / 'packages' / label
                archive_capture.pack(raw, packed)
                _, metadata = archive_capture.inspect(packed / 'capture.zip')
                checker.write_json(packed / 'transfer.json', {'stage': label, 'sha256': checker.sha(packed / 'capture.zip'),
                    'bytes': (packed / 'capture.zip').stat().st_size, 'metadata': metadata,
                    'status': 'VERIFIED HOST BYTES', 'reference_qualified': False})
            called = []
            def stub(path, *_):
                label = path.name.removeprefix('raw-'); called.append(label)
                return {'status': 'PASS', 'observations_checked': {'instrument': 630, 'tail': 315, 'cancel': 175}[label]}
            with patch.object(checker, 'verify', side_effect=stub), patch.object(checker, 'verify_cancellation', side_effect=stub), \
                    patch.object(checker, 'continuity', return_value={'status': 'PASS'}):
                report = checker.validate(artifact, base / 'validated', owner / supplied_name)
            expected = 'PASS' if not missing and child_status == 'COLLECTED' and owner_status == 'PASS' and supplied_name == 'receipt.json' else 'FAIL'
            self.assertEqual(report['status'], expected)
            if child_status != 'COLLECTED': self.assertIn('original upstream collection failed or missing', report['errors'])
            self.assertEqual(called, ['instrument', 'cancel'] if missing else ['instrument', 'tail', 'cancel'])
            self.assertFalse(report['reference_qualified'])


if __name__ == '__main__': unittest.main()
