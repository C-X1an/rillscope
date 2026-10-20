"""Full verifier rejects reduced scope, omitted failures and missing provenance."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import verify_kvm_reference as check
from workloads import descriptors, sort_null_descriptors
from kvm_reference_common import SEEDS


class FullValidation(unittest.TestCase):
    def payload(self):
        files = [['Cargo.toml', 'a' * 64]]
        return {'commit': 'b' * 40, 'source': {'files': files,
            'sha256': hashlib.sha256(json.dumps(files, separators=(',', ':')).encode()).hexdigest()}}

    def test_declared_full_scope_cannot_pass_with_a_reduced_or_incomplete_result(self):
        payload = self.payload()
        manifest = {'source': payload['source'], 'commit': payload['commit'], 'dirty': False,
            'schema_version': 3, 'profile': 'full', 'warmups': 5, 'repetitions': 30, 'seeds': SEEDS,
            'chosen_workloads': descriptors(), 'expected_cases': 410, 'expected_observations': 43050}
        result = {'schema_version': 3, 'profile': 'full', 'completed_cases': 410, 'expected_cases': 410,
            'complete_grid': True, 'instrumentation_status': 'PASS', 'invalid_observations': 0,
            'source_binary_inputs_stable': True}
        check.completed_scope('grid', manifest, result, payload)
        for field, value in [('completed_cases', 409), ('complete_grid', False), ('invalid_observations', 1)]:
            bad = {**result, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                check.completed_scope('grid', manifest, bad, payload)
        manifest['chosen_workloads'] = descriptors()[:6]
        with self.assertRaises(ValueError): check.completed_scope('grid', manifest, result, payload)

    def test_every_seed_keeps_p95_target_misses_and_separate_end_to_end(self):
        rows = []
        for index, seed in enumerate(SEEDS):
            rows.append({'workload': {'id': 'B01-n100000-s10-null10-b1024'}, 'seed': seed,
                'independent_semantic_comparisons': 60,
                'metrics': {'rust-on': {'success_only_execution_ns': {'n': 30, 'p95': 999999999 if index == 0 else 1000000000},
                    'all_outcome_metrics': {'wall_ns': {'n': 30, 'p95': 2000000000}}}}})
        targets = check.filter_targets({'summaries': rows})
        self.assertEqual([row['seed'] for row in targets], SEEDS)
        self.assertEqual([row['observed_target_status'] for row in targets], ['MET', 'MISSED', 'MISSED', 'MISSED', 'MISSED'])
        self.assertEqual(targets[0]['end_to_end_ns']['p95'], 2000000000)
        self.assertFalse(targets[0]['reference_qualified'])
        for bad in [rows[:-1], rows + [rows[0]]]:
            with self.assertRaises(ValueError): check.filter_targets({'summaries': bad})
        rows[0]['metrics']['rust-on']['success_only_execution_ns']['n'] = 29
        with self.assertRaises(ValueError): check.filter_targets({'summaries': rows})

    def test_cancellation_misses_are_reported_without_changing_correctness(self):
        result = {'status': 'PASS', 'observations': 175, 'measured_observations': 150,
            'invalid_observations': 0, 'target_observations_over_100ms': 1,
            'cancel_upper_bound_ns': {'n': 150, 'p95': 100000001}}
        target = check.cancel_target(result)
        self.assertEqual(target['observed_target_status'], 'MISSED')
        self.assertFalse(target['reference_qualified'])
        result['measured_observations'] = 149
        with self.assertRaises(ValueError): check.cancel_target(result)

    def test_missing_original_input_produces_all_three_failed_scopes_and_no_success(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.local-runs') as temp:
            base = Path(temp); artifact = base / 'artifact'; artifact.mkdir()
            result = check.validate(artifact, base / 'validation', base / 'missing-owner/receipt.json')
            self.assertEqual(result['status'], 'FAIL')
            self.assertFalse(result['reference_qualified'])
            self.assertEqual([row['stage'] for row in result['campaigns']], ['grid', 'cancel', 'sort-null'])
            self.assertTrue(all(row['status'] == 'FAIL' for row in result['campaigns']))
            self.assertEqual(result['canonical_fresh'], 'NOT RUN')
            self.assertTrue(result['errors'])
            self.assertTrue((base / 'validation/results.json').is_file())


class OriginalDevicePreflight(unittest.TestCase):
    def fixture(self, base):
        artifact = base / 'artifact'; guest = base / 'guest'; owner = base / 'owner'
        for path in [artifact, guest, owner / 'capture-device-open']: path.mkdir(parents=True)
        payload = {'commit': '1' * 40, 'source': {'sha256': '2' * 64}}
        raw = b'{"original_payload":true}\n'; (artifact / 'payload.json').write_bytes(raw)
        value = {'alias': '/dev/virtio-ports/org.rillscope.reference-capture',
            'node': '/dev/vport1p2', 'port_name': 'org.rillscope.reference-capture',
            'major': 1, 'minor': 2, 'filesystem_device': 7, 'inode': 91,
            'rdev': 258, 'uid': 65534, 'gid': 65534, 'mode': 0o600}
        common = {'identity_before': value, 'identity_after': value, 'groups': [],
            'bytes_read': 0, 'bytes_written': 0}
        grant = dict(common, status='GRANTED', uid=0, gid=0, opened_monotonic_ns=100, closed_monotonic_ns=200)
        probe = dict(common, status='OPENED', uid=65534, gid=65534, opened_monotonic_ns=300, closed_monotonic_ns=400)
        report = {'schema_version': 1, 'status': 'VERIFIED', 'commit': payload['commit'],
            'source_sha256': payload['source']['sha256'], 'grant': grant, 'probe': probe}
        (guest / 'device-access.json').write_text(json.dumps(report))
        (owner / 'capture-device-open/stdout.txt').write_text(json.dumps(probe))
        inputs = [{'path': '/work/c/.local-runs/kvm-input/payload.json',
            'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}]
        receipt = {'command': ['/usr/bin/setpriv', '--reuid=65534', '--regid=65534', '--clear-groups', '--',
            '/usr/bin/python3', '/work/c/scripts/kvm_reference_device.py', 'probe'],
            'inputs_before': inputs, 'inputs_after': inputs}
        return artifact, payload, guest, owner, report, receipt

    def test_original_source_bound_nobody_open_and_close_before_measurement_are_mandatory(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.local-runs') as temp:
            artifact, payload, guest, owner, report, receipt = self.fixture(Path(temp))
            with patch.object(check, 'passing_receipt', return_value=receipt) as passing:
                self.assertEqual(check.capture_device_access(artifact, payload, guest, owner, 1000), report)
            passing.assert_called_once_with(owner / 'capture-device-open', payload['source'])
            (guest / 'device-access.json').unlink()
            with self.assertRaisesRegex(ValueError, 'bounded regular measurement record'):
                check.capture_device_access(artifact, payload, guest, owner, 1000)

    def test_root_probe_changed_input_or_source_and_late_preflight_are_rejected(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.local-runs') as temp:
            artifact, payload, guest, owner, report, receipt = self.fixture(Path(temp))
            for field, value in [('status', 'FAIL'), ('source_sha256', '3' * 64), ('schema_version', True)]:
                changed = copy.deepcopy(report); changed[field] = value
                (guest / 'device-access.json').write_text(json.dumps(changed))
                with patch.object(check, 'passing_receipt', return_value=receipt), self.assertRaises(ValueError):
                    check.capture_device_access(artifact, payload, guest, owner, 1000)
            (guest / 'device-access.json').write_text(json.dumps(report))
            for changed in [dict(receipt, command=receipt['command'][5:]),
                dict(receipt, inputs_after=[])]:
                with patch.object(check, 'passing_receipt', return_value=changed), self.assertRaises(ValueError):
                    check.capture_device_access(artifact, payload, guest, owner, 1000)
            with patch.object(check, 'passing_receipt', return_value=receipt), self.assertRaises(ValueError):
                check.capture_device_access(artifact, payload, guest, owner, 399)

    def test_retained_stdout_must_equal_the_validated_probe_observation(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.local-runs') as temp:
            artifact, payload, guest, owner, report, receipt = self.fixture(Path(temp))
            changed = copy.deepcopy(report['probe']); changed['uid'] = 0
            (owner / 'capture-device-open/stdout.txt').write_text(json.dumps(changed))
            with patch.object(check, 'passing_receipt', return_value=receipt), self.assertRaises(ValueError):
                check.capture_device_access(artifact, payload, guest, owner, 1000)


class FullResultsMetadata(unittest.TestCase):
    def full_fixture(self):
        # Independently specified, full-scale producer-shaped metadata. These
        # literal statistics are a parser fixture, never benchmark measurements.
        metric_names = ['wall_ns', 'cpu_user_ns', 'cpu_system_ns', 'peak_rss_bytes',
            'execution_only_ns', 'execution_call_wall_ns', 'load_ns', 'compile_ns',
            'serialization_ns', 'materialization_ns', 'consumed_work', 'visible_work', 'peak_reserved_bytes']
        distribution = {'n': 30, 'min': 123456789, 'p50': 234567890,
            'p95': 345678901, 'p99': 456789012, 'max': 456789012,
            'median_absolute_deviation': 12345678}
        modes = {name: {'observations': 30, 'outcomes': {'OK': 30}, 'invalid_observations': 0,
            'all_outcome_metrics': {metric: distribution for metric in metric_names},
            'success_only_execution_ns': distribution} for name in ['rust-on', 'rust-off', 'sqlite']}
        modes['pairing'] = {'pairs': 30, 'wall_on_minus_off_ns': distribution,
            'p99_interpretation': 'nearest-rank descriptive order statistic; 30 observations do not establish a tail guarantee'}
        rows = [{'workload': description, 'seed': seed,
            'inputs': {name: {'bytes': 16384, 'sha256': 'a' * 64}
                for name in ['catalog.json', 'context.json', 'query.json', 'case.json']},
            'input_identity_stable': True, 'invalid_observations': 0,
            'independent_semantic_comparisons': 60, 'warmup_observations': 15,
            'measured_observations': 90, 'metrics': modes}
            for description in descriptors() for seed in [20261014, 20261015, 20261016, 20261017, 20261018]]
        self.assertEqual(len(rows), 410)
        return {'schema_version': 3, 'profile': 'full', 'completed_cases': 410, 'expected_cases': 410,
            'complete_grid': True, 'invalid_observations': 0, 'source_binary_inputs_stable': True,
            'independent_semantic_comparisons': 24600, 'instrumentation_status': 'PASS', 'summaries': rows}

    def test_full_scale_report_uses_archive_file_bound_while_small_metadata_stays_bounded(self):
        value = self.full_fixture(); raw = (json.dumps(value, indent=2) + '\n').encode()
        self.assertGreater(len(raw), 4 * 1024**2)
        self.assertLess(len(raw), check.archive_capture.MAX_FILE)
        with tempfile.TemporaryDirectory(dir=ROOT / '.local-runs') as temp:
            path = Path(temp) / 'results.json'; path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, 'bounded regular measurement record'):
                check.read_json(path)
            self.assertEqual(check.read_results(path), value)
        self.assertEqual(check.MAX_RESULTS_BYTES, check.archive_capture.MAX_FILE)

    def test_oversized_results_are_rejected_before_json_allocation(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.local-runs') as temp:
            path = Path(temp) / 'results.json'; path.write_bytes(b' ' * 1024 + b'{}')
            with patch.object(check, 'MAX_RESULTS_BYTES', 1024, create=True), \
                 patch.object(check, 'strict_json', side_effect=AssertionError('oversize must fail before parsing')):
                with self.assertRaisesRegex(ValueError, 'bounded regular measurement record'):
                    check.read_results(path)

    def test_full_results_preserve_closed_json_objects_duplicate_and_nonfinite_rejection(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.local-runs') as temp:
            path = Path(temp) / 'results.json'
            for raw in [b'{"n":NaN}', b'{"n":1,"n":2}', b'[]']:
                path.write_bytes(raw)
                with self.subTest(raw=raw), self.assertRaises(ValueError): check.read_results(path)


class OriginalLifetimeBinding(unittest.TestCase):
    def fixture(self, base):
        # Literal setup records from the independent epoch/latency unit fixture.
        # These are checker inputs, never a claim of a collected VM experiment.
        from test_kvm_reference_lifetime import original_records, COMMIT, SOURCE, BOOT, NS
        host, guest_record, original_vm = original_records()
        artifact = base / 'artifact'; guest = base / 'guest'
        (artifact / 'guest-config').mkdir(parents=True); guest.mkdir()
        payload = {'commit': COMMIT, 'source': {'sha256': SOURCE, 'files': [['Cargo.toml', 'a' * 64]]}}
        config = {'original_root': '/original/public', 'original_output': '.local-runs/kf'}
        command = ['/usr/bin/python3', '/original/public/scripts/kvm_reference_receiver.py',
            '--socket', '/original/public/.local-runs/kf/runtime/capture.sock',
            '--out', '/original/public/.local-runs/kf/artifact/packages', '--timeout', '18000',
            '--vm-started-monotonic-ns', str(1000 * NS), '--commit', COMMIT, '--source-sha256', SOURCE]
        vm = {'started_monotonic_ns': 1000 * NS, 'deadline_monotonic_ns': 19000 * NS,
            'receiver_command': command}
        rows = [(artifact / 'host-lifetime.json', host), (guest / 'guest-lifetime.json', guest_record),
            (artifact / 'vm-lifetime.json', original_vm),
            (artifact / 'guest-config/measurement-config.json', {'deadline_monotonic_ns': 24756 * NS}),
            (guest / 'device-access.json', {'probe': {'closed_monotonic_ns': 7001 * NS}}),
            (artifact / 'reference-receiver-result.json', {'status': 'PASS', 'lifetime_exchange': host,
                'source_before': payload['source'], 'source_after': payload['source']})]
        for path, row in rows: path.write_text(json.dumps(row), encoding='utf-8')
        events = [{'phase': 'setup-start', 'boot_id': BOOT, 'monotonic_ns': 7000 * NS},
            {'phase': 'setup-end', 'boot_id': BOOT, 'monotonic_ns': 7009 * NS}]
        return artifact, payload, guest, config, vm, events, 7010 * NS, 1127 * NS

    def test_original_vm_source_messages_cutoff_and_prequery_order_are_required(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.local-runs') as temp:
            args = self.fixture(Path(temp)); result = check.lifetime_bounds(*args)
            self.assertEqual(result['status'], 'BOUND')
            self.assertEqual(result['deadline_monotonic_ns'], 24756 * 10**9)
            self.assertFalse(result['reference_qualified'])
            (args[0] / 'host-lifetime.json').unlink()
            with self.assertRaises(ValueError): check.lifetime_bounds(*args)

    def test_receiver_cannot_restart_its_clock_or_increase_the_vm_limit(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.local-runs') as temp:
            args = self.fixture(Path(temp))
            for index, value in [(7, '18001'), (9, str(1001 * 10**9)),
                                 (11, '3' * 40), (13, '4' * 64)]:
                changed = copy.deepcopy(args[4]); changed['receiver_command'][index] = value
                with self.subTest(index=index), self.assertRaises(ValueError):
                    check.lifetime_bounds(*args[:4], changed, *args[5:])
            changed = dict(args[4], started_monotonic_ns=1001 * 10**9)
            with self.assertRaises(ValueError): check.lifetime_bounds(*args[:4], changed, *args[5:])

    def test_changed_config_or_discarded_receiver_record_never_qualifies_lifetime(self):
        for name, changed in [('guest-config/measurement-config.json', {'deadline_monotonic_ns': 24762 * 10**9}),
            ('reference-receiver-result.json', {'status': 'FAIL'})]:
            with tempfile.TemporaryDirectory(dir=ROOT / '.local-runs') as temp:
                args = self.fixture(Path(temp))
                (args[0] / name).write_text(json.dumps(changed), encoding='utf-8')
                with self.subTest(name=name), self.assertRaises(ValueError): check.lifetime_bounds(*args)

    def test_late_device_probe_or_host_readiness_cannot_authorize_prior_measurements(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.local-runs') as temp:
            args = self.fixture(Path(temp))
            for ready in [1125 * 10**9, 3400 * 10**9]:
                with self.assertRaises(ValueError): check.lifetime_bounds(*args[:-1], ready)
            (args[2] / 'device-access.json').write_text(json.dumps(
                {'probe': {'closed_monotonic_ns': 7011 * 10**9}}), encoding='utf-8')
            with self.assertRaises(ValueError): check.lifetime_bounds(*args)


if __name__ == '__main__': unittest.main()
