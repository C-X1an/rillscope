"""Literal synthetic allocation controls; none constitutes an actual host receipt."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'benchmarks'))
import reference_allocation as allocation

BOOT = '12345678-1234-1234-1234-123456789abc'
IDENTITY = {'commit': '1' * 40, 'source_sha256': '2' * 64}
EVIDENCE = b'UNIT FIXTURE ONLY: operator allocation evidence; no real resource booking.\n'
ACTUAL = {'system': 'Linux', 'machine': 'x86_64', 'logical_processors': 4,
    'cpu_model': 'UNIT CPU', 'physical_memory_bytes': 8326950912,
    'resource_inspection_status': 'MEASURED', 'effective_cpu_capacity': 4,
    'process_affinity_cpu_count': 4, 'cgroup_memory_limit_bytes': None,
    'cgroup_memory_high_bytes': None, 'virtualization': 'hypervisor flag present'}
DOCUMENT = {'schema_version': 1, 'source': 'actual host allocation and inspection',
    'dedicated': True, 'operator': 'UNIT OPERATOR; NOT AN ACTUAL ALLOCATION',
    'allocation_id': '3' * 32, 'evidence_sha256': hashlib.sha256(EVIDENCE).hexdigest(),
    **IDENTITY, 'boot_id': BOOT, 'inspected_monotonic_ns': 100,
    'expires_monotonic_ns': 1000, 'system': 'Linux', 'machine': 'x86_64',
    'logical_processors': 4, 'cpu_model': 'UNIT CPU', 'configured_memory_bytes': 8589934592}


class ReferenceAllocation(unittest.TestCase):
    def validate(self, document=None, actual=None, identity=None, boot_id=BOOT, now=200, evidence=None):
        return allocation.validate(copy.deepcopy(DOCUMENT if document is None else document),
            copy.deepcopy(ACTUAL if actual is None else actual),
            dict(IDENTITY if identity is None else identity), boot_id, now,
            hashlib.sha256(EVIDENCE if evidence is None else evidence).hexdigest())

    def test_literal_virtual_guest_shape_does_not_claim_benchmark_qualification(self):
        value = self.validate()
        self.assertEqual(value['status'], 'RECORDED')
        self.assertIs(value['reference_qualified'], False)
        self.assertEqual((value['logical_processors'], value['actual_boot_id']), (4, BOOT))
        self.assertEqual(value['actual_environment']['physical_memory_bytes'], 8326950912)
        self.assertEqual(value['actual_environment']['virtualization'], 'hypervisor flag present')
        self.assertEqual(value['operator_allocation']['configured_memory_bytes'], 8589934592)

    def test_dedication_is_required_from_operator_and_not_inferred_from_hardware(self):
        for value in (None, False, 1, 'true'):
            document = dict(DOCUMENT, dedicated=value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.validate(document)

    def test_exact_commit_source_and_boot_must_match(self):
        for field, value in [('commit', '4' * 40), ('source_sha256', '5' * 64),
                             ('boot_id', '87654321-4321-4321-4321-abcdef123456')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(dict(DOCUMENT, **{field: value}))

    def test_positive_document_without_original_evidence_is_rejected(self):
        with self.assertRaises(ValueError):
            self.validate(evidence=b'different original evidence')
        with self.assertRaises(ValueError):
            self.validate(dict(DOCUMENT, evidence_sha256='not-a-digest'))

    def test_actual_machine_and_effective_limits_must_match(self):
        changes = [('system', 'Windows'), ('logical_processors', 8), ('effective_cpu_capacity', 2),
            ('process_affinity_cpu_count', 2), ('physical_memory_bytes', 16 * 1024**3),
            ('cgroup_memory_limit_bytes', 4 * 1024**3), ('cgroup_memory_high_bytes', 4 * 1024**3),
            ('resource_inspection_status', 'NOT MEASURED'), ('cpu_model', 'DIFFERENT UNIT CPU')]
        for field, value in changes:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(actual=dict(ACTUAL, **{field: value}))

    def test_integer_booleans_and_nonfinite_capacity_cannot_pass(self):
        for field in ('schema_version', 'logical_processors', 'configured_memory_bytes',
                      'inspected_monotonic_ns', 'expires_monotonic_ns'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(dict(DOCUMENT, **{field: True}))
        for field, value in [('logical_processors', True), ('process_affinity_cpu_count', True),
                             ('physical_memory_bytes', True), ('effective_cpu_capacity', True),
                             ('effective_cpu_capacity', float('nan'))]:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.validate(actual=dict(ACTUAL, **{field: value}))

    def test_future_expired_and_unbounded_clocks_are_rejected(self):
        for now in (99, 1000, 1001, True, 0, 2**63):
            with self.subTest(now=now), self.assertRaises(ValueError):
                self.validate(now=now)
        self.assertEqual(self.validate(now=100)['preflight_monotonic_ns'], 100)
        self.assertEqual(self.validate(now=999)['preflight_monotonic_ns'], 999)

    def test_closed_document_and_duplicate_json_keys(self):
        extra = dict(DOCUMENT, fake_qualification=True)
        missing = dict(DOCUMENT)
        del missing['operator']
        for document in (extra, missing):
            with self.assertRaises(ValueError):
                self.validate(document)
        with self.assertRaises(ValueError):
            allocation.decode_document(b'{"dedicated":false,"dedicated":true}')
        with self.assertRaises(ValueError):
            allocation.decode_document(b'{"value":NaN}')

    def test_json_depth_and_bytes_are_bounded_while_quoted_structure_is_data(self):
        with self.assertRaisesRegex(ValueError, 'allocation JSON nesting exceeds decoding bound'):
            allocation.decode_document(b'[' * 2000 + b']' * 2000)
        with self.assertRaisesRegex(ValueError, 'bounded allocation document required'):
            allocation.decode_document(b' ' * 65537)
        document = dict(DOCUMENT, operator='UNIT "quoted" [{] \\ operator')
        self.assertEqual(allocation.decode_document(json.dumps(document).encode('utf-8')), document)

    def test_empty_supporting_evidence_never_produces_a_receipt(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            document, evidence, out = root / 'unit-operator.json', root / 'unit-evidence.txt', root / 'unit-result.json'
            value = dict(DOCUMENT, evidence_sha256=hashlib.sha256(b'').hexdigest())
            document.write_text(json.dumps(value), encoding='utf-8')
            evidence.write_bytes(b'')
            with patch.object(allocation, 'environment', return_value=dict(ACTUAL)), \
                 patch.object(allocation, 'repository_identity', return_value=dict(IDENTITY)), \
                 patch.object(allocation, 'observed_boot_id', return_value=BOOT), \
                 patch.object(allocation.time, 'monotonic_ns', side_effect=[200, 201]):
                with self.assertRaisesRegex(ValueError, 'nonempty original allocation evidence required'):
                    allocation.capture(document, evidence, out)
            self.assertFalse(out.exists())

    def test_bounded_regular_file_reader(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'input'
            path.write_bytes(b'1234')
            self.assertEqual(allocation.read_bounded(path, 4), b'1234')
            with self.assertRaises(ValueError):
                allocation.read_bounded(path, 3)
            with self.assertRaises(ValueError):
                allocation.read_bounded(Path(folder), 100)

    def test_actual_input_write_during_read_is_detected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'input'
            path.write_bytes(b'original')
            real_fdopen = allocation.os.fdopen

            def intervening_reader(*args, **kwargs):
                stream = real_fdopen(*args, **kwargs)

                class WriterDuringRead:
                    def __enter__(self):
                        return self

                    def read(self, limit):
                        raw = stream.read(limit)
                        path.write_bytes(b'changed literal bytes')
                        return raw

                    def __exit__(self, *exception):
                        stream.close()

                return WriterDuringRead()

            with patch.object(allocation.os, 'fdopen', side_effect=intervening_reader):
                with self.assertRaisesRegex(ValueError, 'input changed or exceeded bound'):
                    allocation.read_bounded(path, 100)

    def capture_fixture(self, folder, *, after=None, identity_after=None, boot_after=None):
        root = Path(folder)
        document, evidence, out = root / 'operator.json', root / 'evidence.txt', root / 'receipt.json'
        document.write_text(json.dumps(DOCUMENT), encoding='utf-8')
        evidence.write_bytes(EVIDENCE)
        with patch.object(allocation, 'environment', side_effect=[dict(ACTUAL), dict(ACTUAL if after is None else after)]), \
             patch.object(allocation, 'repository_identity', side_effect=[dict(IDENTITY), dict(IDENTITY if identity_after is None else identity_after)]), \
             patch.object(allocation, 'observed_boot_id', side_effect=[BOOT, BOOT if boot_after is None else boot_after]), \
             patch.object(allocation.time, 'monotonic_ns', side_effect=[200, 201]):
            result = allocation.capture(document, evidence, out)
        return result, out

    def test_capture_binds_exact_input_bytes_and_stays_unqualified(self):
        with tempfile.TemporaryDirectory() as folder:
            result, out = self.capture_fixture(folder)
            self.assertEqual(result['allocation_evidence_sha256'], hashlib.sha256(EVIDENCE).hexdigest())
            self.assertEqual(result['operator_document_sha256'], hashlib.sha256((Path(folder) / 'operator.json').read_bytes()).hexdigest())
            self.assertIs(result['inputs_and_source_stable'], True)
            self.assertIs(json.loads(out.read_bytes())['reference_qualified'], False)
            self.assertEqual(result['actual_source'], IDENTITY)

    def test_changed_resources_source_or_boot_never_publish_a_receipt(self):
        for keywords, reason in (
                ({'after': dict(ACTUAL, effective_cpu_capacity=2)}, 'actual resource configuration changed during preflight'),
                ({'identity_after': dict(IDENTITY, commit='6' * 40)}, 'source or boot changed during preflight'),
                ({'boot_after': 'different boot'}, 'source or boot changed during preflight')):
            with self.subTest(keywords=keywords), tempfile.TemporaryDirectory() as folder:
                with self.assertRaisesRegex(ValueError, reason):
                    self.capture_fixture(folder, **keywords)
                self.assertFalse((Path(folder) / 'receipt.json').exists())

    def test_operator_document_change_during_preflight_never_publishes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            document, evidence, out = root / 'operator.json', root / 'evidence.txt', root / 'receipt.json'
            document.write_text(json.dumps(DOCUMENT), encoding='utf-8')
            evidence.write_bytes(EVIDENCE)

            def changed_after_initial_reads():
                document.write_text(json.dumps(dict(DOCUMENT, operator='CHANGED UNIT OPERATOR')), encoding='utf-8')
                return 200

            with patch.object(allocation, 'environment', return_value=dict(ACTUAL)), \
                 patch.object(allocation, 'repository_identity', return_value=dict(IDENTITY)), \
                 patch.object(allocation, 'observed_boot_id', return_value=BOOT), \
                 patch.object(allocation.time, 'monotonic_ns', side_effect=changed_after_initial_reads):
                with self.assertRaisesRegex(ValueError, 'allocation inputs changed during preflight'):
                    allocation.capture(document, evidence, out)
            self.assertFalse(out.exists())

    def test_existing_receipt_is_never_clobbered(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / 'receipt.json'
            out.write_bytes(b'original private receipt')
            with self.assertRaisesRegex(ValueError, 'new private receipt output required'):
                allocation.capture(Path(folder) / 'missing', Path(folder) / 'missing', out)
            self.assertEqual(out.read_bytes(), b'original private receipt')

    def test_actual_non_linux_entry_is_blocked_before_read_or_output(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(allocation.platform, 'system', return_value='Windows'), \
             patch.object(allocation, 'read_bounded', side_effect=AssertionError('must not read inputs')):
            out = Path(folder) / 'receipt.json'
            self.assertEqual(allocation.main(['--allocation', 'missing', '--evidence', 'missing', '--out', str(out)]), 77)
            self.assertFalse(out.exists())


if __name__ == '__main__':
    unittest.main()
