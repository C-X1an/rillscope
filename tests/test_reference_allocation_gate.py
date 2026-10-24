"""Synthetic receipt-consumption controls; every build/measurement is trapped."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'benchmarks'), str(ROOT / 'tests')]
import reference_allocation as allocation
import reference_gate as gate
from test_reference_allocation import DOCUMENT, ACTUAL, IDENTITY, BOOT, EVIDENCE


class BuildReached(Exception):
    pass


def unit_receipt():
    result = allocation.validate(copy.deepcopy(DOCUMENT), dict(ACTUAL), dict(IDENTITY), BOOT, 200,
                                 hashlib.sha256(EVIDENCE).hexdigest())
    result.update(operator_document_sha256='a' * 64,
        allocation_evidence_sha256=DOCUMENT['evidence_sha256'], allocation_evidence_bytes=len(EVIDENCE),
        inputs_and_source_stable=True)
    return result


class StructuredAllocationGate(unittest.TestCase):
    def gate_attempt(self, raw, *, identity=IDENTITY, boot=BOOT, now=200, ready=False):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            receipt, output = root / 'UNIT-SYNTHETIC-RECEIPT.json', root / 'unit-preflight'
            receipt.write_bytes(raw)
            with patch.object(sys, 'argv', ['reference_gate', '--out', str(output), '--host-receipt', str(receipt)]), \
                 patch.object(gate, 'environment', return_value=dict(ACTUAL)), \
                 patch.object(gate, 'build_release', side_effect=BuildReached('unit trap; no compiler/query')) as build, \
                 patch.object(allocation, 'repository_identity', return_value=dict(identity)), \
                 patch.object(allocation, 'observed_boot_id', return_value=boot), \
                 patch.object(allocation.time, 'monotonic_ns', return_value=now):
                if ready:
                    with self.assertRaises(BuildReached):
                        gate.main()
                    self.assertTrue(build.called)
                else:
                    try:
                        code = gate.main()
                    except BuildReached:
                        code = None
                    self.assertFalse(build.called)
                    self.assertEqual(code, 77)
            result = json.loads((output / 'reference-preflight.json').read_bytes())
            self.assertEqual(result['status'], 'READY' if ready else 'BLOCKED')
            return result

    def test_current_structured_receipt_can_reach_the_trapped_build(self):
        self.gate_attempt(json.dumps(unit_receipt()).encode(), ready=True)

    def test_expired_lease_blocks_before_build(self):
        self.gate_attempt(json.dumps(unit_receipt()).encode(), now=1000)

    def test_another_boot_blocks_before_build(self):
        self.gate_attempt(json.dumps(unit_receipt()).encode(), boot='87654321-4321-4321-4321-abcdef123456')

    def test_changed_source_blocks_before_build(self):
        self.gate_attempt(json.dumps(unit_receipt()).encode(), identity=dict(IDENTITY, source_sha256='9' * 64))

    def test_expiration_during_experiment_is_not_hidden_by_unchanged_hardware(self):
        observations = {name: dict(ACTUAL) for name in
            ('grid-start', 'grid-end', 'cancellation-start', 'cancellation-end', 'wrapper-end')}
        with patch.object(allocation, 'repository_identity', return_value=dict(IDENTITY)), \
             patch.object(allocation, 'observed_boot_id', return_value=BOOT), \
             patch.object(allocation.time, 'monotonic_ns', return_value=1000):
            errors = gate.experiment_environment_errors(dict(ACTUAL), unit_receipt(), observations)
        self.assertTrue(any('lease has expired' in reason for reason in errors), errors)

    def test_legacy_operator_receipt_keeps_its_existing_checks(self):
        receipt = {name: DOCUMENT[name] for name in ('source', 'dedicated', 'logical_processors', 'machine', 'cpu_model')}
        self.assertEqual(gate.host_reasons(dict(ACTUAL), receipt), [])
        with patch.object(allocation, 'repository_identity', side_effect=AssertionError('legacy path must not invent structured fields')):
            self.assertEqual(gate.allocation_binding_errors(dict(ACTUAL), receipt), [])
        self.assertTrue(gate.host_reasons(dict(ACTUAL, logical_processors=8), receipt))

    def test_malformed_structured_receipt_cannot_fall_back_to_legacy(self):
        for change in ({'method': 'unknown'}, {'inputs_and_source_stable': 1},
                       {'allocation_evidence_bytes': 0}, {'reference_qualified': True}):
            with self.subTest(change=change):
                result = unit_receipt()
                result.update(change)
                self.gate_attempt(json.dumps(result).encode())
        for removed in (('method',), ('method', 'operator_allocation', 'actual_boot_id')):
            result = unit_receipt()
            for name in removed:
                del result[name]
            self.gate_attempt(json.dumps(result).encode())

    def test_invalid_duplicate_and_oversized_receipts_block_before_build(self):
        for raw in (b'[]', b'{"dedicated":false,"dedicated":true}', b' ' * 65537):
            with self.subTest(raw_length=len(raw)):
                self.gate_attempt(raw)


if __name__ == '__main__':
    unittest.main()
