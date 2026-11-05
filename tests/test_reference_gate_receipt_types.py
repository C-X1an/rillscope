"""Malformed operator architecture values block before any compiler or query."""
import contextlib
import copy
import hashlib
import io
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
from test_reference_allocation import ACTUAL, IDENTITY, BOOT
from test_reference_allocation_gate import unit_receipt


class ReceiptArchitectureTypes(unittest.TestCase):
    def test_non_string_architecture_records_blocked_preflight_for_both_formats(self):
        legacy = {'source': 'actual host allocation and inspection', 'dedicated': True,
                  'logical_processors': 4, 'machine': 'x86_64', 'cpu_model': 'UNIT CPU'}
        for frame in ('legacy', 'structured'):
            for machine in (None, 7, [], {}):
                with self.subTest(frame=frame, machine=machine), tempfile.TemporaryDirectory() as folder:
                    receipt = copy.deepcopy(legacy if frame == 'legacy' else unit_receipt())
                    receipt['machine'] = machine
                    root = Path(folder)
                    receipt_file, output = root / 'UNIT-RECEIPT.json', root / 'preflight'
                    raw = json.dumps(receipt).encode('utf-8')
                    receipt_file.write_bytes(raw)
                    code = unexpected = None
                    with patch.object(sys, 'argv', ['reference_gate', '--out', str(output),
                                                   '--host-receipt', str(receipt_file)]), \
                         patch.object(gate, 'environment', return_value=dict(ACTUAL)), \
                         patch.object(gate, 'build_release', side_effect=AssertionError('compiler forbidden')) as build, \
                         patch.object(allocation, 'repository_identity', return_value=dict(IDENTITY)), \
                         patch.object(allocation, 'observed_boot_id', return_value=BOOT), \
                         patch.object(allocation.time, 'monotonic_ns', return_value=200), \
                         contextlib.redirect_stdout(io.StringIO()):
                        try:
                            code = gate.main()
                        except Exception as error:
                            unexpected = (type(error).__name__, str(error))
                    self.assertIsNone(unexpected, 'malformed receipt must return an explicit BLOCKED preflight')
                    self.assertFalse(build.called)
                    self.assertEqual(code, 77)
                    record = json.loads((output / 'reference-preflight.json').read_bytes())
                    self.assertEqual(record['status'], 'BLOCKED')
                    self.assertIn('reference receipt architecture differs from actual host', record['reasons'])
                    self.assertEqual(record['allocation_receipt_sha256'], hashlib.sha256(raw).hexdigest())


if __name__ == '__main__':
    unittest.main()
