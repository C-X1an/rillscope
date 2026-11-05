"""Closed serial lifecycle rejects changed methods, reboots and replay."""
import base64
import json
from pathlib import Path
import sys
import unittest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import kvm_reference_events as events
from kvm_reference_common import METHOD


def frame(row): return events.PREFIX + base64.b64encode(json.dumps(row).encode()).decode()


class FullEvents(unittest.TestCase):
    def row(self, phase='setup-start', clock=1):
        return {'phase': phase, 'method': METHOD, 'boot_id': '12345678-1234-1234-1234-123456789abc',
            'utc_ns': clock, 'monotonic_ns': clock, 'reference_qualified': False}

    def test_foreign_pilot_and_non_protocol_logs_are_not_full_evidence(self):
        self.assertEqual(events.parse('ordinary boot log\nRILLSCOPE_KVM_PILOT_V1 e30=\n'), [])
        row = self.row(); row['method'] = 'rillscope-reference-fresh-v1'
        with self.assertRaises(ValueError): events.parse(frame(row))

    def test_ready_requires_full_source_binary_and_original_request_identity(self):
        row = self.row('ready')
        with self.assertRaises(ValueError): events.parse(frame(row))
        row.update(stage='grid', commit='1' * 40, source_sha256='2' * 64,
            binary_sha256={'rillscope': '3' * 64, 'rillscope-measure': '4' * 64},
            request_sha256='5' * 64, config_sha256='6' * 64)
        self.assertEqual(events.parse(frame(row)), [row])
        with self.assertRaises(ValueError): events.parse(frame(row) + '\n' + frame({**row, 'monotonic_ns': 2}))

    def test_boot_clock_and_record_count_bounds_fail_closed(self):
        row = self.row(); later = self.row('setup-end', 2)
        self.assertEqual(events.parse(frame(row) + '\n' + frame(later)), [row, later])
        later['boot_id'] = '87654321-1234-1234-1234-123456789abc'
        with self.assertRaises(ValueError): events.parse(frame(row) + '\n' + frame(later))
        with self.assertRaises(ValueError): events.parse(frame(row) + '\n' + frame(row))
        with self.assertRaises(ValueError): events.parse('\n'.join(frame(self.row(clock=i+1)) for i in range(17)))

    def test_duplicate_keys_and_numeric_false_are_rejected(self):
        row = self.row(); row['reference_qualified'] = 0
        with self.assertRaises(ValueError): events.parse(frame(row))
        data = json.dumps(self.row())[:-1] + ',"method":"' + METHOD + '"}'
        with self.assertRaises(ValueError):
            events.parse(events.PREFIX + base64.b64encode(data.encode()).decode())


if __name__ == '__main__': unittest.main()
