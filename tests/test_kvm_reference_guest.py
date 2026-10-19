"""Finite full guest configuration and safe entry guard; no VM qualification."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import kvm_reference_guest as guest
from kvm_reference_common import METHOD


class GuestConfiguration(unittest.TestCase):
    def setUp(self):
        self.payload = {'mode': METHOD, 'commit': '1' * 40, 'source': {'sha256': '2' * 64},
            'bins': {'rillscope': {}, 'rillscope-measure': {}}, 'reference_qualified': False}
        self.boot = '12345678-1234-1234-1234-123456789abc'

    def test_source_bound_configs_have_finite_shared_end_and_separate_collection_reserve(self):
        measure, export = guest.configurations(self.payload, 1_000_000_000, 101_000_000_000, self.boot)
        self.assertEqual(measure['method'], METHOD)
        self.assertEqual(measure['source_sha256'], '2' * 64)
        self.assertEqual(measure['boot_id'], self.boot)
        self.assertEqual(measure['deadline_monotonic_ns'], export['deadline_monotonic_ns'])
        self.assertEqual(measure['deadline_monotonic_ns'] - 101_000_000_000, 15600 * 10**9)
        self.assertEqual(export['transfer_seconds'], 180)
        self.assertFalse(measure['reference_qualified'])

    def test_setup_may_not_borrow_collection_and_shutdown_reserves(self):
        with self.assertRaisesRegex(ValueError, 'setup'):
            guest.configurations(self.payload, 1_000_000_000, 2301_000_000_000, self.boot)

    def test_pilot_payload_cannot_silently_become_a_full_collection(self):
        self.payload['mode'] = 'unqualified-kvm-feasibility-pilot'
        with self.assertRaisesRegex(ValueError, 'payload'):
            guest.configurations(self.payload, 1_000_000_000, 101_000_000_000, self.boot)

    def test_boolean_qualification_and_closed_binaries_are_required(self):
        self.payload['reference_qualified'] = 0
        with self.assertRaises(ValueError): guest.configurations(self.payload, 1, 2, self.boot)
        self.payload['reference_qualified'] = False
        self.payload['bins']['unexpected'] = {}
        with self.assertRaises(ValueError): guest.configurations(self.payload, 1, 2, self.boot)

    def test_non_guest_entry_never_installs_packages_or_runs_a_query(self):
        with patch.object(guest.platform, 'system', return_value='Windows'), patch.object(guest, 'collect') as operation:
            self.assertEqual(guest.main(), 77)
        operation.assert_not_called()


if __name__ == '__main__': unittest.main()
