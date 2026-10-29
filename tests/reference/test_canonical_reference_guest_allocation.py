"""Synthetic producer-adapter controls; no actual guest allocation evidence."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import canonical_reference_allocation as protocol
import canonical_reference_guest_allocation as guest
from . import test_canonical_reference_allocation as allocation_fixtures


class GuestAllocationTests(unittest.TestCase):
    def setUp(self):
        fixture = allocation_fixtures.CanonicalAllocationTests(); fixture.setUp()
        self.request, self.grant = fixture.request, fixture.grant()
        self.actual = copy.deepcopy(self.request['environment'])
        self.keywords = {'commit': 'a' * 40, 'source_sha256': 'b' * 64,
            'boot_id': '11111111-2222-3333-4444-555555555555',
            'received_ns': 5_003_000_000_000, 'inspected_ns': 5_005_000_000_000,
            'tail_ns': 120_000_000_000}

    def document(self, actual=None, keywords=None):
        return guest.document_for(protocol.encode(self.request), protocol.encode(self.grant),
            self.actual if actual is None else actual, **(self.keywords if keywords is None else keywords))

    def test_unchanged_closed_document_and_literal_expiration(self):
        document, cutoff = self.document()
        self.assertEqual(len(document), 16)
        self.assertEqual(cutoff, 24_840_000_000_000)
        self.assertEqual(document['expires_monotonic_ns'], 24_840_000_000_000)
        self.assertEqual(document['configured_memory_bytes'], 8_589_934_592)
        self.assertEqual(document['allocation_id'], 'd' * 32)
        self.assertEqual(document['operator'], 'synthetic unit-test controller')

    def test_changed_actual_boot_source_and_clocks_rejected(self):
        for key, value in [('boot_id', 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'),
            ('source_sha256', 'e' * 64), ('commit', 'e' * 40),
            ('inspected_ns', 25_000_000_000_000), ('received_ns', True)]:
            with self.subTest(key=key):
                keywords = dict(self.keywords); keywords[key] = value
                with self.assertRaises(ValueError): self.document(keywords=keywords)

    def test_changed_resource_identity_is_not_reallocated(self):
        for key, value in [('cpu_model', 'different synthetic CPU'), ('physical_memory_bytes', 8_300_000_000),
            ('effective_cpu_capacity', 3), ('cgroup_memory_limit_bytes', 1024)]:
            with self.subTest(key=key):
                actual = copy.deepcopy(self.actual); actual[key] = value
                with self.assertRaises(ValueError): self.document(actual=actual)

    def test_mutated_grant_bytes_do_not_become_a_document(self):
        changed = copy.deepcopy(self.grant); changed['authority']['operator'] = 'different synthetic controller'
        with self.assertRaises(ValueError):
            guest.document_for(protocol.encode(self.request), protocol.encode(changed), self.actual, **self.keywords)

    def test_runtime_stops_before_marker_or_any_write_without_actual_guest(self):
        with patch.object(guest.platform, 'system', return_value='Windows'):
            with patch.object(guest.original, 'read_bounded') as read:
                with self.assertRaisesRegex(ValueError, 'actual existing owned canonical Linux guest'):
                    guest.record_guest_allocation(b'{}', b'{}', commit='a' * 40, source_sha256='b' * 64,
                        received_ns=1, tail_ns=120_000_000_000)
                read.assert_not_called()


if __name__ == '__main__': unittest.main()
