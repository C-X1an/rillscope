"""Literal sampled-resource fixtures; no root/KVM/residency claim."""
import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import canonical_reference_observer as observer
from . import test_canonical_reference_allocation as fixtures

BOOT = '11111111-2222-3333-4444-555555555555'


def sample():
    source = fixtures.CanonicalAllocationTests(); source.setUp()
    return {'boot_id': BOOT, 'clock_source': 'kvm-clock',
        'clock_properties': {'monotonic': True, 'adjustable': False},
        'utc_ns': 10_000, 'monotonic_ns': 1_000_000_000,
        'environment': copy.deepcopy(source.request['environment']),
        'vmstat': {'status': 'MEASURED', 'values': {'pswpin': 0, 'pswpout': 0}},
        'network': {'interfaces': [{'name': 'unit0', 'carrier': '1', 'operstate': 'up'}]}}


class CanonicalObserverContracts(unittest.TestCase):
    def test_prefix_network_is_observed_and_measurement_requires_actual_carrier_down(self):
        row = sample()
        self.assertIsNone(observer.check_sample(row, boot_id=BOOT, measured=False))
        with self.assertRaises(ValueError): observer.check_sample(row, boot_id=BOOT, measured=True)
        row['network']['interfaces'][0].update(carrier='0', operstate='down')
        self.assertIsNone(observer.check_sample(row, boot_id=BOOT, measured=True))

    def test_exact_fifteen_second_gap_bound_and_monotonic_order(self):
        first = sample(); row = copy.deepcopy(first)
        row['monotonic_ns'] = 16_000_000_000
        self.assertIsNone(observer.check_sample(row, boot_id=BOOT, previous=first, first=first))
        for stamp in [1_000_000_000, 999_999_999, 16_000_000_001]:
            with self.subTest(stamp=stamp):
                row['monotonic_ns'] = stamp
                with self.assertRaises(ValueError): observer.check_sample(row, boot_id=BOOT, previous=first, first=first)

    def test_boot_clock_swap_and_resource_changes_fail(self):
        first = sample()
        for key, value in [('boot_id', 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'),
            ('clock_source', 'unstable'), ('monotonic_ns', True), ('environment', {}),
            ('vmstat', {'status': 'UNKNOWN', 'values': {}})]:
            with self.subTest(key=key):
                row = copy.deepcopy(first); row[key] = value
                with self.assertRaises(ValueError): observer.check_sample(row, boot_id=BOOT)
        row = copy.deepcopy(first); row['vmstat']['values']['pswpout'] = 1
        with self.assertRaises(ValueError): observer.check_sample(row, boot_id=BOOT, first=first)
        row = copy.deepcopy(first); row['environment']['logical_processors'] = 8
        with self.assertRaises(ValueError): observer.check_sample(row, boot_id=BOOT)


if __name__ == '__main__': unittest.main()
