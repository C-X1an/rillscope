"""Synthetic lifecycle records; these do not describe a real guest run."""
import base64
import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import canonical_reference_allocation as allocation
import canonical_reference_events as events
from . import test_canonical_reference_allocation as fixtures


def rows():
    fixture = fixtures.CanonicalAllocationTests(); fixture.setUp(); grant = fixture.grant()
    common = {'schema_version': 1, 'method': allocation.METHOD, 'commit': grant['commit'],
        'source_sha256': grant['source_sha256'], 'boot_id': grant['boot_id'],
        'allocation_sha256': allocation.digest(grant), 'utc_ns': 1000,
        'monotonic_ns': grant['guest_pre_send_monotonic_ns'] + 10, 'reference_qualified': False}
    return grant, [dict(common, phase='prefix-start'),
        dict(common, phase='ready', stage='grid', request_sha256='d' * 64,
            config_sha256='e' * 64, monotonic_ns=common['monotonic_ns'] + 10),
        dict(common, phase='attempt-end', status='PASS', monotonic_ns=common['monotonic_ns'] + 20)]


def serial(values):
    return '\n'.join('kernel-prefix ' + events.PREFIX + base64.b64encode(allocation.encode(row)).decode()
        for row in values) + '\n'


class CanonicalEvents(unittest.TestCase):
    def test_ordered_events_bind_to_the_exact_prior_grant(self):
        grant, values = rows()
        self.assertEqual(events.parse(serial(values)), values)
        for row in values: self.assertEqual(events.bind(row, grant), row)

    def test_failed_early_attempt_is_retained_without_a_success_prefix(self):
        _, values = rows(); end = dict(values[-1], status='FAIL')
        self.assertEqual(events.parse(serial([end])), [end])
        with self.assertRaises(ValueError): events.parse(serial([values[-1]]))

    def test_replay_reordering_reboot_regrant_and_clock_reversal_rejected(self):
        _, values = rows()
        variants = [values + [values[-1]], [values[1], values[0]], [values[0], values[0]]]
        for key, value in [('commit', 'f' * 40), ('boot_id', 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'),
            ('allocation_sha256', '0' * 64), ('monotonic_ns', values[0]['monotonic_ns'])]:
            changed = copy.deepcopy(values); changed[1][key] = value; variants.append(changed)
        for value in variants:
            with self.subTest(value=value):
                with self.assertRaises(ValueError): events.parse(serial(value))

    def test_closed_types_bounds_old_method_and_changed_grant_rejected(self):
        grant, values = rows()
        for key, value in [('extra', 1), ('schema_version', True), ('utc_ns', True),
            ('method', 'rillscope-kvm-full-capture-v1'), ('reference_qualified', True), ('phase', [])]:
            changed = dict(values[0]); changed[key] = value
            with self.subTest(key=key):
                with self.assertRaises(ValueError): events.check(changed)
        changed = dict(values[0], allocation_sha256='f' * 64)
        with self.assertRaises(ValueError): events.bind(changed, grant)
        for encoded in ['!!!', 'x' * 25000]:
            with self.assertRaises(ValueError): events.parse(events.PREFIX + encoded)


if __name__ == '__main__': unittest.main()
