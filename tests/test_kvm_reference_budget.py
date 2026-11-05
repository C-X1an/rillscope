"""Whole-lifetime accounting and finite record bounds; no timing prediction."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import kvm_reference_budget as budget


class FullBudget(unittest.TestCase):
    def test_every_named_job_and_guest_phase_is_accounted_for(self):
        row = budget.declaration()
        self.assertEqual(sum(row['components_seconds'].values()), 21600)
        self.assertEqual(row['owner_seconds'], 19500)
        self.assertEqual(sum(row['guest_seconds'].values()), row['vm_seconds'])
        self.assertEqual(row['vm_seconds'], 18000)
        self.assertEqual(row['full_duration_fit'], 'NOT YET MEASURED')
        self.assertFalse(row['reference_qualified'])

    def test_caps_cover_declared_periods_and_final_samples_with_finite_byte_limits(self):
        caps = budget.declaration()['sample_caps']
        self.assertEqual((caps['host'], caps['guest']), (36004, 9004))
        self.assertEqual(caps['host_log_bytes'], caps['host'] * 16384)
        self.assertEqual(caps['guest_log_bytes'], caps['guest'] * 16384)

    def test_an_extra_unbudgeted_phase_cannot_be_silently_added(self):
        with patch.object(budget, 'UPLOAD_SECONDS', 901), self.assertRaisesRegex(ValueError, 'whole-job'):
            budget.declaration()

    def test_guest_finish_reserve_cannot_be_borrowed_without_reaccounting(self):
        with patch.object(budget, 'COLLECTION_SECONDS', 15600), self.assertRaisesRegex(ValueError, 'guest'):
            budget.declaration()

    def test_reclaim_keeps_the_fixed_guest_cutoff_and_finish_reserve(self):
        policy = budget.declaration()['collection_window_policy']
        self.assertEqual(policy['base_collection_seconds'], 15000)
        self.assertEqual(policy['maximum_collection_seconds_before_setup'], 17280)
        self.assertEqual(policy['finish_reserve_seconds'], 600)
        self.assertEqual(policy['vm_tail_seconds'], 120)
        for setup_seconds in [0, 1, 100, 2000, 2279]:
            started = 10**9
            ready = started + setup_seconds * 10**9
            # Ten seconds were spent before guest entry, on the host VM clock.
            deadline = budget.guest_command_deadline_ns(started, ready,
                request_ns=ready, received_ns=ready, host_remaining_ns=(17990 - setup_seconds) * 10**9)
            self.assertEqual(deadline, started + 17870 * 10**9)
            self.assertEqual((deadline - ready) // 10**9 - 600, 17270 - setup_seconds)
            self.assertLess(deadline, started + 18000 * 10**9)

    def test_reclaim_rejects_invalid_clocks_and_the_exact_exhausted_setup_boundary(self):
        for started, ready in [(True, 2), (1, True), (0, 1), (2, 1), (1, 1.5),
                               (10**9, 2281 * 10**9)]:
            with self.assertRaisesRegex(ValueError, 'setup'):
                budget.guest_command_deadline_ns(started, ready,
                    request_ns=ready, received_ns=ready, host_remaining_ns=17000 * 10**9)

    def test_distinct_clock_epochs_and_transit_leave_the_original_host_tail(self):
        # Synthetic event arithmetic: host starts at1000s, guest enters121s
        # later at its unrelated7000s epoch. Request at host122s, host reply125s,
        # guest receives at host128s and configures at129s. No VM is claimed.
        cutoff = budget.guest_command_deadline_ns(7000 * 10**9, 7008 * 10**9,
            request_ns=7001 * 10**9, received_ns=7007 * 10**9,
            host_remaining_ns=17875 * 10**9)
        self.assertEqual(cutoff, 24756 * 10**9)
        host_elapsed_at_cutoff = 121 * 10**9 + cutoff - 7000 * 10**9
        self.assertEqual(host_elapsed_at_cutoff, 17877 * 10**9)
        self.assertEqual(18000 * 10**9 - host_elapsed_at_cutoff, 123 * 10**9)
        self.assertLessEqual(host_elapsed_at_cutoff, 17880 * 10**9)

    def test_missing_or_exhausted_host_remaining_lifetime_cannot_extend_collection(self):
        for remainder in [True, 0, -1, 18000 * 10**9 + 1, 719 * 10**9]:
            with self.subTest(remainder=remainder), self.assertRaises(ValueError):
                budget.guest_command_deadline_ns(10**9, 2 * 10**9,
                    request_ns=2 * 10**9, received_ns=2 * 10**9, host_remaining_ns=remainder)


if __name__ == '__main__': unittest.main()
