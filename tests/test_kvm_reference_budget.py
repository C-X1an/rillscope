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


if __name__ == '__main__': unittest.main()
