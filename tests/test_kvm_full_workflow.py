"""Provider ceilings, immutable source guard and lossless failure paths."""
import json
from pathlib import Path
import re
import sys
import unittest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from kvm_reference_budget import declaration


class FullWorkflow(unittest.TestCase):
    def setUp(self):
        # JSON is an unambiguous YAML subset, including the literal 'on' key.
        self.workflow = json.loads((ROOT / '.github/workflows/kvm-full-capture.yml').read_bytes())

    def test_capture_step_bounds_leave_the_declared_finalization_reserve(self):
        budget = declaration(); job = self.workflow['jobs']['collect']
        self.assertEqual(job['timeout-minutes'], 360)
        self.assertEqual(sum(step['timeout-minutes'] for step in job['steps']), 359)
        self.assertEqual(budget['provider_seconds'], 21600)
        self.assertEqual(sum(budget['actions_reserve_seconds'].values()), 900)
        script = next(step['run'] for step in job['steps'] if step.get('id') == 'collection')
        self.assertIn('--timeout 19500', script)
        self.assertNotIn('--capture-only', script)
        self.assertNotIn('clean_verify', script)

    def test_both_jobs_guard_exact_commit_before_noncredential_checkout_and_pin_actions(self):
        self.assertEqual(self.workflow['permissions'], {'contents': 'read'})
        for job in self.workflow['jobs'].values():
            guard, checkout = job['steps'][:2]
            self.assertEqual(guard['id'], 'source_guard')
            self.assertIn('GITHUB_SHA', guard['run']); self.assertIn('[0-9a-f]{40}', guard['run'])
            self.assertIs(checkout['with']['persist-credentials'], False)
            for step in job['steps']:
                if 'uses' in step: self.assertRegex(step['uses'], r'^actions/[a-z-]+@[0-9a-f]{40}$')
            self.assertLessEqual(sum(step['timeout-minutes'] for step in job['steps']), 359)

    def test_failed_collection_still_recovers_uploads_and_is_not_repaired_by_validation(self):
        capture = self.workflow['jobs']['collect']['steps']
        fallback = next(step for step in capture if 'recover_kvm_reference.py' in step.get('run', ''))
        self.assertIn('always()', fallback['if'])
        upload = next(step for step in capture if 'upload-artifact@' in step.get('uses', ''))
        self.assertIn('always()', upload['if'])
        paths = upload['with']['path'].splitlines()
        self.assertIn('.local-runs/kf/artifact/', paths)
        self.assertIn('.local-runs/kf/commands/', paths)
        self.assertNotIn('.local-runs/kf/', paths)
        self.assertEqual(upload['with']['if-no-files-found'], 'error')
        verify = self.workflow['jobs']['validate-all-records']
        self.assertIn('always()', verify['if'])
        self.assertEqual(verify['needs'], 'collect')
        self.assertTrue(any('ORIGINAL_COLLECTION_RESULT' in step.get('env', {}) for step in verify['steps']))
        download = next(step for step in verify['steps'] if 'download-artifact@' in step.get('uses', ''))
        self.assertEqual(download['with']['digest-mismatch'], 'error')
        self.assertFalse(any(step.get('continue-on-error') for step in capture + verify['steps']))


if __name__ == '__main__': unittest.main()
