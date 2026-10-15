"""Actual public artifact corruption controls and independent percentile fixtures."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'benchmarks'))
import release_audit
from run import distribution


class PublicEvidenceTests(unittest.TestCase):
    def test_real_public_artifact_digest_pass_fail_pass(self):
        index = json.loads((ROOT / 'verification/product/index.json').read_bytes())
        self.assertEqual(release_audit.audit(index)['audit_status'], 'PASS')
        mutated = copy.deepcopy(index)
        name = next(iter(mutated['artifacts']))
        mutated['artifacts'][name]['sha256'] = '0' * 64
        result = release_audit.audit(mutated)
        self.assertEqual(result['audit_status'], 'FAIL')
        self.assertIn('public evidence digest mismatch: ' + name, result['errors'])
        self.assertEqual(release_audit.audit(index)['audit_status'], 'PASS')

    def test_missing_locked_criterion_cannot_audit_green(self):
        index = json.loads((ROOT / 'verification/product/index.json').read_bytes())
        del index['criteria']['AC-023']
        self.assertEqual(release_audit.audit(index)['audit_status'], 'FAIL')

    def test_thirty_observation_nearest_rank_is_not_a_tail_guarantee(self):
        result = distribution(list(range(1, 31)))
        self.assertEqual((result['n'], result['p50'], result['p95'], result['p99']), (30, 15.5, 29, 30))
        self.assertEqual(distribution([]), {'n': 0, 'status': 'NOT MEASURED'})


if __name__ == '__main__': unittest.main()
