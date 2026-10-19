"""Full verifier rejects reduced scope, omitted failures and missing provenance."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import verify_kvm_reference as check
from workloads import descriptors, sort_null_descriptors
from kvm_reference_common import SEEDS


class FullValidation(unittest.TestCase):
    def payload(self):
        files = [['Cargo.toml', 'a' * 64]]
        return {'commit': 'b' * 40, 'source': {'files': files,
            'sha256': hashlib.sha256(json.dumps(files, separators=(',', ':')).encode()).hexdigest()}}

    def test_declared_full_scope_cannot_pass_with_a_reduced_or_incomplete_result(self):
        payload = self.payload()
        manifest = {'source': payload['source'], 'commit': payload['commit'], 'dirty': False,
            'schema_version': 3, 'profile': 'full', 'warmups': 5, 'repetitions': 30, 'seeds': SEEDS,
            'chosen_workloads': descriptors(), 'expected_cases': 410, 'expected_observations': 43050}
        result = {'schema_version': 3, 'profile': 'full', 'completed_cases': 410, 'expected_cases': 410,
            'complete_grid': True, 'instrumentation_status': 'PASS', 'invalid_observations': 0,
            'source_binary_inputs_stable': True}
        check.completed_scope('grid', manifest, result, payload)
        for field, value in [('completed_cases', 409), ('complete_grid', False), ('invalid_observations', 1)]:
            bad = {**result, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                check.completed_scope('grid', manifest, bad, payload)
        manifest['chosen_workloads'] = descriptors()[:6]
        with self.assertRaises(ValueError): check.completed_scope('grid', manifest, result, payload)

    def test_every_seed_keeps_p95_target_misses_and_separate_end_to_end(self):
        rows = []
        for index, seed in enumerate(SEEDS):
            rows.append({'workload': {'id': 'B01-n100000-s10-null10-b1024'}, 'seed': seed,
                'independent_semantic_comparisons': 60,
                'metrics': {'rust-on': {'success_only_execution_ns': {'n': 30, 'p95': 999999999 if index == 0 else 1000000000},
                    'all_outcome_metrics': {'wall_ns': {'n': 30, 'p95': 2000000000}}}}})
        targets = check.filter_targets({'summaries': rows})
        self.assertEqual([row['seed'] for row in targets], SEEDS)
        self.assertEqual([row['observed_target_status'] for row in targets], ['MET', 'MISSED', 'MISSED', 'MISSED', 'MISSED'])
        self.assertEqual(targets[0]['end_to_end_ns']['p95'], 2000000000)
        self.assertFalse(targets[0]['reference_qualified'])
        for bad in [rows[:-1], rows + [rows[0]]]:
            with self.assertRaises(ValueError): check.filter_targets({'summaries': bad})
        rows[0]['metrics']['rust-on']['success_only_execution_ns']['n'] = 29
        with self.assertRaises(ValueError): check.filter_targets({'summaries': rows})

    def test_cancellation_misses_are_reported_without_changing_correctness(self):
        result = {'status': 'PASS', 'observations': 175, 'measured_observations': 150,
            'invalid_observations': 0, 'target_observations_over_100ms': 1,
            'cancel_upper_bound_ns': {'n': 150, 'p95': 100000001}}
        target = check.cancel_target(result)
        self.assertEqual(target['observed_target_status'], 'MISSED')
        self.assertFalse(target['reference_qualified'])
        result['measured_observations'] = 149
        with self.assertRaises(ValueError): check.cancel_target(result)

    def test_missing_original_input_produces_all_three_failed_scopes_and_no_success(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.local-runs') as temp:
            base = Path(temp); artifact = base / 'artifact'; artifact.mkdir()
            result = check.validate(artifact, base / 'validation', base / 'missing-owner/receipt.json')
            self.assertEqual(result['status'], 'FAIL')
            self.assertFalse(result['reference_qualified'])
            self.assertEqual([row['stage'] for row in result['campaigns']], ['grid', 'cancel', 'sort-null'])
            self.assertTrue(all(row['status'] == 'FAIL' for row in result['campaigns']))
            self.assertEqual(result['canonical_fresh'], 'NOT RUN')
            self.assertTrue(result['errors'])
            self.assertTrue((base / 'validation/results.json').is_file())


if __name__ == '__main__': unittest.main()
