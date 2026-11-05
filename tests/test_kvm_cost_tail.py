"""Closed pilot scope controls; no execution or reference-host claim."""
import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from feasibility_profile import PROFILE, IDS, expectations, header_errors
from workloads import descriptors, SEEDS
from run import WARMUPS, REPETITIONS, MODES


class CostTail(unittest.TestCase):
    def header(self):
        return {'profile': PROFILE, 'chosen_workloads': expectations(), 'seeds': [20261014],
                'warmups': 5, 'repetitions': 30, 'expected_cases': 3, 'expected_observations': 315}

    def result(self):
        return {'profile': PROFILE, 'completed_cases': 3, 'expected_cases': 3, 'complete_grid': False}

    def test_selected_original_cases_and_full_contract(self):
        original = {row['id']: row for row in descriptors()}
        self.assertEqual([original[name] for name in IDS], expectations())
        self.assertEqual([row['rows'] for row in expectations()], [1000000, 30000, 100000])
        self.assertEqual(header_errors(self.header(), self.result()), [])
        self.assertEqual(len(descriptors()) * len(SEEDS), 410)
        self.assertEqual((WARMUPS, REPETITIONS, len(MODES)), (5, 30, 3))

    def test_changed_id_dimension_expectation_or_duplicate_is_rejected(self):
        for key, value in (('id', 'different'), ('rows', 10000),
                           ('expected_product_status', 'OK'), ('batch_rows', 4096)):
            with self.subTest(key=key):
                manifest = self.header(); manifest['chosen_workloads'][0][key] = value
                self.assertTrue(header_errors(manifest, self.result()))
        manifest = self.header(); manifest['chosen_workloads'][1] = copy.deepcopy(manifest['chosen_workloads'][0])
        self.assertTrue(header_errors(manifest, self.result()))
        manifest = self.header(); manifest['chosen_workloads'][1]['composite'] = 1
        self.assertTrue(header_errors(manifest, self.result()), 'JSON bool must not become int')

    def test_seed_order_counts_and_full_claim_are_rejected(self):
        for key, value in (('seeds', [20261015]), ('seeds', [20261014, 20261014]),
                           ('warmups', 0), ('repetitions', 1), ('expected_cases', 2),
                           ('expected_observations', 630)):
            with self.subTest(key=key, value=value):
                manifest = self.header(); manifest[key] = value
                self.assertTrue(header_errors(manifest, self.result()))
        for key, value in (('complete_grid', True), ('completed_cases', 2), ('profile', 'full')):
            with self.subTest(key=key):
                result = self.result(); result[key] = value
                self.assertTrue(header_errors(self.header(), result))

    def test_expected_descriptions_do_not_share_mutable_capture_state(self):
        changed = expectations(); changed[1]['allowed_product_statuses'].append('E_INPUT')
        self.assertEqual(expectations()[1]['allowed_product_statuses'], ['OK', 'E_BUDGET'])


if __name__ == '__main__': unittest.main()
