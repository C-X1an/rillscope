"""Independent pairing outcomes; synthetic values are not performance measurements."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'benchmarks'))
import run


SCHEMA = [{'name': 'x', 'type': 'i64', 'nullable': True}]


def success(rows):
    return {'status': 'ok', 'schema': copy.deepcopy(SCHEMA), 'rows': rows}


def pairing(on, off, oracle, *, ordered=False, description=None):
    triplet = [({'mode': mode, 'phase': 'measured', 'repetition': 9}, result)
               for mode, result in zip(run.MODES, (on, off, oracle))]
    before = copy.deepcopy(triplet)
    result = run.pair_verdict(triplet, {'ordered': ordered, 'description': description or {}})
    if triplet != before: raise AssertionError('pairing mutated an original terminal or sample')
    return result


class PairingOutcomes(unittest.TestCase):
    def test_unordered_bags_preserve_duplicates_nulls_and_original_samples(self):
        verdict = pairing(success([[None], [2], [2]]), success([[2], [None], [2]]),
                          success([[2], [2], [None]]))
        self.assertEqual(verdict, {'phase': 'measured', 'repetition': 9, 'modes': {
            mode: {'problems': [], 'oracle_comparison': 'EXACT'} for mode in run.MODES}})

    def test_order_schema_duplicate_counts_and_scalar_types_still_disagree(self):
        cases = [
            (success([[None], [2]]), success([[2], [None]]), True),
            (success([[2]]), success([[2], [2]]), False),
            (success([[True]]), success([[1]]), False),
            (success([[None]]), success([['null']]), False),
            ({'status': 'ok', 'schema': [{'name': 'different', 'type': 'i64', 'nullable': True}], 'rows': [[2]]}, success([[2]]), False),
        ]
        for actual, expected, ordered in cases:
            with self.subTest(actual=actual, expected=expected, ordered=ordered):
                verdict = pairing(actual, copy.deepcopy(expected), expected, ordered=ordered)['modes']
                self.assertEqual(verdict['rust-on']['problems'], ['independent SQLite result mismatch'])
                self.assertEqual(verdict['rust-on']['oracle_comparison'], 'NO SUCCESSFUL RESULT TO COMPARE')
                self.assertEqual(verdict['rust-off'], {'problems': [], 'oracle_comparison': 'EXACT'})
                self.assertEqual(verdict['sqlite'], {'problems': [], 'oracle_comparison': 'EXACT'})

    def test_missing_and_failed_oracles_keep_all_failure_outcomes(self):
        failed = {'status': 'error', 'error': {'code': 'E_OUTPUT_LIMIT'}}
        for oracle, expected in [(None, 'terminal result unavailable'),
                                 (failed, 'predetermined independent baseline outcome mismatch')]:
            verdict = pairing(success([[2]]), success([[2]]), oracle)['modes']
            self.assertEqual(verdict['sqlite']['problems'], [expected])
            for mode in ('rust-on', 'rust-off'):
                self.assertEqual(verdict[mode]['problems'], ['successful Rust output has no successful independent oracle'])
                self.assertEqual(verdict[mode]['oracle_comparison'], 'NO SUCCESSFUL RESULT TO COMPARE')
        budget = {'status': 'error', 'error': {'code': 'E_BUDGET'}}
        verdict = pairing(budget, copy.deepcopy(budget), success([[2]]),
                          description={'expected_product_status': 'OK'})['modes']
        for mode in ('rust-on', 'rust-off'):
            self.assertEqual(verdict[mode]['problems'], ['required product outcome mismatch'])
        self.assertEqual(verdict['sqlite'], {'problems': [], 'oracle_comparison': 'EXACT'})

    def test_changed_terminal_is_compared_again_on_the_next_call(self):
        actual = success([[2]]); other = success([[2]]); oracle = success([[2]])
        self.assertEqual(pairing(actual, other, oracle)['modes']['rust-on']['oracle_comparison'], 'EXACT')
        actual['rows'].append([2])
        self.assertEqual(pairing(actual, other, oracle)['modes']['rust-on']['problems'], ['independent SQLite result mismatch'])

    def test_distribution_keeps_nearest_rank_tails_median_and_mad(self):
        self.assertEqual(run.distribution([6, 1, 0, 2, 1]), {
            'n': 5, 'min': 0, 'p50': 1, 'p95': 6, 'p99': 6, 'max': 6, 'median_absolute_deviation': 1})
        self.assertEqual(run.distribution([-2, 0]), {
            'n': 2, 'min': -2, 'p50': -1, 'p95': 0, 'p99': 0, 'max': 0, 'median_absolute_deviation': 1})
        self.assertEqual(run.distribution([]), {'n': 0, 'status': 'NOT MEASURED'})


if __name__ == '__main__': unittest.main()
