"""Declared-result and bounded-CAS unit checks; no full campaign is simulated."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import archive_capture
from canonical_reference_campaigns import check_complete, check_manifest_binding, view_document, validate_campaigns
from capture_read_view import CaptureReadView


def literal(stage):
    if stage == 'cancel':
        return {'status': 'PASS', 'errors': [], 'observations_checked': 175}, {
            'status': 'PASS', 'observations': 175, 'measured_observations': 150,
            'invalid_observations': 0, 'source_binary_input_identity_stable': True}
    cases, observations, successes, comparisons = (410, 43050, 290, 17400) if stage == 'grid' else (40, 4200, 40, 2400)
    return {'status': 'PASS', 'errors': [], 'observations_checked': observations,
        'cases_checked': cases, 'required_success_cases_checked': successes,
        'independent_semantic_comparisons': comparisons}, {'schema_version': 3,
        'profile': 'full' if stage == 'grid' else 'sort-null-supplement',
        'completed_cases': cases, 'expected_cases': cases, 'complete_grid': stage == 'grid',
        'instrumentation_status': 'PASS', 'invalid_observations': 0, 'source_binary_inputs_stable': True}


class CanonicalCampaignRecords(unittest.TestCase):
    def workspace(self):
        local = ROOT / '.local-runs'; local.mkdir(exist_ok=True)
        return tempfile.TemporaryDirectory(prefix='cc-', dir=local)

    def test_exact_declared_three_campaign_summaries(self):
        for stage in ('grid', 'cancel', 'sort-null'):
            with self.subTest(stage=stage):
                verification, result = literal(stage)
                self.assertIsNone(check_complete(stage, verification, result))

    def test_reduced_counts_success_cases_or_comparisons_are_rejected(self):
        for stage in ('grid', 'sort-null'):
            for field in ('observations_checked', 'cases_checked', 'required_success_cases_checked', 'independent_semantic_comparisons'):
                with self.subTest(stage=stage, field=field):
                    verification, result = literal(stage); verification[field] -= 1
                    with self.assertRaises(ValueError): check_complete(stage, verification, result)

    def test_failed_original_verifier_or_original_result_stays_failed(self):
        for stage in ('grid', 'cancel', 'sort-null'):
            verification, result = literal(stage)
            with self.subTest(stage=stage, case='verifier'):
                failed = copy.deepcopy(verification); failed['errors'] = ['retained failed observation']
                with self.assertRaises(ValueError): check_complete(stage, failed, result)
            with self.subTest(stage=stage, case='result'):
                result['invalid_observations'] = 1
                with self.assertRaises(ValueError): check_complete(stage, verification, result)

    def test_boolean_counts_and_missing_cancellation_measurements_are_rejected(self):
        verification, result = literal('cancel'); verification['observations_checked'] = True
        with self.assertRaises(ValueError): check_complete('cancel', verification, result)
        verification, result = literal('cancel'); result['measured_observations'] = 149
        with self.assertRaises(ValueError): check_complete('cancel', verification, result)
        verification, result = literal('grid'); result['invalid_observations'] = False
        with self.assertRaises(ValueError): check_complete('grid', verification, result)

    def test_host_prebuilt_payload_cannot_replace_checked_native_associations(self):
        with self.workspace() as name:
            root = Path(name); artifact = root / 'artifact'; artifact.mkdir(); out = root / 'checked'
            with self.assertRaisesRegex(ValueError, 'checked native association'):
                validate_campaigns(artifact, None, {'mode': 'rillscope-full-capture-v1'},
                    commit='a' * 40, source={'sha256': 'b' * 64}, export_config_sha256='c' * 64, out=out)
            self.assertFalse(out.exists())

    def test_real_small_cas_metadata_read_is_bounded_and_creates_no_expanded_files(self):
        with self.workspace() as name:
            root = Path(name); source = root / 'raw'; source.mkdir()
            expected = {'fixture': 'small CAS metadata; no benchmark or execution'}
            original = (json.dumps(expected) + '\n').encode(); (source / 'manifest.json').write_bytes(original)
            package = root / 'capture'; archive_capture.pack(source, package)
            mount = root / 'view'
            with CaptureReadView(package / 'capture.zip', mount) as view:
                self.assertEqual(view_document(view, 'manifest.json', len(original)), expected)
                with self.assertRaises(ValueError): view_document(view, 'manifest.json', len(original) - 1)
                with self.assertRaises(ValueError): view_document(view, 'missing.json', 4096)
            self.assertFalse(mount.exists())

    def test_native_and_captured_manifest_must_be_the_exact_same_bytes_and_role(self):
        for stage, role, experiment, inner in [('grid', 'full-grid', 'benchmark-123', 'grid'),
            ('cancel', 'full-cancel', 'benchmark-123', 'cancel'), ('sort-null', 'sort-null', 'bench/s-123', 'grid')]:
            binding = {'role': role, 'linked_metadata_sha256': 'd' * 64,
                'linked_source': '.local-runs/clean-fixture/c/.local-runs/' + experiment + '/' + inner + '/manifest.json'}
            with self.subTest(stage=stage):
                self.assertEqual(check_manifest_binding(stage, binding, 'd' * 64).name, 'manifest.json')
                with self.assertRaisesRegex(ValueError, 'exact original native manifest'):
                    check_manifest_binding(stage, binding, 'e' * 64)
                wrong = {**binding, 'linked_source': binding['linked_source'].replace('/manifest.json', '/other.json')}
                with self.assertRaisesRegex(ValueError, 'path differs'): check_manifest_binding(stage, wrong, 'd' * 64)
                with self.assertRaises(ValueError): check_manifest_binding(stage, {**binding, 'linked_metadata_sha256': True}, 'd' * 64)


if __name__ == '__main__': unittest.main()
