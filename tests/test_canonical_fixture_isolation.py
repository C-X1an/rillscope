"""Inherited live authority must never reach simulated orchestration controls."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CASES = [
    'test_capture_dispatch.CaptureDispatch.test_default_full_propagates_validation_failure',
    'test_capture_dispatch.CaptureDispatch.test_explicit_capture_collects_full_profile_without_claiming_validation',
    'test_capture_dispatch.CaptureDispatch.test_failed_collection_cannot_be_hidden_by_capture_only',
    'test_reference_capture_export.CaptureExport.test_null_sort_original_failure_is_retained_before_return_without_a_validator_rerun',
    'test_reference_retention.ReferenceRetention.test_archive_bound_failure_stops_the_reference_attempt',
    'test_reference_retention.ReferenceRetention.test_complete_raw_packages_exist_before_validation_failure',
    'test_reference_retention.ReferenceRetention.test_failed_collection_is_packaged_and_keeps_its_original_failure',
]
KEYS = ['RILLSCOPE_REFERENCE_' + part for part in
    ('MEASUREMENT_CONFIG', 'MEASUREMENT_CONFIG_SHA256', 'EXPORT_CONFIG', 'EXPORT_CONFIG_SHA256')]


class CanonicalFixtureIsolation(unittest.TestCase):
    def test_seven_original_controls_keep_assertions_without_reading_or_using_ambient_authority(self):
        before = {key: os.environ.get(key) for key in KEYS}
        with tempfile.TemporaryDirectory(prefix='rill-config-authority-sentinel-') as directory:
            path = Path(directory) / 'live-authority-trap.json'
            original = b'SYNTHETIC AUTHORITY TRAP: reading this as a config must fail\n'
            path.write_bytes(original)
            env = dict(os.environ)
            env.update({key: hashlib.sha256(original).hexdigest() if key.endswith('_SHA256') else str(path)
                for key in KEYS})
            env['PYTHONDONTWRITEBYTECODE'] = '1'
            env['PYTHONPATH'] = os.pathsep.join(str(ROOT / part) for part in ('tests', 'scripts', 'benchmarks'))
            child = subprocess.run([sys.executable, '-B', '-m', 'unittest', *CASES, '-v'],
                cwd=ROOT, env=env, capture_output=True, timeout=60, check=False)
            self.assertEqual(child.returncode, 0, child.stderr.decode('utf-8', errors='backslashreplace'))
            self.assertIn(b'Ran 7 tests', child.stderr)
            self.assertNotIn(b'skipped=', child.stderr)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual([item.name for item in Path(directory).iterdir()], [path.name])
        self.assertEqual({key: os.environ.get(key) for key in KEYS}, before)


if __name__ == '__main__': unittest.main()
