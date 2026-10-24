"""New host preparation guards and resource controls; no KVM/image action."""
import copy
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import canonical_reference_host_setup as setup


class HostPreparationControls(unittest.TestCase):
    def parameters(self):
        return {'commit': 'a' * 40, 'source_sha256': 'b' * 64, 'run_as': 'runner',
            'host_seconds': 600, 'guest_setup_seconds': 3000, 'tail_seconds': 60,
            'retention_seconds': 180, 'mode': 'native-setup-diagnostic'}

    def test_exact_finite_new_parameters_never_infer_provider_fit(self):
        row = self.parameters(); self.assertEqual(setup.parameters(**row), row)
        for key, value in [('commit', 'bad'), ('source_sha256', 'bad'), ('run_as', 'root/other'),
            ('host_seconds', True), ('host_seconds', 1801), ('guest_setup_seconds', 3601),
            ('tail_seconds', 0), ('retention_seconds', 601), ('mode', 'full'), ('mode', [])]:
            with self.subTest(key=key, value=value):
                changed = copy.deepcopy(row); changed[key] = value
                with self.assertRaises(ValueError): setup.parameters(**changed)

    def test_remote_storage_floor_is_distinct_from_local_cap_and_not_fit(self):
        with patch.object(setup.shutil, 'disk_usage', return_value=(100 * 1024**3, 20 * 1024**3, 80 * 1024**3)):
            row = setup.storage(Path('synthetic'))
            self.assertEqual(row['required_headroom_bytes'], 60 * 1024**3)
            self.assertEqual(row['whole_campaign_fit'], 'NOT MEASURED')
        for values in [(100 * 1024**3, 50 * 1024**3, 50 * 1024**3), (True, 0, 1), (100, 0, -1)]:
            with patch.object(setup.shutil, 'disk_usage', return_value=values):
                with self.assertRaises(ValueError): setup.storage(Path('synthetic'))

    def test_actual_windows_platform_stops_before_paths_users_or_source(self):
        with patch.object(setup.platform, 'system', return_value='Windows'), patch.object(setup, 'source_check') as source:
            row = self.parameters()
            with self.assertRaisesRegex(ValueError, 'actual existing scoped Linux root'):
                setup.prepare(Path('missing'), ownership=None, **row)
            source.assert_not_called()

    def test_actual_workflow_scope_must_match_before_any_preparation(self):
        with patch.object(setup.platform, 'system', return_value='Linux'), \
            patch.object(setup.os, 'geteuid', return_value=0, create=True), \
            patch.dict(os.environ, {'GITHUB_REPOSITORY': 'unrelated/repository',
                'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'}):
            with self.assertRaisesRegex(ValueError, 'actual authorized scoped workflow'):
                setup.actual_controller()


if __name__ == '__main__': unittest.main()
