"""Closed boot protocol fixtures and syntax checks; no guest boot is claimed."""
import ast
import base64
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import canonical_reference_boot as boot


class NativeBootControls(unittest.TestCase):
    def fixture(self):
        return {'schema_version': 1, 'method': 'rillscope-controller-owned-canonical-reference-v1',
            'boot_id': '11111111-2222-3333-4444-555555555555', 'commit': 'a' * 40,
            'source_sha256': 'b' * 64, 'seed_sha256': 'c' * 64, 'mode': 'canonical',
            'started_monotonic_ns': 100, 'finished_monotonic_ns': 200, 'utc_ns': 300,
            'worker_pid': 201, 'worker_exit': 0, 'worker_stopped': True, 'unmount_status': 'PASS',
            'status': 'PASS', 'errors': [], 'reference_qualified': False}

    def encode(self, row):
        return boot.BOOT_PREFIX + base64.b64encode(json.dumps(row, separators=(',', ':')).encode()).decode() + '\n'

    def test_exact_new_boot_footer_and_setup_diagnostic_preserve_unqualified_scope(self):
        row = self.fixture(); self.assertEqual(boot.parse_boot('[kernel]\n' + self.encode(row)), row)
        row['mode'] = 'native-setup-diagnostic'
        self.assertEqual(boot.parse_boot(self.encode(row)), row)
        row.update(status='FAIL', worker_exit=1, unmount_status='FAIL')
        self.assertEqual(boot.parse_boot(self.encode(row))['status'], 'FAIL')

    def test_incomplete_or_failed_worker_unmount_or_cleanup_cannot_serialize_success(self):
        for key, value in [('worker_exit', 1), ('worker_exit', False), ('worker_stopped', False),
            ('worker_pid', None), ('unmount_status', 'FAIL'), ('unmount_status', 'NOT MOUNTED'),
            ('reference_qualified', True), ('finished_monotonic_ns', 99), ('schema_version', True),
            ('seed_sha256', None), ('mode', 'full'), ('errors', [{'phase': 'stop', 'error': 'OSError',
                'reason': 'original error', 'traceback': 'original traceback'}])]:
            with self.subTest(key=key, value=value):
                row = copy.deepcopy(self.fixture()); row[key] = value
                with self.assertRaises(ValueError): boot.parse_boot(self.encode(row))

    def test_missing_duplicate_oversized_and_old_method_records_are_rejected(self):
        row = self.fixture(); frame = self.encode(row)
        for serial in ('', frame + frame, 'RILLSCOPE_PILOT_BOOT_V1 e30=\n',
            boot.BOOT_PREFIX + 'x' * 24001, self.encode({})):
            with self.subTest(serial=serial[:80]):
                with self.assertRaises(ValueError): boot.parse_boot(serial)
        row['method'] = 'rillscope-full-capture-v1'
        with self.assertRaises(ValueError): boot.parse_boot(self.encode(row))

    def test_cloud_payload_contains_distinct_marker_worker_and_no_login_user(self):
        config = boot.cloud_config()
        self.assertEqual(config['users'], [])
        self.assertIs(config['disable_root'], True); self.assertIs(config['ssh_pwauth'], False)
        self.assertEqual(config['bootcmd'], [['/usr/bin/systemctl', 'mask', '--runtime', '--now', 'serial-getty@ttyS0.service']])
        source = base64.b64decode(config['write_files'][0]['content'], validate=True).decode('ascii')
        self.assertEqual(source, boot.BOOTSTRAP); ast.parse(source)
        self.assertIn('/run/rillscope-owned-canonical-reference', source)
        self.assertIn('/work/c/scripts/canonical_reference_guest_start.py', source)
        self.assertNotIn('/work/c/scripts/kvm_pilot_guest.py', source)
        self.assertNotIn('/run/rillscope-owned-pilot', source)


if __name__ == '__main__': unittest.main()
