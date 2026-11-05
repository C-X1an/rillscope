"""Closed boot protocol fixtures and syntax checks; no guest boot is claimed."""
import ast
import base64
import copy
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import canonical_reference_boot as boot


def actual_marker_fragment():
    """Extract the unchanged real creation statements; never run mount/VM code."""
    module = ast.parse(boot.BOOTSTRAP)
    candidates = [node for node in ast.walk(module) if isinstance(node, ast.Try)
        and any(isinstance(row, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'marker'
            for target in row.targets) for row in node.body)]
    if len(candidates) != 1: raise AssertionError('one actual bootstrap marker creation block required')
    body = candidates[0].body
    index = next(index for index, row in enumerate(body) if isinstance(row, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == 'marker' for target in row.targets))
    selected = body[index:index + 3]
    if len(selected) != 3 or not isinstance(selected[-1], ast.Try):
        raise AssertionError('complete actual marker open/write/close fragment required')
    return ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[]))


def create_actual_marker_fixture(path, fchmod=None):
    """Relocate only the constant destination; real Linux uses real syscalls."""
    def destination(value):
        if value != '/run/rillscope-owned-canonical-reference': raise AssertionError('unexpected marker destination')
        return path
    class MarkerOS:
        def __getattr__(self, name):
            if name == 'O_NOFOLLOW' and os.name == 'nt' and fchmod is not None: return 0
            return getattr(os, name)
        def open(self, destination, flags, mode):
            if os.name == 'nt' and fchmod is not None: flags |= os.O_BINARY
            return os.open(destination, flags, mode)
        def fchmod(self, descriptor, mode):
            return (os.fchmod if fchmod is None else fchmod)(descriptor, mode)
    exec(compile(actual_marker_fragment(), '<actual-bootstrap-marker-fragment>', 'exec'),
         {'os': MarkerOS(), 'pathlib': SimpleNamespace(Path=destination)})


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

    def test_actual_marker_creation_preserves_constant_bytes_and_final_read_only_mode(self):
        with tempfile.TemporaryDirectory(prefix='rill-marker-mode-unit-') as directory:
            marker = Path(directory) / 'marker'; modes = []
            def chmod(descriptor, mode):
                modes.append(mode)
                # Windows has no fchmod; this adapter checks its file mode and
                # byte operations only. The mandatory Linux gate uses fchmod
                # and a real UID65534 consumer without this adapter.
                if hasattr(os, 'fchmod'): os.fchmod(descriptor, mode)
                else: os.chmod(marker, mode)
            previous = os.umask(0o077)
            try:
                create_actual_marker_fixture(marker, chmod)
                self.assertEqual(marker.read_bytes(), b'owned-ephemeral-canonical-reference\n')
                self.assertEqual(modes, [0o444])
                self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o444)
            finally:
                os.umask(previous)
                if marker.exists(): os.chmod(marker, 0o600)

    def test_actual_marker_creation_cannot_replace_an_existing_marker(self):
        with tempfile.TemporaryDirectory(prefix='rill-marker-exclusive-unit-') as directory:
            marker = Path(directory) / 'marker'; marker.write_bytes(b'original existing marker')
            with self.assertRaises(FileExistsError):
                create_actual_marker_fixture(marker, lambda *_args: self.fail('existing marker must not be changed'))
            self.assertEqual(marker.read_bytes(), b'original existing marker')


if __name__ == '__main__': unittest.main()
