"""Read-only layout and actual-child rejection; no disk/VM recovery is mocked as real."""
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import canonical_reference_recovery as recovery


class RecoveryControls(unittest.TestCase):
    def test_closed_fixed_layout_keeps_diagnostics_distinct_from_canonical(self):
        self.assertEqual([row[0] for row in recovery.layout('native-setup-diagnostic')], ['boot', 'setup', 'start'])
        self.assertEqual([row[0] for row in recovery.layout('canonical')],
            ['boot', 'setup', 'start', 'allocation', 'owner', 'control', 'observer'])
        for value in ('full', 'pilot', [], True):
            with self.assertRaises(ValueError): recovery.layout(value)
        self.assertEqual(recovery.layout('canonical')[3][1], '/c/.local-runs/canonical-allocation')

    def test_success_shaped_cleanup_cannot_substitute_for_actual_stopped_qemu(self):
        for cleanup in ({'status': 'FAIL', 'remaining_active_processes': 0},
            {'status': 'PASS', 'remaining_active_processes': False},
            {'status': 'PASS', 'remaining_active_processes': 1},
            {'status': 'PASS', 'remaining_active_processes': 0}):
            with self.subTest(cleanup=cleanup):
                with self.assertRaises(ValueError): recovery.stopped(None, [], None, cleanup)

    def test_real_finished_python_child_cannot_impersonate_the_original_vm(self):
        command = [sys.executable, '-c', 'pass']
        with subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            process.communicate(timeout=5)
            with self.assertRaisesRegex(ValueError, 'actual stopped original owned QEMU'):
                recovery.stopped(process, command, None, {'status': 'PASS', 'remaining_active_processes': 0})

    def test_unavailable_runtime_cannot_read_or_create_any_disk_artifact(self):
        with patch.object(recovery, 'actual_controller', side_effect=ValueError('actual existing controller required')), \
            patch.object(recovery, 'disk_identity') as disk:
            with self.assertRaisesRegex(ValueError, 'actual existing controller'):
                recovery.recover(Path('missing'), process=None, command=[], channel=None, cleanup={},
                    mode='canonical', deadline=1, checked=None)
            disk.assert_not_called()


if __name__ == '__main__': unittest.main()
