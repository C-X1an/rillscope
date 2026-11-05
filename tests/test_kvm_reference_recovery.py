"""Read-only recovery ownership and original failure preservation controls."""
from pathlib import Path, PurePosixPath
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import kvm_reference_recovery as recovery
import recover_kvm_reference as fallback


class FullRecovery(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / '.local-runs')
        self.out = Path(self.temp.name); (self.out / 'artifact').mkdir()
        self.source = {'sha256': 'a' * 64, 'files': []}
        self.owner = {'cwd': str(ROOT), 'source_before': self.source,
            'source_after_sha256': 'a' * 64,
            'process_cleanup': {'status': 'PASS', 'remaining_active_processes': 0},
            'command': ['python3', 'scripts/kvm_reference_host.py', '--out', str(self.out)]}

    def tearDown(self): self.temp.cleanup()

    def test_failed_original_owner_can_only_authorize_read_only_recovery_after_cleanup(self):
        self.owner['verification_status'] = 'FAIL'; self.owner['exit_code'] = 1
        before = self.owner.copy()
        # The production entry is Linux-only. Keep real Windows temporary files
        # for these association controls while adapting only its native-path
        # check; the original closed debugfs command is checked separately.
        with patch.object(fallback, 'source_identity', return_value=self.source), \
             patch.object(fallback, 'owned_output', side_effect=lambda value: Path(value).resolve()):
            fallback.owner_stopped(self.owner, self.out)
        self.assertEqual(self.owner, before)
        self.owner['process_cleanup'] = {'status': 'FAIL', 'remaining_active_processes': 1}
        with patch.object(fallback, 'source_identity', return_value=self.source), \
             patch.object(fallback, 'owned_output', side_effect=lambda value: Path(value).resolve()), self.assertRaises(ValueError):
            fallback.owner_stopped(self.owner, self.out)

    def test_pilot_or_other_output_receipt_cannot_authorize_full_recovery(self):
        with patch.object(fallback, 'source_identity', return_value=self.source), \
             patch.object(fallback, 'owned_output', side_effect=lambda value: Path(value).resolve()):
            self.owner['command'][1] = 'scripts/kvm_benchmark_pilot.py'
            with self.assertRaises(ValueError): fallback.owner_stopped(self.owner, self.out)
            self.owner['command'][1] = 'scripts/kvm_reference_host.py'
            self.owner['command'][-1] = str(self.out / 'other')
            with self.assertRaises(ValueError): fallback.owner_stopped(self.owner, self.out)

    def test_missing_disk_and_failed_helpers_preserve_all_missing_stages_as_fail(self):
        commands = []
        def checked(name, command, **kwargs):
            commands.append(command)
            raise OSError('injected read-only recovery error')
        def native_path_adapter(image, source, destination, *, directory=False):
            self.assertTrue(Path(destination).is_relative_to(self.out))
            self.assertTrue(source.startswith('/c/.local-runs/kvm-reference/'))
            self.assertNotIn('..', source)
            return ['debugfs', '-R', ('rdump ' if directory else 'dump -p ') + source + ' ' + str(destination), str(image)]
        with patch.object(recovery, 'disk_identity', side_effect=OSError('original disk missing')), \
             patch.object(recovery, 'debugfs_command', side_effect=native_path_adapter):
            result = recovery.recover(self.out, checked, recovery.time.monotonic() + 10)
        self.assertEqual(result['status'], 'FAIL')
        self.assertTrue(result['read_only'])
        self.assertEqual([row['stage'] for row in result['packages']], ['grid', 'cancel', 'sort-null'])
        self.assertTrue(all(row['status'] == 'FAIL' for row in result['packages']))
        self.assertTrue(all('-w' not in command and 'mount' not in command and 'fsck' not in command for command in commands))
        self.assertTrue(any('/c/.local-runs/kvm-reference/control' in ' '.join(command) for command in commands))
        self.assertTrue((self.out / 'artifact/recovery.json').is_file())

    def test_actual_native_debugfs_command_has_no_write_or_mount_option(self):
        command = recovery.debugfs_command(PurePosixPath('/owned/work.raw'), '/c/.local-runs/kvm-reference/control',
            PurePosixPath('/owned/artifact/control'), directory=True)
        self.assertEqual(command, ['debugfs', '-R',
            'rdump /c/.local-runs/kvm-reference/control /owned/artifact/control', '/owned/work.raw'])
        with self.assertRaises(ValueError):
            recovery.debugfs_command(PurePosixPath('/owned/work.raw'), '/c/../secret', PurePosixPath('/owned/out'))


if __name__ == '__main__': unittest.main()
