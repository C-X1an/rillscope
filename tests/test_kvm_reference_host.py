"""Full host command/boot contracts remain isolated from the pilot."""
import base64
from pathlib import Path
import sys
import unittest
from unittest.mock import patch, Mock
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import kvm_reference_host as host
import kvm_benchmark_pilot as pilot
from kvm_reference_channel import PORT_NAME


class HostContract(unittest.TestCase):
    def test_closed_qemu_command_keeps_kvm_memory_uid_no_shares_and_own_port(self):
        original = pilot.qemu_command(Path('/owned'), Path('/owned/base.img'), 'runner', 1234)
        command = host.qemu_command(Path('/owned'), Path('/owned/base.img'), 'runner', 1234)
        self.assertEqual(command[command.index('-accel') + 1], 'kvm')
        self.assertEqual(command[command.index('-runas') + 1], 'runner')
        self.assertIn('4,sockets=1,cores=4,threads=1', command)
        self.assertIn('memory-backend-ram,id=ram0,size=8G,prealloc=on,merge=off', command)
        self.assertIn('virtserialport,chardev=capture,name=' + PORT_NAME, command)
        self.assertNotIn('-virtfs', command); self.assertNotIn('hostfwd=', ' '.join(command))
        self.assertEqual(pilot.qemu_command(Path('/owned'), Path('/owned/base.img'), 'runner', 1234), original)
        self.assertNotEqual(command[command.index('-name') + 1], original[original.index('-name') + 1])

    def test_bootstrap_retains_console_mask_unmount_shutdown_and_uses_only_full_worker(self):
        config = host.cloud_config()
        data = base64.b64decode(config['write_files'][0]['content']).decode()
        self.assertIn('/work/c/scripts/kvm_reference_guest.py', data)
        self.assertIn('owned-ephemeral-full-collection', data)
        self.assertIn('RILLSCOPE_FULL_BOOT_V1 ', data)
        self.assertNotIn('kvm-pilot', data); self.assertNotIn('rillscope-owned-pilot', data)
        self.assertNotIn('kvm_pilot_guest.py', data)
        self.assertIn("subprocess.run(['/usr/bin/umount','/work']", data)
        self.assertIn("subprocess.run(['/usr/sbin/shutdown','-h','now']", data)
        self.assertIn("stage('shutdown-start')", data)
        self.assertEqual(config['bootcmd'], [['/usr/bin/systemctl', 'mask', '--runtime', '--now', 'serial-getty@ttyS0.service']])
        compile(data, 'actual-full-bootstrap', 'exec')

    def test_storage_guard_preserves_actual_insufficient_measurement(self):
        with patch.object(host.shutil, 'disk_usage', return_value=(100, 99, 1)):
            with self.assertRaisesRegex(ValueError, 'storage'): host.storage(Path('/owned'))
        with patch.object(host.shutil, 'disk_usage', return_value=(1000, 1, 1000)), \
             patch.object(host, 'MIN_FREE_BYTES', 999):
            result = host.storage(Path('/owned'))
        self.assertEqual(result['free_bytes'], 1000)
        self.assertEqual(result['required_headroom_bytes'], 999)
        self.assertFalse(result['full_fit_established'])

    def test_non_linux_entry_never_prepares_or_launches_a_guest(self):
        with patch.object(host.platform, 'system', return_value='Windows'), patch.object(host, 'prepare_host') as prepare:
            self.assertEqual(host.main(['--out', '.local-runs/test', '--run-as', 'runner',
                '--build-receipt', '.local-runs/build/build.json', '--commit', '1' * 40]), 77)
        prepare.assert_not_called()

    def test_receiver_inherits_the_exact_pre_qemu_vm_start_without_new_time(self):
        payload = {'commit': '1' * 40, 'source': {'sha256': '2' * 64}}
        command = host.receiver_command(Path('/owned'), payload, 123456789)
        self.assertEqual(command, [sys.executable, str(ROOT / 'scripts/kvm_reference_receiver.py'),
            '--socket', str(Path('/owned/runtime/capture.sock')), '--out', str(Path('/owned/artifact/packages')),
            '--timeout', '18000', '--vm-started-monotonic-ns', '123456789',
            '--commit', '1' * 40, '--source-sha256', '2' * 64])
        for start in [True, 0, -1, 1.5]:
            with self.assertRaises(ValueError): host.receiver_command(Path('/owned'), payload, start)

    def test_diagnostic_or_shutdown_error_cannot_suppress_owned_descendant_stop(self):
        process = Mock(); process.pid = 1234; process.poll.return_value = None
        process.wait.side_effect = OSError('shutdown wait failed')
        process.terminate.side_effect = OSError('direct terminate failed')
        ownership = Mock(); ownership.terminate.return_value = {'status': 'PASS', 'remaining_active_processes': 0}
        with patch.object(host.pilot, 'collect_boot_diagnostics', side_effect=OSError('diagnostic disk full')), \
             patch.object(host.pilot, 'qmp', side_effect=OSError('QMP unavailable')):
            result = host.stop_vm(Path('/owned'), process, None, [], 1234, ownership, {'error': 'OriginalError'})
        ownership.terminate.assert_called_once_with(1234)
        self.assertEqual(result['cleanup']['status'], 'PASS')
        self.assertTrue(result['errors'])

    def test_reaped_receiver_without_an_observed_exit_is_not_reported_as_exit_zero(self):
        receiver = Mock(); receiver.poll.return_value = None
        ownership = Mock(); ownership.terminate.return_value = {'status': 'PASS', 'remaining_active_processes': 0}
        with patch.object(host.time, 'monotonic', side_effect=[0, 6]):
            result = host.stop_vm(Path('/owned'), None, receiver, [], 1234, ownership, None)
        self.assertIsNone(result['receiver_exit_observed_before_stop'])
        self.assertTrue(result['errors'])
        ownership.terminate.assert_called_once_with(None)


if __name__ == '__main__': unittest.main()
