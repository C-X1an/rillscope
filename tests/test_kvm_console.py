"""Owned console failure controls; unit fixtures never establish VM qualification."""
import contextlib
import errno
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import kvm_benchmark_pilot as pilot
import kvm_pilot_guest as guest


class FailedConsole(io.StringIO):
    def write(self, _value): raise OSError(errno.EIO, 'controlled console I/O failure')


class ConsoleFailures(unittest.TestCase):
    def worker(self, mode, stream):
        (ROOT / '.local-runs').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='kgc-', dir=ROOT / '.local-runs') as directory:
            base = Path(directory) / 'worker'; payload = Path(directory) / 'payload.json'
            payload.write_text('{}', encoding='utf-8'); finished = []
            marker = Path('/run/rillscope-owned-pilot')
            boot = Path('/proc/sys/kernel/random/boot_id')
            original_file, original_text = Path.is_file, Path.read_text
            def is_file(path): return True if path == marker else original_file(path)
            def read_text(path, *args, **kwargs):
                if path == marker: return 'owned-ephemeral-kvm-pilot\n'
                if path == boot: return '12345678-1234-1234-1234-123456789abc\n'
                return original_text(path, *args, **kwargs)
            def finish(_):
                finished.append(True)
                return {'status': 'PASS', 'remaining_active_processes': 0}
            def collect(*_):
                if mode == 'primary-error': raise ValueError('original collector failure')
                if mode == 'ready': guest.emit('ready')
                return {'status': 'COLLECTED', 'reference_qualified': False}
            with patch.object(guest, 'ROOT', Path('/work/c')), patch.object(guest, 'BASE', base), \
                    patch.object(guest, 'INPUT', payload), patch.object(guest.platform, 'system', return_value='Linux'), \
                    patch.object(guest.os, 'geteuid', return_value=0, create=True), \
                    patch.object(Path, 'is_file', is_file), patch.object(Path, 'read_text', read_text), \
                    patch.object(guest, 'collect', side_effect=collect), \
                    patch.object(guest, 'LinuxOwnedChildren', return_value=SimpleNamespace(finish=finish)), \
                    patch.object(guest.os, 'sync', create=True), patch.object(guest.signal, 'signal'), \
                    contextlib.redirect_stdout(stream):
                code = guest.main()
            self.assertEqual(code, 1, 'unavailable control output must be a finite failure')
            self.assertEqual(finished, [True], 'console failure must not bypass owned cleanup')
            result = json.loads((base / 'exports/guest-result.json').read_bytes())
            self.assertEqual(result['status'], 'FAIL')
            self.assertEqual(result['cleanup'], {'status': 'PASS', 'remaining_active_processes': 0})
            self.assertIn('Traceback', result['first_error']['traceback'])
            self.assertLessEqual(len(result['first_error']['traceback']), 8192)
            if mode == 'primary-error':
                self.assertEqual(result['first_error']['error'], 'ValueError')
                self.assertEqual(result['first_error']['reason'], 'original collector failure')
                self.assertEqual([row['phase'] for row in result['failures']],
                                 ['collect', 'guest-failure-event', 'guest-exit-event'])
            elif mode == 'ready':
                self.assertEqual(result['first_error']['phase'], 'collect')
                self.assertEqual(result['first_error']['error'], 'OSError')
                self.assertIn('emit', result['first_error']['traceback'])
            else:
                self.assertEqual(result['first_error']['phase'], 'guest-exit-event')
            return result

    def test_ready_output_eio_is_saved_with_traceback_and_cleanup(self): self.worker('ready', FailedConsole())

    def test_secondary_console_errors_preserve_original_collection_error(self):
        self.worker('primary-error', FailedConsole())

    def test_failed_final_event_cannot_leave_a_collected_disk_result(self):
        self.worker('exit', FailedConsole())

    def test_bootstrap_console_failure_still_saves_unmounts_and_requests_shutdown(self):
        (ROOT / '.local-runs').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='kgb-', dir=ROOT / '.local-runs') as directory:
            work = Path(directory) / 'work'; calls = []; real_path = Path
            def mapped(value):
                path = real_path(value)
                self.assertTrue(path.is_relative_to(real_path('/work')))
                return work / path.relative_to(real_path('/work'))
            def command(argv, **_):
                calls.append(argv)
                return subprocess.CompletedProcess(argv, 0)
            with patch('pathlib.Path', side_effect=mapped), patch('subprocess.run', side_effect=command), \
                    patch('os.sync', create=True), contextlib.redirect_stdout(FailedConsole()):
                exec(compile(pilot.BOOTSTRAP, '<owned-boot-fixture>', 'exec'), {})
            self.assertEqual(calls[0][0], '/usr/bin/mount')
            self.assertFalse(any('/work/c/scripts/kvm_pilot_guest.py' in row for row in calls),
                             'unavailable lifecycle output must prevent campaign launch')
            self.assertEqual([row[0] for row in calls[-2:]], ['/usr/bin/umount', '/usr/sbin/shutdown'])
            record = json.loads((work / 'c/.local-runs/kvm-pilot/exports/boot-result.json').read_bytes())
            self.assertIsNone(record['worker_exit'])
            self.assertEqual(record['unmount_status'], 'PENDING')
            self.assertTrue(record['console_errors'])
            self.assertIn('Traceback', record['traceback'])
            self.assertIn('before unmount', record['scope'])

    def test_only_the_owned_guest_serial_getty_is_runtime_masked_before_console_open(self):
        configure = getattr(pilot, 'cloud_config', None)
        self.assertTrue(callable(configure), 'seed configuration needs an independently inspectable console policy')
        config = configure()
        self.assertEqual(config['bootcmd'], [['/usr/bin/systemctl', 'mask', '--runtime', '--now',
                                             'serial-getty@ttyS0.service']])
        self.assertEqual(config['runcmd'], [['/bin/sh', '-c',
            '/usr/bin/python3 /opt/rillscope-pilot-boot.py > /dev/ttyS0 2>&1']])

    def test_late_console_error_cannot_suppress_unmount_or_shutdown(self):
        class LateConsole(io.StringIO):
            failed = False
            def write(self, value):
                if self.failed: raise OSError(errno.EIO, 'controlled late console failure')
                return super().write(value)
        (ROOT / '.local-runs').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='kgl-', dir=ROOT / '.local-runs') as directory:
            work = Path(directory) / 'work'; calls = []; real_path = Path; stream = LateConsole()
            def mapped(value):
                path = real_path(value)
                self.assertTrue(path.is_relative_to(real_path('/work')) or path == real_path('/run/rillscope-owned-pilot'))
                return work / ('owned-marker' if path == real_path('/run/rillscope-owned-pilot')
                               else path.relative_to(real_path('/work')))
            def command(argv, **_):
                calls.append(argv)
                if '/work/c/scripts/kvm_pilot_guest.py' in argv:
                    stream.failed = True
                    return subprocess.CompletedProcess(argv, 7)
                return subprocess.CompletedProcess(argv, 0)
            with patch('pathlib.Path', side_effect=mapped), patch('subprocess.run', side_effect=command), \
                    patch('os.sync', create=True), contextlib.redirect_stdout(stream):
                exec(compile(pilot.BOOTSTRAP, '<owned-late-boot-fixture>', 'exec'), {})
            self.assertEqual([row[0] for row in calls[-2:]], ['/usr/bin/umount', '/usr/sbin/shutdown'])
            record = json.loads((work / 'c/.local-runs/kvm-pilot/exports/boot-result.json').read_bytes())
            self.assertEqual(record['worker_exit'], 7)
            self.assertEqual(record['unmount_status'], 'PENDING')
            self.assertTrue(record['console_errors'])
            self.assertIn('Traceback', record['console_errors'][0]['traceback'])

    def test_final_frame_includes_a_one_shot_shutdown_marker_failure(self):
        class OneShotConsole(io.StringIO):
            def write(self, value):
                if value.startswith('RILLSCOPE_PILOT_BOOT_STAGE_V1 ') and '"stage":"shutdown-start"' in value:
                    raise OSError(errno.EIO, 'controlled shutdown marker failure')
                return super().write(value)
        (ROOT / '.local-runs').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='kgs-', dir=ROOT / '.local-runs') as directory:
            work = Path(directory) / 'work'; real_path = Path; calls = []; stream = OneShotConsole()
            def mapped(value):
                path = real_path(value)
                self.assertTrue(path.is_relative_to(real_path('/work')) or path == real_path('/run/rillscope-owned-pilot'))
                return work / ('owned-marker' if path == real_path('/run/rillscope-owned-pilot')
                               else path.relative_to(real_path('/work')))
            def command(argv, **_):
                calls.append(argv)
                return subprocess.CompletedProcess(argv, 0)
            with patch('pathlib.Path', side_effect=mapped), patch('subprocess.run', side_effect=command), \
                    patch('os.sync', create=True), contextlib.redirect_stdout(stream):
                exec(compile(pilot.BOOTSTRAP, '<owned-shutdown-boot-fixture>', 'exec'), {})
            self.assertEqual([row[0] for row in calls[-2:]], ['/usr/bin/umount', '/usr/sbin/shutdown'])
            final = pilot.parse_boot(stream.getvalue())
            self.assertEqual(final['worker_exit'], 0)
            self.assertEqual(final['unmount_status'], 'PASS')
            self.assertEqual([row['phase'] for row in final['console_errors']], ['shutdown-start'])
            saved = json.loads((work / 'c/.local-runs/kvm-pilot/exports/boot-result.json').read_bytes())
            self.assertEqual(saved['console_errors'], [], 'pre-unmount record must not invent later observations')


if sys.platform == 'linux':
    class RealOwnedPty(unittest.TestCase):
        def test_real_closed_master_eio_retains_original_failure_and_cleanup(self):
            # These are two new owned PTY descriptors, never the host console.
            master, slave = os.openpty(); stream = None
            try:
                self.assertEqual(os.write(slave, b'owned-pty-before-hangup\n'), 24)
                self.assertIn(b'owned-pty-before-hangup', os.read(master, 128))
                os.close(master); master = None
                with self.assertRaises(OSError) as error: os.write(slave, b'after-owned-master-close\n')
                self.assertEqual(error.exception.errno, errno.EIO)
                stream = os.fdopen(os.dup(slave), 'w', encoding='utf-8', buffering=1)
                result = ConsoleFailures().worker('ready', stream)
                self.assertIn('[Errno 5]', result['first_error']['reason'])
            finally:
                if master is not None: os.close(master)
                if stream is not None:
                    try: stream.close()
                    except OSError as error:
                        if error.errno != errno.EIO: raise
                os.close(slave)


if __name__ == '__main__': unittest.main()
