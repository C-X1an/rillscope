"""Boot selection and bounded diagnostic unit controls; no VM execution claim."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import kvm_benchmark_pilot as pilot


class BootDiagnostics(unittest.TestCase):
    def test_only_the_intended_os_device_has_explicit_boot_priority(self):
        command = pilot.qemu_command(Path('/owned'), Path('/owned/image.qcow2'), 'runner', 12345)
        drives = [command[i + 1] for i, item in enumerate(command) if item == '-drive']
        devices = [command[i + 1] for i, item in enumerate(command) if item == '-device']
        self.assertIn('file=' + str(Path('/owned') / 'disk.qcow2') + ',if=none,format=qcow2,id=rillboot-disk', drives)
        self.assertIn('virtio-blk-pci,drive=rillboot-disk,bootindex=1', devices)
        self.assertEqual([item for item in devices if 'bootindex=' in item],
                         ['virtio-blk-pci,drive=rillboot-disk,bootindex=1'])
        self.assertEqual([command[i + 1] for i, item in enumerate(command) if item == '-boot'], ['strict=on'])
        self.assertFalse(any('order=' in item or 'once=' in item for item in command))

    def test_bootstrap_reports_entry_and_mount_attempt_even_when_mount_fails(self):
        output = io.StringIO(); commands = []
        def run(command, **kwargs):
            commands.append(command)
            if command[0] == '/usr/bin/mount': raise subprocess.CalledProcessError(32, command)
            return subprocess.CompletedProcess(command, 0)
        with patch('pathlib.Path'), patch('subprocess.run', side_effect=run), contextlib.redirect_stdout(output):
            exec(compile(pilot.BOOTSTRAP, '<boot-fixture>', 'exec'), {})
        lines = output.getvalue().splitlines()
        stages = [json.loads(line.split(' ', 1)[1])['stage'] for line in lines
                  if line.startswith('RILLSCOPE_PILOT_BOOT_STAGE_V1 ')]
        self.assertEqual(stages, ['bootstrap-enter', 'work-mount-start', 'shutdown-start'])
        self.assertEqual(pilot.parse_boot(output.getvalue())['error'], 'CalledProcessError')
        self.assertEqual(commands[0][0], '/usr/bin/mount')
        self.assertEqual(commands[-1], ['/usr/sbin/shutdown', '-h', 'now'])

    def test_failed_query_does_not_suppress_device_register_and_real_fixture_bytes(self):
        collect = getattr(pilot, 'collect_boot_diagnostics', None)
        self.assertTrue(callable(collect), 'bounded early boot diagnostics must exist')
        (ROOT / '.local-runs').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='kb-', dir=ROOT / '.local-runs') as temporary:
            out = Path(temporary); (out / 'artifact').mkdir(); (out / 'runtime').mkdir()
            calls = []; framebuffer = b'P6\n1 1\n255\n\x01\x02\x03'
            def query(port, command, arguments=None, **kwargs):
                calls.append(command)
                if command == 'query-block': raise OSError('deliberate diagnostic query failure')
                if command == 'screendump': (out / 'runtime/boot.ppm').write_bytes(framebuffer)
                return {'return': 'actual fixture reply for ' + command}
            with patch.object(pilot, 'qmp', side_effect=query): report = collect(out, 12345)
            self.assertEqual(calls, ['query-status', 'query-block', 'info-qtree', 'info-registers', 'screendump'])
            self.assertEqual(report['status'], 'PARTIAL')
            self.assertEqual([row['status'] for row in report['observations']], ['PASS', 'FAIL', 'PASS', 'PASS', 'PASS'])
            self.assertEqual((out / 'artifact/boot-diagnostics/framebuffer.ppm').read_bytes(), framebuffer)
            self.assertFalse(report['reference_qualified'])

    def test_qmp_rejects_arbitrary_monitor_commands_and_screenshot_paths_before_connecting(self):
        with patch.object(pilot.socket, 'create_connection') as connect:
            for command, arguments in [('human-monitor-command', {'command-line': 'quit'}),
                    ('info-qtree', {'command-line': 'quit'}),
                    ('screendump', {'filename': '/outside/owned/output.ppm'})]:
                with self.subTest(command=command), self.assertRaises(ValueError):
                    pilot.qmp(12345, command, arguments)
            connect.assert_not_called()


if __name__ == '__main__': unittest.main()
