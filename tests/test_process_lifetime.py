"""Real owned child lifetime controls, distinct from product performance samples."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ProcessLifetime(unittest.TestCase):
    def run_fixture(self, mode):
        local = ROOT / '.local-runs'; local.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='pl-', dir=local) as temporary:
            self.assertTrue(Path(temporary).resolve().is_relative_to(local.resolve()))
            sentinel = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(30)'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                result = subprocess.run([sys.executable, str(ROOT / 'tests/process_lifetime_worker.py'),
                    str(ROOT), str(Path(temporary) / 'm'), mode], capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
                report = json.loads(result.stdout)
                print(json.dumps(report, separators=(',', ':')))
                self.assertIsNone(sentinel.poll(), 'capture must leave a separate owned sentinel running')
                return report
            finally:
                if sentinel.poll() is None: sentinel.kill()
                sentinel.wait(timeout=3)

    def test_timeout_stops_session_changing_pipe_holder_and_retains_real_bytes(self):
        report = self.run_fixture('held-pipe'); usage = report['usage']
        self.assertTrue(usage['timed_out'])
        self.assertEqual(usage['process_outcome'], 'TIMEOUT')
        self.assertLess(usage['wall_ns'], 3_000_000_000)
        self.assertFalse(report['child_alive_at_return'])
        self.assertIn(b'root-ready', bytes.fromhex(report['stdout_hex']))
        self.assertIn(b'child-ready', bytes.fromhex(report['stdout_hex']))
        self.assertEqual(bytes.fromhex(report['stderr_hex']), b'')

    def test_success_stops_detached_worker_even_after_it_closed_capture_pipes(self):
        report = self.run_fixture('closed-pipe'); usage = report['usage']
        self.assertEqual(usage['process_outcome'], 'EXECUTED')
        self.assertFalse(usage['timed_out'])
        self.assertFalse(report['child_alive_at_return'])
        self.assertEqual(bytes.fromhex(report['stdout_hex']), b'root-ready\r\n' if sys.platform == 'win32' else b'root-ready\n')

    def test_startup_time_cannot_be_added_on_top_of_the_declared_deadline(self):
        usage = self.run_fixture('delayed-launch')['usage']
        self.assertTrue(usage['timed_out'])
        self.assertEqual(usage['process_outcome'], 'TIMEOUT')
        self.assertGreaterEqual(usage['wall_ns'], 300_000_000)

    def assert_interrupted_capture(self, mode, kind):
        report = self.run_fixture(mode)
        self.assertEqual(report['propagated']['type'], kind)
        if kind == 'SystemExit': self.assertEqual(report['propagated']['code'], 29)
        self.assertFalse(report['child_alive_at_return'])
        self.assertIsNotNone(report['usage'], 'interruption must retain process metadata')
        usage = report['usage']
        self.assertEqual(usage['process_outcome'], 'INTERRUPTED')
        self.assertEqual(usage['instrument_problem'], kind)
        self.assertEqual(usage['process_cleanup']['status'], 'PASS')
        self.assertEqual(usage['process_cleanup']['remaining_active_processes'], 0)
        self.assertTrue(usage['capture_complete'])
        self.assertIn(b'actual-before-interrupt', bytes.fromhex(report['stdout_hex']))
        self.assertIn(b'actual-stderr-before-interrupt', bytes.fromhex(report['stderr_hex']))

    def test_keyboard_interrupt_retains_actual_bytes_and_metadata_before_propagating(self):
        self.assert_interrupted_capture('interrupt-capture', 'KeyboardInterrupt')

    def test_system_exit_retains_actual_bytes_and_metadata_before_propagating(self):
        self.assert_interrupted_capture('exit-capture', 'SystemExit')

    # This exercises an actual suspended Windows process and native job object.
    # Linux runs the portable controls above; it cannot establish this property.
    if sys.platform == 'win32':
        def test_interruption_before_assignment_stops_the_held_suspended_root(self):
            report = self.run_fixture('interrupt-setup')
            self.assertEqual(report['propagated']['type'], 'KeyboardInterrupt')
            self.assertFalse(report['child_alive_at_return'], 'an empty job cannot confirm cleanup of an unassigned root')
            self.assertIsNotNone(report['usage'])
            self.assertEqual(report['usage']['process_outcome'], 'INTERRUPTED')
            self.assertEqual(report['usage']['process_cleanup']['status'], 'PASS')
            self.assertTrue(report['usage']['process_cleanup']['owned_root_reaped'])
            self.assertFalse(report['usage']['process_cleanup']['job_setup_completed'])
            self.assertEqual(bytes.fromhex(report['stdout_hex']), b'')
            self.assertEqual(bytes.fromhex(report['stderr_hex']), b'')


if __name__ == '__main__': unittest.main()
