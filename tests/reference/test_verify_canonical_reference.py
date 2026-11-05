"""Real rejecting worker smokes and synthetic parent-deadline negatives only."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import verify_canonical_reference as verifier
from . import test_canonical_reference_bundle as fixtures


class CompleteValidatorOwner(unittest.TestCase):
    def workspace(self):
        local = ROOT / '.local-runs'; local.mkdir(exist_ok=True)
        return tempfile.TemporaryDirectory(prefix='vc-', dir=local)

    def execute(self, archive, out, size=1048576, seconds=60):
        args = ['--archive', str(archive), '--out', str(out), '--max-expanded-bytes', str(size), '--budget-seconds', str(seconds)]
        with contextlib.redirect_stdout(io.StringIO()): return verifier.main(args)

    def test_real_rejecting_worker_retains_terminal_cleanup_and_raw_failure(self):
        with self.workspace() as name:
            root = Path(name).resolve(); archive = root / 'invalid.zip'; archive.write_bytes(b'not a ZIP'); out = root / 'inspect'
            self.assertEqual(self.execute(archive, out), 1)
            row = json.loads((out / 'validation-owner.json').read_bytes())
            self.assertEqual(row['status'], 'FAIL'); self.assertEqual(row['exit_code'], 1)
            self.assertEqual(row['execution_outcome'], 'EXECUTED')
            self.assertEqual(row['process_cleanup']['remaining_active_processes'], 0)
            self.assertIs(row['reference_qualified'], False)
            progress = json.loads((out / 'record-inspection.json').read_bytes())
            self.assertEqual(progress['steps'][0], {'name': 'bundle', 'status': 'FAIL'})
            self.assertTrue((out / 'stdout.txt').is_file()); self.assertTrue((out / 'stderr.txt').is_file())

    def test_real_byte_budget_failure_cannot_expand_or_repair_synthetic_owner(self):
        with self.workspace() as name:
            root = Path(name).resolve(); archive, record = fixtures.fixture(root); out = root / 'inspect'
            self.assertEqual(self.execute(archive, out, size=1), 1)
            self.assertFalse((out / 'original').exists())
            self.assertEqual(json.loads((out / 'validation-owner.json').read_bytes())['status'], 'FAIL')

    def test_original_terminal_owner_is_required_after_successful_byte_restoration(self):
        with self.workspace() as name:
            root = Path(name).resolve(); archive, record = fixtures.fixture(root); out = root / 'inspect'
            self.assertEqual(self.execute(archive, out), 1)
            progress = json.loads((out / 'record-inspection.json').read_bytes())
            self.assertEqual(progress['steps'][0], {'name': 'bundle', 'status': 'PASS'})
            self.assertEqual(progress['steps'][1], {'name': 'terminal-owner', 'status': 'FAIL'})
            self.assertEqual(progress['status'], 'FAIL'); self.assertIs(progress['reference_qualified'], False)

    def test_source_inspection_spends_original_budget_before_worker_launch(self):
        with self.workspace() as name:
            root = Path(name).resolve(); archive = root / 'unused.zip'; archive.write_bytes(b'fixture'); out = root / 'inspect'
            clock = [1000000000]
            def inspect(_root): clock[0] += 2000000000; return {'sha256': 'a' * 64, 'files': []}
            with patch.object(verifier.time, 'monotonic_ns', side_effect=lambda: clock[0]), \
                patch.object(verifier, 'source_identity', side_effect=inspect), patch.object(verifier, 'run_owned') as launch:
                self.assertEqual(self.execute(archive, out, seconds=1), 1)
                launch.assert_not_called()

    def test_late_terminal_persistence_cannot_pass_even_with_synthetic_complete_worker_report(self):
        with self.workspace() as name:
            root = Path(name).resolve(); archive = root / 'unused.zip'; archive.write_bytes(b'fixture'); out = root / 'inspect'
            clock = [1000000000]; real_write = verifier.write_json; source = verifier.source_identity(ROOT)
            def worker(*args, **kwargs):
                real_write(out / 'record-inspection.json', {'status': verifier.RESULT, 'source_sha256': source['sha256'],
                    'reference_qualified': False, 'steps': [{'name': step, 'status': 'PASS'} for step in verifier.STEPS],
                    'fixture': 'No worker executed; synthetic negative for parent terminal deadline only'})
                return 0, b'No worker executed; parent negative only\n', b'', 'EXECUTED', {'status': 'PASS', 'remaining_active_processes': 0}
            def persist(path, row):
                real_write(path, row)
                if path.name == 'validation-owner.json' and row.get('status') == verifier.RESULT: clock[0] = 3000000000
            with patch.object(verifier.time, 'monotonic_ns', side_effect=lambda: clock[0]), \
                patch.object(verifier, 'run_owned', side_effect=worker), patch.object(verifier, 'write_json', side_effect=persist):
                self.assertEqual(self.execute(archive, out, seconds=1), 1)
            self.assertEqual(json.loads((out / 'validation-owner.json').read_bytes())['status'], 'FAIL')


if __name__ == '__main__': unittest.main()
