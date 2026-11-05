"""Closed plan and real-runtime rejection controls; no VM is simulated as real."""
import copy
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
import run_canonical_reference as driver


class CanonicalDriverPlan(unittest.TestCase):
    def plan(self):
        return {'schema_version': 1, 'method': driver.allocation.METHOD, 'mode': 'canonical',
            'commit': 'a' * 40, 'source_sha256': 'b' * 64, 'provision_seconds': 120,
            'prepare_seconds': 180, 'vm_seconds': 20040, 'guest_setup_seconds': 900,
            'guest_tail_seconds': 60, 'guest_retention_seconds': 180, 'recovery_seconds': 300,
            'cleanup_reserve_seconds': 120, 'whole_seconds': 20880}

    def test_explicit_plan_is_bounded_but_does_not_claim_actual_fit(self):
        plan = self.plan(); self.assertIs(driver.validate_plan(plan), plan)
        self.assertEqual(plan['vm_seconds'], 20040)
        self.assertNotIn('reference_qualified', plan)
        boundary = copy.deepcopy(plan); boundary['whole_seconds'] = 20820
        self.assertIs(driver.validate_plan(boundary), boundary)

    def test_undeclared_reduced_boolean_or_renewed_bounds_are_rejected(self):
        for key, value in [('mode', 'native-setup-diagnostic'), ('schema_version', True),
            ('vm_seconds', 17999), ('vm_seconds', 21601), ('guest_setup_seconds', True),
            ('whole_seconds', 20819), ('whole_seconds', 21601), ('cleanup_reserve_seconds', 119),
            ('extra', 'closed')]:
            with self.subTest(key=key, value=value):
                plan = copy.deepcopy(self.plan()); plan[key] = value
                with self.assertRaises(ValueError): driver.validate_plan(plan)

    def test_success_shaped_vm_without_original_cutoff_never_reaches_disk_reads(self):
        with patch.object(driver, 'bounded_bytes') as read:
            with self.assertRaisesRegex(ValueError, 'original canonical VM producer'):
                driver.check_collected(Path('unused'), {'status': 'CAPTURED', 'failure': None}, {}, {})
            read.assert_not_called()

    def test_unavailable_controller_stops_before_reading_plan_or_creating_output(self):
        with patch.object(driver, 'actual_controller', side_effect=ValueError('actual scoped controller missing')), \
            patch.object(driver.archive_capture, 'owned') as owned:
            self.assertEqual(driver.main(['--config', 'unused', '--out', 'unused-output', '--run-as', 'runner']), 77)
            owned.assert_not_called()


class CanonicalDriverDeadlines(unittest.TestCase):
    def execute(self, *, recovery_shortfall=False, overrun_write=None, overrun_recovery=False):
        plan = {'schema_version': 1, 'method': driver.allocation.METHOD, 'mode': 'canonical',
            'commit': 'a' * 40, 'source_sha256': 'b' * 64, 'provision_seconds': 1,
            'prepare_seconds': 1, 'vm_seconds': 18000, 'guest_setup_seconds': 900,
            'guest_tail_seconds': 60, 'guest_retention_seconds': 180, 'recovery_seconds': 300,
            'cleanup_reserve_seconds': 120, 'whole_seconds': 18482}
        class Clock:
            value = 100.0
            def monotonic(self): return self.value
            def monotonic_ns(self): return int(self.value * 10**9)
        class Owner:
            def finish(self, pid): return {'status': 'PASS', 'remaining_active_processes': 0}
        clock = Clock(); recoveries = []; writes = []
        def vm(*args, execution, **kwargs):
            execution.update(process=object(), command=['SYNTHETIC NONEXECUTION'], channel=None)
            if recovery_shortfall: clock.value = 18262.0
            return {'status': 'CAPTURED', 'cleanup': {'status': 'PASS'}}
        def recover(*args, deadline, **kwargs):
            recoveries.append(deadline - clock.value)
            if overrun_recovery: clock.value = deadline + 1
            return {'status': 'SYNTHETIC INCLUDED BYTES ONLY'}
        actual_write = driver.write_json
        def write(path, row):
            actual_write(path, row); writes.append(path)
            if len(writes) == overrun_write: clock.value = 18583.0
        local = ROOT / '.local-runs'; local.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='cd-', dir=local) as folder:
            root = Path(folder); config = root / 'plan.json'; config.write_text(json.dumps(plan)); out = root / 'out'
            with contextlib.ExitStack() as stack:
                replacements = [(driver, 'actual_controller', lambda: None),
                    (driver.archive_capture, 'owned', lambda path: Path(path).resolve()),
                    (driver, 'source_check', lambda *args: None), (driver, 'fsync_directory', lambda *args: None),
                    (driver, 'LinuxOwnedChildren', Owner),
                    (driver, 'provision', lambda *args: {'status': 'PREPARED HOST UTILITIES ONLY'}),
                    (driver, 'prepare', lambda *args, **kwargs: {'image': 'SYNTHETIC', 'port': 1, 'seed': {}}),
                    (driver, 'run_vm', vm), (driver, 'recover', recover),
                    (driver, 'check_collected', lambda *args: {'scope': 'SYNTHETIC orchestration fixture only'}),
                    (driver, 'write_json', write), (driver.time, 'monotonic', clock.monotonic),
                    (driver.time, 'monotonic_ns', clock.monotonic_ns)]
                for target, key, replacement in replacements: stack.enter_context(patch.object(target, key, replacement))
                with contextlib.redirect_stdout(io.StringIO()):
                    code = driver.main(['--config', str(config), '--out', str(out), '--run-as', 'runner'])
            record = json.loads((out / 'driver-result.json').read_bytes())
        return code, record, recoveries

    def test_full_declared_recovery_has_original_budget_and_no_qualification(self):
        code, record, recoveries = self.execute()
        self.assertEqual(code, 0); self.assertEqual(recoveries, [300.0])
        self.assertEqual(record['recovery_budget']['status'], 'DECLARED BUDGET AVAILABLE')
        self.assertIs(record['reference_qualified'], False)

    def test_short_preservation_keeps_failed_bytes_and_cannot_satisfy_declared_budget(self):
        code, record, recoveries = self.execute(recovery_shortfall=True)
        self.assertEqual(recoveries, [200.0]); self.assertEqual(code, 1)
        self.assertEqual(record['status'], 'FAIL'); self.assertEqual(record['recovery_budget']['status'], 'FAIL')
        self.assertEqual(record['recovery']['status'], 'SYNTHETIC INCLUDED BYTES ONLY')

    def test_first_or_terminal_result_write_crossing_original_cutoff_is_failure(self):
        for number in (1, 2):
            with self.subTest(number=number):
                code, record, recoveries = self.execute(overrun_write=number)
                self.assertEqual(code, 1); self.assertEqual(record['status'], 'FAIL')
                self.assertGreater(record['finished_monotonic_ns'], record['deadline_monotonic_ns'])
                self.assertEqual(recoveries, [300.0])

    def test_recovery_return_past_its_original_cutoff_fails_with_whole_budget_remaining(self):
        code, record, recoveries = self.execute(overrun_recovery=True)
        self.assertEqual(code, 1); self.assertEqual(record['status'], 'FAIL')
        self.assertEqual(recoveries, [300.0])
        self.assertLess(record['finished_monotonic_ns'], record['deadline_monotonic_ns'])
        self.assertIn('recovery cutoff', record['reason'])


if __name__ == '__main__': raise SystemExit(unittest.main())
