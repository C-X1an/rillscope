"""Synthetic contract fixtures, not a Linux guest or canonical execution."""
import copy
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import canonical_reference_guest_owner as owner
import canonical_reference_attempt_check as checker
import canonical_reference_allocation as allocation
import canonical_reference_device as device
import kvm_reference_budget as old_budget
from kvm_reference_common import METHOD as INNER_METHOD


def fresh_fixture():
    return {'mode': 'fresh-committed-Rust-checkout', 'status': 'PASS',
        'commit': 'a' * 40, 'source_sha256': 'b' * 64, 'source_stable': True,
        'target_directory_was_fresh': True, 'cargo_target_dir_enforced_inside_fresh_clone': True,
        'same_os_and_toolchain_installation': True, 'commands': [
            {'target': target, 'role': 'canonical', 'state': 'COMPLETED', 'status': 'PASS', 'exit_code': 0}
            for target in ('bootstrap', 'verify', 'demo')], 'diagnostic_commands': [], 'not_run': []}


class CanonicalOwnerContracts(unittest.TestCase):
    def test_device_marker_is_the_distinct_root_owned_canonical_guest(self):
        info = SimpleNamespace(st_mode=0o100644, st_uid=0, st_gid=0)
        self.assertIsNone(device.check_marker(info, b'owned-ephemeral-canonical-reference\n'))
        for raw in [b'owned-ephemeral-full-collection\n', b'owned-ephemeral-canonical-reference']:
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError): device.check_marker(info, raw)
        for changed in [SimpleNamespace(st_mode=0o100666, st_uid=0, st_gid=0),
            SimpleNamespace(st_mode=0o120644, st_uid=0, st_gid=0),
            SimpleNamespace(st_mode=0o100644, st_uid=65534, st_gid=0)]:
            with self.assertRaises(ValueError): device.check_marker(changed, b'owned-ephemeral-canonical-reference\n')

    def test_device_probe_stops_without_real_guest_before_open_or_permission_change(self):
        with patch.object(device.platform, 'system', return_value='Windows'):
            with patch.object(device, 'inspect_port') as inspect:
                with self.assertRaisesRegex(ValueError, 'actual canonical Linux guest'):
                    device.operate({}, configure=True)
                inspect.assert_not_called()

    def test_lease_budget_floors_subsecond_time_and_preserves_finish_reserve(self):
        self.assertEqual(owner.command_budget(2_000_900_000_000, 1_000_000_000_000, 300), 700)
        for cutoff, now, reserve in [(2_000_000_000_000, 1_000_000_000_000, True),
            (2_000_000_000_000, 1_000_000_000_000, 601),
            (1_900_000_000_000, 1_000_000_000_000, 300), (1, 2, 1),
            (1 + 21_601_000_000_000, 1, 1), (True, 1, 1)]:
            with self.subTest(cutoff=cutoff, now=now, reserve=reserve):
                with self.assertRaises(ValueError): owner.command_budget(cutoff, now, reserve)

    def test_inner_closed_protocol_keeps_original_method_and_deadline(self):
        measure, export = owner.inner_configurations('a' * 40, 'b' * 64,
            '11111111-2222-3333-4444-555555555555', 20_000_000_000_000, session='c' * 32)
        self.assertEqual(measure['method'], INNER_METHOD)
        self.assertEqual(export['method'], INNER_METHOD)
        self.assertNotEqual(allocation.METHOD, INNER_METHOD)
        self.assertEqual(measure['deadline_monotonic_ns'], 20_000_000_000_000)
        self.assertEqual(export['deadline_monotonic_ns'], 20_000_000_000_000)
        self.assertEqual(old_budget.VM_SECONDS, 18000)
        self.assertEqual(old_budget.OWNER_SECONDS, 19500)
        self.assertEqual(measure['control_root'], '/work/c/.local-runs/kvm-reference/control')

    def test_missing_real_guest_stops_before_allocation_and_writes(self):
        with patch.object(owner.platform, 'system', return_value='Windows'):
            with patch.object(owner.guest_allocation, 'record_guest_allocation') as write:
                with self.assertRaisesRegex(ValueError, 'actual existing owned canonical Linux root'):
                    owner.run_attempt(b'{}', b'{}', received_ns=1, tail_seconds=120, retention_seconds=300)
                write.assert_not_called()

    def test_native_command_uses_existing_nonroot_identity_and_exact_recipe(self):
        command = owner.nonroot(['/usr/bin/python3', str(ROOT / 'scripts/clean_verify.py'), '--budget-seconds', '1000'])
        self.assertEqual(command[:6], ['/usr/bin/setpriv', '--reuid=65534', '--regid=65534', '--clear-groups', '--', '/usr/bin/env'])
        self.assertIn('CARGO_INCREMENTAL=0', command)
        self.assertEqual(command[-4:], ['/usr/bin/python3', str(ROOT / 'scripts/clean_verify.py'), '--budget-seconds', '1000'])
        self.assertFalse(any(value in command for value in ('--demo-only', '--capture-only', 'diagnostic')))

    def test_canonical_shape_accepts_complete_literal_contract_only(self):
        self.assertEqual(len(checker.canonical_shape(fresh_fixture(), commit='a' * 40, source_sha256='b' * 64)), 3)

    def test_demo_diagnostic_and_partial_success_cannot_replace_canonical(self):
        for key, value in [('mode', 'fresh-committed-Rust-demo-checkout'), ('status', 'FAIL'),
            ('commit', 'c' * 40), ('source_sha256', 'd' * 64), ('source_stable', False),
            ('target_directory_was_fresh', False), ('cargo_target_dir_enforced_inside_fresh_clone', False),
            ('diagnostic_commands', [{'target': 'demo', 'status': 'PASS'}]),
            ('not_run', [{'target': 'benchmark'}]), ('commands', [])]:
            with self.subTest(key=key):
                result = fresh_fixture(); result[key] = value
                with self.assertRaises(ValueError): checker.canonical_shape(result, commit='a' * 40, source_sha256='b' * 64)

    def test_wrong_order_role_pending_failure_and_boolean_exit_rejected(self):
        result = fresh_fixture(); result['commands'].reverse()
        with self.assertRaises(ValueError): checker.canonical_shape(result, commit='a' * 40, source_sha256='b' * 64)
        for index in range(3):
            for key, value in [('role', 'diagnostic'), ('state', 'STARTED'), ('status', 'FAIL'), ('exit_code', False), ('exit_code', 1)]:
                with self.subTest(index=index, key=key):
                    result = fresh_fixture(); result['commands'][index][key] = value
                    with self.assertRaises(ValueError): checker.canonical_shape(result, commit='a' * 40, source_sha256='b' * 64)


if __name__ == '__main__': unittest.main()
