"""Literal Linux metadata fixtures; no runtime reservation is synthesized."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import canonical_reference_reservation as reservation


class ReservationTests(unittest.TestCase):
    def test_new_directory_entry_is_flushed_after_actual_mkdir(self):
        with tempfile.TemporaryDirectory(prefix='rill-dir-') as directory:
            parent = Path(directory); target = parent / 'one'
            observed = []
            def flush(actual_parent):
                self.assertTrue(target.is_dir())
                observed.append(actual_parent)
            with patch.object(reservation, 'fsync_directory', side_effect=flush):
                reservation.durable_mkdir(target, mode=0o700)
            self.assertEqual(observed, [parent])
            with self.assertRaises(FileExistsError):
                reservation.durable_mkdir(target, mode=0o700)

    def test_failed_parent_flush_keeps_original_slot_closed(self):
        with tempfile.TemporaryDirectory(prefix='rill-dir-') as directory:
            target = Path(directory) / 'one'
            with patch.object(reservation, 'fsync_directory', side_effect=OSError('fsync failed')):
                with self.assertRaisesRegex(OSError, 'fsync failed'):
                    reservation.durable_mkdir(target, mode=0o700)
            self.assertTrue(target.is_dir())
            with self.assertRaises(FileExistsError):
                reservation.durable_mkdir(target, mode=0o700)

    def test_stat_fields_follow_the_last_comm_parenthesis(self):
        raw = b'201 (name with ) spaces) S 200 ' + b'0 ' * 17 + b'12345 0 0\n'
        self.assertEqual(reservation.parse_stat(raw, 201), {'pid': 201, 'ppid': 200, 'start_ticks': 12345})

    def test_malformed_or_wrong_process_stat(self):
        for raw in [b'201 (x) S 200 0', b'202 (x) S 200 ' + b'0 ' * 18,
            b'201 (x) S true ' + b'0 ' * 18, b'x' * 65537]:
            with self.subTest(raw=raw[:30]):
                with self.assertRaises(ValueError): reservation.parse_stat(raw, 201)

    def test_exact_uid_tuple(self):
        self.assertEqual(reservation.parse_uids(b'Name:\tqemu\nUid:\t1001\t1001\t1001\t1001\n'), [1001] * 4)
        for raw in [b'', b'Uid:\t1001\t1001\n', b'Uid:\t1\t1\t1\t1\nUid:\t1\t1\t1\t1\n',
            b'Uid:\ttrue\t1\t1\t1\n', b'x' * 65537]:
            with self.subTest(raw=raw[:30]):
                with self.assertRaises(ValueError): reservation.parse_uids(raw)

    def test_missing_existing_linux_root_stops_before_any_side_effect(self):
        with patch.object(reservation.platform, 'system', return_value='Windows'):
            with patch.object(reservation, 'source_check') as source:
                with self.assertRaisesRegex(ValueError, 'actual existing Linux root'):
                    reservation.create_grant(None, [], 1001, 1000, b'{}', commit='a' * 40,
                        source_sha256='b' * 64, vm_started_ns=1, vm_deadline_ns=2, allocation_id='c' * 32)
                source.assert_not_called()

    def test_qmp_endpoint_and_vcpu_task_membership_bind_to_actual_child(self):
        command = ['qemu-system-x86_64', '-qmp', 'tcp:127.0.0.1:12345,server=on,wait=off']
        sample = {'qemu_pid': 201, 'vcpu_threads': [{'thread_id': value} for value in (301, 302, 303, 304)]}
        self.assertIsNone(reservation.validate_qmp_binding(command, 12345, sample, 201, {201, 301, 302, 303, 304}))
        for changed_port, changed_command in [(12346, command), (True, command),
            (12345, command + ['-qmp', 'tcp:127.0.0.1:12345,server=on,wait=off']),
            (12345, ['qemu-system-x86_64', '-qmp']),
            (12345, ['qemu-system-x86_64', '-qmp', 'tcp:0.0.0.0:12345,server=on,wait=off'])]:
            with self.subTest(port=changed_port, command=changed_command):
                with self.assertRaises(ValueError):
                    reservation.validate_qmp_binding(changed_command, changed_port, sample, 201, {201, 301, 302, 303, 304})

    def test_qmp_from_another_vm_or_duplicate_thread_cannot_grant_resources(self):
        command = ['qemu-system-x86_64', '-qmp', 'tcp:127.0.0.1:12345,server=on,wait=off']
        for pid, threads, tasks in [(202, (301, 302, 303, 304), {201, 301, 302, 303, 304}),
            (201, (301, 302, 303, 900), {201, 301, 302, 303, 304}),
            (201, (301, 302, 303, 303), {201, 301, 302, 303, 304}),
            (201, (301, 302, 303, True), {201, 301, 302, 303, 304}),
            (201, (301, 302, 303, 304), {301, 302, 303, 304})]:
            with self.subTest(pid=pid, threads=threads, tasks=tasks):
                sample = {'qemu_pid': pid, 'vcpu_threads': [{'thread_id': value} for value in threads]}
                with self.assertRaises(ValueError):
                    reservation.validate_qmp_binding(command, 12345, sample, 201, tasks)

    def test_recorded_membership_keeps_the_observed_set_including_non_vcpu_tasks(self):
        sample={'qemu_pid':201,'vcpu_threads':[{'thread_id':value} for value in (301,302,303,304)]}
        observed={201,301,302,303,304,900}
        with patch.object(reservation,'actual_tasks',return_value=observed) as read:
            retained,members=reservation.observed_membership(sample,201)
        read.assert_called_once_with(201)
        self.assertEqual(retained['actual_qemu_task_ids'],[201,301,302,303,304,900])
        self.assertIs(members,observed)
        self.assertNotIn('actual_qemu_task_ids',sample)

    def test_failed_or_invalid_task_observation_is_not_replaced_with_qmp_claims(self):
        sample={'qemu_pid':201,'vcpu_threads':[{'thread_id':value} for value in (301,302,303,304)]}
        with patch.object(reservation,'actual_tasks',side_effect=OSError('literal vanished process fixture')):
            with self.assertRaises(OSError):reservation.observed_membership(sample,201)
        for members in ({301,302,303,304},{201,True},[201,301,302,303,304]):
            with self.subTest(members=members),patch.object(reservation,'actual_tasks',return_value=members):
                with self.assertRaises(ValueError):reservation.observed_membership(sample,201)
        with patch.object(reservation,'actual_tasks') as read:
            with self.assertRaises(ValueError):reservation.observed_membership(sample,202)
            read.assert_not_called()


if __name__ == '__main__': unittest.main()
