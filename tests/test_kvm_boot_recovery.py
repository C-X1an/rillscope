"""Closed GPT/log recovery unit fixtures; disk helpers are explicitly stubbed."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import kvm_boot_recovery as boot


def gpt(*, second_linux=False, overlap=False, out_of_range=False):
    data = bytearray(1024**2); data[510:512] = b'\x55\xaa'; data[450] = 0xee
    data[512:520] = b'EFI PART'
    struct.pack_into('<IIII', data, 520, 0x10000, 92, 0, 0)
    struct.pack_into('<QQQQ', data, 536, 1, 32767, 34, 32734)
    struct.pack_into('<QII', data, 584, 2, 128, 128)
    data[1024:1040] = uuid.UUID(boot.LINUX_FS).bytes_le
    struct.pack_into('<QQ', data, 1056, 2048, 40000 if out_of_range else 4095)
    data[1152:1168] = uuid.UUID(boot.LINUX_FS if second_linux else 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b').bytes_le
    struct.pack_into('<QQ', data, 1184, 3000 if overlap else 34, 5000 if overlap else 1023)
    struct.pack_into('<I', data, 600, zlib.crc32(data[1024:17408]))
    struct.pack_into('<I', data, 528, zlib.crc32(data[512:604]))
    return bytes(data)


class RootBootRecovery(unittest.TestCase):
    def test_selects_the_unique_root_partition_with_independent_expected_offset_and_length(self):
        row = boot.root_partition(gpt(), 16 * 1024**2)
        self.assertEqual(row['index'], 1)
        self.assertEqual(row['offset_bytes'], 1_048_576)
        self.assertEqual(row['bytes'], 1_048_576)

    def test_unchanged_primary_gpt_is_valid_before_a_resized_guest_updates_its_backup(self):
        self.assertEqual(boot.root_partition(gpt(), boot.ROOT_BYTES)['bytes'], 1_048_576)

    def test_rejects_header_and_entry_corruption_without_guessing_a_partition(self):
        for position in (540, 1100):
            data = bytearray(gpt()); data[position] ^= 1
            with self.subTest(position=position), self.assertRaises(ValueError):
                boot.root_partition(bytes(data), 16 * 1024**2)

    def test_rejects_valid_checksum_but_ambiguous_overlapping_or_out_of_range_partitions(self):
        for options in ({'second_linux': True}, {'overlap': True}, {'out_of_range': True}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                boot.root_partition(gpt(**options), 16 * 1024**2)

    def test_slice_uses_only_read_conversion_and_rejects_image_option_injection(self):
        partition = {'offset_bytes': 1048576, 'bytes': 1048576}
        command = boot.slice_command(Path('/owned/disk.qcow2'), Path('/owned/root.raw'), partition)
        self.assertEqual(command[:7], ['qemu-img', 'convert', '--image-opts', '-O', 'raw', '-S', '4096'])
        self.assertIn('offset=1048576,size=1048576,', command[7])
        self.assertNotIn('-U', command)
        for path in ('/owned/a,driver=file', '/owned/a\nother'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                boot.slice_command(Path(path), Path('/owned/root.raw'), partition)

    def recover_fixture(self, fault=None):
        (ROOT / '.local-runs').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='kr-', dir=ROOT / '.local-runs') as temporary:
            out = Path(temporary); (out / 'artifact').mkdir()
            files = {path: ('actual fixture bytes ' + path).encode() for path in boot.BOOT_LOGS}
            calls = []; identities = []
            def identity(path, deadline, limit):
                identities.append(path.name)
                value = boot.IMAGE_SHA if path.name == boot.IMAGE else '1' * 64
                if fault == 'changed' and len(identities) == 3: value = '2' * 64
                return {'bytes': 64, 'sha256': value}
            def checked(name, command, **kwargs):
                calls.append(command)
                if name == 'boot-recover-image-info':
                    return json.dumps({'format': 'qcow2', 'virtual-size': boot.ROOT_BYTES,
                        'backing-filename': str(out / boot.IMAGE)}).encode()
                if name == 'boot-recover-header':
                    Path(command[-1].removeprefix('of=')).write_bytes(gpt()); return b''
                if name == 'boot-recover-root-slice':
                    with Path(command[-1]).open('xb') as stream: stream.truncate(1_048_576)
                    return b''
                if name == 'boot-recover-filesystem-state': return b'Filesystem state: clean\n'
                if name.startswith('boot-recover-log-stat-'):
                    source = command[2].removeprefix('stat ')
                    if fault == 'interrupted': raise boot.TrialInterrupted('deliberate first-log interruption')
                    if fault == 'unavailable' and source == boot.BOOT_LOGS[0]: return b''
                    return ('Inode: 12 Type: regular\nUser: 0 Group: 0 Size: ' + str(len(files[source])) + '\n').encode()
                if name.startswith('boot-recover-log-dump-'):
                    source = boot.BOOT_LOGS[int(name.rsplit('-', 1)[1])]
                    target = out / 'artifact/root-boot-logs' / Path(source).name
                    data = files[source]
                    if fault == 'short' and source == boot.BOOT_LOGS[0]: data = data[:-1]
                    target.write_bytes(data); return b''
                self.fail('unexpected helper: ' + name)
            with patch.object(boot, 'disk_identity', side_effect=identity):
                if fault == 'interrupted':
                    with self.assertRaises(boot.TrialInterrupted):
                        boot.recover_boot_logs(out, checked, time.monotonic() + 10)
                    report = json.loads((out / 'artifact/root-boot-recovery.json').read_bytes())
                    self.assertEqual(report['status'], 'FAIL', 'an unfinished log prefix must never become COLLECTED')
                    self.assertEqual(report['files'], [])
                    self.assertTrue(report['errors'])
                    self.assertEqual(identities, ['disk.qcow2', boot.IMAGE, 'disk.qcow2', boot.IMAGE])
                    return report
                report = boot.recover_boot_logs(out, checked, time.monotonic() + 10)
            self.assertEqual(report['status'], 'COLLECTED' if fault is None else 'PARTIAL' if fault == 'unavailable' else 'FAIL')
            self.assertEqual(len(report['files']), 6)
            self.assertEqual(identities, ['disk.qcow2', boot.IMAGE, 'disk.qcow2', boot.IMAGE])
            self.assertTrue(all(command[0] not in ('mount', 'fsck', 'e2fsck', 'qemu-nbd') for command in calls))
            self.assertTrue(all('-w' not in command for command in calls if command[0] == 'debugfs'))
            self.assertFalse(report['reference_qualified'])
            self.assertFalse(report['derived_disk_uploaded'])
            for path in boot.BOOT_LOGS[1:]:
                self.assertEqual((out / 'artifact/root-boot-logs' / Path(path).name).read_bytes(), files[path])
            return report

    def test_recovers_selected_original_bytes_without_mount_or_image_writes(self): self.recover_fixture()
    def test_short_log_capture_fails_and_preserves_later_independent_logs(self): self.recover_fixture('short')
    def test_changed_original_disk_cannot_be_called_read_only_success(self): self.recover_fixture('changed')
    def test_empty_stat_output_does_not_claim_a_missing_file_or_complete_capture(self):
        result = self.recover_fixture('unavailable')
        self.assertEqual(result['files'][0]['status'], 'STAT UNAVAILABLE')
        self.assertEqual([row['status'] for row in result['files'][1:]], ['COLLECTED'] * 5)

    def test_interrupted_log_sequence_stays_failed_even_after_read_only_identity_checks(self):
        self.recover_fixture('interrupted')


if __name__ == '__main__': unittest.main()
