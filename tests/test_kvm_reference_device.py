"""Exact-port and descriptor controls; mocked devices do not qualify a VM."""
import copy
import io
import os
from pathlib import Path, PurePosixPath
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import kvm_reference_device as device

NODE = '/dev/vport1p2'
PORT = '/dev/virtio-ports/org.rillscope.reference-capture'


def observation(uid=0, gid=0, mode=0o600):
    return {'alias': PORT, 'node': NODE, 'port_name': 'org.rillscope.reference-capture',
        'major': 1, 'minor': 2, 'filesystem_device': 7, 'inode': 91,
        'rdev': 258, 'uid': uid, 'gid': gid, 'mode': mode}


def stat_row(value, kind=stat.S_IFCHR):
    return SimpleNamespace(st_mode=kind | value['mode'], st_uid=value['uid'], st_gid=value['gid'],
        st_dev=value['filesystem_device'], st_ino=value['inode'], st_rdev=value['rdev'])


def access_records():
    after = observation(65534, 65534)
    common = {'uid': 0, 'gid': 0, 'groups': [], 'bytes_read': 0, 'bytes_written': 0}
    grant = dict(common, status='GRANTED', identity_before=observation(), identity_after=after,
        opened_monotonic_ns=100, closed_monotonic_ns=200)
    probe = dict(common, uid=65534, gid=65534, status='OPENED', identity_before=after,
        identity_after=after, opened_monotonic_ns=300, closed_monotonic_ns=400)
    return copy.deepcopy(grant), copy.deepcopy(probe)


class PortInspection(unittest.TestCase):
    def inspect(self, *, node=NODE, kind=stat.S_IFCHR, port_name=None, dev=b'1:2\n'):
        files = {'/sys/class/virtio-ports/vport1p2/name':
            (port_name or 'org.rillscope.reference-capture').encode() + b'\n',
            '/sys/class/virtio-ports/vport1p2/dev': dev}
        class FakePath(PurePosixPath):
            def resolve(self, strict=False):
                if str(self) == PORT: return FakePath(node)
                raise AssertionError('unexpected resolution')
            def lstat(self):
                return stat_row(observation(), stat.S_IFLNK if str(self) == PORT else kind)
            def open(self, mode): return io.BytesIO(files[str(self)])
        with patch.object(device, 'Path', FakePath), \
             patch.object(device.os, 'major', lambda value: value >> 8, create=True), \
             patch.object(device.os, 'minor', lambda value: value & 255, create=True):
            return device.inspect_port()

    def test_exact_symlink_character_node_and_sysfs_name_and_number(self):
        node, value = self.inspect()
        self.assertEqual(str(node), NODE); self.assertEqual(value, observation())

    def test_arbitrary_device_or_noncanonical_vport_path_is_rejected(self):
        for node in ['/dev/null', '/tmp/vport1p2', '/dev/vport1p2/child', '/dev/vport1p2.extra']:
            with self.subTest(node=node), self.assertRaises(ValueError): self.inspect(node=node)

    def test_regular_file_or_symlink_at_resolved_node_is_rejected(self):
        for kind in [stat.S_IFREG, stat.S_IFLNK]:
            with self.assertRaises(ValueError): self.inspect(kind=kind)

    def test_wrong_port_name_or_sysfs_device_number_cannot_be_granted(self):
        with self.assertRaises(ValueError): self.inspect(port_name='another.port')
        for number in [b'1:3\n', b'1:2 junk\n', b'9' * 300]:
            with self.assertRaises(ValueError): self.inspect(dev=number)


class DescriptorOwnership(unittest.TestCase):
    def fixture(self, *, probe=False):
        before = observation(65534, 65534) if probe else observation()
        after = observation(65534, 65534)
        guard = patch.object(device, 'guard', return_value={'uid': 65534 if probe else 0,
            'gid': 65534 if probe else 0, 'groups': []})
        inspect = patch.object(device, 'inspect_port', side_effect=[(PurePosixPath(NODE), before),
            (PurePosixPath(NODE), after)])
        stats = patch.object(device.os, 'fstat', side_effect=[stat_row(before), stat_row(after)])
        return guard, inspect, stats

    def test_grant_changes_only_opened_exact_descriptor_and_closes_it(self):
        record = {}; guard, inspect, stats = self.fixture()
        with guard, inspect, stats, \
             patch.object(device.os, 'O_NOFOLLOW', 0x20000, create=True), \
             patch.object(device.os, 'O_NONBLOCK', 0x800, create=True), \
             patch.object(device.os, 'O_CLOEXEC', 0x80000, create=True), \
             patch.object(device.os, 'open', return_value=23) as opened, \
             patch.object(device.os, 'fchown', create=True) as chown, \
             patch.object(device.os, 'fchmod') as chmod, patch.object(device.os, 'close') as closed:
            device.grant(record)
        chown.assert_called_once_with(23, 65534, 65534)
        chmod.assert_called_once_with(23, 0o600); closed.assert_called_once_with(23)
        self.assertEqual(str(opened.call_args.args[0]), NODE)
        self.assertTrue(opened.call_args.args[1] & 0x20000)
        self.assertEqual(record['identity_before']['uid'], 0)
        self.assertEqual(record['identity_after'], observation(65534, 65534))
        self.assertEqual(record['status'], 'GRANTED')
        self.assertEqual(record['bytes_read'], 0); self.assertEqual(record['bytes_written'], 0)

    def test_descriptor_swap_is_rejected_before_any_permission_change(self):
        bad = observation(); bad['inode'] += 1
        with patch.object(device, 'guard', return_value={'uid': 0, 'gid': 0, 'groups': []}), \
             patch.object(device, 'inspect_port', return_value=(PurePosixPath(NODE), observation())), \
             patch.object(device.os, 'fstat', return_value=stat_row(bad)), \
             patch.object(device.os, 'O_NOFOLLOW', 0x20000, create=True), \
             patch.object(device.os, 'O_NONBLOCK', 0x800, create=True), \
             patch.object(device.os, 'O_CLOEXEC', 0x80000, create=True), \
             patch.object(device.os, 'open', return_value=23), \
             patch.object(device.os, 'fchown', create=True) as chown, patch.object(device.os, 'close') as close:
            with self.assertRaisesRegex(ValueError, 'descriptor'): device.grant({})
        chown.assert_not_called(); close.assert_called_once_with(23)

    def test_grant_failure_is_original_failure_and_still_closes_descriptor(self):
        report = {}; guard, inspect, stats = self.fixture()
        with guard, inspect, stats, \
             patch.object(device.os, 'O_NOFOLLOW', 0x20000, create=True), \
             patch.object(device.os, 'O_NONBLOCK', 0x800, create=True), \
             patch.object(device.os, 'O_CLOEXEC', 0x80000, create=True), \
             patch.object(device.os, 'open', return_value=23), \
             patch.object(device.os, 'fchown', create=True), \
             patch.object(device.os, 'fchmod', side_effect=PermissionError('original chmod error')), \
             patch.object(device.os, 'close') as close:
            with self.assertRaisesRegex(PermissionError, 'original chmod error'): device.grant(report)
        close.assert_called_once_with(23)
        self.assertEqual(report['identity_before'], observation())
        self.assertNotEqual(report.get('status'), 'GRANTED')

    def test_nobody_probe_opens_and_closes_without_transport_io_or_permission_writes(self):
        report = {}; guard, inspect, stats = self.fixture(probe=True)
        with guard, inspect, stats, \
             patch.object(device.os, 'O_NOFOLLOW', 0x20000, create=True), \
             patch.object(device.os, 'O_NONBLOCK', 0x800, create=True), \
             patch.object(device.os, 'O_CLOEXEC', 0x80000, create=True), \
             patch.object(device.os, 'open', return_value=24), \
             patch.object(device.os, 'fchown', create=True) as chown, \
             patch.object(device.os, 'read') as read, patch.object(device.os, 'write') as write, \
             patch.object(device.os, 'close') as close:
            device.probe(report)
        close.assert_called_once_with(24); chown.assert_not_called()
        read.assert_not_called(); write.assert_not_called()
        self.assertEqual(report['status'], 'OPENED'); self.assertEqual(report['uid'], 65534)

    def test_entry_guard_cannot_touch_a_host_device(self):
        with patch.object(device.platform, 'system', return_value='Windows'), patch.object(device.os, 'open') as opened:
            with self.assertRaises(ValueError): device.grant({})
            with self.assertRaises(ValueError): device.probe({})
        opened.assert_not_called()


class AccessEvidence(unittest.TestCase):
    def test_matching_grant_and_real_identity_probe_are_required(self):
        grant, probe = access_records()
        device.validate_access(grant, probe)
        for key, value in [('uid', 0), ('groups', [0]), ('bytes_written', 1),
            ('status', 'FAIL'), ('opened_monotonic_ns', 150)]:
            bad = copy.deepcopy(probe); bad[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): device.validate_access(grant, bad)

    def test_mode_inode_device_name_and_exact_types_cannot_be_forged(self):
        grant, probe = access_records()
        for key, value in [('mode', 0o666), ('inode', 92), ('rdev', 259),
            ('port_name', 'other.port'), ('major', True)]:
            bad = copy.deepcopy(probe); bad['identity_after'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): device.validate_access(grant, bad)
        grant['identity_after']['mode'] = 0o666
        with self.assertRaises(ValueError): device.validate_access(grant, probe)


if __name__ == '__main__': unittest.main()
