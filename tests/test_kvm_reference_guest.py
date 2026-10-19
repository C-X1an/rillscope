"""Finite full guest configuration and safe entry guard; no VM qualification."""
from pathlib import Path
import json
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import kvm_reference_guest as guest
from kvm_reference_common import METHOD


class GuestConfiguration(unittest.TestCase):
    def setUp(self):
        self.payload = {'mode': METHOD, 'commit': '1' * 40, 'source': {'sha256': '2' * 64},
            'bins': {'rillscope': {}, 'rillscope-measure': {}}, 'reference_qualified': False}
        self.boot = '12345678-1234-1234-1234-123456789abc'

    def test_source_bound_configs_have_finite_shared_end_and_separate_collection_reserve(self):
        measure, export = guest.configurations(self.payload, 1_000_000_000, 101_000_000_000, self.boot)
        self.assertEqual(measure['method'], METHOD)
        self.assertEqual(measure['source_sha256'], '2' * 64)
        self.assertEqual(measure['boot_id'], self.boot)
        self.assertEqual(measure['deadline_monotonic_ns'], export['deadline_monotonic_ns'])
        self.assertEqual(measure['deadline_monotonic_ns'] - 101_000_000_000, 15600 * 10**9)
        self.assertEqual(export['transfer_seconds'], 180)
        self.assertFalse(measure['reference_qualified'])

    def test_setup_may_not_borrow_collection_and_shutdown_reserves(self):
        with self.assertRaisesRegex(ValueError, 'setup'):
            guest.configurations(self.payload, 1_000_000_000, 2301_000_000_000, self.boot)

    def test_pilot_payload_cannot_silently_become_a_full_collection(self):
        self.payload['mode'] = 'unqualified-kvm-feasibility-pilot'
        with self.assertRaisesRegex(ValueError, 'payload'):
            guest.configurations(self.payload, 1_000_000_000, 101_000_000_000, self.boot)

    def test_boolean_qualification_and_closed_binaries_are_required(self):
        self.payload['reference_qualified'] = 0
        with self.assertRaises(ValueError): guest.configurations(self.payload, 1, 2, self.boot)
        self.payload['reference_qualified'] = False
        self.payload['bins']['unexpected'] = {}
        with self.assertRaises(ValueError): guest.configurations(self.payload, 1, 2, self.boot)

    def test_non_guest_entry_never_installs_packages_or_runs_a_query(self):
        with patch.object(guest.platform, 'system', return_value='Windows'), patch.object(guest, 'collect') as operation:
            self.assertEqual(guest.main(), 77)
        operation.assert_not_called()


class GuestDevicePreflight(unittest.TestCase):
    def records(self):
        value = {'alias': '/dev/virtio-ports/org.rillscope.reference-capture',
            'node': '/dev/vport1p2', 'port_name': 'org.rillscope.reference-capture',
            'major': 1, 'minor': 2, 'filesystem_device': 7, 'inode': 91,
            'rdev': 258, 'uid': 65534, 'gid': 65534, 'mode': 0o600}
        common = {'identity_before': value, 'identity_after': value, 'groups': [],
            'bytes_read': 0, 'bytes_written': 0}
        return (dict(common, status='GRANTED', uid=0, gid=0, opened_monotonic_ns=100, closed_monotonic_ns=200),
            dict(common, status='OPENED', uid=65534, gid=65534, opened_monotonic_ns=300, closed_monotonic_ns=400))

    def test_actual_nobody_command_is_required_and_source_bound_observations_are_saved(self):
        grant, probe = self.records()
        with tempfile.TemporaryDirectory(dir=ROOT / '.local-runs') as temp:
            base = Path(temp); (base / 'exports').mkdir()
            checked = Mock(return_value=json.dumps(probe).encode())
            with patch.object(guest, 'BASE', base), \
                 patch.object(guest.capture_device, 'grant', side_effect=lambda row: row.update(grant)):
                guest.prepare_capture_device({'commit': '1' * 40, 'source': {'sha256': '2' * 64}}, checked)
            result = json.loads((base / 'exports/device-access.json').read_bytes())
        self.assertEqual(result['status'], 'VERIFIED'); self.assertEqual(result['probe'], probe)
        self.assertEqual(result['source_sha256'], '2' * 64)
        name, command = checked.call_args.args
        self.assertEqual(name, 'capture-device-open')
        self.assertEqual(command[:5], ['/usr/bin/setpriv', '--reuid=65534', '--regid=65534', '--clear-groups', '--'])
        self.assertEqual(command[5:], ['/usr/bin/python3', str(ROOT / 'scripts/kvm_reference_device.py'), 'probe'])
        self.assertEqual(checked.call_args.kwargs['timeout'], 15)
        self.assertEqual(checked.call_args.kwargs['inputs'], (guest.INPUT,))

    def test_original_open_error_is_not_retried_or_replaced_with_a_success(self):
        grant, _ = self.records()
        with tempfile.TemporaryDirectory(dir=ROOT / '.local-runs') as temp:
            base = Path(temp); (base / 'exports').mkdir()
            checked = Mock(side_effect=PermissionError('actual open failed'))
            with patch.object(guest, 'BASE', base), \
                 patch.object(guest.capture_device, 'grant', side_effect=lambda row: row.update(grant)):
                with self.assertRaisesRegex(PermissionError, 'actual open failed'):
                    guest.prepare_capture_device({'commit': '1' * 40, 'source': {'sha256': '2' * 64}}, checked)
            result = json.loads((base / 'exports/device-access.json').read_bytes())
        self.assertEqual(checked.call_count, 1); self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['grant'], grant); self.assertIn('actual open failed', result['error'])

    def test_failed_device_setup_prevents_coordinator_and_every_query(self):
        payload = {'mode': METHOD, 'commit': '1' * 40, 'source': {'sha256': '2' * 64},
            'bins': {'rillscope': {}, 'rillscope-measure': {}}, 'reference_qualified': False,
            'host_build_environment': {}}
        seen = []
        def checked(name, command, **kwargs):
            seen.append(name)
            return b'LoadState=masked\nActiveState=inactive\n' if name == 'serial-getty-state' else b''
        account = SimpleNamespace(pw_uid=65534, pw_gid=65534)
        with tempfile.TemporaryDirectory(dir=ROOT / '.local-runs') as temp:
            base = Path(temp); (base / 'exports').mkdir()
            with patch.object(guest, 'BASE', base), patch.object(guest, 'TrialCommands', return_value=checked), \
                 patch.object(guest, 'probe_identity', return_value={}), \
                 patch.object(guest.platform, 'libc_ver', return_value=('glibc', '2.39')), \
                 patch.object(guest, 'snapshot', return_value={'boot_id': '12345678-1234-1234-1234-123456789abc'}), \
                 patch.dict(sys.modules, {'pwd': SimpleNamespace(getpwnam=lambda name: account)}), \
                 patch.object(guest.os, 'chmod'), patch.object(guest.os, 'chown', create=True), \
                 patch.object(guest, 'emit'), patch.object(guest.os, 'environ', dict(guest.os.environ)), \
                 patch.object(guest, 'Coordinator') as coordinator, \
                 patch.object(guest.capture_device, 'grant', side_effect=PermissionError('device refused')):
                coordinator.return_value.close.return_value = {'status': 'OBSERVED',
                    'armed_stages': list(guest.STAGES), 'missing_stages': []}
                try:
                    with self.assertRaisesRegex(PermissionError, 'device refused'):
                        guest.collect(payload, Mock(), time.monotonic_ns())
                finally:
                    coordinator.assert_not_called()
                    self.assertNotIn('full-collection', seen)
            result = json.loads((base / 'exports/device-access.json').read_bytes())
        coordinator.assert_not_called(); self.assertNotIn('full-collection', seen)
        self.assertEqual(result['status'], 'FAIL')


if __name__ == '__main__': unittest.main()
