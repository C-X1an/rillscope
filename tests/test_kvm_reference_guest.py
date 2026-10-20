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
import kvm_reference_lifetime as lifetime


class GuestConfiguration(unittest.TestCase):
    def setUp(self):
        self.payload = {'mode': METHOD, 'commit': '1' * 40, 'source': {'sha256': '2' * 64},
            'bins': {'rillscope': {}, 'rillscope-measure': {}}, 'reference_qualified': False}
        self.boot = '12345678-1234-1234-1234-123456789abc'

    def lifetime(self, started=10**9, ready=101 * 10**9, pre_entry_seconds=10):
        # Independently specified synthetic host/guest epochs and setup events.
        request = {'schema_version': 1, 'method': METHOD, 'kind': lifetime.REQUEST_KIND,
            'commit': '1' * 40, 'source_sha256': '2' * 64, 'nonce': 'a' * 32,
            'boot_id': self.boot, 'guest_request_monotonic_ns': ready, 'reference_qualified': False}
        elapsed = pre_entry_seconds * 10**9 + ready - started
        response = dict(request, kind=lifetime.RESPONSE_KIND, request_sha256=lifetime.digest(request),
            host_vm_started_monotonic_ns=5000 * 10**9,
            host_vm_deadline_monotonic_ns=23000 * 10**9,
            host_reply_monotonic_ns=5000 * 10**9 + elapsed,
            host_remaining_ns=18000 * 10**9 - elapsed)
        return {'schema_version': 1, 'method': METHOD, 'status': 'BOUND', 'reference_qualified': False,
            'request': request, 'response': response, 'request_sha256': lifetime.digest(request),
            'response_sha256': lifetime.digest(response), 'guest_started_monotonic_ns': started,
            'guest_received_monotonic_ns': ready, 'guest_configured_monotonic_ns': ready,
            'deadline_monotonic_ns': started + (17880 - pre_entry_seconds) * 10**9}

    def test_source_bound_configs_have_finite_shared_end_and_separate_collection_reserve(self):
        measure, export = guest.configurations(self.payload, 1_000_000_000, 101_000_000_000, self.boot, self.lifetime())
        self.assertEqual(measure['method'], METHOD)
        self.assertEqual(measure['source_sha256'], '2' * 64)
        self.assertEqual(measure['boot_id'], self.boot)
        self.assertEqual(measure['deadline_monotonic_ns'], export['deadline_monotonic_ns'])
        self.assertEqual(measure['deadline_monotonic_ns'] - 1_000_000_000, 17870 * 10**9)
        self.assertEqual(measure['deadline_monotonic_ns'] - 101_000_000_000, 17770 * 10**9)
        self.assertEqual(export['transfer_seconds'], 180)
        self.assertFalse(measure['reference_qualified'])

    def test_setup_may_not_borrow_collection_and_shutdown_reserves(self):
        with self.assertRaisesRegex(ValueError, 'setup'):
            guest.configurations(self.payload, 1_000_000_000, 2301_000_000_000, self.boot, self.lifetime())

    def test_unused_setup_time_is_reclaimed_only_before_the_fixed_vm_cutoff(self):
        started = 1_000_000_000
        early, _ = guest.configurations(self.payload, started, 101_000_000_000, self.boot, self.lifetime())
        late, _ = guest.configurations(self.payload, started, 2271_000_000_000, self.boot,
            self.lifetime(ready=2271 * 10**9))
        self.assertEqual(early['deadline_monotonic_ns'], started + 17870 * 10**9)
        self.assertEqual(late['deadline_monotonic_ns'], early['deadline_monotonic_ns'])
        # The collection child still leaves the existing600-second finish
        # reserve inside this cutoff; setup cannot extend the18,000-second VM.
        self.assertEqual((early['deadline_monotonic_ns'] - 600 * 10**9
            - 101_000_000_000) // 10**9, 17170)
        self.assertEqual((late['deadline_monotonic_ns'] - 600 * 10**9
            - 2271_000_000_000) // 10**9, 15000)

    def test_missing_replayed_or_changed_lifetime_cannot_configure_a_measurement(self):
        for changed in [None, {}, dict(self.lifetime(), deadline_monotonic_ns=17881 * 10**9),
                        dict(self.lifetime(), guest_started_monotonic_ns=2 * 10**9)]:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                guest.configurations(self.payload, 10**9, 101 * 10**9, self.boot, changed)

    def test_pilot_payload_cannot_silently_become_a_full_collection(self):
        self.payload['mode'] = 'unqualified-kvm-feasibility-pilot'
        with self.assertRaisesRegex(ValueError, 'payload'):
            guest.configurations(self.payload, 1_000_000_000, 101_000_000_000, self.boot, self.lifetime())

    def test_boolean_qualification_and_closed_binaries_are_required(self):
        self.payload['reference_qualified'] = 0
        with self.assertRaises(ValueError): guest.configurations(self.payload, 1, 2, self.boot, self.lifetime())
        self.payload['reference_qualified'] = False
        self.payload['bins']['unexpected'] = {}
        with self.assertRaises(ValueError): guest.configurations(self.payload, 1, 2, self.boot, self.lifetime())

    def test_non_guest_entry_never_installs_packages_or_runs_a_query(self):
        with patch.object(guest.platform, 'system', return_value='Windows'), patch.object(guest, 'collect') as operation:
            self.assertEqual(guest.main(), 77)
        operation.assert_not_called()


class GuestLifetimeSetup(unittest.TestCase):
    def test_original_lifetime_failure_is_retained_even_when_port_close_also_fails(self):
        payload = {'commit': '1' * 40, 'source': {'sha256': '2' * 64}}
        with tempfile.TemporaryDirectory(dir=ROOT / '.local-runs') as temp:
            base = Path(temp); (base / 'exports').mkdir()
            connection = Mock(); connection.close.side_effect = OSError('close failed')
            with patch.object(guest, 'BASE', base), patch.object(guest, 'Device', return_value=connection) as opened, \
                 patch.object(guest.lifetime, 'guest_exchange', side_effect=TimeoutError('original exchange deadline')) as exchange:
                with self.assertRaisesRegex(TimeoutError, 'original exchange deadline'):
                    guest.prepare_lifetime(payload, time.monotonic_ns(), '12345678-1234-1234-1234-123456789abc')
            report = json.loads((base / 'exports/guest-lifetime.json').read_bytes())
        opened.assert_called_once(); exchange.assert_called_once(); connection.close.assert_called_once()
        self.assertEqual(report['status'], 'FAIL'); self.assertEqual(report['error'], 'TimeoutError')
        self.assertIn('original exchange deadline', report['reason'])
        self.assertEqual(report['close_error'], 'OSError')


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
