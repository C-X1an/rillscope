"""Real request/grant bytes with a synthetic peer; no authenticated operator."""
import copy
import hashlib
import itertools
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import canonical_reference_guest_start as start
import canonical_reference_allocation as allocation
import canonical_reference_reservation as reservation
from . import test_canonical_reference_allocation as fixtures


class NativeStartControls(unittest.TestCase):
    def fixture(self):
        value = fixtures.CanonicalAllocationTests(); value.setUp(); return value

    def test_request_uses_actual_closed_resources_source_boot_nonce_and_original_clock(self):
        fixture = self.fixture(); row = fixture.request
        self.assertEqual(start.request_for(row['environment'], commit=row['commit'], source_sha256=row['source_sha256'],
            boot_id=row['boot_id'], nonce=row['nonce'], pre_send_ns=row['guest_pre_send_monotonic_ns']), row)
        for key, value in [('logical_processors', 3), ('resource_inspection_status', 'NOT MEASURED')]:
            environment = copy.deepcopy(row['environment']); environment[key] = value
            with self.assertRaises(ValueError):
                start.request_for(environment, commit=row['commit'], source_sha256=row['source_sha256'],
                    boot_id=row['boot_id'], nonce=row['nonce'], pre_send_ns=row['guest_pre_send_monotonic_ns'])

    def exchange_case(self, *, partial=None):
        fixture = self.fixture(); left, right = socket.socketpair(); errors = []
        # Real socket timing must share the exchange's current clock; the
        # protocol-only fixture deliberately uses an unrelated literal epoch.
        fixture.request['guest_pre_send_monotonic_ns'] = time.monotonic_ns()
        deadline = time.monotonic_ns() + 2 * 10**9
        def peer():
            try:
                self.assertEqual(allocation.read_line(right, deadline), fixture.request)
                if partial is None: allocation.send_line(right, fixture.grant(), deadline)
                else: right.sendall(partial); right.shutdown(socket.SHUT_WR)
            except Exception as error: errors.append(error)
        local = ROOT / '.local-runs'; local.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='guest-wire-', dir=local) as directory, left, right:
            out = Path(directory); worker = threading.Thread(target=peer); worker.start()
            try:
                # Windows cannot perform the Linux directory fsync. Only the
                # sync adapter is mocked; sockets, exact raw writes and hashes run.
                with patch.object(start, 'fsync_directory'), patch.object(reservation, 'fsync_directory'):
                    if partial is None:
                        request, grant, received = start.exchange(left, fixture.request, out, deadline_ns=deadline)
                        self.assertEqual(request, allocation.encode(fixture.request))
                        self.assertEqual(grant, allocation.encode(fixture.grant()))
                        self.assertGreater(received, fixture.request['guest_pre_send_monotonic_ns'])
                        self.assertEqual((out / 'request-wire.raw').read_bytes(), request + b'\n')
                        self.assertEqual((out / 'grant-wire.raw').read_bytes(), grant + b'\n')
                        result = json.loads((out / 'exchange-result.json').read_bytes())
                        self.assertEqual(result['status'], 'RECEIVED SUPPORTING GRANT')
                        self.assertEqual(result['grant_sha256'], hashlib.sha256(grant).hexdigest())
                        self.assertIs(result['reference_qualified'], False)
                    else:
                        with self.assertRaises(ValueError):
                            start.exchange(left, fixture.request, out, deadline_ns=deadline)
                        self.assertEqual((out / 'grant-wire.raw').read_bytes(), partial)
                        self.assertFalse((out / 'grant.json.raw').exists())
                        self.assertEqual(json.loads((out / 'exchange-result.json').read_bytes())['status'], 'FAIL')
            finally: worker.join(3)
            self.assertFalse(worker.is_alive()); self.assertEqual(errors, [])

    def test_actual_socket_exchange_preserves_original_request_and_supporting_grant(self):
        self.exchange_case()

    def test_socket_timing_assertions_hold_for_young_and_long_running_clock_epochs(self):
        for first in (10**9, 6 * 10**12):
            with self.subTest(first=first), patch.object(time, 'monotonic_ns',
                side_effect=itertools.count(first, 1000).__next__):
                self.exchange_case()

    def test_failed_partial_grant_is_retained_without_success_document(self):
        self.exchange_case(partial=b'{"incomplete":')

    def test_actual_windows_guard_precedes_seed_setup_or_device_access(self):
        with patch.object(start.platform, 'system', return_value='Windows'), patch.object(start, 'setup') as setup:
            self.assertEqual(start.main(), 77); setup.assert_not_called()


if __name__ == '__main__': unittest.main()
