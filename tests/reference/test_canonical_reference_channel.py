"""Real socket framing with synthetic allocator callbacks; no actual VM grant."""
import copy
import io
from pathlib import Path
import socket
import struct
import sys
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import canonical_reference_allocation as allocation
import canonical_reference_channel as channel
import canonical_reference_capture_receiver as capture
from . import test_canonical_reference_allocation as fixtures


class CanonicalChannelControls(unittest.TestCase):
    def fixture(self):
        value = fixtures.CanonicalAllocationTests(); value.setUp(); return value

    def test_original_request_is_captured_before_the_synthetic_action_and_reply(self):
        fixture = self.fixture(); left, right = socket.socketpair()
        with left, right:
            trace = io.BytesIO(); expected = allocation.encode(fixture.request) + b'\n'
            def synthetic(raw, *, exchange_deadline_ns, cancelled):
                self.assertEqual(trace.getvalue(), expected)
                self.assertEqual(raw, allocation.encode(fixture.request))
                self.assertGreater(exchange_deadline_ns, time.monotonic_ns())
                self.assertIs(cancelled(), False)
                return allocation.encode(fixture.grant()), Path('synthetic-fixture-only')
            allocation.send_line(right, fixture.request, time.monotonic_ns() + 2_000_000_000)
            result = channel.exchange(left, commit='a' * 40, source_sha256='b' * 64,
                deadline_ns=time.monotonic_ns() + 2_000_000_000, allocate=synthetic, trace=trace)
            self.assertEqual(allocation.read_line(right, time.monotonic_ns() + 2_000_000_000), fixture.grant())
            self.assertEqual(result['request'], fixture.request)
            self.assertFalse(result['grant']['reference_qualified'])

    def test_invalid_source_nonce_or_old_method_cannot_invoke_allocator(self):
        fixture = self.fixture()
        for key, value in [('commit', 'c' * 40), ('source_sha256', 'd' * 64), ('nonce', 'bad'),
            ('method', 'rillscope-kvm-full-capture-v1')]:
            with self.subTest(key=key):
                left, right = socket.socketpair()
                with left, right:
                    request = copy.deepcopy(fixture.request); request[key] = value
                    trace = io.BytesIO(); action = Mock()
                    allocation.send_line(right, request, time.monotonic_ns() + 2_000_000_000)
                    with self.assertRaises(ValueError):
                        channel.exchange(left, commit='a' * 40, source_sha256='b' * 64,
                            deadline_ns=time.monotonic_ns() + 2_000_000_000, allocate=action, trace=trace)
                    action.assert_not_called()
                    self.assertEqual(trace.getvalue(), allocation.encode(request) + b'\n')

    def test_wire_and_issued_grant_cannot_name_a_different_reservation_identity(self):
        fixture = self.fixture()
        changed = copy.deepcopy(fixture.grant()); changed['allocation_id'] = '0' * 32
        with self.subTest(form='wire'):
            with self.assertRaises(ValueError): allocation.validate_grant(changed, fixture.request)
        clocks = dict(fixture.clocks); clocks['allocation_id'] = '0' * 32
        with self.subTest(form='issued'):
            with self.assertRaises(ValueError): fixture.grant(clocks=clocks)

    def test_partial_failed_request_bytes_survive_without_an_allocation(self):
        left, right = socket.socketpair()
        with left, right:
            right.sendall(b'{"partial":'); right.shutdown(socket.SHUT_WR)
            trace = io.BytesIO(); action = Mock()
            with self.assertRaises(ValueError):
                channel.exchange(left, commit='a' * 40, source_sha256='b' * 64,
                    deadline_ns=time.monotonic_ns() + 2_000_000_000, allocate=action, trace=trace)
            self.assertEqual(trace.getvalue(), b'{"partial":'); action.assert_not_called()

    def test_missing_real_root_controller_stops_before_paths_or_children(self):
        with patch.object(channel.platform, 'system', return_value='Windows'):
            with patch.object(channel.reservation, 'live_child') as child:
                with self.assertRaisesRegex(ValueError, 'actual existing Linux root'):
                    channel.CanonicalChannel(Path('missing'), Path('out'), process=None, command=[], uid=1001,
                        qmp_port=12345, commit='a' * 40, source_sha256='b' * 64,
                        vm_started_ns=1, vm_deadline_ns=2, allocation_id='c' * 32)
                child.assert_not_called()

    def test_peer_credential_parser_rejects_wrong_pid_malformed_or_negative_identity(self):
        self.assertEqual(capture.peer_credentials(struct.pack('3i', 201, 1001, 1001), 201),
            {'pid': 201, 'uid': 1001, 'gid': 1001})
        for raw, expected in [(struct.pack('3i', 202, 1001, 1001), 201),
            (struct.pack('3i', 201, -1, 1001), 201), (b'0' * 13, 201), (b'', 201),
            (struct.pack('3i', 201, 1001, 1001), True)]:
            with self.subTest(raw=raw, expected=expected):
                with self.assertRaises(ValueError): capture.peer_credentials(raw, expected)


if __name__ == '__main__': unittest.main()
