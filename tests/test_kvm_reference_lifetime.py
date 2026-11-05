"""Closed setup arithmetic and real local socket controls; no VM qualification."""
import copy
import json
from pathlib import Path
import socket
import sys
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import kvm_reference_lifetime as subject

COMMIT = '1' * 40
SOURCE = '2' * 64
BOOT = '11111111-2222-3333-4444-555555555555'
NS = 10**9


def original_records():
    """Literal synthetic clocks: distinct epochs,121s boot and6s round trip."""
    request = {'schema_version': 1, 'method': 'rillscope-full-capture-v1',
        'kind': 'owned-vm-lifetime-request-v1', 'commit': COMMIT, 'source_sha256': SOURCE,
        'nonce': 'a' * 32, 'boot_id': BOOT, 'guest_request_monotonic_ns': 7001 * NS,
        'reference_qualified': False}
    response = dict(request, kind='owned-vm-lifetime-response-v1', request_sha256=subject.digest(request),
        host_vm_started_monotonic_ns=1000 * NS, host_vm_deadline_monotonic_ns=19000 * NS,
        host_reply_monotonic_ns=1125 * NS, host_remaining_ns=17875 * NS)
    common = {'schema_version': 1, 'method': 'rillscope-full-capture-v1', 'status': 'BOUND',
        'reference_qualified': False, 'request': request, 'response': response,
        'request_sha256': subject.digest(request), 'response_sha256': subject.digest(response)}
    host = dict(common, host_receiver_started_monotonic_ns=1001 * NS,
        host_request_received_monotonic_ns=1124 * NS, host_reply_sent_monotonic_ns=1126 * NS)
    guest = dict(common, guest_started_monotonic_ns=7000 * NS,
        guest_received_monotonic_ns=7007 * NS, guest_configured_monotonic_ns=7008 * NS,
        deadline_monotonic_ns=24756 * NS)
    vm = {'schema_version': 1, 'method': 'rillscope-full-capture-v1', 'commit': COMMIT,
        'source_sha256': SOURCE, 'started_monotonic_ns': 1000 * NS,
        'deadline_monotonic_ns': 19000 * NS, 'reference_qualified': False}
    return copy.deepcopy((host, guest, vm))


class LifetimeBinding(unittest.TestCase):
    def verify(self, host, guest, vm):
        return subject.validate_records(host, guest, vm, commit=COMMIT, source_sha256=SOURCE, boot_id=BOOT)

    def test_distinct_epochs_and_original_round_trip_leave123_seconds_of_host_tail(self):
        host, guest, vm = original_records()
        result = self.verify(host, guest, vm)
        self.assertEqual(result['deadline_monotonic_ns'], 24756 * NS)
        self.assertFalse(result['reference_qualified'])
        mapped_host_cutoff = 1121 * NS + result['deadline_monotonic_ns'] - 7000 * NS
        self.assertEqual(vm['deadline_monotonic_ns'] - mapped_host_cutoff, 123 * NS)

    def test_receipt_clock_start_or_post_receive_cutoff_cannot_extend_original_vm(self):
        host, guest, vm = original_records()
        for changes in [{'deadline_monotonic_ns': 24762 * NS},
                        {'guest_received_monotonic_ns': 7000 * NS},
                        {'guest_configured_monotonic_ns': 7006 * NS},
                        {'deadline_monotonic_ns': True}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.verify(host, dict(guest, **changes), vm)
        for changes in [{'started_monotonic_ns': 1001 * NS},
                        {'deadline_monotonic_ns': 19001 * NS}, {'reference_qualified': True}]:
            with self.assertRaises(ValueError): self.verify(host, guest, dict(vm, **changes))

    def test_replay_other_source_boot_nonce_missing_or_changed_messages_are_rejected(self):
        host, guest, vm = original_records()
        for key, value in [('commit', '3' * 40), ('source_sha256', '4' * 64),
            ('nonce', 'b' * 32), ('boot_id', 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')]:
            changed = copy.deepcopy(guest)
            changed['request'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.verify(host, changed, vm)
        for changed in [None, {}, dict(guest, request_sha256='0' * 64), dict(guest, extra=1)]:
            with self.assertRaises(ValueError): self.verify(host, changed, vm)

    def test_host_reply_must_have_exact_original_duration_remaining_and_setup_clocks(self):
        host, guest, vm = original_records()
        request = guest['request']; response = guest['response']
        for key, value in [('host_vm_started_monotonic_ns', True),
            ('host_vm_deadline_monotonic_ns', 19001 * NS), ('host_reply_monotonic_ns', 3400 * NS),
            ('host_reply_monotonic_ns', 999 * NS), ('host_remaining_ns', 17875 * NS + 1),
            ('request_sha256', '0' * 64), ('nonce', 'b' * 32), ('schema_version', True)]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                subject.validate_response(dict(response, **{key: value}), request)
        for changes in [{'host_receiver_started_monotonic_ns': 999 * NS},
                        {'host_request_received_monotonic_ns': 1126 * NS},
                        {'host_reply_sent_monotonic_ns': 3400 * NS}]:
            with self.assertRaises(ValueError): self.verify(dict(host, **changes), guest, vm)

    def test_request_is_closed_exact_and_unqualified_before_any_time_is_granted(self):
        request = original_records()[1]['request']
        for changes in [{'extra': 0}, {'schema_version': True}, {'reference_qualified': 0},
            {'guest_request_monotonic_ns': False}, {'guest_request_monotonic_ns': 0},
            {'nonce': '../path'}, {'kind': 'archive'}, {'commit': '3' * 40}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                subject.validate_request(dict(request, **changes), commit=COMMIT, source_sha256=SOURCE)


class LifetimeSocket(unittest.TestCase):
    def test_one_real_exchange_has_matching_original_bytes_and_finite_cutoff(self):
        # Actual sockets, threads and clocks; there is no QEMU/VM allocation.
        left, right = socket.socketpair(); host = {}; guest = {}; errors = []
        started = time.monotonic_ns()
        def serve():
            try: subject.host_exchange(right, host, host_started_ns=started, commit=COMMIT, source_sha256=SOURCE)
            except Exception as error: errors.append(error)
        thread = threading.Thread(target=serve)
        thread.start()
        try:
            subject.guest_exchange(left, guest, started_ns=started,
                setup_deadline_ns=started + 2280 * NS, commit=COMMIT, source_sha256=SOURCE, boot_id=BOOT)
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive()); self.assertEqual(errors, [])
            vm = {'schema_version': 1, 'method': 'rillscope-full-capture-v1', 'commit': COMMIT,
                'source_sha256': SOURCE, 'started_monotonic_ns': started,
                'deadline_monotonic_ns': started + 18000 * NS, 'reference_qualified': False}
            bound = subject.validate_records(host, guest, vm, commit=COMMIT, source_sha256=SOURCE, boot_id=BOOT)
            self.assertEqual(host['request'], guest['request'])
            self.assertEqual(host['response'], guest['response'])
            self.assertEqual(bound['deadline_monotonic_ns'], guest['deadline_monotonic_ns'])
            self.assertLessEqual(bound['deadline_monotonic_ns'], started + 17880 * NS)
            self.assertGreater(bound['deadline_monotonic_ns'], time.monotonic_ns() + 600 * NS)
            # Reusing the same record is rejected before a second exchange.
            with self.assertRaisesRegex(ValueError, 'new owned'):
                subject.guest_exchange(left, guest, started_ns=started,
                    setup_deadline_ns=started + 2280 * NS, commit=COMMIT, source_sha256=SOURCE, boot_id=BOOT)
        finally:
            left.close(); right.close(); thread.join(timeout=2)
            self.assertFalse(thread.is_alive())

    def test_empty_or_eof_channel_fails_with_original_deadline(self):
        left, right = socket.socketpair(); right.setblocking(False)
        try:
            with self.assertRaisesRegex(ValueError, 'deadline'):
                subject.read_line(right, time.monotonic_ns() + 20_000_000)
            left.close()
            with self.assertRaisesRegex(ValueError, 'ended'):
                subject.read_line(right, time.monotonic_ns() + NS)
        finally: left.close(); right.close()

    def test_oversize_duplicate_noncanonical_or_partial_bytes_never_become_a_reply(self):
        request = original_records()[1]['request']
        valid = subject.encode(request)
        raw_cases = [b'x' * subject.FRAME_LIMIT, b'{"schema_version":1,' + valid[1:] + b'\n',
                     json.dumps(request).encode() + b'\n', valid[:-1]]
        for raw in raw_cases:
            left, right = socket.socketpair(); right.setblocking(False)
            try:
                left.sendall(raw); left.shutdown(socket.SHUT_WR)
                with self.subTest(bytes=len(raw)), self.assertRaises(ValueError):
                    subject.read_line(right, time.monotonic_ns() + NS)
            finally: left.close(); right.close()


if __name__ == '__main__': unittest.main()
