"""Actual bounded socket/child controls; synthetic grants never qualify a VM."""
import io
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import canonical_reference_allocation as allocation
import canonical_reference_channel as channel
from canonical_reference_deadline import AllocationDeadline
import canonical_reference_reservation as reservation
from evidence import source_identity
from . import test_canonical_reference_allocation as fixtures


class DeadlineControls(unittest.TestCase):
    def test_cancelled_or_expired_original_budget_rejects_before_any_action(self):
        with self.assertRaisesRegex(ValueError, 'cancelled'):
            AllocationDeadline(time.monotonic_ns() + 10**9, lambda: True)
        with self.assertRaisesRegex(ValueError, 'deadline exhausted'):
            AllocationDeadline(time.monotonic_ns() - 1, lambda: False)
        with self.assertRaises(ValueError):
            AllocationDeadline(time.monotonic_ns() + 31 * 10**9, lambda: False)
        with self.assertRaises(ValueError):
            AllocationDeadline(time.monotonic_ns() + 10**9, lambda: 0)

    def test_actual_silent_qmp_uses_one_absolute_deadline(self):
        listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(1)
        stop = threading.Event(); accepted = threading.Event(); errors = []
        def serve():
            try:
                listener.settimeout(1)
                connection, _ = listener.accept()
                with connection: accepted.set(); stop.wait(1)
            except Exception as error: errors.append(error)
        thread = threading.Thread(target=serve); thread.start(); began = time.monotonic()
        try:
            with self.assertRaisesRegex(ValueError, 'deadline exhausted'):
                AllocationDeadline(time.monotonic_ns() + 150_000_000, lambda: False).qmp(
                    listener.getsockname()[1], 'query-kvm')
            self.assertTrue(accepted.is_set())
            self.assertLess(time.monotonic() - began, 1)
        finally:
            stop.set(); thread.join(2); listener.close()
        self.assertFalse(thread.is_alive()); self.assertEqual(errors, [])

    def test_cancelled_actual_child_is_observed_stopped(self):
        stop = threading.Event(); children = []; real = subprocess.Popen
        def start(*args, **kwargs):
            process = real(*args, **kwargs); children.append(process); return process
        timer = threading.Timer(.15, stop.set); timer.start(); began = time.monotonic()
        try:
            with patch('canonical_reference_deadline.subprocess.Popen', side_effect=start):
                with self.assertRaisesRegex(ValueError, 'cancelled'):
                    AllocationDeadline(time.monotonic_ns() + 2 * 10**9, stop.is_set).command(
                        [sys.executable, '-c', 'import time;time.sleep(10)'], ROOT)
        finally: timer.cancel(); timer.join()
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].poll())
        self.assertLess(time.monotonic() - began, 2)

    def test_actual_child_output_is_bounded_and_child_reaped(self):
        children = []; real = subprocess.Popen
        def start(*args, **kwargs):
            process = real(*args, **kwargs); children.append(process); return process
        with patch('canonical_reference_deadline.subprocess.Popen', side_effect=start):
            with self.assertRaisesRegex(ValueError, 'output exceeds bound'):
                AllocationDeadline(time.monotonic_ns() + 3 * 10**9, lambda: False).command(
                    [sys.executable, '-c', 'import os,time;os.write(1,b"x"*100000);time.sleep(10)'], ROOT)
        self.assertEqual(len(children), 1); self.assertIsNotNone(children[0].poll())

    def test_source_selection_matches_unchanged_evidence_including_empty_files(self):
        parent = ROOT / '.local-runs'; parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='deadline-source-', dir=parent) as directory:
            root = Path(directory); (root / 'empty').write_bytes(b'')
            (root / 'source').write_bytes(b'actual source')
            (root / 'verification').mkdir(); (root / 'verification/spec-lock.json').write_bytes(b'{}')
            (root / 'verification/ignored').write_bytes(b'original excluded evidence')
            (root / '.local-runs').mkdir(); (root / '.local-runs/ignored').write_bytes(b'local')
            self.assertEqual(AllocationDeadline(time.monotonic_ns() + 2 * 10**9,
                lambda: False).source_identity(root), source_identity(root))

    def test_same_original_deadline_and_stop_check_reach_action(self):
        fixture = fixtures.CanonicalAllocationTests(); fixture.setUp()
        left, right = socket.socketpair(); stop = threading.Event()
        deadline = time.monotonic_ns() + 2 * 10**9
        def action(raw, *, exchange_deadline_ns, cancelled):
            self.assertEqual(raw, allocation.encode(fixture.request))
            self.assertEqual(exchange_deadline_ns, deadline)
            self.assertEqual(cancelled, stop.is_set)
            return allocation.encode(fixture.grant()), Path('synthetic')
        with left, right:
            allocation.send_line(right, fixture.request, deadline)
            result = channel.exchange(left, commit='a' * 40, source_sha256='b' * 64,
                deadline_ns=deadline, allocate=action, trace=io.BytesIO(), cancelled=stop.is_set)
            self.assertEqual(result['grant'], allocation.read_line(right, deadline))

    def test_cancel_during_action_prevents_wire_grant(self):
        fixture = fixtures.CanonicalAllocationTests(); fixture.setUp()
        left, right = socket.socketpair(); stop = threading.Event()
        deadline = time.monotonic_ns() + 2 * 10**9
        def action(raw, *, exchange_deadline_ns, cancelled):
            self.assertEqual(exchange_deadline_ns, deadline)
            self.assertEqual(cancelled, stop.is_set); stop.set()
            return allocation.encode(fixture.grant()), Path('synthetic')
        with left, right:
            allocation.send_line(right, fixture.request, deadline)
            with self.assertRaisesRegex(ValueError, 'cancelled'):
                channel.exchange(left, commit='a' * 40, source_sha256='b' * 64,
                    deadline_ns=deadline, allocate=action, trace=io.BytesIO(), cancelled=stop.is_set)
            right.setblocking(False)
            with self.assertRaises(BlockingIOError): right.recv(1)

    def test_channel_cleanup_stops_cooperative_allocator_before_returning(self):
        fixture = fixtures.CanonicalAllocationTests(); fixture.setUp()
        owner = channel.CanonicalChannel.__new__(channel.CanonicalChannel)
        owner.stop = threading.Event(); owner.done = threading.Event(); owner.report = {}
        owner.stop_lock = threading.Lock()
        owner.stop_closed = False
        left, right = socket.socketpair(); owner.connection = left
        entered = threading.Event(); errors = []
        def action(_raw, *, exchange_deadline_ns, cancelled):
            budget = AllocationDeadline(exchange_deadline_ns, cancelled); entered.set()
            while True: budget.check(); time.sleep(.005)
        def exchange():
            try:
                channel.exchange(left, commit='a' * 40, source_sha256='b' * 64,
                    deadline_ns=time.monotonic_ns() + 2 * 10**9, allocate=action,
                    trace=io.BytesIO(), cancelled=owner.stop.is_set)
            except ValueError as error: errors.append(str(error))
            finally: owner.done.set()
        with left, right:
            allocation.send_line(right, fixture.request, time.monotonic_ns() + 2 * 10**9)
            owner.thread = threading.Thread(target=exchange); owner.thread.start()
            self.assertTrue(entered.wait(1)); began = time.monotonic()
            try: self.assertEqual(owner.close(), {})
            finally:
                owner.stop.set(); owner.thread.join(2)
            self.assertLess(time.monotonic() - began, 1)
        self.assertFalse(owner.thread.is_alive()); self.assertTrue(owner.done.is_set())
        self.assertEqual(errors, ['original allocation exchange cancelled'])

    def test_expired_grant_budget_precedes_source_or_slot_side_effects(self):
        with patch.object(reservation.platform, 'system', return_value='Linux'), \
            patch.object(reservation.os, 'geteuid', return_value=0, create=True), \
            patch.object(reservation, 'source_check') as source:
            with self.assertRaisesRegex(ValueError, 'deadline exhausted'):
                reservation.create_grant(None, [], 1001, 12345, b'{}', commit='a' * 40,
                    source_sha256='b' * 64, vm_started_ns=1,
                    vm_deadline_ns=time.monotonic_ns() + 10**9, allocation_id='c' * 32,
                    exchange_deadline_ns=time.monotonic_ns() - 1, cancelled=lambda: False)
            source.assert_not_called()


if __name__ == '__main__': unittest.main()
