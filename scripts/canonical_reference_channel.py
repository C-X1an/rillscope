"""Controller-thread prior allocation exchange, then unchanged three CAS frames.

The actual QEMU Popen child stays owned by this process. A separate receiver
process cannot act as its allocator. ACKs establish retained bytes only; the
caller still owns the whole job budget, VM lifetime, cleanup and qualification.
"""
import hashlib
import os
from pathlib import Path
import platform
import select
import socket
import stat
import subprocess
import sys
import threading
import time

import archive_capture
import canonical_reference_allocation as allocation
import canonical_reference_reservation as reservation
from canonical_reference_deadline import AllocationDeadline
from canonical_reference_process import ProcessReadiness
from kvm_pilot_common import write_json
from inspect_reference_guest import BoundedCapture
from reference_allocation import read_bounded, decode_document, DOCUMENT_LIMIT


class RequestCapture:
    """Record exact bounded incoming handshake bytes, including failed prefixes."""
    def __init__(self, connection, stream):
        self.connection, self.stream, self.count = connection, stream, 0

    def setblocking(self, value): self.connection.setblocking(value)
    def gettimeout(self): return self.connection.gettimeout()
    def fileno(self): return self.connection.fileno()

    def recv(self, size):
        block = self.connection.recv(size)
        allocation.require(self.count + len(block) <= allocation.FRAME_LIMIT + 1,
            'original allocation request capture exceeds frame bound')
        allocation.require(self.stream.write(block) == len(block), 'original request capture write incomplete')
        self.count += len(block)
        return block


def exchange(connection, *, commit, source_sha256, deadline_ns, allocate, trace, cancelled=lambda: False):
    """Closed handshake component; the real owner supplies its actual action.

    Tests may supply a synthetic action. Such tests are framing/order controls,
    never real root reservation or an authenticated grant. Runtime uses only
    reservation.create_grant with the live original Popen object below.
    """
    budget = AllocationDeadline(deadline_ns, cancelled)
    request = allocation.read_line(RequestCapture(connection, trace), deadline_ns)
    budget.check()
    allocation.validate_request(request, commit=commit, source_sha256=source_sha256)
    # The trace must reach durable storage before the real action and reply.
    trace.flush()
    if hasattr(trace, 'fileno'):
        try: descriptor = trace.fileno()
        except (OSError, ValueError): descriptor = None
        if descriptor is not None: os.fsync(descriptor)
    raw = allocation.encode(request)
    budget.check()
    grant_raw, slot = allocate(raw, exchange_deadline_ns=deadline_ns, cancelled=cancelled)
    budget.check()
    grant = allocation.decode(grant_raw); allocation.validate_grant(grant, request)
    allocation.send_line(connection, grant, deadline_ns)
    return {'request': request, 'grant': grant, 'slot': slot,
        'request_sha256': hashlib.sha256(raw).hexdigest(),
        'grant_sha256': hashlib.sha256(grant_raw).hexdigest()}


class CanonicalChannel:
    def __init__(self, path, out, *, process, command, uid, qmp_port, commit, source_sha256,
            vm_started_ns, vm_deadline_ns, allocation_id, identity=None):
        allocation.require(platform.system() == 'Linux' and hasattr(os, 'geteuid') and os.geteuid() == 0,
            'actual existing Linux root QEMU controller required')
        allocation.require(all(allocation.integer(value) for value in (vm_started_ns, vm_deadline_ns))
            and 0 < vm_deadline_ns - vm_started_ns <= allocation.MAX_LEASE_NS
            and vm_started_ns <= time.monotonic_ns() < vm_deadline_ns,
            'one original finite VM lifetime required')
        self.path, self.out = archive_capture.owned(path), archive_capture.owned(out)
        allocation.require(stat.S_ISSOCK(self.path.lstat().st_mode), 'actual owned UNIX capture socket required')
        allocation.require(not self.out.exists(), 'new controller channel retention directory required')
        reservation.durable_mkdir(self.out, mode=0o700)
        reservation.source_check(commit, source_sha256)
        allocation.require(type(identity) is ProcessReadiness, 'original process readiness object required before channel admission')
        identity.bind(process, command, uid, commit, source_sha256, vm_started_ns, vm_deadline_ns)
        identity.verify('channel')
        self.identity = identity
        self.process, self.command, self.uid, self.qmp_port = process, command, uid, qmp_port
        self.commit, self.source_sha256 = commit, source_sha256
        self.started_ns, self.deadline_ns, self.allocation_id = vm_started_ns, vm_deadline_ns, allocation_id
        self.controller_pid = os.getpid()
        self.connection = None; self.receiver_process = None; self.receiver_captures = []; self.exchange_record = None
        self.done, self.stop = threading.Event(), threading.Event()
        self.report = {'status': 'RUNNING', 'method': allocation.METHOD, 'reference_qualified': False,
            'commit': commit, 'source_sha256': source_sha256,
            'vm_started_monotonic_ns': vm_started_ns, 'vm_deadline_monotonic_ns': vm_deadline_ns,
            'scope': 'Original prior guest reservation and verified host CAS bytes only; no canonical, semantic, target or whole-job qualification.'}
        self.thread = threading.Thread(target=self.run, name='owned-canonical-channel', daemon=True)

    def persist(self):
        write_json(self.out / 'channel-result.json', self.report)
        reservation.fsync_directory(self.out)

    def run(self):
        try:
            allocation.require(os.getpid() == self.controller_pid, 'allocator must remain in the original QEMU parent process')
            self.connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.connection.settimeout(min(2, max(.001, (self.deadline_ns - time.monotonic_ns()) / 10**9)))
            self.connection.connect(str(self.path)); self.connection.setblocking(False)
            self.report['connected_monotonic_ns'] = time.monotonic_ns(); self.persist()
            # Connect at boot so virtio cannot discard an early request. Wait
            # within the original VM lifetime, then spend at most30s framing,
            # actual reservation, fsync and response; no reception-time reset.
            while True:
                allocation.require(not self.stop.is_set() and time.monotonic_ns() < self.deadline_ns,
                    'original VM ended before its allocation request')
                ready, _, _ = select.select([self.connection], [], [],
                    min(1, max(.001, (self.deadline_ns - time.monotonic_ns()) / 10**9)))
                if ready: break
            self.report['first_request_ready_monotonic_ns'] = time.monotonic_ns()
            deadline = min(self.deadline_ns, time.monotonic_ns() + 30 * 10**9)
            def actual_action(raw, *, exchange_deadline_ns, cancelled):
                allocation.require(os.getpid() == self.controller_pid and not self.stop.is_set(),
                    'original live controller action required')
                return reservation.create_grant(self.process, self.command, self.uid, self.qmp_port,
                    raw, commit=self.commit, source_sha256=self.source_sha256,
                    vm_started_ns=self.started_ns, vm_deadline_ns=self.deadline_ns, allocation_id=self.allocation_id,
                    exchange_deadline_ns=exchange_deadline_ns, cancelled=cancelled, identity=self.identity)
            with (self.out / 'request-wire.raw').open('xb') as trace:
                try:
                    self.exchange_record = exchange(self.connection, commit=self.commit,
                        source_sha256=self.source_sha256, deadline_ns=deadline, allocate=actual_action, trace=trace,
                        cancelled=self.stop.is_set)
                finally: trace.flush(); os.fsync(trace.fileno())
            reservation.fsync_directory(self.out)
            self.report.update(grant_sent_monotonic_ns=time.monotonic_ns(),
                request_sha256=self.exchange_record['request_sha256'], grant_sha256=self.exchange_record['grant_sha256'],
                reservation_slot=self.exchange_record['slot'].relative_to(reservation.ROOT).as_posix())
            self.persist()
            # Only the already-granted byte stream moves to a child. Keeping
            # CAS traversal out of this thread makes its disk writes stoppable
            # by the existing root pidfd/subreaper owner on interruption.
            command = [sys.executable, str(reservation.ROOT / 'scripts/canonical_reference_capture_receiver.py'),
                '--fd', str(self.connection.fileno()), '--out', str(self.out / 'packages'),
                '--grant', str(self.exchange_record['slot'] / 'grant.json.raw'),
                '--controller-pid', str(self.controller_pid)]
            self.report['receiver_command'] = command; self.persist()
            self.receiver_process = subprocess.Popen(command, cwd=reservation.ROOT, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0, start_new_session=True,
                pass_fds=(self.connection.fileno(),))
            self.receiver_captures = [BoundedCapture(self.receiver_process.stdout, self.out / 'receiver.stdout', 4 * 1024**2),
                BoundedCapture(self.receiver_process.stderr, self.out / 'receiver.stderr', 4 * 1024**2)]
            while self.receiver_process.poll() is None:
                allocation.require(not self.stop.is_set() and time.monotonic_ns() < self.deadline_ns,
                    'original canonical capture lifetime exhausted')
                for capture in self.receiver_captures: capture.drain()
                self.stop.wait(.005)
            self.report['receiver_exit_observed'] = self.receiver_process.returncode
            allocation.require(self.receiver_process.returncode == 0, 'actual inherited byte receiver failed')
            result_path = self.out / 'capture-receiver-result.json'
            receiver_raw = read_bounded(result_path, DOCUMENT_LIMIT)
            receiver_report = decode_document(receiver_raw)
            allocation.require(receiver_report.get('status') == 'VERIFIED HOST BYTES'
                and receiver_report.get('grant_sha256') == self.exchange_record['grant_sha256'],
                'actual inherited byte receipt does not match the prior grant')
            self.report['receiver_result'] = receiver_report
            self.report['receiver_result_sha256'] = hashlib.sha256(receiver_raw).hexdigest()
            reservation.source_check(self.commit, self.source_sha256)
            self.report['status'] = 'VERIFIED HOST BYTES'
        except (Exception, KeyboardInterrupt) as error:
            self.report.update(status='FAIL', error=type(error).__name__, reason=str(error)[:2048])
        finally:
            errors = []
            try:
                if self.receiver_process is not None and self.receiver_process.poll() is None:
                    self.receiver_process.terminate()
                    try: self.receiver_process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.receiver_process.kill(); self.receiver_process.wait(timeout=5)
            except Exception as error: errors.append(type(error).__name__ + ': receiver stop')
            for capture in self.receiver_captures:
                try:
                    capture.drain()
                    allocation.require(capture.eof and not capture.exceeded, 'inherited receiver capture is incomplete')
                except Exception as error: errors.append(type(error).__name__ + ': receiver capture')
                finally:
                    try: capture.close()
                    except Exception as error: errors.append(type(error).__name__ + ': capture close')
            try:
                if self.receiver_process is not None:
                    self.receiver_process.stdout.close(); self.receiver_process.stderr.close()
                if self.connection is not None: self.connection.close()
            except Exception as error: errors.append(type(error).__name__ + ': channel close')
            if errors: self.report.update(status='FAIL', close_errors=errors)
            self.report.update(finished_monotonic_ns=time.monotonic_ns())
            try: self.persist()
            except Exception as error: self.report.update(status='FAIL', retention_error=type(error).__name__)
            self.done.set()

    def request_stop(self):
        self.stop.set()
        if self.connection is not None:
            try: self.connection.shutdown(socket.SHUT_RDWR)
            except OSError: pass

    def close(self):
        if not self.done.is_set(): self.request_stop()
        self.thread.join(timeout=10)
        allocation.require(not self.thread.is_alive() and self.done.is_set(),
            'owned canonical channel thread did not stop within bounded cleanup')
        return self.report
