"""Prepare native tools, then request the actual controller's prior allocation."""
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import signal
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import canonical_reference_allocation as allocation
import canonical_reference_device as device
from canonical_reference_guest_setup import setup
from canonical_reference_guest_owner import run_attempt
from canonical_reference_reservation import durable_mkdir, write_original, fsync_directory
from canonical_reference_seed import INPUT_RELATIVE, validate_seed
from inspect_reference_guest import interrupted
from kvm_pilot_common import write_json
from kvm_reference_channel import Device
from kvm_reference_common import strict_json
import reference_allocation as original

BASE = ROOT / '.local-runs/canonical-start'


def request_for(actual, *, commit, source_sha256, boot_id, nonce, pre_send_ns):
    allocation.require(type(actual) is dict and allocation.ENV_KEYS <= set(actual),
        'complete actual pre-send guest environment required')
    row = {'schema_version': 1, 'method': allocation.METHOD, 'kind': allocation.REQUEST_KIND,
        'commit': commit, 'source_sha256': source_sha256, 'boot_id': boot_id, 'nonce': nonce,
        'guest_pre_send_monotonic_ns': pre_send_ns,
        'environment': {key: actual[key] for key in allocation.ENV_KEYS}, 'reference_qualified': False}
    return allocation.validate_request(row, commit=commit, source_sha256=source_sha256)


class WireCapture:
    """Retain exact accepted request bytes and received failed grant prefixes."""
    def __init__(self, connection, sent, received):
        self.connection, self.sent, self.received = connection, sent, received
        self.sent_count = self.received_count = 0

    def fileno(self): return self.connection.fileno()

    def setblocking(self, value):
        allocation.require(value is False, 'guest allocation wire must remain nonblocking')
        if hasattr(self.connection, 'setblocking'): self.connection.setblocking(False)
        else: os.set_blocking(self.connection.fileno(), False)

    def gettimeout(self):
        if hasattr(self.connection, 'gettimeout'): return self.connection.gettimeout()
        return None if os.get_blocking(self.connection.fileno()) else 0

    def send(self, raw):
        count = self.connection.send(raw)
        allocation.require(type(count) is int and 0 < count <= len(raw)
            and self.sent_count + count <= allocation.FRAME_LIMIT + 1, 'bounded original guest send required')
        allocation.require(self.sent.write(raw[:count]) == count, 'guest request wire capture incomplete')
        self.sent_count += count
        return count

    def recv(self, count):
        raw = self.connection.recv(count)
        allocation.require(self.received_count + len(raw) <= allocation.FRAME_LIMIT + 1,
            'guest supporting grant wire capture exceeds frame bound')
        allocation.require(self.received.write(raw) == len(raw), 'guest grant wire capture incomplete')
        self.received_count += len(raw)
        return raw


def exchange(connection, request, out, *, deadline_ns):
    """Real framing; a valid message alone does not authenticate an operator."""
    allocation.validate_request(request, commit=request.get('commit'), source_sha256=request.get('source_sha256'))
    out = Path(out)
    allocation.require(out.is_dir() and not out.is_symlink(), 'new existing owned allocation exchange directory required')
    request_raw = allocation.encode(request)
    record = {'schema_version': 1, 'method': allocation.METHOD, 'status': 'FAIL',
        'request_sha256': hashlib.sha256(request_raw).hexdigest(),
        'guest_pre_send_monotonic_ns': request['guest_pre_send_monotonic_ns'],
        'exchange_deadline_monotonic_ns': deadline_ns, 'reference_qualified': False,
        'scope': 'Original prior-request/supporting-grant transport bytes only; actual root reservation and outer qualification remain separate.'}
    trace = None
    try:
        write_original(out / 'request.json.raw', request_raw)
        # Configure the actual socket or Linux descriptor before retaining the
        # exchange. The adapter forwards each boundary's nonblocking check.
        allocation._nonblocking(connection)
        with (out / 'request-wire.raw').open('xb') as sent, (out / 'grant-wire.raw').open('xb') as received:
            trace = WireCapture(connection, sent, received)
            try:
                allocation.send_line(trace, request, deadline_ns)
                grant = allocation.read_line(trace, deadline_ns)
                received_ns = time.monotonic_ns()
            finally:
                for stream in (sent, received): stream.flush(); os.fsync(stream.fileno())
        fsync_directory(out)
        allocation.validate_grant(grant, request)
        grant_raw = allocation.encode(grant)
        write_original(out / 'grant.json.raw', grant_raw)
        allocation.require(time.monotonic_ns() < deadline_ns, 'original guest allocation exchange deadline exhausted')
        record.update(status='RECEIVED SUPPORTING GRANT', grant_sha256=hashlib.sha256(grant_raw).hexdigest(),
            received_monotonic_ns=received_ns, allocation_id=grant['allocation_id'])
        return request_raw, grant_raw, received_ns
    except (Exception, KeyboardInterrupt) as error:
        record.update(error=type(error).__name__, reason=str(error)[:2048])
        raise
    finally:
        if trace is not None:
            record.update(request_wire_bytes=trace.sent_count, grant_wire_bytes=trace.received_count)
        record['finished_monotonic_ns'] = time.monotonic_ns()
        write_json(out / 'exchange-result.json', record); fsync_directory(out)


def run():
    device.guard(0)
    seed_path = ROOT / INPUT_RELATIVE
    info = seed_path.lstat()
    allocation.require(info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022,
        'actual root-owned source-only guest seed required')
    seed = validate_seed(strict_json(original.read_bounded(seed_path, 4 * 1024**2)))
    prepared = setup(seed)
    allocation.require(prepared['status'] == 'PREPARED NATIVE TOOLS ONLY'
        and prepared['cleanup']['status'] == 'PASS', 'actual native prerequisite setup did not pass')
    for selected in (signal.SIGTERM, signal.SIGINT): signal.signal(selected, interrupted)
    durable_mkdir(BASE, mode=0o700)
    record = {'schema_version': 1, 'method': allocation.METHOD, 'status': 'FAIL',
        'commit': seed['commit'], 'source_sha256': seed['source_sha256'], 'mode': seed['mode'],
        'native_setup_elapsed_seconds': prepared['elapsed_seconds'],
        'canonical': 'NOT RUN', 'reference_qualified': False}
    connection = None
    try:
        if seed['mode'] == 'native-setup-diagnostic':
            record.update(status='PREPARED NATIVE TOOLS ONLY',
                scope='Explicit setup timing diagnostic; no allocation request or canonical command is executed.')
            return record
        identity = original.repository_identity()
        allocation.require(identity == {'commit': seed['commit'], 'source_sha256': seed['source_sha256']},
            'actual native guest source changed before allocation request')
        boot, actual = original.observed_boot_id(), original.environment()
        node, port = device.inspect_port()
        connection = Device(); device.descriptor_matches(connection.fileno(), port)
        record['allocation_device'] = {'path': str(node), 'identity': port}
        request = request_for(actual, **identity, boot_id=boot, nonce=secrets.token_hex(16),
            pre_send_ns=time.monotonic_ns())
        # Spend the original native setup cutoff as well as the fixed handshake
        # bound; a late guest cannot create a fresh setup/VM lifetime here.
        deadline = min(prepared['deadline_monotonic_ns'], time.monotonic_ns() + 30 * 10**9)
        request_raw, grant_raw, received_ns = exchange(connection, request, BASE, deadline_ns=deadline)
        connection.close(); connection = None
        allocation.require(original.observed_boot_id() == boot and original.repository_identity() == identity,
            'actual source or boot changed during prior allocation exchange')
        result = run_attempt(request_raw, grant_raw, received_ns=received_ns,
            tail_seconds=seed['tail_seconds'], retention_seconds=seed['retention_seconds'])
        record.update(status=result['status'], canonical='ATTEMPTED', owner_result=result,
            scope='One actual native owner attempt; final stopped recovery, all-record and allocation/lease qualification remain separate.')
    except (Exception, KeyboardInterrupt) as error:
        record.update(status='FAIL', error=type(error).__name__, reason=str(error)[:2048])
    finally:
        if connection is not None: connection.close()
        record['finished_monotonic_ns'] = time.monotonic_ns()
        write_json(BASE / 'start-result.json', record); fsync_directory(BASE)
    return record


def main():
    if platform.system() != 'Linux' or ROOT != Path('/work/c') or not hasattr(os, 'geteuid') or os.geteuid() != 0:
        print('BLOCKED: actual existing owned canonical Linux root guest required'); return 77
    try:
        row = run(); print(json.dumps(row, sort_keys=True))
        return 0 if row['status'] in {'PASS', 'PREPARED NATIVE TOOLS ONLY'} else 1
    except (Exception, KeyboardInterrupt) as error:
        print(json.dumps({'status': 'FAIL', 'error': type(error).__name__, 'reason': str(error)[:2048]})); return 1


if __name__ == '__main__': raise SystemExit(main())
