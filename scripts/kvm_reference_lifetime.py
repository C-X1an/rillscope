"""One bounded setup exchange binds unrelated guest/host monotonic epochs.

The source-bound reply grants only time within the existing owned VM. It does
not run a command, name a path, qualify a host or acknowledge benchmark bytes.
"""
import hashlib
import json
import re
import secrets
import select
import time

from kvm_pilot_common import require
from kvm_reference_common import METHOD, identity, strict_json
from kvm_reference_budget import (VM_SECONDS, GUEST_SETUP_SECONDS, VM_TAIL_SECONDS,
    guest_command_deadline_ns)

FRAME_LIMIT = 2048
HANDSHAKE_SECONDS = 30
REQUEST_KIND = 'owned-vm-lifetime-request-v1'
RESPONSE_KIND = 'owned-vm-lifetime-response-v1'
REQUEST_KEYS = {'schema_version', 'method', 'kind', 'commit', 'source_sha256',
    'nonce', 'boot_id', 'guest_request_monotonic_ns', 'reference_qualified'}
RESPONSE_KEYS = REQUEST_KEYS | {'request_sha256', 'host_vm_started_monotonic_ns',
    'host_vm_deadline_monotonic_ns', 'host_reply_monotonic_ns', 'host_remaining_ns'}
HOST_KEYS = {'schema_version', 'method', 'status', 'reference_qualified',
    'request', 'response', 'request_sha256', 'response_sha256',
    'host_receiver_started_monotonic_ns', 'host_request_received_monotonic_ns',
    'host_reply_sent_monotonic_ns'}
GUEST_KEYS = {'schema_version', 'method', 'status', 'reference_qualified',
    'request', 'response', 'request_sha256', 'response_sha256',
    'guest_started_monotonic_ns', 'guest_received_monotonic_ns',
    'guest_configured_monotonic_ns', 'deadline_monotonic_ns'}


def encode(value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')
    require(len(raw) < FRAME_LIMIT, 'lifetime frame exceeds fixed byte bound')
    return raw


def digest(value): return hashlib.sha256(encode(value)).hexdigest()


def validate_request(row, *, commit, source_sha256):
    identity(commit, source_sha256)
    require(type(row) is dict and set(row) == REQUEST_KEYS
        and type(row['schema_version']) is int and row['schema_version'] == 1
        and row['method'] == METHOD and row['kind'] == REQUEST_KIND
        and row['commit'] == commit and row['source_sha256'] == source_sha256
        and row['reference_qualified'] is False
        and isinstance(row['nonce'], str) and re.fullmatch('[0-9a-f]{32}', row['nonce'])
        and isinstance(row['boot_id'], str)
        and re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', row['boot_id'])
        and type(row['guest_request_monotonic_ns']) is int and row['guest_request_monotonic_ns'] > 0,
        'closed source-bound lifetime request required')
    return row


def validate_response(row, request):
    require(type(request) is dict and set(request) == REQUEST_KEYS, 'closed original lifetime request required')
    validate_request(request, commit=request['commit'], source_sha256=request['source_sha256'])
    require(type(row) is dict and set(row) == RESPONSE_KEYS and row['kind'] == RESPONSE_KIND
        and all(type(row[key]) is type(request[key]) and row[key] == request[key]
                for key in REQUEST_KEYS - {'kind'})
        and row['request_sha256'] == digest(request)
        and all(type(row[key]) is int and row[key] > 0 for key in
            ['host_vm_started_monotonic_ns', 'host_vm_deadline_monotonic_ns',
             'host_reply_monotonic_ns', 'host_remaining_ns']),
        'closed matching lifetime reply required')
    start, reply, end = (row[key] for key in ['host_vm_started_monotonic_ns',
        'host_reply_monotonic_ns', 'host_vm_deadline_monotonic_ns'])
    require(start <= reply < start + GUEST_SETUP_SECONDS * 10**9
        and end - start == VM_SECONDS * 10**9 and row['host_remaining_ns'] == end - reply,
        'lifetime reply must use the original live host VM deadline')
    return row


def response_for(request, *, host_started_ns, host_reply_ns):
    require(type(host_started_ns) is int and type(host_reply_ns) is int,
        'exact original host lifetime clocks required')
    row = dict(request, kind=RESPONSE_KIND, request_sha256=digest(request),
        host_vm_started_monotonic_ns=host_started_ns,
        host_vm_deadline_monotonic_ns=host_started_ns + VM_SECONDS * 10**9,
        host_reply_monotonic_ns=host_reply_ns,
        host_remaining_ns=host_started_ns + VM_SECONDS * 10**9 - host_reply_ns)
    return validate_response(row, request)


def remaining(deadline_ns):
    require(type(deadline_ns) is int, 'exact lifetime I/O deadline required')
    value = deadline_ns - time.monotonic_ns()
    require(value > 0, 'owned lifetime exchange deadline exhausted')
    return min(value / 10**9, 1)


def send_line(connection, raw, deadline_ns):
    require(type(raw) is bytes and 0 < len(raw) < FRAME_LIMIT and b'\n' not in raw,
        'bounded single lifetime line required')
    view = memoryview(raw + b'\n')
    while view:
        select.select([], [connection], [], remaining(deadline_ns))
        try: count = connection.send(view)
        except BlockingIOError: continue
        require(count > 0, 'owned lifetime channel closed during send')
        view = view[count:]


def read_line(connection, deadline_ns):
    raw = bytearray()
    for _ in range(FRAME_LIMIT):
        while True:
            select.select([connection], [], [], remaining(deadline_ns))
            try: block = connection.recv(1)
            except BlockingIOError: continue
            break
        require(block, 'owned lifetime channel ended before a complete reply')
        if block == b'\n':
            value = strict_json(bytes(raw))
            require(encode(value) == bytes(raw), 'canonical original lifetime bytes required')
            return value
        raw.extend(block)
    raise ValueError('lifetime frame exceeds fixed byte bound')


def host_exchange(connection, report, *, host_started_ns, commit, source_sha256):
    require(type(report) is dict and not report, 'new owned host lifetime record required')
    require(type(host_started_ns) is int and 0 < host_started_ns <= time.monotonic_ns(),
        'actual pre-QEMU host lifetime start required')
    connection.setblocking(False)
    report.update(schema_version=1, method=METHOD, status='FAIL', reference_qualified=False,
        host_receiver_started_monotonic_ns=time.monotonic_ns())
    deadline = host_started_ns + GUEST_SETUP_SECONDS * 10**9
    request = read_line(connection, deadline)
    report.update(request=request, host_request_received_monotonic_ns=time.monotonic_ns())
    validate_request(request, commit=commit, source_sha256=source_sha256)
    response = response_for(request, host_started_ns=host_started_ns, host_reply_ns=time.monotonic_ns())
    report.update(response=response, request_sha256=digest(request), response_sha256=digest(response))
    send_line(connection, encode(response), deadline)
    report.update(host_reply_sent_monotonic_ns=time.monotonic_ns(), status='BOUND')
    return report


def guest_exchange(connection, report, *, started_ns, setup_deadline_ns, commit, source_sha256, boot_id):
    require(type(report) is dict and not report, 'new owned guest lifetime record required')
    require(type(started_ns) is int and type(setup_deadline_ns) is int
        and 0 < started_ns <= time.monotonic_ns() < setup_deadline_ns
        and setup_deadline_ns == started_ns + (GUEST_SETUP_SECONDS - VM_TAIL_SECONDS) * 10**9,
        'original finite guest setup deadline required')
    if hasattr(connection, 'setblocking'): connection.setblocking(False)
    report.update(schema_version=1, method=METHOD, status='FAIL', reference_qualified=False,
        guest_started_monotonic_ns=started_ns)
    request = validate_request({'schema_version': 1, 'method': METHOD, 'kind': REQUEST_KIND,
        'commit': commit, 'source_sha256': source_sha256, 'nonce': secrets.token_hex(16),
        'boot_id': boot_id, 'guest_request_monotonic_ns': time.monotonic_ns(),
        'reference_qualified': False}, commit=commit, source_sha256=source_sha256)
    deadline = min(setup_deadline_ns, request['guest_request_monotonic_ns'] + HANDSHAKE_SECONDS * 10**9)
    report.update(request=request, request_sha256=digest(request))
    send_line(connection, encode(request), deadline)
    response = read_line(connection, deadline)
    report.update(response=response, response_sha256=digest(response),
        guest_received_monotonic_ns=time.monotonic_ns())
    validate_response(response, request)
    configured = time.monotonic_ns()
    cutoff = guest_command_deadline_ns(started_ns, configured,
        request_ns=request['guest_request_monotonic_ns'],
        received_ns=report['guest_received_monotonic_ns'], host_remaining_ns=response['host_remaining_ns'])
    report.update(guest_configured_monotonic_ns=configured, deadline_monotonic_ns=cutoff, status='BOUND')
    return report


def validate_guest_record(guest, *, commit, source_sha256, boot_id, started_ns=None, ready_ns=None):
    require(type(guest) is dict and set(guest) == GUEST_KEYS
        and type(guest['schema_version']) is int and guest['schema_version'] == 1
        and guest['method'] == METHOD and guest['status'] == 'BOUND'
        and guest['reference_qualified'] is False, 'complete original guest lifetime record required')
    request, response = guest['request'], guest['response']
    validate_request(request, commit=commit, source_sha256=source_sha256)
    validate_response(response, request)
    require(request['boot_id'] == boot_id and guest['request_sha256'] == digest(request)
        and guest['response_sha256'] == digest(response), 'guest lifetime source/boot/message hashes differ')
    deadline = guest_command_deadline_ns(guest['guest_started_monotonic_ns'],
        guest['guest_configured_monotonic_ns'], request_ns=request['guest_request_monotonic_ns'],
        received_ns=guest['guest_received_monotonic_ns'], host_remaining_ns=response['host_remaining_ns'])
    require(type(guest['deadline_monotonic_ns']) is int and guest['deadline_monotonic_ns'] == deadline,
        'original guest cutoff did not spend the host reply from pre-send time')
    if started_ns is not None or ready_ns is not None:
        require(type(started_ns) is int and type(ready_ns) is int
            and started_ns == guest['guest_started_monotonic_ns']
            and guest['guest_configured_monotonic_ns'] <= ready_ns,
            'guest configuration must follow its original lifetime exchange')
        require(guest_command_deadline_ns(started_ns, ready_ns,
            request_ns=request['guest_request_monotonic_ns'], received_ns=guest['guest_received_monotonic_ns'],
            host_remaining_ns=response['host_remaining_ns']) == deadline,
            'guest lifetime cutoff changed after the exchange')
    return deadline


def validate_records(host, guest, vm, *, commit, source_sha256, boot_id):
    """Check retained original records; this does not authenticate a host owner."""
    for row, keys in [(host, HOST_KEYS), (guest, GUEST_KEYS)]:
        require(type(row) is dict and set(row) == keys and type(row['schema_version']) is int
            and row['schema_version'] == 1 and row['method'] == METHOD and row['status'] == 'BOUND'
            and row['reference_qualified'] is False, 'complete original lifetime records required')
    require(host['request'] == guest['request'] and host['response'] == guest['response'],
        'original host and guest lifetime messages differ')
    request, response = guest['request'], guest['response']
    validate_request(request, commit=commit, source_sha256=source_sha256)
    validate_response(response, request)
    require(request['boot_id'] == boot_id and all(row['request_sha256'] == digest(request)
        and row['response_sha256'] == digest(response) for row in [host, guest]),
        'original lifetime source/boot/message hashes differ')
    require(type(vm) is dict and set(vm) == {'schema_version', 'method', 'commit', 'source_sha256',
        'started_monotonic_ns', 'deadline_monotonic_ns', 'reference_qualified'}
        and type(vm['schema_version']) is int and vm['schema_version'] == 1 and vm['method'] == METHOD
        and vm['commit'] == commit and vm['source_sha256'] == source_sha256
        and vm['reference_qualified'] is False
        and type(vm['started_monotonic_ns']) is int and type(vm['deadline_monotonic_ns']) is int
        and vm['started_monotonic_ns'] == response['host_vm_started_monotonic_ns']
        and vm['deadline_monotonic_ns'] == response['host_vm_deadline_monotonic_ns'],
        'lifetime reply does not bind the original host VM start')
    names = ['host_receiver_started_monotonic_ns', 'host_request_received_monotonic_ns',
        'host_reply_sent_monotonic_ns']
    require(all(type(host[key]) is int for key in names)
        and vm['started_monotonic_ns'] <= host[names[0]] <= host[names[1]]
        <= response['host_reply_monotonic_ns'] <= host[names[2]]
        < vm['started_monotonic_ns'] + GUEST_SETUP_SECONDS * 10**9,
        'original lifetime host clocks reverse or exceed setup')
    deadline = validate_guest_record(guest, commit=commit, source_sha256=source_sha256, boot_id=boot_id)
    return {'status': 'BOUND', 'deadline_monotonic_ns': deadline,
        'request_sha256': digest(request), 'response_sha256': digest(response),
        'vm_tail_seconds': VM_TAIL_SECONDS, 'reference_qualified': False,
        'scope': 'Original source-bound setup clocks and conservative remaining lifetime only; no performance, allocation or complete-method qualification'}
