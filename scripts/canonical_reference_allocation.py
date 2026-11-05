"""Closed messages for a new controller-owned canonical guest allocation.

These validators check retained identities and clocks. They do not obtain root,
authenticate a fictional operator, or infer dedication from hardware. The caller
must really own/reserve the new QEMU guest, retain its original launch/QMP and
reservation records, enforce one campaign, and preserve these exact bytes before
measurement. The old collection/lifetime protocols are deliberately unchanged.
"""
import hashlib
import json
import os
import re
import select
import time

METHOD = 'rillscope-controller-owned-canonical-reference-v1'
REQUEST_KIND = 'canonical-guest-allocation-request-v1'
GRANT_KIND = 'canonical-guest-allocation-grant-v1'
FRAME_LIMIT = 16 * 1024
MAX_LEASE_NS = 21600 * 10**9
MAX_DEPTH = 6
DEDICATION = 'this newly created guest is assigned exclusively to this one canonical campaign for this lease'
PHYSICAL_SCOPE = 'guest assignment only; provider physical host and hypervisor scheduling may be shared'
ENV_KEYS = {'system', 'machine', 'logical_processors', 'cpu_model', 'physical_memory_bytes',
    'resource_inspection_status', 'effective_cpu_capacity', 'process_affinity_cpu_count',
    'cgroup_memory_limit_bytes', 'cgroup_memory_high_bytes'}
REQUEST_KEYS = {'schema_version', 'method', 'kind', 'commit', 'source_sha256', 'nonce',
    'boot_id', 'guest_pre_send_monotonic_ns', 'environment', 'reference_qualified'}
CONTROLLER_KEYS = {'pid', 'start_ticks', 'euid', 'boot_id', 'repository', 'run_id', 'run_attempt'}
QEMU_KEYS = {'pid', 'ppid', 'start_ticks', 'uid', 'command_sha256', 'executable_sha256'}
AUTHORITY_KEYS = {'operator', 'controller', 'qemu', 'launch_sha256', 'qmp_sha256',
    'reservation_sha256', 'reservation_id', 'reserved_monotonic_ns', 'commit',
    'source_sha256', 'nonce', 'boot_id', 'dedication', 'physical_scope'}
GRANT_KEYS = REQUEST_KEYS | {'request_sha256', 'allocation_id', 'authority',
    'authority_sha256', 'host_vm_started_monotonic_ns', 'host_vm_deadline_monotonic_ns',
    'host_issued_monotonic_ns', 'host_remaining_ns', 'lease_span_ns'}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def integer(value):
    return type(value) is int and 0 < value < 2**63


def hex_value(value, length):
    return type(value) is str and re.fullmatch('[0-9a-f]{' + str(length) + '}', value) is not None


def boot(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', value) is not None


def text(value, maximum):
    return (type(value) is str and 0 < len(value.encode('utf-8')) <= maximum
        and all(32 <= ord(char) != 127 for char in value))


def encode(value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')
    require(0 < len(raw) < FRAME_LIMIT, 'canonical allocation frame exceeds byte bound')
    return raw


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def decode(raw):
    require(type(raw) is bytes and 0 < len(raw) < FRAME_LIMIT, 'bounded original allocation bytes required')
    depth, quoted, escaped = 0, False, False
    for byte in raw:
        if quoted:
            if escaped: escaped = False
            elif byte == 92: escaped = True
            elif byte == 34: quoted = False
        elif byte == 34: quoted = True
        elif byte in (91, 123):
            depth += 1
            require(depth <= MAX_DEPTH, 'allocation frame nesting exceeds bound')
        elif byte in (93, 125): depth -= 1
    def unique(pairs):
        row = {}
        for key, value in pairs:
            require(key not in row, 'duplicate allocation frame key')
            row[key] = value
        return row
    def invalid(_value):
        raise ValueError('nonfinite allocation frame constant')
    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)
    except (UnicodeError, RecursionError) as error:
        raise ValueError('invalid bounded allocation frame') from error
    require(type(value) is dict and encode(value) == raw, 'canonical original object bytes required')
    return value


def validate_environment(row):
    require(type(row) is dict and set(row) == ENV_KEYS, 'closed actual guest environment required')
    require(row['system'] == 'Linux' and row['machine'] == 'x86_64'
        and row['resource_inspection_status'] == 'MEASURED'
        and type(row['logical_processors']) is int and row['logical_processors'] == 4
        and type(row['process_affinity_cpu_count']) is int and row['process_affinity_cpu_count'] == 4
        and type(row['effective_cpu_capacity']) in (int, float) and row['effective_cpu_capacity'] == 4
        and integer(row['physical_memory_bytes'])
        and 7.5 * 1024**3 <= row['physical_memory_bytes'] <= 8.5 * 1024**3
        and text(row['cpu_model'], 512), 'actual four-CPU/8GiB x86_64 Linux guest required')
    for key in ('cgroup_memory_limit_bytes', 'cgroup_memory_high_bytes'):
        require(row[key] is None or integer(row[key]) and row[key] >= 7.5 * 1024**3,
            'guest cgroup memory restriction differs')
    return row


def validate_request(row, *, commit, source_sha256):
    require(hex_value(commit, 40) and hex_value(source_sha256, 64), 'exact expected source required')
    require(type(row) is dict and set(row) == REQUEST_KEYS
        and type(row['schema_version']) is int and row['schema_version'] == 1
        and row['method'] == METHOD and row['kind'] == REQUEST_KIND
        and row['commit'] == commit and row['source_sha256'] == source_sha256
        and hex_value(row['nonce'], 32) and boot(row['boot_id'])
        and integer(row['guest_pre_send_monotonic_ns']) and row['reference_qualified'] is False,
        'closed source/boot/nonce-bound canonical allocation request required')
    validate_environment(row['environment'])
    encode(row)
    return row


def validate_authority(row, request):
    """Validate a prior original reservation description, not external authority."""
    require(type(row) is dict and set(row) == AUTHORITY_KEYS
        and text(row['operator'], 256) and hex_value(row['reservation_id'], 32)
        and integer(row['reserved_monotonic_ns'])
        and all(row[key] == request[key] for key in ('commit', 'source_sha256', 'nonce', 'boot_id'))
        and row['dedication'] == DEDICATION and row['physical_scope'] == PHYSICAL_SCOPE
        and all(hex_value(row[key], 64) for key in ('launch_sha256', 'qmp_sha256', 'reservation_sha256')),
        'prior positive guest-scoped reservation and original evidence hashes required')
    controller, qemu = row['controller'], row['qemu']
    require(type(controller) is dict and set(controller) == CONTROLLER_KEYS
        and integer(controller['pid']) and integer(controller['start_ticks'])
        and type(controller['euid']) is int and controller['euid'] == 0
        and boot(controller['boot_id']) and controller['repository'] == 'C-X1an/rillscope'
        and integer(controller['run_id']) and integer(controller['run_attempt']),
        'existing root controller and exact scoped workflow identity required')
    require(type(qemu) is dict and set(qemu) == QEMU_KEYS
        and integer(qemu['pid']) and qemu['pid'] != controller['pid']
        and qemu['ppid'] == controller['pid'] and type(qemu['ppid']) is int
        and integer(qemu['start_ticks']) and integer(qemu['uid'])
        and all(hex_value(qemu[key], 64) for key in ('command_sha256', 'executable_sha256')),
        'original owned nonroot QEMU process/start/launch identity required')
    encode(row)
    return row


def issue_grant(request, authority, *, commit, source_sha256, allocation_id,
        host_started_ns, host_deadline_ns, host_issued_ns):
    """Serialize the caller's real prior reservation; never infer one from facts."""
    validate_request(request, commit=commit, source_sha256=source_sha256)
    validate_authority(authority, request)
    require(all(integer(value) for value in (host_started_ns, host_deadline_ns, host_issued_ns)),
        'exact original host clock types required before deriving a grant')
    grant = {**request, 'kind': GRANT_KIND, 'request_sha256': digest(request),
        'allocation_id': allocation_id, 'authority': authority, 'authority_sha256': digest(authority),
        'host_vm_started_monotonic_ns': host_started_ns,
        'host_vm_deadline_monotonic_ns': host_deadline_ns,
        'host_issued_monotonic_ns': host_issued_ns,
        'host_remaining_ns': host_deadline_ns - host_issued_ns,
        'lease_span_ns': host_deadline_ns - host_started_ns}
    return validate_grant(grant, request)


def validate_grant(row, request):
    require(type(request) is dict, 'original canonical request object required')
    validate_request(request, commit=request.get('commit'), source_sha256=request.get('source_sha256'))
    require(type(row) is dict and set(row) == GRANT_KEYS and row['kind'] == GRANT_KIND
        and all(type(row[key]) is type(request[key]) and row[key] == request[key]
            for key in REQUEST_KEYS - {'kind'})
        and hex_value(row['allocation_id'], 32) and row['request_sha256'] == digest(request)
        and row['authority_sha256'] == digest(row['authority']),
        'closed matching canonical allocation grant required')
    validate_authority(row['authority'], request)
    # The real controller uses one identifier for the reservation, grant and
    # subsequent sixteen-field operator document; preserve that same mapping.
    require(row['allocation_id'] == row['authority']['reservation_id'],
        'grant allocation identity differs from its original reservation')
    clocks = [row[key] for key in ('host_vm_started_monotonic_ns', 'host_vm_deadline_monotonic_ns',
        'host_issued_monotonic_ns', 'host_remaining_ns', 'lease_span_ns')]
    require(all(integer(value) for value in clocks), 'exact bounded canonical host clocks required')
    start, end, issued, remaining, span = clocks
    require(start <= row['authority']['reserved_monotonic_ns'] <= issued < end
        and 0 < span == end - start <= MAX_LEASE_NS and remaining == end - issued,
        'grant must spend its one original reserved VM lifetime')
    encode(row)
    return row


def guest_deadline(grant, request, *, received_ns, configured_ns, tail_ns):
    validate_grant(grant, request)
    sent = request['guest_pre_send_monotonic_ns']
    require(all(integer(value) for value in (received_ns, configured_ns, tail_ns))
        and sent <= received_ns <= configured_ns and 0 < tail_ns <= 600 * 10**9,
        'ordered actual guest clocks and explicit bounded finish tail required')
    cutoff = sent + grant['host_remaining_ns'] - tail_ns
    require(integer(cutoff) and cutoff > configured_ns,
        'allocation round trip/setup consumed the remaining guest lease')
    return cutoff


class GrantSession:
    """One-shot in-process guard; outer owner must also persist/exclusively lock it."""
    def __init__(self, *, commit, source_sha256):
        require(hex_value(commit, 40) and hex_value(source_sha256, 64), 'exact session source required')
        self.commit, self.source_sha256 = commit, source_sha256
        self.grant_sha256 = None
        self.measurement_started = False

    def grant(self, request, authority, **clocks):
        require(self.grant_sha256 is None and not self.measurement_started,
            'allocation is one-shot; overlap/replay/post-measurement grant forbidden')
        row = issue_grant(request, authority, commit=self.commit, source_sha256=self.source_sha256, **clocks)
        self.grant_sha256 = digest(row)
        return row

    def begin_measurement(self, grant_sha256):
        require(self.grant_sha256 is not None and not self.measurement_started
            and grant_sha256 == self.grant_sha256, 'original prior grant required once before measurement')
        self.measurement_started = True


def _remaining(deadline_ns):
    require(integer(deadline_ns), 'finite local allocation I/O deadline required')
    remaining = deadline_ns - time.monotonic_ns()
    require(0 < remaining <= 30 * 10**9, 'allocation exchange exceeded its finite 30second I/O bound')
    return min(remaining / 10**9, 1)


def _nonblocking(connection):
    """Enforce bounded I/O at this boundary, including default blocking sockets."""
    if hasattr(connection, 'setblocking'):
        connection.setblocking(False)
        require(connection.gettimeout() == 0, 'allocation socket must be nonblocking')
    else:
        descriptor = connection.fileno()
        require(type(descriptor) is int and descriptor >= 0 and not os.get_blocking(descriptor),
            'allocation device descriptor must already be nonblocking')


def send_line(connection, row, deadline_ns):
    raw = encode(row)
    require(b'\n' not in raw, 'single canonical allocation frame required')
    _nonblocking(connection)
    pending = memoryview(raw + b'\n')
    while pending:
        _, ready, _ = select.select([], [connection], [], _remaining(deadline_ns))
        if not ready: continue
        try: count = connection.send(pending)
        except BlockingIOError: continue
        require(type(count) is int and 0 < count <= len(pending), 'allocation channel closed during send')
        pending = pending[count:]


def read_line(connection, deadline_ns):
    _nonblocking(connection)
    raw = bytearray()
    for _ in range(FRAME_LIMIT):
        while True:
            ready, _, _ = select.select([connection], [], [], _remaining(deadline_ns))
            if not ready: continue
            try: block = connection.recv(1)
            except BlockingIOError: continue
            break
        require(block, 'allocation channel ended before complete frame')
        if block == b'\n': return decode(bytes(raw))
        raw.extend(block)
    raise ValueError('allocation channel frame exceeds byte bound')
