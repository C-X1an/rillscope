"""Synthetic protocol fixtures only; never genuine allocation/runtime evidence."""
import copy
import hashlib
from pathlib import Path
import socket
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import canonical_reference_allocation as allocation


class CanonicalAllocationTests(unittest.TestCase):
    def setUp(self):
        self.request = {'schema_version': 1,
            'method': 'rillscope-controller-owned-canonical-reference-v1',
            'kind': 'canonical-guest-allocation-request-v1', 'commit': 'a' * 40,
            'source_sha256': 'b' * 64, 'nonce': 'c' * 32,
            'boot_id': '11111111-2222-3333-4444-555555555555',
            'guest_pre_send_monotonic_ns': 5_000_000_000_000,
            'environment': {'system': 'Linux', 'machine': 'x86_64', 'logical_processors': 4,
                'cpu_model': 'synthetic unit-test CPU', 'physical_memory_bytes': 8_589_934_592,
                'resource_inspection_status': 'MEASURED', 'effective_cpu_capacity': 4,
                'process_affinity_cpu_count': 4, 'cgroup_memory_limit_bytes': None,
                'cgroup_memory_high_bytes': None}, 'reference_qualified': False}
        self.authority = {'operator': 'synthetic unit-test controller',
            'controller': {'pid': 200, 'start_ticks': 1000, 'euid': 0,
                'boot_id': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
                'repository': 'C-X1an/rillscope', 'run_id': 123, 'run_attempt': 1},
            'qemu': {'pid': 201, 'ppid': 200, 'start_ticks': 1001, 'uid': 1001,
                'command_sha256': '1' * 64, 'executable_sha256': '2' * 64},
            'launch_sha256': '3' * 64, 'qmp_sha256': '4' * 64, 'reservation_sha256': '5' * 64,
            'reservation_id': 'd' * 32, 'reserved_monotonic_ns': 120_000_000_000,
            'commit': 'a' * 40, 'source_sha256': 'b' * 64, 'nonce': 'c' * 32,
            'boot_id': '11111111-2222-3333-4444-555555555555',
            'dedication': 'this newly created guest is assigned exclusively to this one canonical campaign for this lease',
            'physical_scope': 'guest assignment only; provider physical host and hypervisor scheduling may be shared'}
        self.clocks = {'allocation_id': 'd' * 32, 'host_started_ns': 100_000_000_000,
            'host_deadline_ns': 20_100_000_000_000, 'host_issued_ns': 140_000_000_000}

    def grant(self, request=None, authority=None, clocks=None):
        return allocation.issue_grant(self.request if request is None else request,
            self.authority if authority is None else authority, commit='a' * 40,
            source_sha256='b' * 64, **(self.clocks if clocks is None else clocks))

    def test_literal_binding_and_conservative_unrelated_epochs(self):
        grant = self.grant()
        self.assertEqual(grant['host_remaining_ns'], 19_960_000_000_000)
        self.assertEqual(grant['lease_span_ns'], 20_000_000_000_000)
        cutoff = allocation.guest_deadline(grant, self.request, received_ns=5_003_000_000_000,
            configured_ns=5_005_000_000_000, tail_ns=120_000_000_000)
        self.assertEqual(cutoff, 24_840_000_000_000)
        self.assertFalse(grant['reference_qualified'])
        self.assertEqual(grant['request_sha256'], hashlib.sha256(allocation.encode(self.request)).hexdigest())
        self.assertEqual(allocation.decode(allocation.encode(grant)), grant)

    def test_wrong_expected_source_and_closed_request(self):
        for key, value in [('commit', 'e' * 40), ('source_sha256', 'f' * 64),
            ('method', 'rillscope-kvm-full-capture-v1'), ('schema_version', True),
            ('nonce', 'bad'), ('boot_id', 'bad'), ('guest_pre_send_monotonic_ns', True),
            ('reference_qualified', True), ('extra', 'closed')]:
            with self.subTest(key=key):
                request = copy.deepcopy(self.request); request[key] = value
                with self.assertRaises(ValueError): self.grant(request=request)

    def test_wrong_actual_resources(self):
        for key, value in [('logical_processors', True), ('logical_processors', 8),
            ('physical_memory_bytes', 1024), ('effective_cpu_capacity', float('nan')),
            ('effective_cpu_capacity', True), ('process_affinity_cpu_count', 2),
            ('resource_inspection_status', 'UNKNOWN'), ('machine', 'aarch64'),
            ('cgroup_memory_high_bytes', True), ('cgroup_memory_limit_bytes', 1024)]:
            with self.subTest(key=key, value=value):
                request = copy.deepcopy(self.request); request['environment'][key] = value
                with self.assertRaises(ValueError): self.grant(request=request)

    def test_arbitrary_or_unprivileged_claim_is_rejected(self):
        for key, value in [('dedication', True), ('physical_scope', 'exclusive physical host'),
            ('operator', ''), ('launch_sha256', 'no hash'), ('reservation_id', 'bad'),
            ('commit', 'e' * 40), ('nonce', 'e' * 32),
            ('boot_id', 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')]:
            with self.subTest(key=key):
                authority = copy.deepcopy(self.authority); authority[key] = value
                with self.assertRaises(ValueError): self.grant(authority=authority)
        for location, key, value in [('controller', 'euid', 1001), ('controller', 'euid', False),
            ('controller', 'repository', 'unrelated/repo'), ('controller', 'run_attempt', True),
            ('qemu', 'uid', 0), ('qemu', 'ppid', 300), ('qemu', 'start_ticks', False),
            ('qemu', 'executable_sha256', 'bad')]:
            with self.subTest(location=location, key=key):
                authority = copy.deepcopy(self.authority); authority[location][key] = value
                with self.assertRaises(ValueError): self.grant(authority=authority)

    def test_lifetime_does_not_reset_or_expand_old_method(self):
        for key, value in [('host_issued_ns', 20_100_000_000_000),
            ('host_started_ns', 150_000_000_000), ('host_deadline_ns', 22_000_000_000_001),
            ('host_issued_ns', True), ('allocation_id', 'bad')]:
            with self.subTest(key=key):
                clocks = dict(self.clocks); clocks[key] = value
                with self.assertRaises(ValueError): self.grant(clocks=clocks)
        grant = self.grant()
        for key, value in [('method', 'rillscope-kvm-full-capture-v1'),
            ('host_remaining_ns', 20_000_000_000_000), ('lease_span_ns', 18_000_000_000_000),
            ('request_sha256', 'e' * 64), ('authority_sha256', 'e' * 64),
            ('allocation_id', False), ('extra', 1)]:
            with self.subTest(key=key):
                changed = copy.deepcopy(grant); changed[key] = value
                with self.assertRaises(ValueError): allocation.validate_grant(changed, self.request)

    def test_expired_reversed_and_nonconservative_guest_clocks(self):
        grant = self.grant()
        for received, configured, tail in [(4_999_000_000_000, 5_005_000_000_000, 120_000_000_000),
            (5_003_000_000_000, 5_002_000_000_000, 120_000_000_000),
            (5_003_000_000_000, 25_000_000_000_000, 120_000_000_000),
            (5_003_000_000_000, 5_005_000_000_000, True),
            (5_003_000_000_000, 5_005_000_000_000, 601_000_000_000)]:
            with self.subTest(received=received, configured=configured, tail=tail):
                with self.assertRaises(ValueError):
                    allocation.guest_deadline(grant, self.request, received_ns=received,
                        configured_ns=configured, tail_ns=tail)

    def test_one_shot_rejects_replay_overlap_replacement_and_post_measurement_grant(self):
        session = allocation.GrantSession(commit='a' * 40, source_sha256='b' * 64)
        with self.assertRaises(ValueError): session.begin_measurement('e' * 64)
        grant = session.grant(self.request, self.authority, **self.clocks)
        with self.assertRaises(ValueError): session.grant(self.request, self.authority, **self.clocks)
        with self.assertRaises(ValueError): session.begin_measurement('e' * 64)
        session.begin_measurement(allocation.digest(grant))
        with self.assertRaises(ValueError): session.begin_measurement(allocation.digest(grant))
        with self.assertRaises(ValueError): session.grant(self.request, self.authority, **self.clocks)

    def test_bounded_original_json(self):
        for raw in [b'{"a":1,"a":1}', b'{"a":NaN}', b'{"a":Infinity}',
            b'{"a": ' + b'[' * 7 + b'0' + b']' * 7 + b'}',
            b' ' * (16 * 1024), b'{ "a":1}', b'[]', b'\xff']:
            with self.subTest(raw=raw[:40]):
                with self.assertRaises(ValueError): allocation.decode(raw)

    def test_real_socket_framing_and_closed_channel(self):
        left, right = socket.socketpair()
        with left, right:
            left.setblocking(False); right.setblocking(False)
            deadline = time.monotonic_ns() + 2_000_000_000
            allocation.send_line(left, self.request, deadline)
            self.assertEqual(allocation.read_line(right, deadline), self.request)
        left, right = socket.socketpair()
        with left, right:
            left.close(); right.setblocking(False)
            with self.assertRaises(ValueError):
                allocation.read_line(right, time.monotonic_ns() + 2_000_000_000)

    def _stalled_socket(self, operation):
        # A separate real process gives the regression its own finite stop even
        # against the original blocking bug. No timeout is converted to PASS.
        script = '''import socket,sys,time
sys.path.insert(0,sys.argv[1])
import canonical_reference_allocation as allocation
left,right=socket.socketpair()
with left,right:
    if sys.argv[2]=='send':
        left.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,1024)
        left.setblocking(False)
        while True:
            try: left.send(b'x'*4096)
            except BlockingIOError: break
        left.setblocking(True)
    started=time.monotonic()
    try:
        if sys.argv[2]=='send': allocation.send_line(left,{'bounded':'frame'},time.monotonic_ns()+100_000_000)
        else: allocation.read_line(left,time.monotonic_ns()+100_000_000)
    except ValueError:
        assert time.monotonic()-started<1.5
        print('expired deadline rejected');sys.exit(0)
    raise AssertionError('silent peer must not complete a frame')
'''
        try:
            result = subprocess.run([sys.executable, '-c', script, str(ROOT / 'scripts'), operation],
                capture_output=True, text=True, timeout=2)
        except subprocess.TimeoutExpired:
            self.fail('blocking ' + operation + ' exceeded its finite deadline')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'expired deadline rejected')

    def test_default_blocking_silent_peer_read_has_finite_deadline(self):
        self._stalled_socket('read')

    def test_default_blocking_stalled_send_has_finite_deadline(self):
        self._stalled_socket('send')


if __name__ == '__main__': unittest.main()
