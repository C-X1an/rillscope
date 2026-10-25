"""Synthetic original-byte association controls; no live allocation or VM."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import archive_capture
import canonical_reference_continuity as continuity
import canonical_reference_recovered_records as recovered_records
import canonical_reference_guest_allocation as guest_allocation
from . import test_canonical_reference_recovered_records as previous
from . import test_canonical_reference_allocation as allocation_fixtures
from . import test_canonical_reference_observer as observer_fixtures
import base64


def raw(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')
def sha(value): return hashlib.sha256(value).hexdigest()


def fixture(root):
    """Every value here is literal/synthetic; pure producers execute no guest."""
    attempt, artifact, terminal, source = previous.prerequisite_fixture(root); second = 10**9
    terminal['plan']['source_sha256'] = source['sha256']
    example = allocation_fixtures.CanonicalAllocationTests(); example.setUp()
    request = copy.deepcopy(example.request); request['guest_pre_send_monotonic_ns'] = 113 * second
    controller = {'pid': 200, 'start_ticks': 41, 'euid': 0, 'boot_id': '99999999-9999-9999-9999-999999999999',
        'repository': 'C-X1an/rillscope', 'run_id': 111, 'run_attempt': 1}
    vm = terminal['collector']['vm']
    argv = json.loads((artifact / 'original-process.json').read_bytes())['command']
    qemu = {'pid': 202, 'ppid': 200, 'start_ticks': 42, 'uid': 1001,
        'command_sha256': sha(b'\0'.join(value.encode() for value in argv) + b'\0'), 'executable_sha256': 'd' * 64}
    common = {'method': continuity.protocol.METHOD, 'commit': request['commit'], 'source_sha256': request['source_sha256']}
    claim = {**common, 'status': 'RESERVED ONE CAMPAIGN SLOT', 'controller': controller, 'qemu': qemu,
        'allocation_id': 'd' * 32, 'monotonic_ns': 127 * second, 'scope': continuity.protocol.PHYSICAL_SCOPE, 'reference_qualified': False}
    sample = {'monotonic_ns': 128 * second, 'qemu_pid': 202,
        'vcpu_threads': [{'thread_id': value, 'affinity': [0, 1, 2, 3]} for value in (301, 302, 303, 304)],
        'actual_qemu_task_ids': [202, 301, 302, 303, 304, 900], 'kvm': {'return': {'enabled': True}},
        'memory': {'return': {'base-memory': 8589934592}}, 'hotplug_memory': {'return': []},
        'run_status': {'return': {'status': 'running'}}, 'environment': {'effective_cpu_capacity': 4, 'process_affinity_cpu_count': 4},
        'process_status': {'VmRSS': '8388608 kB', 'Uid': '1001 1001 1001 1001', 'VmSwap': '0 kB'}}
    launch = {**common, 'controller': controller, 'qemu': qemu, 'command': argv,
        'vm_started_monotonic_ns': vm['started_monotonic_ns'], 'vm_deadline_monotonic_ns': vm['deadline_monotonic_ns'],
        'observed_monotonic_ns': 129 * second}
    positive = {**common, 'status': 'ALLOCATED TO ONE CANONICAL CAMPAIGN', 'allocation_id': 'd' * 32,
        'boot_id': request['boot_id'], 'nonce': request['nonce'], 'controller': controller, 'qemu': qemu,
        'reserved_monotonic_ns': 130 * second, 'dedication': continuity.protocol.DEDICATION,
        'physical_scope': continuity.protocol.PHYSICAL_SCOPE, 'claim_created_sha256': sha(raw(claim)), 'reference_qualified': False}
    authority = {'operator': 'scoped workflow root controller 111/1', 'controller': controller, 'qemu': qemu,
        'launch_sha256': sha(raw(launch)), 'qmp_sha256': sha(raw(sample)), 'reservation_sha256': sha(raw(positive)),
        'reservation_id': 'd' * 32, 'reserved_monotonic_ns': 130 * second, 'commit': request['commit'],
        'source_sha256': request['source_sha256'], 'boot_id': request['boot_id'], 'nonce': request['nonce'],
        'dedication': continuity.protocol.DEDICATION, 'physical_scope': continuity.protocol.PHYSICAL_SCOPE}
    grant = continuity.protocol.issue_grant(request, authority, commit=request['commit'], source_sha256=request['source_sha256'],
        allocation_id='d' * 32, host_started_ns=vm['started_monotonic_ns'], host_deadline_ns=vm['deadline_monotonic_ns'], host_issued_ns=131 * second)
    request_raw, grant_raw = continuity.protocol.encode(request), continuity.protocol.encode(grant)
    slot = '.local-runs/canonical-reservations/vm-202-42'
    result = {'method': continuity.protocol.METHOD, 'status': 'PRIOR GUEST ASSIGNMENT GRANTED', 'grant_sha256': sha(grant_raw),
        'slot': slot, 'completed_monotonic_ns': 132 * second, 'reference_qualified': False}
    reservation = root / '.local-runs/reservation'; reservation.mkdir()
    for name, value in [('claim-created.json', raw(claim)), ('request.json.raw', request_raw), ('grant.json.raw', grant_raw),
        ('qmp-observation-before-membership.json', raw({key: value for key, value in sample.items() if key != 'actual_qemu_task_ids'})),
        ('qmp-and-resource-inspection.json', raw(sample)), ('original-launch-inspection.json', raw(launch)),
        ('positive-reservation.json', raw(positive)), ('reservation-result.json', raw(result))]: (reservation / name).write_bytes(value)
    receiver = {'status': 'VERIFIED HOST BYTES', 'method': continuity.protocol.METHOD, 'controller_pid': 200,
        'grant_sha256': sha(grant_raw), 'peer': {'pid': 202, 'uid': 0, 'gid': 0},
        'started_monotonic_ns': 134 * second, 'finished_monotonic_ns': 18999 * second, 'reference_qualified': False}
    channel = {**common, 'status': 'VERIFIED HOST BYTES', 'reference_qualified': False, 'grant_sha256': sha(grant_raw),
        'request_sha256': sha(request_raw), 'reservation_slot': slot, 'vm_started_monotonic_ns': vm['started_monotonic_ns'],
        'vm_deadline_monotonic_ns': vm['deadline_monotonic_ns'], 'grant_sent_monotonic_ns': 133 * second,
        'receiver_result': receiver, 'receiver_result_sha256': sha(raw(receiver)), 'receiver_exit_observed': 0}
    vm['channel'] = channel; channel_root = artifact / 'channel'; channel_root.mkdir()
    (channel_root / 'channel-result.json').write_bytes(raw(channel)); (channel_root / 'request-wire.raw').write_bytes(request_raw + b'\n')
    (channel_root / 'capture-receiver-result.json').write_bytes(raw(receiver)); (artifact / 'vm-result.json').write_bytes(raw(vm))
    document, cutoff = guest_allocation.document_for(request_raw, grant_raw, request['environment'],
        commit=request['commit'], source_sha256=request['source_sha256'], boot_id=request['boot_id'], received_ns=114 * second,
        inspected_ns=115 * second, tail_ns=60 * second)
    document_raw = raw(document)
    receipt = continuity.original_allocation.validate(document, request['environment'],
        {'commit': request['commit'], 'source_sha256': request['source_sha256']}, request['boot_id'], 116 * second, sha(grant_raw))
    receipt.update(operator_document_sha256=sha(document_raw), allocation_evidence_sha256=sha(grant_raw),
        allocation_evidence_bytes=len(grant_raw), inputs_and_source_stable=True); receipt_raw = raw(receipt)
    for name, value in [('request.json.raw', request_raw), ('supporting-grant.json.raw', grant_raw),
        ('operator-document.json', document_raw), ('reference-host-receipt.json', receipt_raw)]:
        (artifact / 'recovery/allocation' / name).write_bytes(value)
    exchange = {'status': 'RECEIVED SUPPORTING GRANT', 'method': continuity.protocol.METHOD, 'request_sha256': sha(request_raw),
        'grant_sha256': sha(grant_raw), 'guest_pre_send_monotonic_ns': 113 * second, 'allocation_id': 'd' * 32,
        'request_wire_bytes': len(request_raw) + 1, 'grant_wire_bytes': len(grant_raw) + 1, 'reference_qualified': False,
        'received_monotonic_ns': 114 * second, 'finished_monotonic_ns': 114500000000, 'exchange_deadline_monotonic_ns': 143 * second}
    for name, value in [('request.json.raw', request_raw), ('grant.json.raw', grant_raw), ('request-wire.raw', request_raw + b'\n'),
        ('grant-wire.raw', grant_raw + b'\n'), ('exchange-result.json', raw(exchange))]: (artifact / 'recovery/start' / name).write_bytes(value)
    owner_path = artifact / 'recovery/owner/owner-result.json'; owner = json.loads(owner_path.read_bytes())
    owner.update(cutoff_monotonic_ns=cutoff, allocation_sha256=sha(grant_raw), allocation_receipt_sha256=sha(receipt_raw)); owner_path.write_bytes(raw(owner))
    start_path = artifact / 'recovery/start/start-result.json'; start = json.loads(start_path.read_bytes()); start['owner_result'] = owner; start_path.write_bytes(raw(start))
    previous.reindex(artifact, terminal['collector']['recovery'])
    return attempt, artifact, terminal, source, reservation


def measured_fixture(root):
    attempt, artifact, terminal, source, reservation = fixture(root); second = 10**9
    owner_path = artifact / 'recovery/owner/owner-result.json'; owner = json.loads(owner_path.read_bytes())
    owner.update(canonical_finished_monotonic_ns=160 * second, finished_monotonic_ns=170 * second)
    owner['native_retention'].update(started_monotonic_ns=161 * second, finished_monotonic_ns=169 * second, cutoff_monotonic_ns=341 * second)
    grant = continuity.protocol.decode((reservation / 'grant.json.raw').read_bytes())
    down = {'interfaces': [{'name': 'unit0', 'carrier': '0', 'operstate': 'down'}]}
    def sample(stamp, measured, final=False):
        row = observer_fixtures.sample()
        row.update(monotonic_ns=stamp * second, utc_ns=(1000 + stamp) * second,
            method=continuity.protocol.METHOD, sample_kind='final' if final else 'interval',
            phase='measurement' if measured else 'prefix', observation_status='OBSERVED',
            observer_wall_ns=1, observer_cpu_ns=1, reference_qualified=False,
            swaps='Filename\tType\tSize\tUsed\tPriority\n')
        if measured: row['network'] = copy.deepcopy(down)
        return row
    config = {'schema_version': 1, 'method': continuity.INNER_METHOD, 'commit': grant['commit'],
        'source_sha256': source['sha256'], 'boot_id': grant['boot_id'], 'session': 'e' * 32,
        'control_root': '/work/c/.local-runs/kvm-reference/control', 'deadline_monotonic_ns': owner['cutoff_monotonic_ns'],
        'handshake_seconds': 30, 'reference_qualified': False}
    export = {key: config[key] for key in ('schema_version', 'method', 'commit', 'source_sha256', 'deadline_monotonic_ns')}
    export['transfer_seconds'] = 180
    owner_root = artifact / 'recovery/owner'; (owner_root / 'measurement-config.json').write_bytes(raw(config))
    (owner_root / 'export-config.json').write_bytes(raw(export))
    for stage, requested, armed, begin, end in [('grid', 132, 134, 135, 140), ('cancel', 141, 142, 143, 148), ('sort-null', 149, 150, 151, 158)]:
        request = {key: config[key] for key in ('schema_version', 'method', 'session', 'commit', 'source_sha256', 'boot_id', 'reference_qualified')}
        request.update(stage=stage, config_sha256=sha(raw(config)), utc_ns=(1000 + requested) * second, monotonic_ns=requested * second)
        control = artifact / 'recovery/control'; (control / (stage + '-request.json')).write_bytes(raw(request))
        (control / (stage + '-armed.json')).write_bytes(raw({**request, 'status': 'ARMED', 'request_sha256': sha(raw(request)),
            'utc_ns': (1000 + armed) * second, 'monotonic_ns': armed * second}))
        for position, stamp in [('start', begin), ('end', end)]:
            boundary = {**request, 'position': position, 'status': 'OBSERVED', 'collection_exit_code': None if position == 'start' else 0,
                'sample': sample(stamp, True), 'network': copy.deepcopy(down), 'observer_wall_ns': 1, 'observer_cpu_ns': 1}
            (control / (stage + '-' + position + '.json')).write_bytes(raw(boundary))
    events = []
    for phase, stamp in [('prefix-start', 122), ('ready', 133), ('attempt-end', 171)]:
        event = {'schema_version': 1, 'method': continuity.protocol.METHOD, 'phase': phase, 'commit': grant['commit'],
            'source_sha256': source['sha256'], 'boot_id': grant['boot_id'], 'allocation_sha256': sha(raw(grant)),
            'utc_ns': (1000 + stamp) * second, 'monotonic_ns': stamp * second, 'reference_qualified': False}
        if phase == 'ready': event.update(stage='grid', request_sha256=sha((artifact / 'recovery/control/grid-request.json').read_bytes()), config_sha256=sha(raw(config)))
        if phase == 'attempt-end': event['status'] = 'PASS'
        events.append(event)
    serial = b''.join(b'RILLSCOPE_CANONICAL_REFERENCE_V1 ' + base64.b64encode(continuity.protocol.encode(row)) + b'\n' for row in events)
    footer = recovered_records.parse_boot((artifact / 'serial.txt').read_text())
    footer.update(finished_monotonic_ns=180 * second, utc_ns=1180 * second)
    (artifact / 'serial.txt').write_bytes(serial + b'RILLSCOPE_CANONICAL_BOOT_V1 ' + base64.b64encode(raw(footer)) + b'\n')
    vm = terminal['collector']['vm']; vm.update(events=events, prefix_received_monotonic_ns=140 * second,
        ready_received_monotonic_ns=150 * second, end_received_monotonic_ns=185 * second,
        qemu_exit_observed_monotonic_ns=300 * second)
    received = [{'received_utc_ns': (990 + stamp) * second, 'received_monotonic_ns': stamp * second, 'guest': event}
        for stamp, event in zip((140, 150, 185), events)]
    (artifact / 'received-events.jsonl').write_bytes(b''.join(raw(row) + b'\n' for row in received))
    host_template = json.loads((reservation / 'qmp-and-resource-inspection.json').read_bytes())
    hosts = []
    for stamp in (130, 140, 150, 160, 170, 180, 190, 200):
        hosts.append({**host_template, 'monotonic_ns': stamp * second, 'utc_ns': (990 + stamp) * second,
            'method': continuity.protocol.METHOD, 'required_interval': 140 <= stamp <= 190,
            'observation_status': 'OBSERVED', 'observer_wall_ns': 1, 'observer_cpu_ns': 1, 'qemu_affinity': [0, 1, 2, 3],
            'clock_source': 'tsc', 'clock_properties': 'namespace(monotonic=True, adjustable=False)'})
    (artifact / 'host-samples.jsonl').write_bytes(b''.join(raw(row) + b'\n' for row in hosts))
    vm.update(host_samples=8, host_append_cost={'calls': 8, 'wall_ns': 8, 'cpu_ns': 8}, host_final_fsync_ns=1)
    (artifact / 'host-link-down.json').write_bytes(raw({'requested_monotonic_ns': 151 * second, 'finished_monotonic_ns': 152 * second,
        'response': {'return': {}}, 'grant_sha256': sha(raw(grant))}))
    guests = [sample(stamp, stamp >= 133, final=stamp == 165) for stamp in (120, 121, 130, 133, 140, 150, 160, 165)]
    (artifact / 'recovery/observer/canonical-guest-samples.jsonl').write_bytes(b''.join(raw(row) + b'\n' for row in guests))
    observed = {'status': 'OBSERVED', 'method': continuity.protocol.METHOD, 'boot_id': grant['boot_id'], 'error': None,
        'final_sampled': True, 'measurement_armed': True, 'measurement_sample_observed': True, 'observations': 8,
        'first_monotonic_ns': 120 * second, 'last_monotonic_ns': 165 * second, 'maximum_gap_ns': 10 * second,
        'gap_bound_ns': continuity.MAX_GAP_NS, 'append_calls_completed': 8, 'sample_cap': continuity.MAX_GUEST_SAMPLES,
        'record_byte_cap': continuity.MAX_SAMPLE_BYTES, 'log_byte_cap': continuity.MAX_GUEST_LOG_BYTES,
        'append_wall_total_ns': 8, 'append_cpu_total_ns': 8, 'final_fsync_ns': 1}
    owner['coordination'] = {'status': 'OBSERVED', 'method': continuity.protocol.METHOD, 'inner_measurement_method': continuity.INNER_METHOD,
        'armed_stages': ['grid', 'cancel', 'sort-null'], 'missing_stages': [], 'error': None,
        'allocation_receipt_sha256': owner['allocation_receipt_sha256'], 'network_after': down, 'sampler': observed}
    owner_path.write_bytes(raw(owner))
    start_path = artifact / 'recovery/start/start-result.json'; start = json.loads(start_path.read_bytes())
    start.update(owner_result=owner, finished_monotonic_ns=172 * second); start_path.write_bytes(raw(start))
    receiver_path = artifact / 'channel/capture-receiver-result.json'; receiver = json.loads(receiver_path.read_bytes())
    receiver['finished_monotonic_ns'] = 299 * second; receiver_path.write_bytes(raw(receiver))
    vm['channel'].update(receiver_result=receiver, receiver_result_sha256=sha(raw(receiver)))
    (artifact / 'channel/channel-result.json').write_bytes(raw(vm['channel'])); (artifact / 'vm-result.json').write_bytes(raw(vm))
    terminal['collector']['recovery'].update(finished_monotonic_ns=310 * second)
    terminal['collector']['recovery_budget'].update(started_monotonic_ns=305 * second, completed_monotonic_ns=315 * second, actual_deadline_monotonic_ns=605 * second)
    terminal['collector']['finished_monotonic_ns'] = 316 * second
    previous.reindex(artifact, terminal['collector']['recovery'])
    return attempt, artifact, terminal, source, reservation


class PriorAllocationControls(unittest.TestCase):
    def execute(self, change=None):
        with tempfile.TemporaryDirectory(prefix='rill-continuity-unit-') as name:
            root = Path(name).resolve(); attempt, artifact, terminal, source, reservation_path = fixture(root)
            with patch.object(archive_capture, 'ROOT', root):
                prerequisites = recovered_records.validate_prerequisites(attempt, terminal, source=source, deadline=time.monotonic() + 30)
                owner_receipt = {'process_cleanup': {'owned_root_pid': 200}}
                if change: change(prerequisites, reservation_path, owner_receipt)
                reservation = continuity.validate_reservation(reservation_path, prerequisites, terminal, owner_receipt, deadline=time.monotonic() + 30)
                allocation = continuity.validate_guest_allocation(prerequisites, reservation)
                prerequisites['recovered'].unchanged(); reservation['files'].unchanged()
                return reservation, allocation

    def test_all_original_prior_action_and_guest_wire_preflight_bindings_are_checked(self):
        reservation, allocation = self.execute()
        self.assertEqual(reservation['status'], 'CHECKED ORIGINAL PRIOR GUEST RESERVATION')
        self.assertEqual(allocation['status'], 'CHECKED ORIGINAL GUEST ALLOCATION')
        self.assertEqual(allocation['cutoff_monotonic_ns'], 20088000000000)
        self.assertEqual(reservation['receiver']['peer']['uid'], 0)
        self.assertIs(allocation['reference_qualified'], False)

    def test_unrelated_enclosing_owner_pid_or_executable_cannot_authorize_this_claim(self):
        for mutate in [lambda p, r, o: o['process_cleanup'].update(owned_root_pid=999),
            lambda p, r, o: p['prepared'].update(qemu_sha256='e' * 64)]:
            with self.subTest(mutation=mutate), self.assertRaisesRegex(ValueError, 'controller/PID/UID/command/executable'): self.execute(mutate)

    def test_missing_actual_task_membership_is_never_synthesized_from_qmp(self):
        command = ['qemu-system-x86_64', '-qmp', 'tcp:127.0.0.1:1234,server=on,wait=off']
        sample = {'qemu_pid': 202, 'vcpu_threads': [{'thread_id': value} for value in (301, 302, 303, 304)]}
        for values in [None, [202, 301, 302, 303], [202, 301, 301, 302, 303, 304], [True, 202, 301, 302, 303, 304]]:
            with self.subTest(values=values), self.assertRaises(ValueError):
                continuity.recorded_members({**sample, 'actual_qemu_task_ids': values}, command=command, port=1234, qemu_pid=202)

    def test_host_request_wire_and_unchanged_original_guest_grant_are_required(self):
        def changed_wire(prerequisites, reservation, owner):
            path = prerequisites['recovered'].root / 'channel/request-wire.raw'; path.write_bytes(b'changed\n')
        with self.assertRaisesRegex(ValueError, 'original incoming host request framing differs'): self.execute(changed_wire)
        def changed_guest(prerequisites, reservation, owner):
            recovered = prerequisites['recovered']; path = recovered.path(recovered.members['allocation']['supporting-grant.json.raw'])
            path.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'original metadata snapshot changed'): self.execute(changed_guest)

    def test_original_positive_reservation_status_and_grant_hash_cannot_be_repaired(self):
        def mutate(prerequisites, reservation, owner):
            path = reservation / 'reservation-result.json'; row = json.loads(path.read_bytes()); row['status'] = 'FAIL'; path.write_bytes(raw(row))
        with self.assertRaisesRegex(ValueError, 'completed prior reservation result'): self.execute(mutate)

    def test_sample_stream_count_and_complete_hash_are_checked_without_unbounded_read(self):
        with tempfile.TemporaryDirectory(prefix='rill-continuity-unit-') as name:
            root = Path(name).resolve(); folder = root / '.local-runs/samples'; folder.mkdir(parents=True)
            (folder / 'rows.jsonl').write_bytes(b'{"value":1}\n{"value":2}\n')
            with patch.object(archive_capture, 'ROOT', root):
                records = recovered_records.OriginalRecords(folder, time.monotonic() + 30)
                rows = list(continuity.json_records(records, 'rows.jsonl', max_count=2, max_bytes=100))
                self.assertEqual(rows, [{'value': 1}, {'value': 2}])
                with self.assertRaises(ValueError): list(continuity.json_records(records, 'rows.jsonl', max_count=1, max_bytes=100))
                (folder / 'rows.jsonl').write_bytes(b'{"value":9}\n{"value":2}\n')
                with self.assertRaises(ValueError): list(continuity.json_records(records, 'rows.jsonl', max_count=2, max_bytes=100))

    def measurements(self, change=None):
        with tempfile.TemporaryDirectory(prefix='rill-continuity-unit-') as name:
            root = Path(name).resolve(); attempt, artifact, terminal, source, reservation_path = measured_fixture(root)
            if change: change(artifact)
            previous.reindex(artifact, terminal['collector']['recovery'])
            with patch.object(archive_capture, 'ROOT', root):
                prerequisites = recovered_records.validate_prerequisites(attempt, terminal, source=source, deadline=time.monotonic() + 30)
                reservation = continuity.validate_reservation(reservation_path, prerequisites, terminal,
                    {'process_cleanup': {'owned_root_pid': 200}}, deadline=time.monotonic() + 30)
                allocation = continuity.validate_guest_allocation(prerequisites, reservation)
                controls = continuity.validate_controls(prerequisites, reservation)
                return continuity.validate_resources(prerequisites, reservation, allocation, controls)

    def test_original_three_stage_controls_and_prefix_measurement_final_sample_coverage(self):
        row = self.measurements()
        self.assertEqual(row['status'], 'CHECKED ORIGINAL SAMPLED CONTINUITY')
        self.assertEqual((row['host_samples'], row['required_host_samples'], row['guest_samples']), (8, 6, 8))
        self.assertEqual(row['maximum_guest_gap_ns'], 10000000000)
        self.assertIs(row['reference_qualified'], False)

    def test_incomplete_control_set_and_changed_first_request_are_rejected(self):
        for mutate in [lambda a: (a / 'recovery/control/cancel-end.json').unlink(),
            lambda a: (a / 'recovery/control/grid-request.json').write_bytes(b'{}')]:
            with self.subTest(mutation=mutate), self.assertRaises(ValueError): self.measurements(mutate)

    def test_removed_required_host_observation_and_unfinished_guest_sampler_are_rejected(self):
        def filtered(artifact):
            path = artifact / 'host-samples.jsonl'; rows = [json.loads(line) for line in path.read_bytes().splitlines()]
            rows[3]['required_interval'] = False; path.write_bytes(b''.join(raw(row) + b'\n' for row in rows))
        with self.assertRaisesRegex(ValueError, 'filtered'): self.measurements(filtered)
        def missing_final(artifact):
            path = artifact / 'recovery/observer/canonical-guest-samples.jsonl'; rows = [json.loads(line) for line in path.read_bytes().splitlines()]
            rows[-1]['sample_kind'] = 'interval'; path.write_bytes(b''.join(raw(row) + b'\n' for row in rows))
        with self.assertRaisesRegex(ValueError, 'endpoints'): self.measurements(missing_final)


if __name__ == '__main__': unittest.main()
