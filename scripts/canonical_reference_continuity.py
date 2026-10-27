"""Replay original guest assignment, transport and sampled resource continuity.

No metadata is a new allocation action. These checks require originals created
by the scoped controller before its native attempt and leave independent
qualification separate. They never backfill an earlier benchmark capture.
"""
import hashlib
import os
from pathlib import PurePosixPath
import re
import stat

import canonical_reference_allocation as protocol
from canonical_reference_recovered_records import OriginalRecords
from canonical_reference_reservation import validate_qmp_binding
from kvm_reference_host import check_sample as check_host
from canonical_reference_host import MAX_GAP_NS, MAX_HOST_SAMPLES, MAX_HOST_LOG_BYTES, MAX_SAMPLE_BYTES
from canonical_reference_events import parse as parse_events, bind as bind_event
from canonical_reference_observer import (check_sample as check_guest, MAX_SAMPLES as MAX_GUEST_SAMPLES,
    MAX_LOG_BYTES as MAX_GUEST_LOG_BYTES)
from kvm_reference_common import METHOD as INNER_METHOD, STAGES, strict_json
from kvm_pilot_guest import network_down
from feasibility_profile import exact
import reference_measurement_barrier as barrier
import reference_allocation as original_allocation

require = protocol.require
digest = lambda raw: hashlib.sha256(raw).hexdigest()
MAX_SUPPORT = 256 * 1024


def recorded_members(sample, *, command, port, qemu_pid):
    members = sample.get('actual_qemu_task_ids')
    require(type(members) is list and 0 < len(members) <= 256
        and all(protocol.integer(value) for value in members) and members == sorted(set(members)),
        'original actually observed QEMU task membership required; never derive it from QMP')
    validate_qmp_binding(command, port, sample, qemu_pid, set(members))


def validate_reservation(reservation, prerequisites, terminal, owner_receipt, *, deadline):
    """Bind each included host reservation original to the enclosing owner PID."""
    files = OriginalRecords(reservation, deadline); required = {'claim-created.json', 'request.json.raw',
        'qmp-observation-before-membership.json', 'qmp-and-resource-inspection.json',
        'original-launch-inspection.json', 'positive-reservation.json', 'grant.json.raw', 'reservation-result.json'}
    names = set()
    for item in files.root.iterdir():
        files.remaining(); require(len(names) < 32 and item.is_file() and not item.is_symlink(), 'bounded original reservation file set required')
        names.add(item.name)
    require(names == required, 'original reservation file set is missing, extra or failed')
    request_raw = files.raw('request.json.raw', protocol.FRAME_LIMIT)
    grant_raw = files.raw('grant.json.raw', protocol.FRAME_LIMIT)
    request, grant = protocol.decode(request_raw), protocol.decode(grant_raw)
    commit = terminal['plan']['commit']; source = terminal['plan']['source_sha256']
    protocol.validate_request(request, commit=commit, source_sha256=source); protocol.validate_grant(grant, request)
    authority = grant['authority']; controller, qemu = authority['controller'], authority['qemu']
    process, vm, prepared = (prerequisites[key] for key in ('process', 'vm', 'prepared'))
    require(type(owner_receipt.get('process_cleanup')) is dict
        and type(owner_receipt['process_cleanup'].get('owned_root_pid')) is int
        and controller['pid'] == owner_receipt['process_cleanup']['owned_root_pid']
        and qemu['pid'] == process['pid'] and qemu['uid'] == prepared['qemu_run_as_uid']
        and qemu['executable_sha256'] == prepared['qemu_sha256']
        and qemu['command_sha256'] == digest(b'\0'.join(os.fsencode(item) for item in process['command']) + b'\0')
        and authority['operator'] == 'scoped workflow root controller ' + str(controller['run_id']) + '/' + str(controller['run_attempt']),
        'original reservation controller/PID/UID/command/executable differs from enclosing recorded execution')
    launch = files.document('original-launch-inspection.json', MAX_SUPPORT)
    require(digest(files.raw('original-launch-inspection.json', MAX_SUPPORT)) == authority['launch_sha256']
        and launch.get('method') == protocol.METHOD and launch.get('commit') == commit
        and launch.get('source_sha256') == source and launch.get('controller') == controller and launch.get('qemu') == qemu
        and launch.get('command') == process['command']
        and launch.get('vm_started_monotonic_ns') == vm['started_monotonic_ns'] == grant['host_vm_started_monotonic_ns']
        and launch.get('vm_deadline_monotonic_ns') == vm['deadline_monotonic_ns'] == grant['host_vm_deadline_monotonic_ns'],
        'original host launch/parent/source/lease differs from prior grant')
    sample = files.document('qmp-and-resource-inspection.json', MAX_SUPPORT)
    require(digest(files.raw('qmp-and-resource-inspection.json', MAX_SUPPORT)) == authority['qmp_sha256']
        and {key: value for key, value in sample.items() if key != 'actual_qemu_task_ids'}
            == files.document('qmp-observation-before-membership.json', MAX_SUPPORT), 'original QMP/membership snapshots differ')
    recorded_members(sample, command=process['command'], port=prepared['qmp_port'], qemu_pid=process['pid'])
    check_host(sample, qemu['uid'])
    claim = files.document('claim-created.json', MAX_SUPPORT)
    require(claim.get('method') == protocol.METHOD and claim.get('status') == 'RESERVED ONE CAMPAIGN SLOT'
        and claim.get('commit') == commit and claim.get('source_sha256') == source and claim.get('controller') == controller
        and claim.get('qemu') == qemu and claim.get('allocation_id') == grant['allocation_id']
        and claim.get('scope') == protocol.PHYSICAL_SCOPE and claim.get('reference_qualified') is False,
        'original exclusive controller claim differs')
    positive = files.document('positive-reservation.json', MAX_SUPPORT)
    require(digest(files.raw('positive-reservation.json', MAX_SUPPORT)) == authority['reservation_sha256']
        and positive.get('method') == protocol.METHOD and positive.get('status') == 'ALLOCATED TO ONE CANONICAL CAMPAIGN'
        and all(positive.get(key) == authority[key] for key in ('commit', 'source_sha256', 'boot_id', 'nonce', 'controller',
            'qemu', 'reserved_monotonic_ns', 'dedication', 'physical_scope'))
        and positive.get('allocation_id') == grant['allocation_id'] and positive.get('reference_qualified') is False
        and positive.get('claim_created_sha256') == digest(files.raw('claim-created.json', MAX_SUPPORT)),
        'original positive reservation differs from hash-bound claim and grant')
    slot = '.local-runs/canonical-reservations/vm-' + str(qemu['pid']) + '-' + str(qemu['start_ticks'])
    result = files.document('reservation-result.json', MAX_SUPPORT)
    require(result.get('method') == protocol.METHOD and result.get('status') == 'PRIOR GUEST ASSIGNMENT GRANTED'
        and result.get('grant_sha256') == digest(grant_raw) and result.get('slot') == slot
        and result.get('reference_qualified') is False, 'original completed prior reservation result differs')
    channel = prerequisites['recovered'].document('channel/channel-result.json', MAX_SUPPORT)
    require(channel == vm.get('channel') and channel.get('status') == 'VERIFIED HOST BYTES'
        and channel.get('method') == protocol.METHOD and channel.get('commit') == commit
        and channel.get('source_sha256') == source and channel.get('grant_sha256') == digest(grant_raw)
        and channel.get('request_sha256') == digest(request_raw) and channel.get('reservation_slot') == slot
        and channel.get('vm_started_monotonic_ns') == vm['started_monotonic_ns']
        and channel.get('vm_deadline_monotonic_ns') == vm['deadline_monotonic_ns'], 'original host transport/grant/source differs')
    require(prerequisites['recovered'].raw('channel/request-wire.raw', protocol.FRAME_LIMIT + 1) == request_raw + b'\n',
        'original incoming host request framing differs from retained allocation request')
    clocks = [claim.get('monotonic_ns'), sample.get('monotonic_ns'), launch.get('observed_monotonic_ns'),
        authority['reserved_monotonic_ns'], grant['host_issued_monotonic_ns'], result.get('completed_monotonic_ns'),
        channel.get('grant_sent_monotonic_ns')]
    require(all(protocol.integer(value) for value in clocks) and clocks == sorted(clocks)
        and vm['started_monotonic_ns'] <= clocks[0] <= clocks[-1] < vm['deadline_monotonic_ns'],
        'original reservation/request/inspection/grant clocks are reversed or outside original lease')
    receiver_raw = prerequisites['recovered'].raw('channel/capture-receiver-result.json', 65536)
    receiver = prerequisites['recovered'].document('channel/capture-receiver-result.json', 65536)
    peer = receiver.get('peer')
    require(receiver == channel.get('receiver_result') and digest(receiver_raw) == channel.get('receiver_result_sha256')
        and receiver.get('status') == 'VERIFIED HOST BYTES' and receiver.get('method') == protocol.METHOD
        and receiver.get('controller_pid') == controller['pid'] and receiver.get('grant_sha256') == digest(grant_raw)
        and type(peer) is dict and set(peer) == {'pid', 'uid', 'gid'} and type(peer['pid']) is int and peer['pid'] == qemu['pid']
        and all(type(peer[key]) is int and peer[key] >= 0 for key in ('uid', 'gid')),
        'original inherited capture socket belongs to another controller/QEMU peer')
    # The original receiver binds the peer PID. Its observed socket UID/GID
    # remain recorded facts, separate from the live child's inspected UID.
    require(type(channel.get('receiver_exit_observed')) is int and channel['receiver_exit_observed'] == 0
        and all(protocol.integer(receiver.get(key)) for key in ('started_monotonic_ns', 'finished_monotonic_ns'))
        and clocks[-1] <= receiver['started_monotonic_ns'] < receiver['finished_monotonic_ns'] < vm['deadline_monotonic_ns'],
        'original capture receiver exit/lease interval differs')
    files.unchanged()
    return {'status': 'CHECKED ORIGINAL PRIOR GUEST RESERVATION', 'request': request, 'grant': grant,
        'request_raw': request_raw, 'grant_raw': grant_raw, 'slot': slot, 'files': files, 'receiver': receiver,
        'reference_qualified': False,
        'scope': 'Recorded scoped root-controller action, original owner/child identity, reservation hashes and inherited peer checked; independent review and resource/all-record qualification remain separate.'}


def validate_guest_allocation(prerequisites, reservation):
    recovered = prerequisites['recovered']; request, grant = reservation['request'], reservation['grant']
    request_raw, grant_raw = reservation['request_raw'], reservation['grant_raw']; owner = prerequisites['owner']
    def raw(tree, path, limit=65536): return recovered.raw(recovered.members[tree][path], limit)
    require(raw('allocation', 'request.json.raw', protocol.FRAME_LIMIT) == request_raw
        and raw('allocation', 'supporting-grant.json.raw', protocol.FRAME_LIMIT) == grant_raw
        and raw('start', 'request.json.raw', protocol.FRAME_LIMIT) == request_raw
        and raw('start', 'grant.json.raw', protocol.FRAME_LIMIT) == grant_raw
        and raw('start', 'request-wire.raw', protocol.FRAME_LIMIT + 1) == request_raw + b'\n'
        and raw('start', 'grant-wire.raw', protocol.FRAME_LIMIT + 1) == grant_raw + b'\n',
        'actual guest prior allocation/transport originals differ from controller grant')
    exchange = recovered.tree_document('start', 'exchange-result.json')
    require(exchange.get('status') == 'RECEIVED SUPPORTING GRANT' and exchange.get('method') == protocol.METHOD
        and exchange.get('request_sha256') == digest(request_raw) and exchange.get('grant_sha256') == digest(grant_raw)
        and exchange.get('guest_pre_send_monotonic_ns') == request['guest_pre_send_monotonic_ns']
        and exchange.get('allocation_id') == grant['allocation_id'] and exchange.get('reference_qualified') is False
        and type(exchange.get('request_wire_bytes')) is int and exchange['request_wire_bytes'] == len(request_raw) + 1
        and type(exchange.get('grant_wire_bytes')) is int and exchange['grant_wire_bytes'] == len(grant_raw) + 1,
        'original guest request/grant exchange is incomplete or substituted')
    document_raw = raw('allocation', 'operator-document.json'); document = recovered.tree_document('allocation', 'operator-document.json')
    receipt_raw = raw('allocation', 'reference-host-receipt.json'); receipt = recovered.tree_document('allocation', 'reference-host-receipt.json')
    require(type(receipt) is dict and set(receipt) == original_allocation.RECEIPT_FIELDS
        and receipt['operator_document_sha256'] == digest(document_raw) and receipt['allocation_evidence_sha256'] == digest(grant_raw)
        and type(receipt['allocation_evidence_bytes']) is int and receipt['allocation_evidence_bytes'] == len(grant_raw)
        and receipt['inputs_and_source_stable'] is True and receipt['operator_allocation'] == document,
        'original unchanged sixteen-field preflight receipt/raw evidence differs')
    cutoff = protocol.guest_deadline(grant, request, received_ns=exchange['received_monotonic_ns'],
        configured_ns=document.get('inspected_monotonic_ns'), tail_ns=prerequisites['seed']['tail_seconds'] * 10**9)
    identity = {'commit': grant['commit'], 'source_sha256': grant['source_sha256']}
    expected = original_allocation.validate(document, receipt['actual_environment'], identity,
        request['boot_id'], receipt['preflight_monotonic_ns'], digest(grant_raw))
    require(all(type(receipt[key]) is type(value) and receipt[key] == value for key, value in expected.items())
        and document['operator'] == grant['authority']['operator'] and document['allocation_id'] == grant['allocation_id']
        and document['expires_monotonic_ns'] == cutoff == owner['cutoff_monotonic_ns']
        and request['environment'] == {key: receipt['actual_environment'][key] for key in protocol.ENV_KEYS}
        and request['boot_id'] == prerequisites['footer']['boot_id']
        and owner.get('allocation_sha256') == digest(grant_raw) and owner.get('allocation_receipt_sha256') == digest(receipt_raw),
        'original actual allocation preflight/source/boot/operator/lease differs from prior grant')
    clocks = [request['guest_pre_send_monotonic_ns'], exchange['received_monotonic_ns'], exchange.get('finished_monotonic_ns'),
        document['inspected_monotonic_ns'], receipt['preflight_monotonic_ns'], owner['started_monotonic_ns']]
    require(all(protocol.integer(value) for value in clocks) and clocks == sorted(clocks)
        and prerequisites['setup']['finished_monotonic_ns'] <= clocks[0] < clocks[-1] < cutoff
        and protocol.integer(exchange.get('exchange_deadline_monotonic_ns'))
        and exchange['received_monotonic_ns'] <= exchange['exchange_deadline_monotonic_ns']
            <= min(prerequisites['setup']['deadline_monotonic_ns'], clocks[0] + 30_010_000_000),
        'original guest allocation preflight was not prior to canonical execution or reset its handshake budget')
    return {'status': 'CHECKED ORIGINAL GUEST ALLOCATION', 'receipt': receipt, 'receipt_sha256': digest(receipt_raw),
        'cutoff_monotonic_ns': cutoff, 'reference_qualified': False}


def json_records(records, name, *, max_count, max_bytes, line_bytes=MAX_SAMPLE_BYTES):
    """Stream original lines and verify the complete held file before returning."""
    records.remaining(); path = records.path(name); before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= max_bytes, 'bounded nonempty original observation stream required')
    identity = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns)
    hasher = hashlib.sha256(); count = total = 0
    with path.open('rb') as stream:
        require(identity(os.fstat(stream.fileno())) == identity(before), 'observation descriptor changed before reading')
        while line := stream.readline(line_bytes + 1):
            records.remaining(); count += 1; total += len(line)
            require(count <= max_count and len(line) <= line_bytes and line.endswith(b'\n') and total <= before.st_size,
                'original observation count/line/byte bound exceeded')
            hasher.update(line); row = strict_json(line)
            require(type(row) is dict, 'original observation object required'); yield row
        require(identity(os.fstat(stream.fileno())) == identity(before), 'observation descriptor changed during reading')
    value = (total, hasher.hexdigest())
    require(count > 0 and total == before.st_size and identity(path.lstat()) == identity(before)
        and (name not in records.identities or records.identities[name] == value), 'original complete observation stream changed')
    records.identities[name] = value; records.remaining()


def validate_controls(prerequisites, reservation):
    """Use the unchanged inner request/armed/start/end protocol for all stages."""
    recovered, owner = prerequisites['recovered'], prerequisites['owner']
    config_raw = recovered.raw(recovered.members['owner']['measurement-config.json'], 8192)
    export_raw = recovered.raw(recovered.members['owner']['export-config.json'], 8192)
    import canonical_reference_config_handoff as config_handoff
    access_raw = recovered.raw(recovered.members['owner']['configuration-access.json'], 65536)
    require(protocol.hex_value(owner.get('configuration_access_sha256'), 64)
        and digest(access_raw) == owner['configuration_access_sha256'],
        'original root owner configuration access record binding differs')
    access = strict_json(access_raw)
    config_handoff.validate_record(access,
        {'measurement-config.json': config_raw, 'export-config.json': export_raw})
    config, export = strict_json(config_raw), strict_json(export_raw)
    fields = {'schema_version', 'method', 'commit', 'source_sha256', 'boot_id', 'session', 'control_root',
        'deadline_monotonic_ns', 'handshake_seconds', 'reference_qualified'}
    grant = reservation['grant']; fixed = {key: grant[key] for key in ('commit', 'source_sha256', 'boot_id')}
    require(type(config) is dict and set(config) == fields and type(config['schema_version']) is int and config['schema_version'] == 1
        and config['method'] == INNER_METHOD and config['reference_qualified'] is False
        and all(type(config[key]) is type(value) and config[key] == value for key, value in fixed.items())
        and protocol.hex_value(config['session'], 32) and config['control_root'] == '/work/c/.local-runs/kvm-reference/control'
        and type(config['deadline_monotonic_ns']) is int and config['deadline_monotonic_ns'] == owner['cutoff_monotonic_ns']
        and type(config['handshake_seconds']) is int and config['handshake_seconds'] == 30,
        'original complete canonical inner measurement configuration differs')
    require(type(export) is dict and set(export) == {'schema_version', 'method', 'commit', 'source_sha256', 'transfer_seconds', 'deadline_monotonic_ns'}
        and type(export['schema_version']) is int and export['schema_version'] == 1 and export['method'] == INNER_METHOD
        and export['commit'] == grant['commit'] and export['source_sha256'] == grant['source_sha256']
        and type(export['deadline_monotonic_ns']) is int and export['deadline_monotonic_ns'] == owner['cutoff_monotonic_ns']
        and type(export['transfer_seconds']) is int and export['transfer_seconds'] == 180,
        'original complete canonical export configuration differs')
    wanted = {stage + '-' + position + '.json' for stage in STAGES for position in ('request', 'armed', 'start', 'end')}
    require(set(recovered.members['control']) == wanted, 'all twelve original inner control records required')
    events = parse_events(prerequisites['serial'])
    require(events == prerequisites['vm']['events'] and [row['phase'] for row in events] == ['prefix-start', 'ready', 'attempt-end']
        and events[-1]['status'] == 'PASS', 'original canonical serial lifecycle is incomplete or substituted')
    for event in events: bind_event(event, grant)
    require(owner['canonical_started_monotonic_ns'] <= events[0]['monotonic_ns'] < events[-1]['monotonic_ns']
        and owner['finished_monotonic_ns'] <= events[-1]['monotonic_ns'] < owner['cutoff_monotonic_ns'],
        'original canonical lifecycle and owner clocks differ')
    boundaries = {}; requests = {}; acknowledgements = {}; previous = events[0]['monotonic_ns']
    for stage in STAGES:
        request_raw = recovered.raw(recovered.members['control'][stage + '-request.json'], barrier.MAX_RECORD)
        request = strict_json(request_raw)
        expected = {key: config[key] for key in ('schema_version', 'method', 'session', 'commit', 'source_sha256', 'boot_id', 'reference_qualified')}
        expected.update(stage=stage, config_sha256=digest(config_raw))
        require(type(request) is dict and set(request) == barrier.REQUEST_KEYS
            and all(exact(request.get(key), value) for key, value in expected.items())
            and all(protocol.integer(request.get(key)) for key in ('utc_ns', 'monotonic_ns'))
            and previous < request['monotonic_ns'], 'original inner request source/order differs')
        ack = recovered.tree_document('control', stage + '-armed.json', barrier.MAX_RECORD)
        require(set(ack) == barrier.REQUEST_KEYS | {'status', 'request_sha256'} and ack['status'] == 'ARMED'
            and all(exact(ack.get(key), value) for key, value in expected.items()) and ack['request_sha256'] == digest(request_raw)
            and all(protocol.integer(ack.get(key)) for key in ('utc_ns', 'monotonic_ns'))
            and request['monotonic_ns'] <= ack['monotonic_ns'] <= request['monotonic_ns'] + config['handshake_seconds'] * 10**9,
            'original inner ARMED bytes/hash/clock differs')
        for position in ('start', 'end'):
            row = recovered.tree_document('control', stage + '-' + position + '.json', barrier.MAX_RECORD)
            require(all(exact(row.get(key), value) for key, value in request.items()) and row.get('position') == position
                and row.get('status') == 'OBSERVED' and exact(row.get('collection_exit_code'), None if position == 'start' else 0)
                and 'collection_error' not in row and 'error' not in row and type(row.get('sample')) is dict
                and all(type(row.get(key)) is int and row[key] >= 0 for key in ('observer_wall_ns', 'observer_cpu_ns')),
                'original inner measurement boundary failed or differs')
            network_down(row['network']); require(row['sample']['boot_id'] == config['boot_id'], 'original boundary guest boot changed')
            boundaries[stage + '-' + position] = row
        begin, end = (boundaries[stage + '-' + position]['sample'].get('monotonic_ns') for position in ('start', 'end'))
        require(protocol.integer(begin) and protocol.integer(end) and ack['monotonic_ns'] <= begin < end < owner['cutoff_monotonic_ns']
            and end <= owner['canonical_finished_monotonic_ns'], 'original measured stage exceeded canonical interval/lease')
        previous = end; requests[stage] = request; acknowledgements[stage] = ack
        if stage == 'grid':
            ready = events[1]
            require(ready['config_sha256'] == digest(config_raw) and ready['request_sha256'] == digest(request_raw)
                and request['monotonic_ns'] <= ready['monotonic_ns'] <= ack['monotonic_ns'], 'original ready event belongs to another request')
    coordination = owner.get('coordination')
    require(type(coordination) is dict and coordination.get('status') == 'OBSERVED' and coordination.get('method') == protocol.METHOD
        and coordination.get('inner_measurement_method') == INNER_METHOD and coordination.get('armed_stages') == list(STAGES)
        and coordination.get('missing_stages') == [] and coordination.get('error') is None
        and coordination.get('allocation_receipt_sha256') == owner['allocation_receipt_sha256'], 'original guest coordination did not finish')
    network_down(coordination['network_after'])
    return {'status': 'CHECKED ORIGINAL MEASUREMENT CONTROLS', 'config': config, 'config_sha256': digest(config_raw),
        'export_sha256': digest(export_raw), 'configuration_access': access,
        'events': events, 'boundaries': boundaries, 'requests': requests,
        'acknowledgements': acknowledgements, 'coordination': coordination, 'reference_qualified': False}


def nonnegative(value): return type(value) is int and value >= 0


def validate_resources(prerequisites, reservation, allocation, controls):
    recovered, vm, owner = (prerequisites[key] for key in ('recovered', 'vm', 'owner'))
    grant = reservation['grant']; qemu = grant['authority']['qemu']
    received = list(json_records(recovered, 'received-events.jsonl', max_count=3, max_bytes=3 * 65536, line_bytes=65536))
    require(len(received) == 3 and [row.get('guest') for row in received] == controls['events']
        and all(set(row) == {'received_utc_ns', 'received_monotonic_ns', 'guest'} and
            all(protocol.integer(row.get(key)) for key in ('received_utc_ns', 'received_monotonic_ns')) for row in received),
        'complete original host reception of canonical events required')
    received_times = [row['received_monotonic_ns'] for row in received]
    require(received_times == sorted(set(received_times)) and grant['host_issued_monotonic_ns'] <= received_times[0]
        < received_times[-1] < vm['qemu_exit_observed_monotonic_ns']
        and received_times == [vm.get(key) for key in ('prefix_received_monotonic_ns', 'ready_received_monotonic_ns', 'end_received_monotonic_ns')],
        'original received event clocks/source/VM interval differs')
    link = recovered.document('host-link-down.json', 65536)
    require(set(link) == {'requested_monotonic_ns', 'response', 'finished_monotonic_ns', 'grant_sha256'}
        and protocol.integer(link['requested_monotonic_ns']) and protocol.integer(link['finished_monotonic_ns'])
        and type(link['response']) is dict and link['response'].get('return') == {} and 'error' not in link['response']
        and link['grant_sha256'] == digest(reservation['grant_raw'])
        and received_times[1] <= link['requested_monotonic_ns'] <= link['finished_monotonic_ns'] < received_times[-1],
        'original actual host NIC link-down ACK/grant/interval differs')
    first_required = last_required = previous = None; required_closed = False; host_count = required_count = 0; host_gap = 0
    for row in json_records(recovered, 'host-samples.jsonl', max_count=MAX_HOST_SAMPLES, max_bytes=MAX_HOST_LOG_BYTES):
        host_count += 1; now = row.get('monotonic_ns')
        require(protocol.integer(now) and vm['started_monotonic_ns'] <= now < vm['qemu_exit_observed_monotonic_ns']
            and (previous is None or previous < now) and row.get('method') == protocol.METHOD
            and type(row.get('required_interval')) is bool
            and all(nonnegative(row.get(key)) for key in ('observer_wall_ns', 'observer_cpu_ns')),
            'original host observation clock/phase/cost is missing or reversed')
        previous = now
        if not row['required_interval']:
            if first_required is not None: required_closed = True
            continue
        require(not required_closed and row.get('observation_status') == 'OBSERVED', 'required host observations were filtered or failed')
        check_host(row, qemu['uid'])
        recorded_members(row, command=prerequisites['process']['command'], port=prerequisites['prepared']['qmp_port'], qemu_pid=qemu['pid'])
        affinity = row.get('qemu_affinity')
        require(type(affinity) is list and len(affinity) == 4 and all(nonnegative(value) for value in affinity)
            and affinity == sorted(set(affinity)) and all(thread['affinity'] == affinity for thread in row['vcpu_threads'])
            and type(row.get('clock_source')) is str and 0 < len(row['clock_source']) <= 128
            and type(row.get('clock_properties')) is str and len(row['clock_properties']) <= 4096
            and 'monotonic=True' in row['clock_properties'] and 'adjustable=False' in row['clock_properties'],
            'original full QEMU affinity or stable host monotonic clock differs')
        if first_required is None: first_required = now
        if last_required is not None:
            gap = now - last_required; require(0 < gap <= MAX_GAP_NS, 'required original host sample gap exceeded'); host_gap = max(host_gap, gap)
        last_required = now; required_count += 1
    require(first_required is not None and 0 <= first_required - received_times[0] <= MAX_GAP_NS
        and first_required <= received_times[1] <= link['requested_monotonic_ns']
        and received_times[-1] <= last_required and last_required - received_times[-1] <= MAX_GAP_NS
        and type(vm.get('host_samples')) is int and vm['host_samples'] == host_count,
        'original host samples do not cover canonical prefix/measurement/end')
    cost = vm.get('host_append_cost')
    require(type(cost) is dict and set(cost) == {'calls', 'wall_ns', 'cpu_ns'} and type(cost['calls']) is int
        and cost['calls'] == host_count and nonnegative(cost['wall_ns']) and nonnegative(cost['cpu_ns'])
        and nonnegative(vm.get('host_final_fsync_ns')), 'original host append/fsync observations incomplete')
    error_path = recovered.path('host-observation-errors.jsonl')
    if error_path.exists():
        for error in json_records(recovered, 'host-observation-errors.jsonl', max_count=MAX_HOST_SAMPLES, max_bytes=MAX_HOST_LOG_BYTES):
            require(error.get('required_interval') is not True, 'original required host observation error remains')
    first_guest = previous_guest = None; first_measured = None; guest_count = 0; guest_gap = 0; final_sampled = False
    guest_name = recovered.members['observer']['canonical-guest-samples.jsonl']
    for row in json_records(recovered, guest_name, max_count=MAX_GUEST_SAMPLES, max_bytes=MAX_GUEST_LOG_BYTES):
        guest_count += 1
        require(not final_sampled and row.get('method') == protocol.METHOD and row.get('reference_qualified') is False
            and row.get('observation_status') == 'OBSERVED' and row.get('sample_kind') in ('interval', 'final')
            and row.get('phase') in ('prefix', 'measurement')
            and all(nonnegative(row.get(key)) for key in ('observer_wall_ns', 'observer_cpu_ns')),
            'original guest observation failed, changed phase or omitted final endpoint')
        measured = row['phase'] == 'measurement'
        require(first_measured is None or measured, 'original guest measured observation phase reversed')
        check_guest(row, boot_id=grant['boot_id'], previous=previous_guest, first=first_guest, measured=measured)
        require(request_environment_equal(row['environment'], reservation['request']['environment'])
            and owner['started_monotonic_ns'] <= row['monotonic_ns'] < owner['cutoff_monotonic_ns']
            and (previous_guest is None or previous_guest['utc_ns'] <= row['utc_ns'])
            and type(row.get('swaps')) is str and len(row['swaps']) <= 65536
            and re.fullmatch(r'Filename\s+Type\s+Size\s+Used\s+Priority\s*', row['swaps']) is not None,
            'original guest allocation/clock/swap configuration changed')
        if first_guest is None:
            require(not measured and row['sample_kind'] == 'interval', 'actual original prefix observation required before measurement')
            first_guest = row
        if previous_guest is not None: guest_gap = max(guest_gap, row['monotonic_ns'] - previous_guest['monotonic_ns'])
        if measured and first_measured is None: first_measured = row['monotonic_ns']
        previous_guest = row; final_sampled = row['sample_kind'] == 'final'
    observed = controls['coordination'].get('sampler')
    require(first_guest is not None and final_sampled and first_measured is not None
        and first_guest['monotonic_ns'] <= owner['canonical_started_monotonic_ns']
        and previous_guest['monotonic_ns'] >= owner['canonical_finished_monotonic_ns']
        and previous_guest['monotonic_ns'] <= owner['finished_monotonic_ns']
        and first_measured <= controls['acknowledgements']['grid']['monotonic_ns'],
        'original guest sample endpoints do not bracket complete canonical recipe and measured start')
    require(type(observed) is dict and observed.get('status') == 'OBSERVED' and observed.get('method') == protocol.METHOD
        and observed.get('boot_id') == grant['boot_id'] and observed.get('error') is None
        and observed.get('final_sampled') is True and observed.get('measurement_armed') is True
        and observed.get('measurement_sample_observed') is True
        and all(type(observed.get(key)) is int and observed[key] == value for key, value in {
            'observations': guest_count, 'first_monotonic_ns': first_guest['monotonic_ns'], 'last_monotonic_ns': previous_guest['monotonic_ns'],
            'maximum_gap_ns': guest_gap, 'gap_bound_ns': MAX_GAP_NS, 'append_calls_completed': guest_count,
            'sample_cap': MAX_GUEST_SAMPLES, 'record_byte_cap': MAX_SAMPLE_BYTES, 'log_byte_cap': MAX_GUEST_LOG_BYTES}.items())
        and all(nonnegative(observed.get(key)) for key in ('append_wall_total_ns', 'append_cpu_total_ns', 'final_fsync_ns')),
        'original guest sampled coordination/count/gap/cost summary differs')
    for name, boundary in controls['boundaries'].items():
        sample = boundary['sample']
        # Both fields come from this same original boundary record; no live or
        # synthetic sample, payload, clock epoch or observation is substituted.
        check_guest({**sample, 'network': boundary['network']}, boot_id=grant['boot_id'], first=first_guest, measured=True)
        require(request_environment_equal(sample['environment'], reservation['request']['environment'])
            and first_measured <= sample['monotonic_ns'] <= previous_guest['monotonic_ns'],
            'original measured boundary differs from actual sampled allocation interval')
    require(allocation['cutoff_monotonic_ns'] == owner['cutoff_monotonic_ns'], 'original guest lease changed during continuity replay')
    recovered.unchanged()
    return {'status': 'CHECKED ORIGINAL SAMPLED CONTINUITY', 'host_samples': host_count, 'required_host_samples': required_count,
        'maximum_required_host_gap_ns': host_gap, 'host_append_cost': cost, 'host_final_fsync_ns': vm['host_final_fsync_ns'],
        'guest_samples': guest_count, 'maximum_guest_gap_ns': guest_gap, 'guest_append_and_fsync': observed,
        'reference_qualified': False,
        'scope': 'Original sampled prefix/three-stage/final allocation, clock, swap and network continuity and observer costs only; uninterrupted residency and physical exclusivity are not established.'}


def request_environment_equal(actual, expected):
    return type(actual) is dict and all(key in actual and type(actual[key]) is type(expected[key])
        and actual[key] == expected[key] for key in protocol.ENV_KEYS)
