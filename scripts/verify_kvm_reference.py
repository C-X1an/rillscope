"""Inspect original full captures and every record; execute no product query.

Passing this command establishes included byte/outcome/provenance and sampled
conditions only. Independent review must decide virtual reference eligibility;
neither this collector nor an ACK establishes canonical fresh reproduction.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import archive_capture
from evidence import source_identity
from kvm_pilot_common import require, write_json, sha
from kvm_reference_common import METHOD, STAGES, SEEDS, strict_json, validate_scope
from kvm_reference_channel import inspected_manifest, header
from kvm_reference_events import parse as parse_events, MAX_EVENTS
from kvm_reference_host import check_sample, parse_boot
from kvm_reference_budget import (MAX_HOST_SAMPLES, MAX_GUEST_SAMPLES, MAX_SAMPLE_BYTES,
    MAX_HOST_LOG_BYTES, MAX_GUEST_LOG_BYTES, MAX_GAP_NS, declaration)
from verify_kvm_pilot import passing_receipt, recovered_tree, sampling, down
from verify import verify
from cancellation import verify_cancellation
from feasibility_profile import exact
from reference_guest_observer import GuestObserver
import reference_measurement_barrier as barrier
import kvm_reference_device as capture_device

COUNTS = {'grid': (410, 43050), 'cancel': (5, 175), 'sort-null': (40, 4200)}
# A genuine410-case report exceeds4MiB. Results were already inspected under
# the archive's finite per-file limit; use that same limit only for results.
# Payloads, owner/control records and other metadata keep their smaller bounds.
MAX_RESULTS_BYTES = archive_capture.MAX_FILE


def read_json(path, limit=4 * 1024**2):
    value = strict_json(barrier.bounded(path, limit))
    require(type(value) is dict, 'bounded original metadata object required')
    return value


def read_results(path):
    return read_json(path, MAX_RESULTS_BYTES)


def json_lines(path, count, byte_limit, line_limit=MAX_SAMPLE_BYTES):
    rows = []; size = 0
    with path.open('rb') as stream:
        while line := stream.readline(line_limit + 1):
            size += len(line)
            require(len(line) <= line_limit and size <= byte_limit and line.endswith(b'\n') and len(rows) < count,
                    'full observation byte/line/count bound exceeded')
            row = strict_json(line); require(type(row) is dict, 'full observation object required'); rows.append(row)
    require(rows, 'full observations missing'); return rows


def completed_scope(stage, manifest, result, payload):
    validate_scope(manifest, stage, commit=payload['commit'], source_sha256=payload['source']['sha256'])
    if stage == 'cancel':
        expected = {'status': 'PASS', 'observations': 175, 'measured_observations': 150,
            'invalid_observations': 0, 'source_binary_input_identity_stable': True}
    else:
        expected = {'schema_version': 3, 'profile': 'full' if stage == 'grid' else 'sort-null-supplement',
            'completed_cases': COUNTS[stage][0], 'expected_cases': COUNTS[stage][0], 'complete_grid': stage == 'grid',
            'instrumentation_status': 'PASS', 'invalid_observations': 0, 'source_binary_inputs_stable': True}
    require(all(exact(result.get(key), value) for key, value in expected.items()),
            'original full result incomplete, invalid or reduced')


def filter_targets(grid):
    chosen = [row for row in grid['summaries'] if row['workload']['id'] == 'B01-n100000-s10-null10-b1024']
    require(len(chosen) == 5 and sorted(row['seed'] for row in chosen) == SEEDS,
            'all five unique reference target seeds required')
    targets = []
    for row in sorted(chosen, key=lambda item: item['seed']):
        measured = row['metrics']['rust-on']; latency = measured['success_only_execution_ns']
        end_to_end = measured['all_outcome_metrics']['wall_ns']
        require(latency.get('n') == 30 and end_to_end.get('n') == 30
            and row.get('independent_semantic_comparisons') == 60
            and type(latency.get('p95')) is int and latency['p95'] >= 0,
            'complete independently checked30-repetition target distribution required')
        targets.append({'seed': row['seed'], 'execution_ns': latency, 'end_to_end_ns': end_to_end,
            'independent_semantic_comparisons': row['independent_semantic_comparisons'],
            'observed_target_status': 'MET' if latency['p95'] < 1_000_000_000 else 'MISSED',
            'reference_qualified': False, 'context': 'Observed timing only; virtual reference eligibility awaits independent review'})
    return targets


def cancel_target(result):
    require(result.get('status') == 'PASS' and result.get('observations') == 175
        and result.get('measured_observations') == 150 and result.get('invalid_observations') == 0
        and result['cancel_upper_bound_ns'].get('n') == 150
        and type(result.get('target_observations_over_100ms')) is int
        and 0 <= result['target_observations_over_100ms'] <= 150, 'complete correct cancellation distribution required')
    return {'observed_target_status': 'MET' if result['target_observations_over_100ms'] == 0 else 'MISSED',
        'upper_bound_ns': result['cancel_upper_bound_ns'], 'observations_over_100ms': result['target_observations_over_100ms'],
        'definition': 'All150 measured signal-to-exit upper bounds <=100ms; every miss retained',
        'reference_qualified': False, 'context': 'Observed Linux signal campaign; reference eligibility awaits independent review'}


def native_path(value, root):
    require(isinstance(value, str) and len(value) <= 4096 and '\\' not in value and ':' not in value,
            'closed original Linux command path required')
    path = PurePosixPath(value); require('..' not in path.parts, 'original command path traverses parents')
    return path if path.is_absolute() else root / path


def original_owner(receipt_path, config, payload):
    require(receipt_path.name == 'receipt.json', 'exact original full owner receipt required')
    row = passing_receipt(receipt_path.parent, payload['source'])
    root = PurePosixPath(config['original_root'])
    require(root.is_absolute() and '..' not in root.parts and row['cwd'] == str(root)
        and row['environment']['system'] == 'Linux' and row['git']['commit'] == payload['commit']
        and row['git']['dirty'] is False, 'original full owner source/runtime differs')
    command = row['command']; path = lambda value: native_path(value, root)
    require(len(command) == 10 and path(command[1]) == root / 'scripts/kvm_reference_host.py'
        and command[2::2] == ['--out', '--run-as', '--build-receipt', '--commit']
        and path(command[3]) == path(config['original_output'])
        and path(command[7]) == path(payload['build_receipt']['path']) and command[9] == payload['commit']
        and command[5] == config['command'][config['command'].index('-runas') + 1],
        'original full owner command/output/build association differs')
    require(row.get('inputs_before') == row.get('inputs_after'), 'original full owner inputs changed')
    return {'status': 'PASS', 'receipt_sha256': sha(receipt_path), 'elapsed_seconds': row['elapsed_seconds']}


def input_bindings(row, expected):
    before = row.get('inputs_before'); after = row.get('inputs_after')
    require(type(before) is list and before == after and len(before) == len(expected), 'original full input list changed')
    actual = {}
    for item in before:
        require(type(item) is dict and set(item) == {'path', 'sha256', 'bytes'} and item['path'] not in actual,
                'original full input identity missing or duplicated')
        actual[item['path']] = {'sha256': item['sha256'], 'bytes': item['bytes']}
    require(actual == expected, 'original full input bytes differ from retained source-bound configuration')


def capture_device_access(artifact, payload, guest, owner, first_measurement_ns):
    record = read_json(guest / 'device-access.json', 8192)
    require(set(record) == {'schema_version', 'status', 'commit', 'source_sha256', 'grant', 'probe'}
        and type(record['schema_version']) is int and record['schema_version'] == 1
        and record['status'] == 'VERIFIED' and record['commit'] == payload['commit']
        and record['source_sha256'] == payload['source']['sha256'],
        'original source-bound capture device access proof missing or failed')
    capture_device.validate_access(record['grant'], record['probe'])
    require(type(first_measurement_ns) is int
        and record['probe']['closed_monotonic_ns'] < first_measurement_ns,
        'actual nobody capture device preflight must finish before measurement')
    directory = owner / 'capture-device-open'
    receipt = passing_receipt(directory, payload['source'])
    require(receipt['command'] == ['/usr/bin/setpriv', '--reuid=65534', '--regid=65534',
        '--clear-groups', '--', '/usr/bin/python3', '/work/c/scripts/kvm_reference_device.py', 'probe'],
        'actual capture device probe command or measurement identity differs')
    path = artifact / 'payload.json'
    input_bindings(receipt, {'/work/c/.local-runs/kvm-input/payload.json':
        {'sha256': sha(path), 'bytes': path.stat().st_size}})
    require(read_json(directory / 'stdout.txt', 8192) == record['probe'],
        'original capture device probe stdout differs from retained observation')
    return record


def guest_controls(artifact, payload, guest, events):
    controls = recovered_tree(artifact, 'guest-control', 'control')
    configs = artifact / 'guest-config'
    config_data = barrier.bounded(configs / 'measurement-config.json', 8192)
    config = strict_json(config_data); digest = hashlib.sha256(config_data).hexdigest()
    require(type(config) is dict and set(config) == {'schema_version', 'method', 'commit', 'source_sha256',
        'boot_id', 'session', 'control_root', 'deadline_monotonic_ns', 'handshake_seconds', 'reference_qualified'}
        and type(config['schema_version']) is int and config['schema_version'] == 1 and config['method'] == METHOD
        and config['commit'] == payload['commit'] and config['source_sha256'] == payload['source']['sha256']
        and config['boot_id'] == events[0]['boot_id'] and config['control_root'] == '/work/c/.local-runs/kvm-reference/control'
        and config['reference_qualified'] is False and type(config['deadline_monotonic_ns']) is int
        and type(config['handshake_seconds']) is int and 1 <= config['handshake_seconds'] <= 30
        and isinstance(config['session'], str) and re.fullmatch('[0-9a-f]{32}', config['session']),
        'retained original full measurement configuration differs')
    expected_files = {stage + '-' + position + '.json' for stage in STAGES for position in ['request', 'armed', 'start', 'end']}
    require({path.name for path in controls.iterdir()} == expected_files, 'original full measurement record set incomplete or extra')
    boundaries = {}; previous = None
    for stage in STAGES:
        raw = barrier.bounded(controls / (stage + '-request.json')); request = strict_json(raw)
        fixed = {key: config[key] for key in ['schema_version', 'method', 'session', 'commit', 'source_sha256', 'boot_id', 'reference_qualified']}
        fixed.update(stage=stage, config_sha256=digest)
        require(type(request) is dict and set(request) == barrier.REQUEST_KEYS
            and all(exact(request.get(key), value) for key, value in fixed.items())
            and all(type(request.get(key)) is int and request[key] > 0 for key in ['utc_ns', 'monotonic_ns']),
            'original full stage request differs')
        ack = strict_json(barrier.bounded(controls / (stage + '-armed.json')))
        require(type(ack) is dict and set(ack) == barrier.REQUEST_KEYS | {'status', 'request_sha256'}
            and all(exact(ack.get(key), value) for key, value in fixed.items()) and ack['status'] == 'ARMED'
            and ack['request_sha256'] == hashlib.sha256(raw).hexdigest()
            and all(type(ack.get(key)) is int and ack[key] > 0 for key in ['utc_ns', 'monotonic_ns'])
            and request['monotonic_ns'] <= ack['monotonic_ns'] <= request['monotonic_ns'] + config['handshake_seconds'] * 10**9,
            'original full owner ACK/hash/clock differs')
        if previous is not None: require(request['monotonic_ns'] > previous, 'original full operations overlap or reverse')
        for position in ('start', 'end'):
            row = strict_json(barrier.bounded(controls / (stage + '-' + position + '.json')))
            require(all(exact(row.get(key), value) for key, value in request.items())
                and row.get('position') == position and row.get('status') == 'OBSERVED'
                and exact(row.get('collection_exit_code'), None if position == 'start' else 0)
                and 'collection_error' not in row and 'error' not in row,
                'original full measurement boundary failed or differs')
            down(row['network']); require(row['sample']['boot_id'] == config['boot_id'], 'boundary boot differs')
            require(all(type(row.get(key)) is int and row[key] >= 0 for key in ['observer_wall_ns', 'observer_cpu_ns']),
                    'original measurement observer costs missing')
            boundaries[stage + '-' + position] = row
        begin = boundaries[stage + '-start']['sample']['monotonic_ns']
        end = boundaries[stage + '-end']['sample']['monotonic_ns']
        require(type(begin) is int and type(end) is int and ack['monotonic_ns'] <= begin < end < config['deadline_monotonic_ns'],
                'original full measured clocks do not follow arm or exceed deadline')
        previous = end
        if stage == 'grid':
            ready = next(row for row in events if row['phase'] == 'ready')
            require(ready['config_sha256'] == digest and ready['request_sha256'] == hashlib.sha256(raw).hexdigest()
                and request['monotonic_ns'] <= ready['monotonic_ns'] <= ack['monotonic_ns'], 'ready source/request association differs')
    # Exact retained inputs of both privileged owner and unprivileged original commands.
    expected = {}
    for original_name, path in [('/work/c/.local-runs/kvm-input/payload.json', artifact / 'payload.json'),
        ('/work/c/.local-runs/kvm-reference/measurement-config.json', configs / 'measurement-config.json'),
        ('/work/c/.local-runs/kvm-reference/export-config.json', configs / 'export-config.json')]:
        expected[original_name] = {'sha256': sha(path), 'bytes': path.stat().st_size}
    export = strict_json(barrier.bounded(configs / 'export-config.json', 8192))
    require(set(export) == {'schema_version', 'method', 'commit', 'source_sha256', 'transfer_seconds', 'deadline_monotonic_ns'}
        and type(export['schema_version']) is int and export['schema_version'] == 1 and export['method'] == METHOD
        and export['commit'] == payload['commit'] and export['source_sha256'] == payload['source']['sha256']
        and export['deadline_monotonic_ns'] == config['deadline_monotonic_ns']
        and type(export['transfer_seconds']) is int and export['transfer_seconds'] == 180, 'original export configuration differs')
    owner = recovered_tree(artifact, 'guest-owner', 'setup') / 'commands'
    nested = recovered_tree(artifact, 'guest-command-receipts', 'raw-receipts')
    helpers = recovered_tree(artifact, 'guest-collection-commands', 'commands')
    input_bindings(passing_receipt(owner / 'full-collection', payload['source']), expected)
    for name in ['apt-update', 'apt-install', 'stop-package-services', 'installed-tools', 'gnu-time', 'serial-getty-state']:
        passing_receipt(owner / name, payload['source'])
    require(set((owner / 'serial-getty-state/stdout.txt').read_text(encoding='utf-8').splitlines()) ==
        {'LoadState=masked', 'ActiveState=inactive'}, 'actual full guest console policy differs')
    require(b'RILLTIME ' in (owner / 'gnu-time/stderr.txt').read_bytes(), 'actual full guest GNU time probe missing')
    capture_device_access(artifact, payload, guest, owner,
        boundaries['grid-start']['sample']['monotonic_ns'])
    for stage in STAGES:
        original = passing_receipt(nested / stage, payload['source']); input_bindings(original, expected)
        command = original['command']; root = PurePosixPath('/work/c')
        binary = payload['bins']['rillscope' if stage == 'cancel' else 'rillscope-measure']['path']
        script = 'benchmarks/cancellation.py' if stage == 'cancel' else 'benchmarks/run.py'
        wanted = ['/usr/bin/python3', str(root / script), '--binary', str(root / binary)]
        if stage != 'cancel': wanted += ['--profile', 'full' if stage == 'grid' else 'sort-null-supplement']
        wanted += ['--build-receipt', str(root / payload['build_receipt']['path']), '--out',
                   '/work/c/.local-runs/kvm-reference/raw/' + stage]
        require(command == wanted and original['git']['commit'] == payload['commit']
            and original['git']['dirty'] is False, 'original full campaign command or Git differs')
        passing_receipt(helpers / ('campaign-' + stage), payload['source'])
        passing_receipt(helpers / ('pack-' + stage), payload['source'])
    return boundaries


def continuity(artifact, payload, config, guest):
    vm = read_json(artifact / 'vm-result.json')
    serial = barrier.bounded(artifact / 'serial.txt', 4 * 1024**2).decode('utf-8', errors='replace')
    events = parse_events(serial)
    require(events == vm['events'] and vm['status'] == 'COLLECTED' and vm['final_host_observed'] is True
        and vm['failure'] is None and [row['phase'] for row in events] == ['setup-start', 'setup-end', 'ready', 'guest-exit']
        and events[-1].get('status') == 'COLLECTED', 'original full VM/lifecycle did not complete')
    require(parse_boot(serial) == vm['boot_result'] and vm['boot_result']['worker_exit'] == 0
        and vm['boot_result']['unmount_status'] == 'PASS' and vm['boot_result']['console_errors'] == []
        and 'error' not in vm['boot_result'] and 'retention_error' not in vm['boot_result'], 'original full boot/unmount/console failed')
    guest_result = read_json(guest / 'guest-result.json'); collection = read_json(guest / 'collection-result.json')
    require(guest_result['status'] == 'COLLECTED' and guest_result['cleanup']['status'] == 'PASS'
        and guest_result['collection'] == collection and collection['status'] == 'COLLECTED'
        and collection['cleanup']['status'] == 'PASS'
        and [row['stage'] for row in collection['campaigns']] == list(STAGES)
        and all(row['status'] == 'COLLECTED' and row['package_status'] == 'HOST ACKNOWLEDGED'
                and row['all_record_validation'] == 'NOT RUN' and row['reference_qualified'] is False for row in collection['campaigns']),
        'original full guest command or stage results failed')
    boundaries = guest_controls(artifact, payload, guest, events)
    received = json_lines(artifact / 'received-events.jsonl', MAX_EVENTS, MAX_EVENTS * 65536, 65536)
    require([row['guest'] for row in received] == events
        and all(type(row.get('received_monotonic_ns')) is int and row['received_monotonic_ns'] > 0 for row in received)
        and all(b['received_monotonic_ns'] >= a['received_monotonic_ns'] for a, b in zip(received, received[1:])),
        'actual received full lifecycle differs')
    ready = next(row for row in received if row['guest']['phase'] == 'ready')['received_monotonic_ns']
    exit_at = received[-1]['received_monotonic_ns']
    hosts = json_lines(artifact / 'host-samples.jsonl', MAX_HOST_SAMPLES, MAX_HOST_LOG_BYTES)
    require(len(hosts) == vm['host_samples'], 'retained full host sample count differs')
    required = [row for row in hosts if row.get('required_interval') is True]
    host_summary = sampling(required)
    link = read_json(artifact / 'host-link-down.json')
    require('return' in link['response'] and ready <= required[0]['monotonic_ns'] <= link['requested']['monotonic_ns']
        <= link['finished_monotonic_ns'] < exit_at <= required[-1]['monotonic_ns']
        and required[-1]['monotonic_ns'] - exit_at <= MAX_GAP_NS, 'actual full host observations do not bracket cutover/exit')
    for row in hosts:
        require(type(row.get('required_interval')) is bool and row.get('method') == METHOD,
                'full host interval/method label missing')
        require(row['required_interval'] is (required[0]['monotonic_ns'] <= row['monotonic_ns'] <= required[-1]['monotonic_ns']),
                'full host required interval contains a filtered observation')
    for row in required:
        check_sample(row, config['qemu_run_as_uid'])
        require(row.get('observation_status') == 'OBSERVED', 'failed original full host observation retained')
    require(len({row['qemu_pid'] for row in required}) == 1
        and all(len(row['qemu_affinity']) == 4 for row in required), 'actual full QEMU PID/affinity changed')
    append_cost = vm['host_append_cost']
    require(append_cost['calls'] == len(hosts)
        and all(type(append_cost.get(key)) is int and append_cost[key] >= 0
                for key in ['wall_ns', 'cpu_ns', 'maximum_wall_ns']), 'actual full host append costs incomplete')
    host_summary['append_cost'] = append_cost
    require(type(vm.get('host_final_fsync_ns')) is int and vm['host_final_fsync_ns'] >= 0,
            'actual full host final log fsync was not observed')
    host_summary['final_fsync_ns'] = vm['host_final_fsync_ns']
    error_path = artifact / 'host-observation-errors.jsonl'
    if error_path.is_file():
        errors = json_lines(error_path, MAX_HOST_SAMPLES, MAX_HOST_LOG_BYTES)
        require(not any(row.get('required_interval') is True for row in errors), 'required full host inspection error retained')
    guests = json_lines(guest / 'guest-samples.jsonl', MAX_GUEST_SAMPLES, MAX_GUEST_LOG_BYTES)
    guest_summary = sampling(guests)
    checker = GuestObserver.__new__(GuestObserver); checker.first = None; checker.last = None; checker.maximum_gap_ns = 0
    for index, row in enumerate(guests):
        require(row.get('method') == METHOD and row.get('observation_status') == 'OBSERVED'
            and row.get('sample_kind') == ('final' if index == len(guests) - 1 else 'interval')
            and row['boot_id'] == events[0]['boot_id'], 'original full guest observation failed or final endpoint missing')
        checker.check(row)
        if checker.first is None: checker.first = row
        checker.last = row
    begin = boundaries['grid-start']['sample']['monotonic_ns']; end = boundaries['sort-null-end']['sample']['monotonic_ns']
    require(0 <= begin - guests[0]['monotonic_ns'] <= MAX_GAP_NS and guests[-1]['monotonic_ns'] >= end,
            'full guest samples do not bracket original measured campaigns')
    coord = guest_result['coordination']; observed = coord['sampler']
    require(coord['status'] == 'OBSERVED' and coord['armed_stages'] == list(STAGES) and coord['missing_stages'] == []
        and coord['error'] is None and observed['status'] == 'OBSERVED' and observed['observations'] == len(guests)
        and observed['final_sampled'] is True and observed['error'] is None
        and observed['first_monotonic_ns'] == guests[0]['monotonic_ns']
        and observed['last_monotonic_ns'] == guests[-1]['monotonic_ns']
        and observed['append_calls_completed'] == len(guests) and type(observed['final_fsync_ns']) is int
        and observed['final_fsync_ns'] >= 0, 'actual full sampler coordination/persistence summary differs')
    for position in ('start', 'end'):
        for stage in STAGES:
            sample = boundaries[stage + '-' + position]['sample']
            for field in ['system', 'machine', 'logical_processors', 'cpu_model', 'physical_memory_bytes',
                'resource_inspection_status', 'effective_cpu_capacity', 'process_affinity_cpu_count',
                'cgroup_memory_limit_bytes', 'cgroup_memory_high_bytes']:
                require(sample['environment'].get(field) == guests[0]['environment'].get(field),
                        'full boundary allocation differs from actual initial guest sample')
    guest_summary['steal_ticks_delta'] = int(guests[-1]['cpu_stat'].split()[8]) - int(guests[0]['cpu_stat'].split()[8])
    guest_summary['append_and_final_fsync'] = observed
    return {'status': 'PASS', 'host': host_summary, 'guest': guest_summary,
        'scope': 'Actual sampled allocation and correlated owned lifecycle only; physical exclusivity/uninterrupted residency unproven. Virtual reference eligibility requires independent review.'}


def select_archive(artifact, guest, stage):
    # Fixed origin precedence, never choose according to a preferred verdict.
    paths = [('host-original', artifact / 'packages' / stage / 'capture.zip'),
        ('guest-original', guest / 'packages' / stage / 'capture.zip'),
        ('host-recovered-raw', artifact / 'partial-packages' / stage / 'capture.zip'),
        ('fallback-original', artifact / 'after-owner-recovery/packages' / stage / 'capture.zip'),
        ('fallback-partial', artifact / 'after-owner-recovery/partial-packages' / stage / 'capture.zip')]
    for origin, path in paths:
        if path.is_file(): return origin, path
    raise ValueError('no available original/partial full capture: ' + stage)


def validate(artifact, out, owner_receipt):
    out.mkdir(parents=True, exist_ok=False)
    report = {'status': 'FAIL', 'method': METHOD, 'errors': [], 'campaigns': [],
        'reference_qualified': False, 'canonical_fresh': 'NOT RUN',
        'scope': 'Offline complete raw-record/source/provenance inspection; no query rerun, implicit replacement, independent review, canonical fresh or final release claim'}
    def attempt(name, operation, errors=None):
        try: return operation()
        except Exception as error:
            (report['errors'] if errors is None else errors).append(name + ': ' + type(error).__name__ + ': ' + str(error)[:2048])
            return None
    config = attempt('configuration', lambda: read_json(artifact / 'configuration.json'))
    payload = config.get('payload') if config else None
    if payload is not None:
        if payload.get('mode') != METHOD or payload.get('source') != source_identity(ROOT):
            report['errors'].append('exact full captured source/method differs from validator')
        report['original_owner'] = attempt('original-owner', lambda: original_owner(owner_receipt, config, payload))
        def binaries():
            require(set(payload['bins']) == {'rillscope', 'rillscope-measure'}, 'closed original binaries required')
            for name, row in payload['bins'].items():
                path = artifact / 'binaries' / name
                with path.open('rb') as stream: magic = stream.read(4)
                require(magic == b'\x7fELF' and sha(path, 64 * 1024**2) == row['sha256'], 'actual retained ELF differs from carried build')
            require(read_json(artifact / 'payload.json') == payload, 'actual retained input payload differs')
            return {'status': 'PASS', 'bins': {name: row['sha256'] for name, row in payload['bins'].items()}}
        report['retained_build_executables'] = attempt('retained-executables', binaries)
    upstream = attempt('original-results', lambda: read_json(artifact / 'results.json'))
    if upstream is None or upstream.get('status') != 'COLLECTED': report['errors'].append('original upstream collection failed/missing')
    recovery = attempt('original-recovery', lambda: read_json(artifact / 'recovery.json'))
    if recovery is None or recovery.get('status') != 'PASS': report['errors'].append('original stopped-disk recovery failed/missing')
    guest = recovered_tree(artifact, 'guest', 'exports')
    results = {}
    for stage in STAGES:
        row = {'stage': stage, 'status': 'FAIL', 'errors': [], 'all_record_validation': 'NOT RUN'}
        selected = attempt('available-capture', lambda: select_archive(artifact, guest, stage), row['errors'])
        if selected is not None:
            origin, archive = selected; row['origin'] = origin
            def all_records():
                before = sha(archive); rows, metadata = archive_capture.inspect(archive)
                row.update(archive_sha256=before, metadata=metadata)
                manifest = inspected_manifest(archive, rows)
                if payload is not None:
                    attempt('declared-scope', lambda: validate_scope(manifest, stage, commit=payload['commit'], source_sha256=payload['source']['sha256']), row['errors'])
                else: row['errors'].append('original full payload missing')
                # Even a failed upstream/ACK/scope does not suppress inspection
                # of every available record. Its failure remains in the report.
                restored = out / ('raw-' + stage); archive_capture.restore(archive, restored)
                verification = verify_cancellation(restored) if stage == 'cancel' else verify(restored, True)
                row['all_record_validation'] = verification['status']; row['verification'] = verification
                write_json(out / ('verified-' + stage + '.json'), verification)
                require(verification['status'] == 'PASS' and verification['observations_checked'] == COUNTS[stage][1],
                        'all-record full validation failed or count differs')
                if stage != 'cancel':
                    require(verification['cases_checked'] == COUNTS[stage][0]
                        and verification['required_success_cases_checked'] == (290 if stage == 'grid' else 40)
                        and verification['independent_semantic_comparisons'] >= (17400 if stage == 'grid' else 2400),
                        'required successful seeded comparisons incomplete')
                result = read_results(restored / 'results.json'); results[stage] = result
                if payload is not None: completed_scope(stage, manifest, result, payload)
                require(before == sha(archive), 'original full CAS changed during offline validation')
                row['all_record_validation'] = 'PASS'
            attempt('all-records', all_records, row['errors'])
            def acknowledged():
                require(origin == 'host-original', 'original host-acknowledged full archive missing; available recovered bytes do not repair it')
                transfer = read_json(archive.parent / 'transfer.json')
                fields = {'schema_version', 'method', 'stage', 'bytes', 'sha256', 'commit', 'source_sha256', 'reference_qualified'}
                require(set(transfer) == fields | {'status', 'started', 'finished', 'metadata'}, 'original host transfer fields differ')
                header({key: transfer[key] for key in fields}, commit=payload['commit'], source_sha256=payload['source']['sha256'])
                require(transfer['status'] == 'VERIFIED HOST BYTES' and transfer['sha256'] == row['archive_sha256']
                    and transfer['bytes'] == archive.stat().st_size and transfer['metadata'] == row['metadata'],
                    'original host transfer differs from actual full archive')
                export = read_json(guest / 'packages' / stage / 'host-export-result.json')
                require(export['status'] == 'HOST ACKNOWLEDGED' and export['stage'] == stage
                    and export['archive_sha256'] == row['archive_sha256']
                    and sha(guest / 'packages' / stage / 'capture.zip') == row['archive_sha256'], 'original guest export/archive differs')
            attempt('original-ACK', acknowledged, row['errors'])
        if not row['errors'] and row['all_record_validation'] == 'PASS': row['status'] = 'PASS'
        report['campaigns'].append(row)
        report['errors'].extend(stage + ': ' + error for error in row['errors']); write_json(out / 'results.json', report)
    if payload is not None:
        report['continuity'] = attempt('full-continuity', lambda: continuity(artifact, payload, config, guest))
    if 'grid' in results: report['filter_project_observed_targets'] = attempt('filter-targets', lambda: filter_targets(results['grid']))
    if 'cancel' in results: report['cancellation_observed_target'] = attempt('cancellation-target', lambda: cancel_target(results['cancel']))
    if not report['errors'] and len(report['campaigns']) == 3 and all(row['status'] == 'PASS' for row in report['campaigns']):
        report['status'] = 'PASS'
    report['virtual_reference_eligibility'] = 'PENDING INDEPENDENT REVIEW' if report['status'] == 'PASS' else 'NOT ESTABLISHED'
    write_json(out / 'results.json', report); return report


def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument('--artifact', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True); parser.add_argument('--owner-receipt', type=Path, required=True)
    args = parser.parse_args(argv)
    result = validate(args.artifact.resolve(), archive_capture.owned(args.out), args.owner_receipt.resolve())
    print(json.dumps({'status': result['status'], 'method': METHOD, 'reference_qualified': False,
        'canonical_fresh': 'NOT RUN', 'errors': result['errors'],
        'campaigns': [{key: row[key] for key in ['stage', 'status', 'all_record_validation']} for row in result['campaigns']]}))
    return int(result['status'] != 'PASS')


if __name__ == '__main__': raise SystemExit(main())
