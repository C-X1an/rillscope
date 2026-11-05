"""Offline all-record validation of one original, unqualified KVM pilot."""
import argparse
import json
from pathlib import Path, PurePosixPath
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import archive_capture
from evidence import source_identity
from kvm_pilot_common import STAGES, MAX_LOG, require, sha, read_json, write_json, parse_events
from feasibility_profile import exact, header_errors
from verify import verify
from cancellation import verify_cancellation

MAX_GAP_NS = 15_000_000_000
INSTRUMENT = [
    {'id': 'pilot-filter-empty', 'family': 'filter', 'rows': 10000, 'selectivity': 0,
     'null_percent': 0, 'batch_rows': 128, 'expected_oracle_status': 'OK', 'expected_product_status': 'OK'},
    {'id': 'B01-n10000-s100-null10-b1024', 'family': 'filter', 'rows': 10000, 'selectivity': 100,
     'null_percent': 10, 'batch_rows': 1024, 'expected_oracle_status': 'OK', 'expected_product_status': 'OK'},
    {'id': 'B02-k1000-uniform-composite1', 'family': 'join', 'rows': 3000, 'keys': 1000, 'skew': 'uniform',
     'composite': True, 'null_percent': 10, 'batch_rows': 1024, 'expected_oracle_status': 'OK', 'expected_product_status': 'OK'},
    {'id': 'B03-all-null', 'family': 'aggregate', 'rows': 10000, 'groups': 0, 'all_null': True,
     'null_percent': 100, 'batch_rows': 1024, 'expected_oracle_status': 'OK', 'expected_product_status': 'OK'},
    {'id': 'B04-n10000-equal', 'family': 'sort', 'rows': 10000, 'order': 'equal', 'null_percent': 0,
     'batch_rows': 1024, 'expected_oracle_status': 'OK', 'expected_product_status': 'OK'},
    {'id': 'B06-tiny-work', 'family': 'budget', 'rows': 100, 'keys': 1, 'skew': 'heavy',
     'null_percent': 0, 'batch_rows': 1024, 'max_work': 1000, 'expected_product_status': 'E_BUDGET', 'expected_oracle_status': 'OK'}]


def json_lines(path, count):
    rows = []; size = 0
    with path.open('rb') as stream:
        while line := stream.readline(65537):
            size += len(line)
            require(len(line) <= 65536 and size <= MAX_LOG and line.endswith(b'\n') and len(rows) < count,
                    'observation byte/line/count bound exceeded')
            rows.append(json.loads(line))
    require(rows, 'observations missing')
    return rows


def down(value):
    rows = value['interfaces']; physical = [row for row in rows if row['name'] != 'lo']
    require(len(rows) <= 8 and len(physical) == 1 and physical[0]['carrier'] == '0'
            and physical[0]['operstate'] in ('down', 'lowerlayerdown'), 'guest network carrier was not down')
    require(isinstance(value['ipv4_routes'], str) and isinstance(value['ipv6_routes'], str), 'network route evidence missing')


def sampling(rows):
    require(len(rows) >= 2 and all(type(row.get(key)) is int and row[key] > 0 for row in rows
        for key in ('utc_ns', 'monotonic_ns')), 'sampling clocks missing')
    gaps = [b['monotonic_ns'] - a['monotonic_ns'] for a, b in zip(rows, rows[1:])]
    require(all(0 < value <= MAX_GAP_NS for value in gaps), 'sampling clock reversed or gap exceeds15seconds')
    costs = [row['observer_wall_ns'] for row in rows]; cpu = [row['observer_cpu_ns'] for row in rows]
    require(all(type(value) is int and value >= 0 for value in costs + cpu), 'observer costs missing')
    return {'observations': len(rows), 'maximum_gap_ns': max(gaps), 'gap_bound_ns': MAX_GAP_NS,
        'observer_wall_total_ns': sum(costs), 'observer_wall_max_ns': max(costs), 'observer_cpu_total_ns': sum(cpu),
        'first_monotonic_ns': rows[0]['monotonic_ns'], 'last_monotonic_ns': rows[-1]['monotonic_ns']}


def scope_header(label, manifest, result):
    if label == 'tail': return header_errors(manifest, result)
    if label != 'instrument': return []
    expected = {'profile': 'instrumentation-pilot', 'chosen_workloads': INSTRUMENT, 'seeds': [20261014],
        'warmups': 5, 'repetitions': 30, 'expected_cases': 6, 'expected_observations': 630}
    errors = ['fixed instrument manifest differs: ' + key for key, value in expected.items()
              if not exact(manifest.get(key), value)]
    for key, value in {'profile': 'instrumentation-pilot', 'completed_cases': 6,
                       'expected_cases': 6, 'complete_grid': False}.items():
        if not exact(result.get(key), value): errors.append('fixed instrument result differs: ' + key)
    return errors


def passing_receipt(directory, source):
    row = read_json(directory / 'receipt.json')
    require(row.get('verification_status') == 'PASS' and row.get('exit_code') == 0
        and row.get('execution_outcome') == 'EXECUTED' and row.get('source_before') == source
        and row.get('source_after_sha256') == source['sha256']
        and row.get('process_cleanup', {}).get('status') == 'PASS'
        and row['process_cleanup'].get('remaining_active_processes') == 0,
        'original command/source/cleanup did not pass: ' + directory.name)
    for label in ('stdout', 'stderr'):
        require(row[label]['file'] == label + '.txt' and sha(directory / (label + '.txt')) == row[label]['sha256'],
                'original command raw bytes differ: ' + directory.name)
    return row


def recovered_tree(artifact, host_name, guest_name):
    path = artifact / host_name
    if (path / guest_name).is_dir():
        require(list(path.iterdir()) == [path / guest_name], 'ambiguous original receipt layout')
        path = path / guest_name
    return path


def original_owner(receipt_path, config, payload):
    require(receipt_path.name == 'receipt.json', 'exact supplied canonical owner receipt required')
    row = passing_receipt(receipt_path.parent, payload['source'])
    root = PurePosixPath(config['original_root'])
    require(root.is_absolute() and '..' not in root.parts and row['cwd'] == str(root)
        and row['environment']['system'] == 'Linux' and row['git']['commit'] == payload['commit']
        and row['git']['dirty'] is False, 'original enclosing owner identity differs')
    def path(value):
        require(isinstance(value, str) and len(value) <= 4096 and '\\' not in value and ':' not in value,
                'closed original Linux command path required')
        value = PurePosixPath(value)
        require('..' not in value.parts, 'original command path traverses parents')
        return value if value.is_absolute() else root / value
    command = row['command']
    require(len(command) == 10 and path(command[1]) == root / 'scripts/kvm_benchmark_pilot.py'
        and command[2::2] == ['--out', '--run-as', '--build-receipt', '--commit']
        and path(command[3]) == path(config['original_output'])
        and path(command[7]) == path(payload['build_receipt']['path']) and command[9] == payload['commit']
        and command[5] == config['command'][config['command'].index('-runas') + 1],
        'original enclosing owner command/output/build association differs')
    return {'status': 'PASS', 'receipt_sha256': sha(receipt_path),
        'stdout_sha256': row['stdout']['sha256'], 'stderr_sha256': row['stderr']['sha256']}


def continuity(artifact, payload, guest):
    vm = read_json(artifact / 'vm-result.json'); serial = (artifact / 'serial.txt').read_bytes()
    require(len(serial) <= 4 * 1024**2, 'serial exceeds bound')
    events = parse_events(serial.decode('utf-8', errors='replace'))
    require(events == vm['events'] and vm['status'] == 'COLLECTED' and vm['post_ready_observation_errors'] == 0,
            'original VM events or observation status differ')
    guest_result = read_json(guest / 'guest-result.json')
    campaigns = read_json(guest / 'campaigns.json')
    require(guest_result['status'] == 'COLLECTED' and guest_result['cleanup']['status'] == 'PASS'
        and guest_result['campaigns'] == campaigns and len(campaigns) == 3, 'original guest outcome differs')
    helpers = recovered_tree(artifact, 'guest-helper-commands', 'commands')
    nested = recovered_tree(artifact, 'guest-command-receipts', 'raw-receipts')
    for name in ('apt-update', 'apt-install', 'stop-package-services', 'installed-tools', 'gnu-time', 'gdb-version', 'serial-getty-state'):
        passing_receipt(helpers / name, payload['source'])
    require(set((helpers / 'serial-getty-state/stdout.txt').read_text(encoding='utf-8').splitlines())
            == {'LoadState=masked', 'ActiveState=inactive'}, 'actual owned console policy differs')
    require(b'RILLTIME ' in (helpers / 'gnu-time/stderr.txt').read_bytes(), 'actual GNU time probe output missing')
    for recorded, (label, profile, seconds) in zip(campaigns, STAGES):
        require(recorded['stage'] == label and recorded['profile'] == profile
            and recorded['declared_timeout_seconds'] == seconds and recorded['status'] == 'COLLECTED'
            and recorded['package_status'] == 'PACKED' and recorded['host_transfer']['status'] == 'HOST ACKNOWLEDGED'
            and recorded.get('export_failed') is False and not recorded.get('interrupted'),
            'original campaign/host acknowledgement failed')
        passing_receipt(nested / label, payload['source'])
        passing_receipt(helpers / ('campaign-' + label), payload['source'])
        passing_receipt(helpers / ('pack-' + label), payload['source'])
    expected = [('stage-start', 'setup'), ('ready', None), ('network-down', None)]
    for label, _, _ in STAGES:
        expected += [(phase, label) for phase in ('stage-start', 'stage-end', 'pack-start', 'pack-end')]
    expected += [('guest-exit', None)]
    require([(row['phase'], row.get('stage')) for row in events] == expected, 'exact campaign lifecycle differs')
    for row in events:
        if row['phase'] in ('ready', 'network-down', 'stage-start') and row.get('stage') != 'setup':
            require(row.get('commit') == payload['commit'] and row.get('source_sha256') == payload['source']['sha256']
                and row.get('binary_sha256') == {name: item['sha256'] for name, item in payload['bins'].items()},
                'guest campaign phase source/executables differ')
        if row['phase'] == 'stage-end': require(row['status'] == 'COLLECTED', 'guest stage failed')
        if row['phase'] == 'pack-end': require(row['status'] == 'PACKED', 'guest pack/transfer failed')
    host = json_lines(artifact / 'host-samples.jsonl', 12000)
    received = json_lines(artifact / 'received-events.jsonl', 64)
    require([row['guest'] for row in received] == events
        and all(type(row['received_monotonic_ns']) is int and row['received_monotonic_ns'] > 0 for row in received)
        and all(b['received_monotonic_ns'] > a['received_monotonic_ns'] for a, b in zip(received, received[1:])),
        'host received lifecycle differs or clocks reversed')
    def receipt(phase, stage=None):
        return next(row['received_monotonic_ns'] for row in received
                    if row['guest']['phase'] == phase and row['guest'].get('stage') == stage)
    ready = receipt('ready'); finished = receipt('guest-exit')
    for row in host:
        require(type(row.get('required_interval')) is bool and row['required_interval'] is
            (ready <= row['monotonic_ns'] < finished), 'host interval label differs from received lifecycle')
    observed = [row for row in host if ready <= row['monotonic_ns'] < finished]
    host_summary = sampling(observed)
    require(0 <= observed[0]['monotonic_ns'] - ready <= MAX_GAP_NS
        and 0 <= finished - observed[-1]['monotonic_ns'] <= MAX_GAP_NS
        and observed[0]['monotonic_ns'] <= receipt('stage-start', 'instrument')
        and observed[-1]['monotonic_ns'] >= receipt('stage-end', 'cancel'),
        'host observations do not cover original campaign lifecycle boundaries')
    uid = read_json(artifact / 'configuration.json')['qemu_run_as_uid']
    for row in observed:
        require(row['kvm'].get('return', {}).get('enabled') is True
            and row['memory'].get('return', {}).get('base-memory') == 8 * 1024**3
            and row['hotplug_memory'].get('return') == [] and row['run_status'].get('return', {}).get('status') == 'running'
            and len(row['vcpu_threads']) == 4 and all(len(item['affinity']) == 4 for item in row['vcpu_threads'])
            and row['environment'].get('effective_cpu_capacity') == 4
            and row['environment'].get('process_affinity_cpu_count') == 4
            and row['process_status'].get('Uid', '').split() == [str(uid)] * 4
            and row['process_status'].get('VmSwap') == '0 kB'
            and int(row['process_status'].get('VmRSS', '0 kB').split()[0]) * 1024 >= 7.5 * 1024**3,
            'original post-ready host allocation/process observation differs')
    guests = json_lines(guest / 'guest-samples.jsonl', 3000); guest_summary = sampling(guests)
    for row in guests:
        require(row['boot_id'] == events[0]['boot_id'] and row['clock_properties']['monotonic'] is True
            and row['clock_properties']['adjustable'] is False and row['environment'].get('effective_cpu_capacity') == 4
            and row['environment'].get('process_affinity_cpu_count') == 4
            and 7.5 * 1024**3 <= row['environment'].get('physical_memory_bytes', 0) <= 8.5 * 1024**3,
            'original guest clock/resources differ')
        down(row['network'])
    begin = next(row for row in events if row['phase'] == 'stage-start' and row.get('stage') == 'instrument')
    end = next(row for row in reversed(events) if row['phase'] == 'stage-end')
    require(0 <= begin['monotonic_ns'] - guests[0]['monotonic_ns'] <= MAX_GAP_NS
        and guests[-1]['monotonic_ns'] >= end['monotonic_ns'],
        'guest samples do not bracket measured campaigns')
    for label, _, _ in STAGES:
        for position in ('before', 'after'): down(read_json(guest / ('network-' + label + '-' + position + '.json')))
    link = read_json(artifact / 'host-link-down.json')
    require('return' in link['response'] and ready <= link['requested']['monotonic_ns']
        <= link['finished_monotonic_ns'] <= receipt('network-down') < receipt('stage-start', 'instrument'),
        'host link-down acknowledgement/timing differs from received lifecycle')
    for counter in ('pswpin', 'pswpout'):
        values = [row['vmstat'] for row in guests]
        require(all(row['status'] == 'MEASURED' for row in values)
            and values[-1]['values'][counter] == values[0]['values'][counter], 'guest swap changed or unmeasured')
    steal = [int(row['cpu_stat'].split()[8]) for row in guests]
    guest_summary['steal_ticks_delta'] = steal[-1] - steal[0]
    guest_summary['pressure_and_swap_raw_retained'] = True
    return {'status': 'PASS', 'host': host_summary, 'guest': guest_summary,
        'scope': 'bounded sampled continuity; physical exclusivity, uninterrupted residency and reference qualification unestablished'}


def validate(artifact, out, owner_receipt=None):
    report = {'status': 'FAIL', 'errors': [], 'campaigns': [], 'reference_qualified': False,
        'scope': 'offline included-byte/all-record inspection only; no product rerun or reference/fresh/full410 qualification'}
    out.mkdir(parents=True, exist_ok=False)
    def attempt(name, operation):
        try: return operation()
        except Exception as error:
            report['errors'].append(name + ': ' + type(error).__name__ + ': ' + str(error)[:2048])
            return None
    config = attempt('configuration', lambda: read_json(artifact / 'configuration.json'))
    payload = config['payload'] if config else None
    if payload is not None:
        owner_receipt = owner_receipt if owner_receipt is not None else artifact.parent.parent / 'kvm-command/receipt.json'
        report['original_owner'] = attempt('original-enclosing-owner', lambda: original_owner(owner_receipt, config, payload))
    if payload is not None and payload['source'] != source_identity(ROOT): report['errors'].append('validator exact public source differs from campaign')
    upstream = attempt('upstream', lambda: read_json(artifact / 'results.json'))
    if upstream is None or upstream.get('status') != 'COLLECTED': report['errors'].append('original upstream collection failed or missing')
    recovery = attempt('recovery', lambda: read_json(artifact / 'recovery.json'))
    if recovery is None or recovery.get('status') != 'PASS': report['errors'].append('original recovery failed or partial')
    guest = artifact / 'guest'
    if (guest / 'exports').is_dir(): guest = guest / 'exports'
    for label, profile, _ in STAGES:
        row = {'stage': label, 'status': 'FAIL', 'profile': profile}
        def campaign():
            archive = artifact / 'packages' / label / 'capture.zip'; before = sha(archive)
            _, metadata = archive_capture.inspect(archive)
            transfer = read_json(archive.parent / 'transfer.json')
            require(transfer['stage'] == label and transfer['sha256'] == before
                and transfer['bytes'] == archive.stat().st_size and transfer['metadata'] == metadata
                and transfer['status'] == 'VERIFIED HOST BYTES' and transfer['reference_qualified'] is False,
                'original host acknowledged transfer differs from exact archive')
            restored = out / ('raw-' + label); archive_capture.restore(archive, restored)
            manifest = read_json(restored / 'manifest.json'); result = read_json(restored / 'results.json')
            require(payload is not None and manifest['source'] == payload['source'], 'campaign exact source differs')
            require(not scope_header(label, manifest, result), 'fixed campaign scope differs')
            verification = verify_cancellation(restored) if label == 'cancel' else verify(restored, True)
            write_json(out / ('verified-' + label + '.json'), verification)
            require(verification['status'] == 'PASS' and verification['observations_checked'] ==
                {'instrument': 630, 'tail': 315, 'cancel': 175}[label], 'all-record validation failed or count differs')
            require(before == sha(archive), 'original CAS changed during offline inspection')
            row.update(status='PASS', archive_sha256=before, metadata=metadata, verification=verification)
        attempt('campaign-' + label, campaign)
        report['campaigns'].append(row); write_json(out / 'results.json', report)
    if payload is not None: report['continuity'] = attempt('continuity', lambda: continuity(artifact, payload, guest))
    if not report['errors'] and all(row['status'] == 'PASS' for row in report['campaigns']): report['status'] = 'PASS'
    write_json(out / 'results.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--artifact', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--owner-receipt', type=Path, required=True); args = parser.parse_args()
    out = archive_capture.owned(args.out)
    result = validate(args.artifact.resolve(), out, args.owner_receipt.resolve())
    print(json.dumps(result, indent=2)); return int(result['status'] != 'PASS')


if __name__ == '__main__': raise SystemExit(main())
