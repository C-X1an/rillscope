"""Collect three separate campaigns inside the owned ephemeral pilot guest."""
import hashlib
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts')); sys.path.insert(0, str(ROOT / 'benchmarks'))
from kvm_pilot_common import (STAGES, SETUP_SECONDS, PACKAGE_SECONDS, require, sha,
    read_json, write_json, append_json, payload_files, emit)
from inspect_reference_guest import TrialCommands, TrialInterrupted, interrupted
from owned_process import LinuxOwnedChildren
from guest_resource_probe import snapshot
from evidence import source_identity
from build import verify_build
from kvm_capture_channel import send_archive

BASE = ROOT / '.local-runs/kvm-pilot'
INPUT = ROOT / '.local-runs/kvm-input/payload.json'


def interfaces():
    rows = []
    for directory in sorted(Path('/sys/class/net').iterdir()):
        fields = {'name': directory.name}
        for name in ('operstate', 'carrier', 'flags', 'address'):
            try: fields[name] = (directory / name).read_text().strip()
            except OSError as error: fields[name] = {'error': type(error).__name__}
        rows.append(fields)
    require(1 <= len(rows) <= 8, 'network interface count differs')
    return {'interfaces': rows, 'ipv4_routes': Path('/proc/net/route').read_text(),
            'ipv6_routes': Path('/proc/net/ipv6_route').read_text()}


def network_down(record):
    physical = [row for row in record['interfaces'] if row['name'] != 'lo']
    require(len(physical) == 1 and physical[0]['carrier'] == '0'
            and physical[0]['operstate'] in ('down', 'lowerlayerdown'),
            'one exposed network interface must actually lose carrier')
    return True


def probe_identity(payload):
    require(source_identity(ROOT) == payload['source'], 'guest public source differs from exact build source')
    build_path = ROOT / payload['build_receipt']['path']
    require(sha(build_path) == payload['build_receipt']['sha256'], 'carried build receipt differs')
    for name, item in payload['bins'].items():
        binary = ROOT / item['path']
        require(binary.is_file() and os.access(binary, os.X_OK) and sha(binary) == item['sha256'],
                'carried executable bytes or mode differ')
        verify_build(build_path, binary, name=name)
    head = subprocess.check_output(['git', '--no-optional-locks', 'rev-parse', 'HEAD'],
                                   cwd=ROOT, text=True, timeout=10).strip()
    dirty = subprocess.check_output(['git', '--no-optional-locks', '-c', 'core.fsmonitor=false',
                                     'status', '--porcelain'], cwd=ROOT, timeout=10)
    require(head == payload['commit'] and not dirty.strip(), 'guest checkout is not exact clean public commit')
    return {'commit': head, 'source_sha256': payload['source']['sha256'],
            'binary_sha256': {name: row['sha256'] for name, row in payload['bins'].items()}}


class GuestObserver:
    def __init__(self):
        self.stop = threading.Event(); self.error = None; self.count = 0
        self.thread = threading.Thread(target=self.run, name='owned-guest-observer', daemon=True)

    def run(self):
        try:
            while not self.stop.is_set():
                started = time.monotonic_ns(); cpu = time.thread_time_ns()
                row = snapshot('interval')
                row['network'] = interfaces()
                row.update(observer_wall_ns=time.monotonic_ns() - started,
                           observer_cpu_ns=time.thread_time_ns() - cpu)
                append_json(BASE / 'exports/guest-samples.jsonl', row)
                self.count += 1
                require(self.count <= 3000, 'guest observation count exceeds pilot bound')
                self.stop.wait(2)
        except Exception as error:
            self.error = type(error).__name__ + ': ' + str(error)

    def close(self):
        self.stop.set(); self.thread.join(timeout=5)
        require(not self.thread.is_alive(), 'guest observer failed to stop')
        require(self.error is None and self.count > 0, 'guest observer failed: ' + str(self.error))


def failed(row, phase, error):
    record = {'phase': phase, 'error': type(error).__name__, 'reason': str(error)[:2048]}
    if isinstance(error, (TrialInterrupted, KeyboardInterrupt)): row['interrupted'] = True
    row['status'] = 'FAIL'; row.setdefault('first_error', record)
    failures = row.setdefault('failures', [])
    require(len(failures) < 16, 'stage failure count exceeds bound')
    failures.append(record)


def attempt(row, phase, operation):
    try: return operation()
    except (Exception, KeyboardInterrupt) as error:
        failed(row, phase, error)
        return None


def finalize_stage(row, label, raw, payload, checked):
    # Diagnostics are independent attempts: none may suppress existing raw bytes.
    attempt(row, 'after-snapshot', lambda: append_json(BASE / 'exports/boundaries.jsonl', snapshot(label + '-after')))
    identity = attempt(row, 'after-identity', lambda: probe_identity(payload))
    if identity is not None: row['identity_after'] = identity
    def observe_network():
        actual = interfaces(); row['network_after'] = actual
        write_json(BASE / ('exports/network-' + label + '-after.json'), actual)
        network_down(actual)
    attempt(row, 'after-network', observe_network)
    attempt(row, 'stage-end-event', lambda: emit('stage-end', stage=label, status=row['status']))
    row['package_status'] = 'MISSING RAW'
    row['export_failed'] = True
    if raw.is_dir():
        attempt(row, 'pack-start-event', lambda: emit('pack-start', stage=label))
        deadline = time.monotonic() + PACKAGE_SECONDS
        try:
            checked('pack-' + label, ['/usr/bin/python3', str(ROOT / 'scripts/archive_capture.py'),
                'pack', '--source', str(raw), '--out', str(BASE / 'exports/packages' / label)],
                timeout=max(.001, deadline - time.monotonic()))
            row['package_status'] = 'PACKED'
            row['host_transfer'] = send_archive(BASE / 'exports/packages' / label / 'capture.zip', label, deadline)
            require(row['host_transfer']['status'] == 'HOST ACKNOWLEDGED', 'host acknowledgement missing')
            row['export_failed'] = False
        except (Exception, KeyboardInterrupt) as error:
            row['package_status'] = 'FAIL'; row['export_failed'] = True; failed(row, 'pack-or-transfer', error)
        attempt(row, 'pack-end-event', lambda: emit('pack-end', stage=label, status=row['package_status']))
    attempt(row, 'sync', os.sync)


def run_stage(label, profile, seconds, payload, checked, observer):
    raw = BASE / 'raw' / label; receipt_out = BASE / 'raw-receipts' / label
    row = {'stage': label, 'profile': profile, 'declared_timeout_seconds': seconds,
           'status': 'FAIL', 'command_attempted': False, 'reference_qualified': False}
    try:
        require(observer.error is None, 'guest observer failed during prior stage')
        actual_network = interfaces()
        write_json(BASE / ('exports/network-' + label + '-before.json'), actual_network)
        network_down(actual_network)
        identity = probe_identity(payload)
        emit('stage-start', stage=label, **identity)
        append_json(BASE / 'exports/boundaries.jsonl', snapshot(label + '-before'))
        measurement = payload['bins']['rillscope-measure']['path']
        if label == 'cancel':
            command = ['/usr/bin/python3', str(ROOT / 'benchmarks/cancellation.py'),
                '--binary', str(ROOT / payload['bins']['rillscope']['path'])]
        else:
            command = ['/usr/bin/python3', str(ROOT / 'benchmarks/run.py'),
                '--binary', str(ROOT / measurement), '--profile', profile]
        command += ['--build-receipt', str(ROOT / payload['build_receipt']['path']), '--out', str(raw)]
        actual_command = ['/usr/bin/setpriv', '--reuid=65534', '--regid=65534', '--clear-groups',
            '--', '/usr/bin/env', 'HOME=' + str(BASE / 'home'), 'GIT_OPTIONAL_LOCKS=0',
            'GIT_CONFIG_COUNT=1', 'GIT_CONFIG_KEY_0=safe.directory', 'GIT_CONFIG_VALUE_0=' + str(ROOT),
            'PYTHONDONTWRITEBYTECODE=1', '/usr/bin/python3', str(ROOT / 'scripts/evidence.py'),
            '--out', str(receipt_out), '--timeout', str(seconds), '--input', str(INPUT), '--', *command]
        row['command_attempted'] = True
        checked('campaign-' + label, actual_command, timeout=seconds + 15, inputs=(INPUT,))
        original = read_json(receipt_out / 'receipt.json')
        require(original['verification_status'] == 'PASS' and original['exit_code'] == 0,
                'campaign command did not pass')
        row['status'] = 'COLLECTED'
    except (Exception, KeyboardInterrupt) as error:
        failed(row, 'campaign', error)
    finally:
        finalize_stage(row, label, raw, payload, checked)
    return row


def collect(payload, ownership):
    checked = TrialCommands(BASE, ownership)
    setup_start = time.monotonic()
    emit('stage-start', stage='setup')
    # This script's entry gate permits only the owned mounted ephemeral guest.
    # No corresponding service or package operation runs on the coordinator host.
    os.environ.update(DEBIAN_FRONTEND='noninteractive', PYTHONDONTWRITEBYTECODE='1', GIT_OPTIONAL_LOCKS='0')
    checked('apt-update', ['/usr/bin/apt-get', 'update'], timeout=300)
    checked('apt-install', ['/usr/bin/apt-get', 'install', '--yes', '--no-install-recommends',
                           'git', 'gdb', 'time', 'util-linux'], timeout=300)
    checked('stop-package-services', ['/usr/bin/systemctl', 'stop', 'apt-daily.timer',
            'apt-daily-upgrade.timer', 'apt-daily.service', 'apt-daily-upgrade.service',
            'unattended-upgrades.service'], timeout=30)
    checked('installed-tools', ['/usr/bin/dpkg-query', '-W',
            '-f=${Package}\t${Version}\n', 'git', 'gdb', 'time', 'libc6', 'python3', 'libsqlite3-0'], timeout=15)
    checked('gnu-time', ['/usr/bin/time', '-f', 'RILLTIME %U %S %M', '--',
                        '/usr/bin/python3', '-c', 'print("owned GNU-time probe")'], timeout=15)
    checked('gdb-version', ['/usr/bin/gdb', '--version'], timeout=15)
    require(payload_files(ROOT) == payload['files'], 'actual transferred checkout/build payload differs')
    identity = probe_identity(payload)
    # The existing nobody identity may write only its owned capture directories.
    # Public source, Git metadata and transported executables remain root owned.
    import pwd
    account = pwd.getpwnam('nobody')
    require(account.pw_uid == account.pw_gid == 65534, 'existing guest nobody identity differs')
    for name in ('raw', 'raw-receipts', 'home', 'exports/packages'):
        path = BASE / name
        require(path.is_dir() and not path.is_symlink(), 'owned guest capture directory required')
        os.chown(path, account.pw_uid, account.pw_gid)
    require(time.monotonic() - setup_start < SETUP_SECONDS - 120, 'guest setup consumed its boot/setup reserve')
    write_json(BASE / 'exports/guest-environment.json', {'snapshot': snapshot('setup-complete'),
        'python': sys.version, 'sqlite': __import__('sqlite3').sqlite_version, 'libc': platform.libc_ver(),
        'host_build_environment': payload['host_build_environment'], 'execution_identity': identity,
        'scope': 'host compilation and guest execution environments are distinct; reference_qualified:false'})
    before_network = interfaces()
    write_json(BASE / 'exports/network-before.json', before_network)
    emit('ready', **identity)
    network_deadline = time.monotonic() + 30
    while True:
        actual = interfaces()
        try: network_down(actual); break
        except ValueError:
            require(time.monotonic() < network_deadline, 'host link-down was not observed')
            time.sleep(.2)
    write_json(BASE / 'exports/network-down.json', actual)
    emit('network-down', **identity)
    observer = GuestObserver(); observer.thread.start()
    first_deadline = time.monotonic() + 5
    while observer.count == 0:
        require(observer.error is None and time.monotonic() < first_deadline, 'initial guest observation missing or failed')
        time.sleep(.01)
    records = []
    try:
        for label, profile, seconds in STAGES:
            records.append(run_stage(label, profile, seconds, payload, checked, observer))
            write_json(BASE / 'exports/campaigns.json', records)
            if records[-1].get('interrupted') or records[-1].get('export_failed'): break
    finally:
        observer.close()
    return {'status': 'COLLECTED' if len(records) == 3 and all(row['status'] == 'COLLECTED'
            and row['package_status'] == 'PACKED' for row in records) else 'FAIL',
        'campaigns': records, 'guest_observations': observer.count, 'reference_qualified': False,
        'scope': 'unqualified feasibility collection; all-record offline validation and full reference targets remain separate'}


def main():
    if (platform.system() != 'Linux' or os.geteuid() != 0 or ROOT != Path('/work/c')
            or not Path('/run/rillscope-owned-pilot').is_file()
            or Path('/run/rillscope-owned-pilot').read_text().strip() != 'owned-ephemeral-kvm-pilot'):
        print('BLOCKED: this worker requires the owned mounted ephemeral pilot guest'); return 77
    require(INPUT.is_file(), 'exact carried payload manifest missing')
    for directory in ('exports', 'exports/packages', 'raw', 'raw-receipts', 'home'):
        (BASE / directory).mkdir(parents=True, exist_ok=False)
    for number in (signal.SIGTERM, signal.SIGINT): signal.signal(number, interrupted)
    ownership = LinuxOwnedChildren(); result = {'status': 'FAIL', 'reference_qualified': False}
    try:
        result = collect(read_json(INPUT), ownership)
    except (Exception, KeyboardInterrupt) as error:
        result.update(status='FAIL', error=type(error).__name__, reason=str(error))
        emit('guest-failure', status='FAIL', error=type(error).__name__)
    finally:
        for number in (signal.SIGTERM, signal.SIGINT): signal.signal(number, signal.SIG_IGN)
        cleanup = ownership.finish(None)
        result['cleanup'] = cleanup
        if cleanup['status'] != 'PASS': result['status'] = 'FAIL'
        write_json(BASE / 'exports/guest-result.json', result)
        os.sync()
    emit('guest-exit', status=result['status'])
    return 0 if result['status'] == 'COLLECTED' else 1


if __name__ == '__main__': raise SystemExit(main())
