"""Own one full collection in the fixed ephemeral guest, with no fresh claim."""
import hashlib
import os
from pathlib import Path
import platform
import re
import secrets
import signal
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts')); sys.path.insert(0, str(ROOT / 'benchmarks'))
from kvm_pilot_common import require, read_json, write_json, payload_files, sha
from kvm_pilot_guest import probe_identity, failed, attempt
from kvm_reference_common import METHOD, STAGES, identity, strict_json
from kvm_reference_budget import (VM_SECONDS, GUEST_SETUP_SECONDS, COLLECTION_SECONDS,
    GUEST_FINISH_SECONDS, PACKAGE_SECONDS)
from kvm_reference_events import emit
from guest_resource_probe import snapshot
from inspect_reference_guest import TrialCommands, interrupted
from owned_process import LinuxOwnedChildren
from reference_guest_owner import Coordinator
import reference_measurement_barrier as barrier
import reference_capture_export as exporter
import kvm_reference_device as capture_device

BASE = ROOT / '.local-runs/kvm-reference'
INPUT = ROOT / '.local-runs/kvm-input/payload.json'
MARKER = Path('/run/rillscope-owned-reference')


def prepare_capture_device(payload, checked):
    identity(payload['commit'], payload['source']['sha256'])
    record = {'schema_version': 1, 'status': 'FAIL', 'commit': payload['commit'],
        'source_sha256': payload['source']['sha256'], 'grant': {}}
    try:
        capture_device.grant(record['grant'])
        raw = checked('capture-device-open', ['/usr/bin/setpriv', '--reuid=65534',
            '--regid=65534', '--clear-groups', '--', '/usr/bin/python3',
            str(ROOT / 'scripts/kvm_reference_device.py'), 'probe'], timeout=15, inputs=(INPUT,))
        require(len(raw) <= 8192, 'bounded actual capture device probe required')
        record['probe'] = strict_json(raw)
        capture_device.validate_access(record['grant'], record['probe'])
        record['status'] = 'VERIFIED'
    except Exception as error:
        record['error'] = type(error).__name__ + ': ' + str(error)[:1024]
        raise
    finally:
        write_json(BASE / 'exports/device-access.json', record)
    return record


def configurations(payload, started_ns, now_ns, boot_id):
    require(type(payload) is dict and payload.get('mode') == METHOD
        and payload.get('reference_qualified') is False and type(payload.get('bins')) is dict
        and set(payload['bins']) == {'rillscope', 'rillscope-measure'}, 'closed full collection payload required')
    identity(payload['commit'], payload['source']['sha256'])
    require(isinstance(boot_id, str) and re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot_id),
            'actual guest boot identity required')
    require(type(started_ns) is int and type(now_ns) is int and 0 < started_ns <= now_ns
        and now_ns - started_ns < (GUEST_SETUP_SECONDS - 120) * 10**9,
        'guest setup consumed its boot/setup reserve')
    deadline = min(started_ns + (VM_SECONDS - 120) * 10**9,
                   now_ns + (COLLECTION_SECONDS + GUEST_FINISH_SECONDS) * 10**9)
    common = {'schema_version': 1, 'method': METHOD, 'commit': payload['commit'],
        'source_sha256': payload['source']['sha256'], 'deadline_monotonic_ns': deadline}
    measure = {**common, 'boot_id': boot_id, 'session': secrets.token_hex(16),
        'control_root': str(barrier.CONTROL_ROOT), 'handshake_seconds': 30, 'reference_qualified': False}
    export = {**common, 'transfer_seconds': PACKAGE_SECONDS}
    return measure, export


def collect(payload, ownership, started_ns):
    setup = BASE / 'setup'; setup.mkdir()
    direct = TrialCommands(setup, ownership)
    def checked(name, command, timeout=60, **keywords):
        remaining = (started_ns + (GUEST_SETUP_SECONDS - 120) * 10**9 - time.monotonic_ns()) / 10**9
        require(remaining > 0, 'whole guest setup deadline exhausted')
        return direct(name, command, timeout=min(timeout, remaining), **keywords)
    emit('setup-start')
    os.environ.update(DEBIAN_FRONTEND='noninteractive', PYTHONDONTWRITEBYTECODE='1', GIT_OPTIONAL_LOCKS='0')
    checked('apt-update', ['/usr/bin/apt-get', 'update'], timeout=300)
    checked('apt-install', ['/usr/bin/apt-get', 'install', '--yes', '--no-install-recommends',
        'git', 'gdb', 'time', 'util-linux'], timeout=300)
    checked('stop-package-services', ['/usr/bin/systemctl', 'stop', 'apt-daily.timer',
        'apt-daily-upgrade.timer', 'apt-daily.service', 'apt-daily-upgrade.service',
        'unattended-upgrades.service'], timeout=30)
    checked('installed-tools', ['/usr/bin/dpkg-query', '-W', '-f=${Package}\t${Version}\n',
        'git', 'gdb', 'time', 'libc6', 'python3', 'libsqlite3-0'], timeout=15)
    checked('gnu-time', ['/usr/bin/time', '-f', 'RILLTIME %U %S %M', '--',
        '/usr/bin/python3', '-c', 'print("owned GNU-time probe")'], timeout=15)
    console = checked('serial-getty-state', ['/usr/bin/systemctl', 'show', '--property=LoadState',
        '--property=ActiveState', 'serial-getty@ttyS0.service'], timeout=15)
    require(set(console.decode().splitlines()) == {'LoadState=masked', 'ActiveState=inactive'},
            'owned guest serial getty must actually be masked and inactive')
    observed_identity = probe_identity(payload)
    actual = snapshot('setup-complete')
    write_json(BASE / 'exports/guest-environment.json', {'snapshot': actual,
        'python': sys.version, 'sqlite': __import__('sqlite3').sqlite_version, 'libc': platform.libc_ver(),
        'host_build_environment': payload['host_build_environment'], 'execution_identity': observed_identity,
        'canonical_fresh': 'NOT RUN', 'reference_qualified': False,
        'scope': 'Source-bound host compilation and distinct guest execution; no native guest build/fresh claim'})
    measure, export = configurations(payload, started_ns, time.monotonic_ns(), actual['boot_id'])
    for name, value, key, digest_key in [('measurement-config.json', measure, barrier.CONFIG_PATH, barrier.CONFIG_DIGEST),
        ('export-config.json', export, exporter.CONFIG_PATH, exporter.CONFIG_DIGEST)]:
        path = BASE / name; write_json(path, value); os.chmod(path, 0o644)
        os.environ[key] = str(path); os.environ[digest_key] = sha(path)
    import pwd
    account = pwd.getpwnam('nobody')
    require(account.pw_uid == account.pw_gid == 65534, 'existing guest nobody identity differs')
    for name in ('raw', 'raw-receipts', 'home', 'commands', 'exports/packages'):
        os.chown(BASE / name, account.pw_uid, account.pw_gid)
    # Sticky control directory lets the child publish only its own new records;
    # root-owned ACK files/configuration cannot be replaced by that identity.
    os.chmod(BASE / 'control', 0o1777)
    os.chmod(BASE / 'exports', 0o1777)
    # Fail before coordination or queries if the actual measurement identity
    # cannot open the one named capture port. No protocol bytes are sent here.
    prepare_capture_device(payload, checked)
    emit('setup-end')
    def ready(stage, request):
        data = barrier.bounded(barrier.CONTROL_ROOT / (stage + '-request.json'))
        emit('ready', stage=stage, **observed_identity,
            request_sha256=hashlib.sha256(data).hexdigest(), config_sha256=request['config_sha256'])
    def owner_failure(_record):
        # Signal this owned root process only. Its established handler and
        # subreaper then stop the one child command and retain original failure.
        os.kill(os.getpid(), signal.SIGTERM)
    coordinator = Coordinator(ready, owner_failure)
    coordinator.thread.start(); result = {'status': 'FAIL', 'method': METHOD, 'reference_qualified': False,
        'all_record_validation': 'NOT RUN', 'canonical_fresh': 'NOT RUN'}
    try:
        command = ['/usr/bin/setpriv', '--reuid=65534', '--regid=65534', '--clear-groups', '--',
            '/usr/bin/env', 'HOME=' + str(BASE / 'home'), 'GIT_OPTIONAL_LOCKS=0',
            'GIT_CONFIG_COUNT=1', 'GIT_CONFIG_KEY_0=safe.directory', 'GIT_CONFIG_VALUE_0=' + str(ROOT),
            'PYTHONDONTWRITEBYTECODE=1', '/usr/bin/python3', str(ROOT / 'scripts/reference_collection.py')]
        direct('full-collection', command,
            timeout=max(.001, (measure['deadline_monotonic_ns'] - time.monotonic_ns()) / 10**9),
            inputs=(INPUT, BASE / 'measurement-config.json', BASE / 'export-config.json'))
        result['collection'] = read_json(BASE / 'exports/collection-result.json')
        require(result['collection']['status'] == 'COLLECTED'
            and [row['stage'] for row in result['collection']['campaigns']] == list(STAGES),
            'original guest command did not collect every required campaign')
        probe_identity(payload)
        result['status'] = 'COLLECTED'
    except (Exception, KeyboardInterrupt) as error:
        failed(result, 'collection-owner', error)
    finally:
        # Close both threads even after original command/source failure.
        result['coordination'] = coordinator.close()
        if (result['coordination']['status'] != 'OBSERVED'
            or result['coordination']['armed_stages'] != list(STAGES)
            or result['coordination']['missing_stages']): result['status'] = 'FAIL'
        write_json(BASE / 'exports/guest-result.json', result)
    return result


def main():
    if (platform.system() != 'Linux' or not hasattr(os, 'geteuid') or os.geteuid() != 0
        or ROOT != Path('/work/c') or not MARKER.is_file()
        or MARKER.read_text().strip() != 'owned-ephemeral-full-collection'):
        print('BLOCKED: requires the owned mounted ephemeral full guest'); return 77
    started_ns = time.monotonic_ns(); payload = read_json(INPUT)
    require(payload.get('mode') == METHOD and payload.get('reference_qualified') is False,
            'original full collection payload required')
    # Check the exact incoming public/Git/build file map before creating any
    # full-route outputs. The original pilot exclusions remain untouched.
    require(payload_files(ROOT) == payload['files'], 'incoming full payload bytes differ')
    for name in ('exports', 'exports/packages', 'raw', 'raw-receipts', 'home', 'commands', 'control'):
        (BASE / name).mkdir(parents=True, exist_ok=False)
    for number in (signal.SIGTERM, signal.SIGINT): signal.signal(number, interrupted)
    ownership = LinuxOwnedChildren(); result = {'status': 'FAIL', 'method': METHOD, 'reference_qualified': False}
    try: result = collect(payload, ownership, started_ns)
    except (Exception, KeyboardInterrupt) as error:
        failed(result, 'guest-owner', error)
        write_json(BASE / 'exports/guest-result.json', result)
        attempt(result, 'guest-failure-event', lambda: emit('guest-failure', status='FAIL', error=type(error).__name__))
    finally:
        for number in (signal.SIGTERM, signal.SIGINT): signal.signal(number, signal.SIG_IGN)
        result['cleanup'] = ownership.finish(None)
        if result['cleanup']['status'] != 'PASS': result['status'] = 'FAIL'
        write_json(BASE / 'exports/guest-result.json', result)
        attempt(result, 'sync', os.sync)
    attempt(result, 'guest-exit-event', lambda: emit('guest-exit', status=result['status']))
    write_json(BASE / 'exports/guest-result.json', result)
    if result['status'] == 'COLLECTED':
        # Keep the actual allocation alive for one full allowed sampling gap
        # after the exit marker. The host must obtain a real final observation;
        # this finite finish overhead cannot stand in for that observation.
        result['post_collection_observation_hold'] = {'started_monotonic_ns': time.monotonic_ns(), 'seconds': 15}
        time.sleep(15)
        result['post_collection_observation_hold']['finished_monotonic_ns'] = time.monotonic_ns()
        write_json(BASE / 'exports/guest-result.json', result)
    return 0 if result['status'] == 'COLLECTED' else 1


if __name__ == '__main__': raise SystemExit(main())
