"""Own one actual native bootstrap/verify/demo under a prior guest allocation.

The new host controller must supply the original positive grant before calling
this entry point, enforce its own lifetime and receive the unchanged inner CAS
frames. This component does not launch a VM or declare that a provider budget
fits. Native tools must already exist; no host-built first-party target is used.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import signal
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import canonical_reference_allocation as allocation
import canonical_reference_guest_allocation as guest_allocation
from canonical_reference_attempt_check import check_fresh
from canonical_reference_coordination import CanonicalCoordinator
from canonical_reference_observer import CanonicalObserver
from canonical_reference_reservation import durable_mkdir, fsync_directory
from inspect_reference_guest import TrialCommands, interrupted
from kvm_pilot_common import write_json
from kvm_reference_common import METHOD as INNER_METHOD, STAGES, strict_json
import canonical_reference_device as capture_device
from owned_process import LinuxOwnedChildren
import reference_allocation as original
import reference_measurement_barrier as barrier
import reference_capture_export as exporter

BASE = ROOT / '.local-runs/canonical-attempt'
HOME = ROOT / '.local-runs/canonical-home'
PREFIX = 'RILLSCOPE_CANONICAL_REFERENCE_V1 '


def command_budget(cutoff_ns, now_ns, retention_seconds):
    allocation.require(all(allocation.integer(value) for value in (cutoff_ns, now_ns, retention_seconds))
        and 1 <= retention_seconds <= 600 and 0 < cutoff_ns - now_ns <= allocation.MAX_LEASE_NS,
        'explicit finite original guest cutoff and retention reserve required')
    seconds = (cutoff_ns - now_ns) // 10**9 - retention_seconds
    allocation.require(seconds >= 660, 'guest lease leaves no finite canonical/cleanup budget')
    return seconds


def inner_configurations(commit, source_sha256, boot_id, cutoff_ns, *, session):
    allocation.require(allocation.hex_value(commit, 40) and allocation.hex_value(source_sha256, 64)
        and allocation.boot(boot_id) and allocation.hex_value(session, 32)
        and allocation.integer(cutoff_ns), 'exact original inner identities and deadline required')
    common = {'schema_version': 1, 'method': INNER_METHOD, 'commit': commit,
        'source_sha256': source_sha256, 'deadline_monotonic_ns': cutoff_ns}
    measure = {**common, 'boot_id': boot_id, 'session': session,
        'control_root': barrier.CONTROL_ROOT.as_posix(), 'handshake_seconds': 30, 'reference_qualified': False}
    export = {**common, 'transfer_seconds': 180}
    return measure, export


def emit(phase, *, commit, source_sha256, boot_id, allocation_sha256, **fields):
    expected = {'prefix-start': set(), 'ready': {'stage', 'request_sha256', 'config_sha256'},
        'attempt-end': {'status'}}
    allocation.require(phase in expected and set(fields) == expected[phase]
        and allocation.hex_value(commit, 40) and allocation.hex_value(source_sha256, 64)
        and allocation.boot(boot_id) and allocation.hex_value(allocation_sha256, 64),
        'closed actual new-method lifecycle event required')
    if phase == 'ready':
        allocation.require(fields['stage'] == 'grid'
            and allocation.hex_value(fields['request_sha256'], 64)
            and allocation.hex_value(fields['config_sha256'], 64), 'exact first original measured request required')
    if phase == 'attempt-end': allocation.require(fields['status'] in {'PASS', 'FAIL'}, 'closed actual attempt status required')
    row = {'schema_version': 1, 'method': allocation.METHOD, 'phase': phase,
        'commit': commit, 'source_sha256': source_sha256, 'boot_id': boot_id,
        'allocation_sha256': allocation_sha256, 'utc_ns': time.time_ns(),
        'monotonic_ns': time.monotonic_ns(), 'reference_qualified': False, **fields}
    raw = json.dumps(row, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')
    allocation.require(len(raw) < allocation.FRAME_LIMIT, 'bounded new-method lifecycle frame required')
    print(PREFIX + base64.b64encode(raw).decode('ascii'), flush=True)
    return row


def existing_runtime():
    allocation.require(platform.system() == 'Linux' and hasattr(os, 'geteuid') and os.geteuid() == 0
        and ROOT == Path('/work/c'), 'BLOCKED: actual existing owned canonical Linux root guest required')
    allocation.require(original.read_bounded(guest_allocation.MARKER, 128) == guest_allocation.MARKER_VALUE
        and guest_allocation.MARKER.lstat().st_uid == 0, 'actual root-owned canonical guest marker required')
    import pwd
    account = pwd.getpwnam('nobody')
    allocation.require(account.pw_uid == account.pw_gid == 65534, 'existing nonroot guest identity differs')
    allocation.require(not (ROOT / 'target').exists(), 'host-built or prior first-party target forbidden in native seed')
    for path in (HOME, HOME / '.cargo', HOME / '.rustup'):
        info = path.lstat()
        allocation.require(stat.S_ISDIR(info.st_mode) and not path.is_symlink()
            and info.st_uid == 65534 and not stat.S_IMODE(info.st_mode) & 0o022,
            'existing prepared nonroot native tool home required')
    allocation.require(not any((ROOT / '.local-runs').glob('clean-*')), 'one new original canonical attempt only')


def nonroot(command):
    return ['/usr/bin/setpriv', '--reuid=65534', '--regid=65534', '--clear-groups', '--',
        '/usr/bin/env', 'HOME=' + str(HOME), 'CARGO_HOME=' + str(HOME / '.cargo'),
        'RUSTUP_HOME=' + str(HOME / '.rustup'), 'CARGO_INCREMENTAL=0',
        'PATH=' + str(HOME / '.cargo/bin') + ':/usr/bin:/bin', 'GIT_OPTIONAL_LOCKS=0',
        'GIT_CONFIG_GLOBAL=' + str(ROOT.parent / 'canonical-git-trust/config'),
        'GIT_CONFIG_COUNT=2', 'GIT_CONFIG_KEY_0=safe.directory', 'GIT_CONFIG_VALUE_0=' + str(ROOT),
        'GIT_CONFIG_KEY_1=safe.directory', 'GIT_CONFIG_VALUE_1=' + str(ROOT / '.git'),
        'PYTHONDONTWRITEBYTECODE=1', *command]


def retain_original_outputs(direct, *, cutoff_ns, retention_seconds, identity, receipt_path):
    """Both retention steps spend one original reserve; retain failures too."""
    allocation.require(type(cutoff_ns) is int and type(retention_seconds) is int
        and 1 <= retention_seconds <= 600, 'finite original retention reserve required')
    started_ns = time.monotonic_ns()
    deadline = min(cutoff_ns, started_ns + retention_seconds * 10**9)
    row = {'status': 'FAIL', 'started_monotonic_ns': started_ns, 'cutoff_monotonic_ns': deadline,
        'native_binaries': 'NOT RUN', 'release_metadata': 'NOT RUN', 'errors': []}
    for name, command, key in [
        ('retain-native-binaries', ['/usr/bin/python3', str(ROOT / 'scripts/canonical_reference_binaries.py'),
            '--out', str(BASE / 'native-binaries'), '--commit', identity['commit'],
            '--source-sha256', identity['source_sha256'], '--cutoff-monotonic-ns', str(deadline)], 'native_binaries'),
        ('retain-canonical', ['/usr/bin/python3', str(ROOT / 'scripts/retain_release.py'),
            '--out', str(BASE / 'retained')], 'release_metadata')]:
        try:
            seconds = (deadline - time.monotonic_ns()) / 10**9
            allocation.require(seconds > 0, 'original shared guest retention reserve exhausted')
            raw = direct(name, command, timeout=seconds, inputs=(receipt_path,))
            if key == 'native_binaries':
                value = strict_json(raw)
                allocation.require(value.get('status') == 'RETAINED ORIGINAL BYTES'
                    and value.get('reference_qualified') is False,
                    'original native executable retention did not complete')
            allocation.require(time.monotonic_ns() < deadline,
                'original shared guest retention reserve exhausted after child return')
            row[key] = 'RETAINED'
        except (Exception, KeyboardInterrupt) as error:
            row[key] = 'FAIL'
            row['errors'].append({'stage': key, 'error': type(error).__name__, 'reason': str(error)[:2048]})
    row['finished_monotonic_ns'] = time.monotonic_ns()
    if row['finished_monotonic_ns'] >= deadline:
        row['errors'].append({'stage': 'finalization', 'error': 'DeadlineExpired',
            'reason': 'original shared guest retention reserve exhausted before final record'})
    if not row['errors']: row['status'] = 'RETAINED'
    return row


def run_attempt(request_raw, grant_raw, *, received_ns, tail_seconds, retention_seconds):
    existing_runtime()
    allocation.require(type(tail_seconds) is int and 1 <= tail_seconds <= 600,
        'explicit original VM finish tail required')
    allocation.require(type(retention_seconds) is int and 1 <= retention_seconds <= 600,
        'explicit bounded guest retention reserve required before allocation')
    identity = original.repository_identity()
    request, grant = allocation.decode(request_raw), allocation.decode(grant_raw)
    allocation.validate_request(request, **identity); allocation.validate_grant(grant, request)
    receipt_path, cutoff = guest_allocation.record_guest_allocation(request_raw, grant_raw,
        **identity, received_ns=received_ns, tail_ns=tail_seconds * 10**9)
    receipt_sha = hashlib.sha256(original.read_bounded(receipt_path, original.DOCUMENT_LIMIT)).hexdigest()
    boot = original.observed_boot_id()
    # Root-owned sticky .local-runs permits exactly the nonroot child's new
    # clean clone while preventing it from replacing prior root allocation data.
    allocation.require((ROOT / '.local-runs').lstat().st_uid == 0, 'root-owned original guest local directory required')
    os.chmod(ROOT / '.local-runs', 0o1777)
    durable_mkdir(BASE, mode=0o700)
    for path, mode in [(barrier.CONTROL_ROOT.parent, 0o755), (barrier.CONTROL_ROOT, 0o1777),
        (barrier.CONTROL_ROOT.parent / 'exports', 0o1777)]:
        durable_mkdir(path, mode=mode)
        os.chmod(path, mode)
    measure, export = inner_configurations(**identity, boot_id=boot, cutoff_ns=cutoff, session=secrets.token_hex(16))
    for name, row, key, digest_key in [('measurement-config.json', measure, barrier.CONFIG_PATH, barrier.CONFIG_DIGEST),
        ('export-config.json', export, exporter.CONFIG_PATH, exporter.CONFIG_DIGEST)]:
        path = BASE / name; write_json(path, row); os.chmod(path, 0o444); fsync_directory(path.parent)
        os.environ[key], os.environ[digest_key] = str(path), hashlib.sha256(path.read_bytes()).hexdigest()
    os.environ['RILLSCOPE_REFERENCE_HOST_RECEIPT'] = str(receipt_path)
    os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
    observer = coordinator = None
    ownership = LinuxOwnedChildren(); direct = TrialCommands(BASE, ownership)
    result = {'schema_version': 1, 'method': allocation.METHOD, 'status': 'FAIL',
        **identity, 'allocation_sha256': hashlib.sha256(grant_raw).hexdigest(),
        'allocation_receipt_sha256': receipt_sha, 'boot_id': boot, 'cutoff_monotonic_ns': cutoff,
        'retention_reserve_seconds': retention_seconds, 'reference_qualified': False,
        'started_monotonic_ns': time.monotonic_ns(),
        'scope': 'One actual native canonical attempt only. Controller authority, host lease/samples/retention and final qualification require separate outer validation.'}
    def persist(): write_json(BASE / 'owner-result.json', result)
    event_fields = {**identity, 'boot_id': boot, 'allocation_sha256': result['allocation_sha256']}
    persist()
    for selected in (signal.SIGTERM, signal.SIGINT): signal.signal(selected, interrupted)
    try:
        def remaining():
            value = (cutoff - time.monotonic_ns()) / 10**9
            allocation.require(value > 0, 'original canonical guest lease exhausted')
            return value
        # Preserve real character-device permission/probe facts; never fabricate
        # access from a proposed mode or a successful helper import.
        device = {'grant': {}}; capture_device.grant(device['grant'])
        raw = direct('capture-device-probe', nonroot(['/usr/bin/python3',
            str(ROOT / 'scripts/canonical_reference_device.py'), 'probe']), timeout=min(15, remaining()), inputs=(receipt_path,))
        device['probe'] = strict_json(raw); capture_device.validate_access(device['grant'], device['probe'])
        write_json(BASE / 'capture-device-access.json', device)
        observer = CanonicalObserver(barrier.CONTROL_ROOT.parent / 'exports/canonical-guest-samples.jsonl', cutoff, boot)
        observer.thread.start()
        allocation.require(observer.ready.wait(min(5, remaining())) and observer.error is None,
            'actual initial canonical guest sample failed')
        def ready(stage, row):
            raw = barrier.bounded(barrier.CONTROL_ROOT / (stage + '-request.json'))
            emit('ready', **event_fields, stage=stage, request_sha256=hashlib.sha256(raw).hexdigest(),
                config_sha256=row['config_sha256'])
        def failed(_row): os.kill(os.getpid(), signal.SIGTERM)
        coordinator = CanonicalCoordinator(observer, receipt_path, receipt_sha, ready, failed)
        coordinator.thread.start()
        seconds = command_budget(cutoff, time.monotonic_ns(), retention_seconds)
        result.update(canonical_budget_seconds=seconds, canonical_started_monotonic_ns=time.monotonic_ns())
        persist(); emit('prefix-start', **event_fields)
        direct('canonical', nonroot(['/usr/bin/python3', str(ROOT / 'scripts/clean_verify.py'),
            '--budget-seconds', str(seconds)]), timeout=seconds, inputs=(receipt_path,
                BASE / 'measurement-config.json', BASE / 'export-config.json'))
        result['canonical_finished_monotonic_ns'] = time.monotonic_ns()
        allocation.require(original.repository_identity() == identity and original.observed_boot_id() == boot,
            'original source or boot changed during canonical execution')
        result['canonical_records'] = check_fresh(ROOT, **identity)
        result['status'] = 'PASS'
    except (Exception, KeyboardInterrupt) as error:
        result.update(status='FAIL', error=type(error).__name__, reason=str(error)[:2048])
    finally:
        for selected in (signal.SIGTERM, signal.SIGINT): signal.signal(selected, signal.SIG_IGN)
        # The direct command has already stopped its owned child group before
        # the endpoint. Then finalize both threads even after an original failure.
        if coordinator is not None:
            result['coordination'] = coordinator.close()
            if (result['coordination']['status'] != 'OBSERVED'
                or result['coordination']['armed_stages'] != list(STAGES)
                or result['coordination']['missing_stages']): result['status'] = 'FAIL'
        elif observer is not None:
            try: observer.close()
            except Exception as error:
                result.update(status='FAIL', observer_error=type(error).__name__ + ': ' + str(error)[:2048])
        persist()
        # Retain the exact failed/incomplete canonical attempt too. This bounded
        # process cannot convert its original failure or a diagnostic into PASS.
        try:
            retained = retain_original_outputs(direct, cutoff_ns=cutoff, retention_seconds=retention_seconds,
                identity=identity, receipt_path=receipt_path)
            result['native_retention'] = retained
            result['retention'] = retained['release_metadata']
            if retained['status'] != 'RETAINED': result['status'] = 'FAIL'
        except (Exception, KeyboardInterrupt) as error:
            result.update(status='FAIL', retention='FAIL', retention_error=type(error).__name__ + ': ' + str(error)[:2048])
        result['cleanup'] = ownership.finish(None)
        if result['cleanup']['status'] != 'PASS': result['status'] = 'FAIL'
        result['finished_monotonic_ns'] = time.monotonic_ns()
        if result['finished_monotonic_ns'] >= cutoff: result['status'] = 'FAIL'
        persist(); emit('attempt-end', **event_fields, status=result['status'])
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--grant', type=Path, required=True)
    parser.add_argument('--received-monotonic-ns', type=int, required=True)
    parser.add_argument('--tail-seconds', type=int, required=True)
    parser.add_argument('--retention-seconds', type=int, required=True)
    args = parser.parse_args()
    if platform.system() != 'Linux' or ROOT != Path('/work/c') or not hasattr(os, 'geteuid') or os.geteuid() != 0:
        print('BLOCKED: actual existing canonical Linux root guest required'); return 77
    try:
        for path in (args.request, args.grant):
            allocation.require(path.is_absolute() and path.is_relative_to(ROOT / '.local-runs')
                and path.lstat().st_uid == 0, 'original root-owned guest allocation messages required')
        result = run_attempt(original.read_bounded(args.request, allocation.FRAME_LIMIT),
            original.read_bounded(args.grant, allocation.FRAME_LIMIT), received_ns=args.received_monotonic_ns,
            tail_seconds=args.tail_seconds, retention_seconds=args.retention_seconds)
        return 0 if result['status'] == 'PASS' else 1
    except (Exception, KeyboardInterrupt) as error:
        print(json.dumps({'status': 'FAIL', 'error': type(error).__name__, 'reason': str(error)[:2048]})); return 1


if __name__ == '__main__': raise SystemExit(main())
