"""One guest-local handshake before each original canonical collection.

The root owner must observe real host link-down and a guest sample before
arming. This module independently checks actual guest carrier and retains
boundaries. An ARMED file never establishes allocation or qualification.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import sys
import time

from evidence import source_identity
from kvm_capture_channel import fsync_directory
from kvm_pilot_common import require
from kvm_pilot_guest import interfaces, network_down
from guest_resource_probe import snapshot
from kvm_reference_common import METHOD, STAGES, identity, strict_json
from reference_capture_export import git_identity
from feasibility_profile import exact

ROOT = Path(__file__).resolve().parents[1]
CONTROL_ROOT = Path('/work/c/.local-runs/kvm-reference/control')
CONFIG_PATH = 'RILLSCOPE_REFERENCE_MEASUREMENT_CONFIG'
CONFIG_DIGEST = 'RILLSCOPE_REFERENCE_MEASUREMENT_CONFIG_SHA256'
MAX_RECORD = 65536
REQUEST_KEYS = {'schema_version', 'method', 'session', 'stage', 'commit', 'source_sha256', 'boot_id',
                'config_sha256', 'utc_ns', 'monotonic_ns', 'reference_qualified'}


def boot_id(): return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def no_links(path):
    require(path.is_absolute(), 'absolute owned measurement path required')
    for part in (path, *path.parents):
        require(not part.is_symlink() and not (hasattr(part, 'is_junction') and part.is_junction()),
                'measurement paths cannot traverse links')


def bounded(path, limit=MAX_RECORD):
    no_links(path)
    require(path.is_file() and path.stat().st_size <= limit, 'bounded regular measurement record required')
    with path.open('rb') as stream: value = stream.read(limit + 1)
    require(len(value) <= limit, 'measurement record exceeded bound')
    return value


def exclusive_json(path, value):
    no_links(path)
    require(path.parent == CONTROL_ROOT and path.parent.is_dir(), 'exact owned guest control directory required')
    require(path.name in {stage + '-' + part + '.json' for stage in STAGES
            for part in ('request', 'armed', 'start', 'end')}, 'closed measurement record name required')
    require(not path.exists(), 'original measurement record already exists; replay forbidden')
    data = (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8')
    require(len(data) <= MAX_RECORD, 'measurement record exceeds explicit bound')
    pending = path.with_name('.' + path.name + '.pending-' + secrets.token_hex(8))
    with pending.open('xb') as stream:
        require(stream.write(data) == len(data), 'measurement write incomplete')
        stream.flush(); os.fsync(stream.fileno())
    # Same-filesystem hard linking publishes complete bytes atomically and
    # fails if an original destination appeared. Failed pending bytes remain.
    os.link(pending, path, follow_symlinks=False); fsync_directory(path.parent)
    pending.unlink(); fsync_directory(path.parent)
    return hashlib.sha256(data).hexdigest()


def configuration(*, live=True):
    name = os.environ.get(CONFIG_PATH); digest = os.environ.get(CONFIG_DIGEST)
    if name is None and digest is None: return None
    require(platform.system() == 'Linux' and name is not None and digest is not None,
            'configured measurement barrier requires actual Linux and both input fields')
    require(re.fullmatch('[0-9a-f]{64}', digest) is not None, 'exact original measurement config hash required')
    path = Path(name); data = bounded(path, 8192)
    require(hashlib.sha256(data).hexdigest() == digest, 'measurement config bytes changed')
    row = strict_json(data)
    require(type(row) is dict and set(row) == {'schema_version', 'method', 'commit', 'source_sha256', 'boot_id',
        'session', 'control_root', 'deadline_monotonic_ns', 'handshake_seconds', 'reference_qualified'},
        'closed measurement config required')
    identity(row['commit'], row['source_sha256'])
    require(type(row['schema_version']) is int and row['schema_version'] == 1 and row['method'] == METHOD
        and row['reference_qualified'] is False and row['control_root'] == str(CONTROL_ROOT)
        and isinstance(row['session'], str) and re.fullmatch('[0-9a-f]{32}', row['session'])
        and isinstance(row['boot_id'], str) and row['boot_id'] == boot_id()
        and re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', row['boot_id'])
        and type(row['deadline_monotonic_ns']) is int and row['deadline_monotonic_ns'] > 0
        and type(row['handshake_seconds']) is int and 1 <= row['handshake_seconds'] <= 30,
        'measurement identity/boot/lifetime differs')
    remaining = row['deadline_monotonic_ns'] - time.monotonic_ns()
    require(remaining <= 21600 * 10**9 and (remaining > 0 or not live), 'measurement whole-attempt deadline exhausted')
    no_links(CONTROL_ROOT); require(CONTROL_ROOT.is_dir(), 'existing owned guest control directory required')
    require(source_identity(ROOT)['sha256'] == row['source_sha256'], 'measurement source differs')
    git_identity(row['commit'])
    return {'path': path, 'bytes': data, 'sha256': digest, 'value': row}


def boundary(token, position, code=None, error=None):
    stage = token['stage']; row = token['request']
    started = time.monotonic_ns(); cpu = time.thread_time_ns()
    record = {**row, 'position': position, 'status': 'FAIL', 'collection_exit_code': code}
    try:
        record['sample'] = snapshot('reference-' + stage + '-' + position)
        record['network'] = interfaces()
        require(record['sample']['boot_id'] == row['boot_id'], 'measurement guest boot changed')
        network_down(record['network'])
        record['status'] = 'OBSERVED'
    except Exception as fault:
        record.update(error=type(fault).__name__, reason=str(fault)[:2048])
    if error is not None: record['collection_error'] = type(error).__name__
    record.update(observer_wall_ns=time.monotonic_ns() - started, observer_cpu_ns=time.thread_time_ns() - cpu)
    exclusive_json(CONTROL_ROOT / (stage + '-' + position + '.json'), record)
    require(record['status'] == 'OBSERVED', 'measurement resource/network boundary failed: ' + record.get('reason', 'unknown'))


def begin(stage):
    config = configuration()
    if config is None: return None
    require(stage in STAGES, 'closed original measurement stage required')
    for other in STAGES:
        path = CONTROL_ROOT / (other + '-request.json')
        if not path.exists(): continue
        require(STAGES.index(other) < STAGES.index(stage) and (CONTROL_ROOT / (other + '-end.json')).is_file(),
                'measurement stage replay, overlap or reversed order')
    row = config['value']
    request = {key: row[key] for key in ['schema_version', 'method', 'session', 'commit', 'source_sha256', 'boot_id', 'reference_qualified']}
    request.update(stage=stage, config_sha256=config['sha256'], utc_ns=time.time_ns(), monotonic_ns=time.monotonic_ns())
    digest = exclusive_json(CONTROL_ROOT / (stage + '-request.json'), request)
    deadline = min(time.monotonic() + row['handshake_seconds'], row['deadline_monotonic_ns'] / 10**9)
    armed = CONTROL_ROOT / (stage + '-armed.json')
    while not armed.exists():
        require(time.monotonic() < deadline, 'measurement parent acknowledgement deadline exhausted')
        time.sleep(.01)
    require(time.monotonic() < deadline, 'measurement parent acknowledgement deadline exhausted')
    ack = strict_json(bounded(armed))
    require(type(ack) is dict and set(ack) == REQUEST_KEYS | {'status', 'request_sha256'}
        and ack.get('status') == 'ARMED' and ack.get('request_sha256') == digest
        and all(exact(ack.get(key), value) for key, value in request.items() if key not in {'utc_ns', 'monotonic_ns'})
        and all(type(ack.get(key)) is int and ack[key] > 0 for key in ['utc_ns', 'monotonic_ns'])
        and request['monotonic_ns'] <= ack['monotonic_ns'] <= time.monotonic_ns(),
        'measurement parent acknowledgement differs from exact source/request/boot')
    require(configuration()['bytes'] == config['bytes'], 'measurement config changed before collection')
    token = {'stage': stage, 'config': config, 'request': request}
    boundary(token, 'start')
    return token


def finish(token, code, error=None):
    if token is None: return
    current = configuration(live=False)
    require(current is not None and current['bytes'] == token['config']['bytes'], 'measurement input changed during collection')
    boundary(token, 'end', code, error)


def failed_finish(token, code, error=None):
    try: finish(token, code, error)
    except Exception as fault:
        print(json.dumps({'measurement_finalization': 'FAIL', 'error': type(fault).__name__,
            'reason': str(fault)[:2048], 'original_collection_exit': code}), file=sys.stderr, flush=True)


def collect(stage, operation):
    token = begin(stage)
    try:
        code = operation()
        require(type(code) is int, 'original collection exit must be an integer')
    except BaseException as error:
        failed_finish(token, None, error); raise
    if code:
        failed_finish(token, code); return code
    finish(token, code)
    return code
