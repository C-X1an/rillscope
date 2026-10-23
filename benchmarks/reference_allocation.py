"""Bind a genuine operator allocation document to this actual Linux preflight.

Hardware inspection cannot establish dedication. The operator's positive
allocation statement and its original supporting evidence are mandatory inputs.
This produces a private input to reference_gate, never a benchmark verdict.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
from evidence import source_identity
from reference_gate import host_reasons
from run import environment

METHOD = 'rillscope-reference-allocation-preflight-v1'
DOCUMENT_LIMIT = 65536
EVIDENCE_LIMIT = 2 * 1024**2
DOCUMENT_DEPTH = 8
FIELDS = {'schema_version', 'source', 'dedicated', 'operator', 'allocation_id',
    'evidence_sha256', 'commit', 'source_sha256', 'boot_id',
    'inspected_monotonic_ns', 'expires_monotonic_ns', 'system', 'machine',
    'logical_processors', 'cpu_model', 'configured_memory_bytes'}
STABLE_ENVIRONMENT = ('system', 'machine', 'logical_processors', 'cpu_model',
    'physical_memory_bytes', 'resource_inspection_status', 'effective_cpu_capacity',
    'process_affinity_cpu_count', 'cgroup_memory_limit_bytes', 'cgroup_memory_high_bytes')


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate allocation JSON key')
        value[key] = item
    return value


def invalid_constant(_value):
    raise ValueError('nonfinite allocation JSON constant')


def decode_document(raw):
    require(isinstance(raw, bytes) and len(raw) <= DOCUMENT_LIMIT, 'bounded allocation document required')
    # Bound structure before decoding; quoted braces and escaped quotes are
    # data. The actual closed allocation schema contains scalar fields only.
    depth = 0
    quoted = escaped = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (123, 91):
            depth += 1
            require(depth <= DOCUMENT_DEPTH, 'allocation JSON nesting exceeds decoding bound')
        elif byte in (125, 93):
            depth -= 1
    try:
        return json.loads(raw, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    except RecursionError as error:
        raise ValueError('allocation JSON nesting exceeds decoding bound') from error


def read_bounded(path, limit):
    """Read one regular input without following links or accepting replacement."""
    path = Path(path).absolute()
    # Windows8.3 aliases can resolve to another spelling of the same regular
    # file. Check every component for links before normalizing its spelling.
    for component in (path, *path.parents):
        info = component.lstat()
        require(not stat.S_ISLNK(info.st_mode)
            and getattr(info, 'st_reparse_tag', 0) not in (0xA0000003, 0xA000000C),
            'link-free input required')
    path = path.resolve(strict=True)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, 'bounded regular input required')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        require((before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino)
            and stat.S_ISREG(opened.st_mode), 'input replaced before open')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            raw = stream.read(limit + 1)
        after = os.fstat(descriptor)
        signature = lambda value: (value.st_dev, value.st_ino, value.st_mode,
                                  value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        require(len(raw) <= limit and signature(opened) == signature(after), 'input changed or exceeded bound')
        # Keep each metadata API's before/after check. Native Windows path
        # and descriptor ctime values can differ for the same unchanged file.
        require(signature(before) == signature(path.lstat()), 'input path replaced during read')
        return raw
    finally:
        os.close(descriptor)


def text(value, maximum):
    return (type(value) is str and 0 < len(value.encode('utf-8')) <= maximum
            and all(ord(char) >= 32 and ord(char) != 127 for char in value))


def hex_value(value, length):
    return type(value) is str and re.fullmatch('[0-9a-f]{' + str(length) + '}', value) is not None


def observed_boot_id():
    value = read_bounded(Path('/proc/sys/kernel/random/boot_id'), 128).decode('ascii').strip()
    require(re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', value) is not None,
            'actual Linux boot identity unavailable')
    return value


def repository_identity():
    def git(*arguments):
        return subprocess.check_output(['git', '-c', 'core.fsmonitor=false', '-c',
            'core.untrackedCache=false', *arguments], cwd=ROOT, text=True,
            stdin=subprocess.DEVNULL, timeout=15).strip()
    require(not git('status', '--porcelain'), 'committed clean source required for allocation preflight')
    commit = git('rev-parse', 'HEAD')
    require(hex_value(commit, 40), 'exact committed source required')
    return {'commit': commit, 'source_sha256': source_identity(ROOT)['sha256']}


def validate(document, actual, identity, boot_id, now_ns, evidence_sha256):
    require(type(document) is dict and set(document) == FIELDS, 'closed operator allocation document required')
    require(type(document['schema_version']) is int and document['schema_version'] == 1,
            'allocation schema version differs')
    require(document['source'] == 'actual host allocation and inspection'
        and document['dedicated'] is True, 'genuine positive operator dedication statement required')
    require(text(document['operator'], 256) and hex_value(document['allocation_id'], 32),
            'bounded operator and exact allocation identity required')
    require(hex_value(document['evidence_sha256'], 64)
        and document['evidence_sha256'] == evidence_sha256, 'original allocation evidence digest differs')
    require(hex_value(document['commit'], 40) and hex_value(document['source_sha256'], 64)
        and document['commit'] == identity['commit']
        and document['source_sha256'] == identity['source_sha256'], 'allocation source identity differs')
    require(type(document['boot_id']) is str and document['boot_id'] == boot_id,
            'allocation boot identity differs')
    require(all(type(value) is int and 0 < value < 2**63 for value in
        (document['inspected_monotonic_ns'], document['expires_monotonic_ns'], now_ns)),
        'exact bounded allocation clocks required')
    require(document['inspected_monotonic_ns'] <= now_ns < document['expires_monotonic_ns'],
            'allocation inspection is future-dated or its lease has expired')
    require(document['system'] == 'Linux' and type(document['logical_processors']) is int
        and document['logical_processors'] == 4
        and type(document['configured_memory_bytes']) is int
        and document['configured_memory_bytes'] == 8 * 1024**3,
        'documented four-CPU8GiB Linux allocation required')
    require(text(document['machine'], 32) and text(document['cpu_model'], 512),
            'bounded architecture and CPU identity required')
    require(type(actual) is dict and all(name in actual for name in STABLE_ENVIRONMENT),
            'complete actual resource inspection required')
    require(type(actual['logical_processors']) is int and type(actual['process_affinity_cpu_count']) is int
        and type(actual['physical_memory_bytes']) is int
        and type(actual['effective_cpu_capacity']) in (int, float), 'exact measured resource types required')
    require(all(value is None or type(value) is int and value > 0 for value in
        (actual['cgroup_memory_limit_bytes'], actual['cgroup_memory_high_bytes'])),
        'actual cgroup limits are malformed')
    require(not host_reasons(actual, document), 'actual resource configuration differs from reference allocation')
    # This is the operator's assertion bound to actual facts, not a deduction
    # of exclusivity from CPU/memory/virtualization or a benchmark PASS.
    return {'method': METHOD, 'status': 'RECORDED', 'reference_qualified': False,
        'source': document['source'], 'dedicated': True,
        'logical_processors': document['logical_processors'], 'machine': document['machine'],
        'cpu_model': document['cpu_model'], 'operator_allocation': document,
        'actual_environment': actual, 'actual_source': identity, 'actual_boot_id': boot_id,
        'preflight_monotonic_ns': now_ns,
        'scope': 'Private operator allocation input and actual preflight only; complete benchmark, continuity, target and canonical fresh verdicts remain separate.'}


def capture(allocation, supporting_evidence, output):
    output = Path(output).absolute()
    require(not output.exists(), 'new private receipt output required')
    resolved = output.resolve()
    require(not resolved.is_relative_to(ROOT) or resolved.is_relative_to(ROOT / '.local-runs'),
            'private allocation receipts must stay outside public source paths')
    raw = read_bounded(allocation, DOCUMENT_LIMIT)
    evidence = read_bounded(supporting_evidence, EVIDENCE_LIMIT)
    require(len(evidence) > 0, 'nonempty original allocation evidence required')
    document = decode_document(raw)
    actual, identity, boot_id = environment(), repository_identity(), observed_boot_id()
    result = validate(document, actual, identity, boot_id, time.monotonic_ns(), hashlib.sha256(evidence).hexdigest())
    require(read_bounded(allocation, DOCUMENT_LIMIT) == raw
        and read_bounded(supporting_evidence, EVIDENCE_LIMIT) == evidence, 'allocation inputs changed during preflight')
    require(repository_identity() == identity and observed_boot_id() == boot_id,
            'source or boot changed during preflight')
    after = environment()
    require(all(after.get(name) == actual[name] for name in STABLE_ENVIRONMENT),
            'actual resource configuration changed during preflight')
    validate(document, after, identity, boot_id, time.monotonic_ns(), hashlib.sha256(evidence).hexdigest())
    result.update(operator_document_sha256=hashlib.sha256(raw).hexdigest(),
        allocation_evidence_sha256=hashlib.sha256(evidence).hexdigest(),
        allocation_evidence_bytes=len(evidence), inputs_and_source_stable=True)
    encoded = (json.dumps(result, indent=2) + '\n').encode('utf-8')
    require(len(encoded) <= DOCUMENT_LIMIT, 'bounded private receipt required')
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('xb') as stream:
        stream.write(encoded)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--allocation', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    if platform.system() != 'Linux':
        print(json.dumps({'status': 'BLOCKED', 'reference_qualified': False,
                          'reason': 'actual Linux reference allocation unavailable on this runtime'}))
        return 77
    try:
        result = capture(args.allocation, args.evidence, args.out)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError) as error:
        print(json.dumps({'status': 'FAIL', 'reference_qualified': False,
                          'reason': type(error).__name__ + ': ' + str(error)[:1024]}))
        return 1
    print(json.dumps({'status': result['status'], 'reference_qualified': False,
                      'operator_document_sha256': result['operator_document_sha256'],
                      'scope': result['scope']}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
