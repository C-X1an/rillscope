"""Consume a prior actual controller grant with the unchanged allocation producer.

The new guest owner calls this before any canonical command. A valid message is
not an authenticated operator by itself: the outer attempt must retain and
validate the actual controller reservation, launch and QMP originals. No old
capture can be backfilled and no benchmark/fresh success is produced here.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import canonical_reference_allocation as protocol
import reference_allocation as original

MARKER = Path('/run/rillscope-owned-canonical-reference')
MARKER_VALUE = b'owned-ephemeral-canonical-reference\n'


def document_for(request_raw, grant_raw, actual, *, commit, source_sha256, boot_id,
        received_ns, inspected_ns, tail_ns):
    """Pure closed document construction; actual owner supplies original facts."""
    request, grant = protocol.decode(request_raw), protocol.decode(grant_raw)
    protocol.validate_request(request, commit=commit, source_sha256=source_sha256)
    protocol.validate_grant(grant, request)
    protocol.require(protocol.boot(boot_id) and request['boot_id'] == boot_id,
        'actual guest boot differs from the prior allocation grant')
    protocol.require(type(actual) is dict and protocol.ENV_KEYS <= set(actual),
        'complete actual current guest environment required')
    environment = {key: actual[key] for key in protocol.ENV_KEYS}
    protocol.validate_environment(environment)
    protocol.require(environment == request['environment'],
        'actual current guest resources differ from the original allocation request')
    cutoff = protocol.guest_deadline(grant, request, received_ns=received_ns,
        configured_ns=inspected_ns, tail_ns=tail_ns)
    document = {'schema_version': 1, 'source': 'actual host allocation and inspection',
        'dedicated': True, 'operator': grant['authority']['operator'],
        'allocation_id': grant['allocation_id'], 'evidence_sha256': hashlib.sha256(grant_raw).hexdigest(),
        'commit': commit, 'source_sha256': source_sha256, 'boot_id': boot_id,
        'inspected_monotonic_ns': inspected_ns, 'expires_monotonic_ns': cutoff,
        'system': actual['system'], 'machine': actual['machine'],
        'logical_processors': actual['logical_processors'], 'cpu_model': actual['cpu_model'],
        'configured_memory_bytes': 8 * 1024**3}
    protocol.require(set(document) == original.FIELDS,
        'unchanged closed sixteen-field operator schema required')
    original.validate(document, actual, {'commit': commit, 'source_sha256': source_sha256},
        boot_id, inspected_ns, hashlib.sha256(grant_raw).hexdigest())
    return document, cutoff


def record_guest_allocation(request_raw, grant_raw, *, commit, source_sha256, received_ns, tail_ns):
    """Record genuine prior grant as supporting input, then run actual preflight.

    Requires the actual owned new guest marker and existing root. The result is
    still RECORDED/reference_qualified=false from the existing producer. It is
    never a canonical ledger, a dedicated physical-host claim or benchmark PASS.
    """
    protocol.require(platform.system() == 'Linux' and hasattr(os, 'geteuid') and os.geteuid() == 0
        and ROOT == Path('/work/c'), 'BLOCKED: actual existing owned canonical Linux guest required')
    marker = original.read_bounded(MARKER, 128)
    protocol.require(marker == MARKER_VALUE and MARKER.lstat().st_uid == 0,
        'original root-owned new canonical guest marker required')
    protocol.require(original.repository_identity() == {'commit': commit, 'source_sha256': source_sha256},
        'actual clean guest source differs before allocation preflight')
    actual, boot_id = original.environment(), original.observed_boot_id()
    document, cutoff = document_for(request_raw, grant_raw, actual, commit=commit,
        source_sha256=source_sha256, boot_id=boot_id, received_ns=received_ns,
        inspected_ns=time.monotonic_ns(), tail_ns=tail_ns)
    directory = ROOT / '.local-runs/canonical-allocation'
    for component in (directory, *directory.parents):
        protocol.require(not component.is_symlink(), 'link-free actual guest allocation path required')
        if component == ROOT: break
    directory.mkdir(mode=0o755, exist_ok=False)
    descriptor = os.open(directory.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)
    protocol.require(directory.lstat().st_uid == 0 and stat.S_IMODE(directory.lstat().st_mode) == 0o755,
        'root-owned guest allocation directory required')
    originals = {'request.json.raw': request_raw, 'supporting-grant.json.raw': grant_raw,
        'operator-document.json': (json.dumps(document, sort_keys=True, indent=2) + '\n').encode('utf-8')}
    for name, raw in originals.items():
        descriptor = os.open(directory / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
        with os.fdopen(descriptor, 'wb') as stream:
            protocol.require(stream.write(raw) == len(raw), 'complete original guest allocation write required')
            stream.flush(); os.fsync(stream.fileno())
    receipt_path = directory / 'reference-host-receipt.json'
    receipt = original.capture(directory / 'operator-document.json',
        directory / 'supporting-grant.json.raw', receipt_path)
    os.chmod(receipt_path, 0o644)
    with receipt_path.open('rb') as stream: os.fsync(stream.fileno())
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)
    protocol.require(receipt['status'] == 'RECORDED' and receipt['reference_qualified'] is False
        and receipt['operator_allocation'] == document and time.monotonic_ns() < cutoff,
        'original actual preflight failed or consumed its finite guest lease')
    for name, raw in originals.items():
        protocol.require(original.read_bounded(directory / name, original.DOCUMENT_LIMIT) == raw,
            'original guest allocation inputs changed')
    return receipt_path, cutoff
