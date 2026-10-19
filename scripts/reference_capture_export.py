"""Optional fixed virtio export for original CAS bytes before inline validation."""
import hashlib
import os
from pathlib import Path
import re
import subprocess
import time

import archive_capture
from evidence import source_identity
from kvm_pilot_common import require, sha, write_json
from kvm_reference_common import METHOD, STAGES, identity, strict_json
from kvm_reference_channel import send_archive

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = 'RILLSCOPE_REFERENCE_EXPORT_CONFIG'
CONFIG_DIGEST = 'RILLSCOPE_REFERENCE_EXPORT_CONFIG_SHA256'


def git_identity(commit):
    command = ['git', '--no-optional-locks', '-c', 'core.fsmonitor=false', '-c', 'safe.directory=' + str(ROOT)]
    head = subprocess.check_output(command + ['rev-parse', 'HEAD'], cwd=ROOT, timeout=10).decode().strip()
    dirty = subprocess.check_output(command + ['status', '--porcelain'], cwd=ROOT, timeout=10)
    require(head == commit and not dirty.strip(), 'exporter requires the exact clean captured commit')


def read_config(path, digest):
    require(path.is_absolute() and re.fullmatch('[0-9a-f]{64}', digest) is not None,
            'absolute original config and exact expected digest required')
    for part in (path, *path.parents):
        require(not part.is_symlink() and not (hasattr(part, 'is_junction') and part.is_junction()),
                'export config cannot traverse links')
    require(path.is_file() and path.stat().st_size <= 8192, 'bounded regular export config required')
    with path.open('rb') as stream: data = stream.read(8193)
    require(len(data) <= 8192 and hashlib.sha256(data).hexdigest() == digest, 'export config bytes changed')
    row = strict_json(data)
    require(type(row) is dict and set(row) == {'schema_version', 'method', 'commit', 'source_sha256',
        'transfer_seconds', 'deadline_monotonic_ns'}, 'closed reference export config required')
    identity(row['commit'], row['source_sha256'])
    require(type(row['schema_version']) is int and row['schema_version'] == 1 and row['method'] == METHOD
        and type(row['transfer_seconds']) is int and 1 <= row['transfer_seconds'] <= 180
        and type(row['deadline_monotonic_ns']) is int
        and 0 < row['deadline_monotonic_ns'] - time.monotonic_ns() <= 21600 * 10**9,
        'finite live export budget required')
    return row, data


def export_capture(archive, stage):
    """An ACK confirms retained bytes only. Every canonical validator still runs."""
    config_path = os.environ.get(CONFIG_PATH); expected_digest = os.environ.get(CONFIG_DIGEST)
    if config_path is None and expected_digest is None:
        return {'status': 'NOT REQUESTED', 'reference_qualified': False, 'all_record_validation': 'NOT RUN'}
    archive = archive_capture.owned(Path(archive))
    result_path = archive.parent / 'host-export-result.json'
    require(not result_path.exists(), 'original host export result must not be overwritten or replayed')
    report = {'status': 'FAIL', 'stage': stage, 'method': METHOD, 'reference_qualified': False,
        'all_record_validation': 'NOT RUN',
        'scope': 'Original CAS export only; upstream collection, inline validation, allocation and canonical fresh results remain separate'}
    try:
        require(stage in STAGES and config_path is not None and expected_digest is not None,
                'closed stage and both original config fields required')
        config_path = Path(config_path)
        config, original_config = read_config(config_path, expected_digest)
        report.update(config_sha256=expected_digest, commit=config['commit'], source_sha256=config['source_sha256'])
        require(source_identity(ROOT)['sha256'] == config['source_sha256'], 'exporter exact source differs')
        git_identity(config['commit'])
        report['archive_sha256'] = sha(archive, archive_capture.MAX_ARCHIVE)
        deadline = min(time.monotonic() + config['transfer_seconds'], config['deadline_monotonic_ns'] / 10**9)
        report['host_transfer'] = send_archive(archive, stage, deadline,
            commit=config['commit'], source_sha256=config['source_sha256'])
        require(report['host_transfer']['status'] == 'HOST ACKNOWLEDGED'
            and report['host_transfer']['sha256'] == report['archive_sha256'], 'verified original host ACK missing')
        _config_after, config_after = read_config(config_path, expected_digest)
        require(config_after == original_config and source_identity(ROOT)['sha256'] == config['source_sha256']
            and sha(archive, archive_capture.MAX_ARCHIVE) == report['archive_sha256'],
            'source/config/archive changed during export')
        git_identity(config['commit'])
        report['status'] = 'HOST ACKNOWLEDGED'
    except (Exception, KeyboardInterrupt) as error:
        report.update(error=type(error).__name__, reason=str(error)[:2048])
    # The package directory is owned by the caller. A write failure remains a
    # real exception to the canonical gate; it can never be converted to success.
    write_json(result_path, report)
    return report
