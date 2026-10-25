"""Actual scoped Linux root-to-existing-runner read-permission control only."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import archive_capture
from canonical_reference_allocation import require
from canonical_reference_host_setup import actual_controller
from export_canonical_failure import export_prefix
from canonical_reference_guest_owner import nonroot
from canonical_reference_device import UID, GID, check_marker
import canonical_reference_boot as boot
from tests.reference.test_canonical_reference_boot import create_actual_marker_fixture


def emit_marker_child_observation(command, outcome, returncode, stdout, stderr):
    """Keep original child bytes in the existing outer evidence stdout sink."""
    def stream(raw):
        return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'base64': base64.b64encode(raw).decode('ascii'),
            'text_utf8_backslashreplace': raw.decode('utf-8', errors='backslashreplace')}
    record = {'command': list(command), 'outcome': outcome, 'returncode': returncode,
        'timeout_seconds': 10, 'stdout': stream(stdout), 'stderr': stream(stderr),
        'bootstrap_sha256': hashlib.sha256(boot.BOOTSTRAP.encode()).hexdigest(),
        'scope': 'Unqualified marker-child observation only; success/identity/permissions not yet validated'}
    print(json.dumps({'canonical_marker_child_observation': record}), flush=True)


def run_marker_child(command):
    try:
        result = subprocess.run(command, cwd='/', capture_output=True, timeout=10, check=False)
    except subprocess.TimeoutExpired as error:
        emit_marker_child_observation(command, 'TIMEOUT', None, error.stdout or b'', error.stderr or b'')
        raise
    emit_marker_child_observation(command, 'EXECUTED', result.returncode, result.stdout, result.stderr)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--run-as', required=True); args = parser.parse_args()
    actual_controller(); account = pwd.getpwnam(args.run_as)
    require(account.pw_uid != 0, 'existing nonroot consumer required')
    out = archive_capture.owned(args.out)
    require(not out.exists() and out.parent.is_dir(), 'new permission control output required')
    out.mkdir(mode=0o755); os.chmod(out, 0o755)
    protected = out / 'protected'; protected.mkdir(mode=0o700)
    original = protected / 'literal.raw'; raw = b'SYNTHETIC PERMISSION CONTROL ONLY; not query or execution evidence\n'
    original.write_bytes(raw); os.chmod(original, 0o600)
    before = [(path.stat().st_uid, path.stat().st_gid, path.stat().st_mode, path.stat().st_mtime_ns) for path in (protected, original)]
    child = 'import hashlib,sys;from pathlib import Path;print(hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest())'
    def read_as_consumer(path):
        started = time.monotonic()
        result = subprocess.run(['runuser', '-u', args.run_as, '--', '/usr/bin/python3', '-c', child, str(path)],
            capture_output=True, timeout=10, check=False)
        return result, time.monotonic() - started
    denied, denied_seconds = read_as_consumer(original)
    (out / 'before-stdout.txt').write_bytes(denied.stdout); (out / 'before-stderr.txt').write_bytes(denied.stderr)
    require(denied.returncode != 0 and b'PermissionError' in denied.stderr, 'original root-private bytes were unexpectedly readable')
    archive = out / 'readable.zip'
    result = export_prefix([('fixture', protected)], archive, budget_seconds=10, owner_sha256=None)
    require(result['reference_qualified'] is False, 'permission control cannot qualify reference execution')
    with zipfile.ZipFile(archive) as bundle:
        manifest = json.loads(bundle.read('manifest.json'))
        require(len(manifest['files']) == 1 and manifest['files'][0]['sha256'] == hashlib.sha256(raw).hexdigest(),
            'literal permission fixture bytes changed')
        require(bundle.read('objects/' + manifest['files'][0]['sha256']) == raw, 'literal permission export bytes differ')
    readable, readable_seconds = read_as_consumer(archive)
    (out / 'after-stdout.txt').write_bytes(readable.stdout); (out / 'after-stderr.txt').write_bytes(readable.stderr)
    require(readable.returncode == 0 and readable.stdout.decode().strip() == result['archive_sha256'],
        'existing nonroot consumer cannot read exact exported bytes')
    require(before == [(path.stat().st_uid, path.stat().st_gid, path.stat().st_mode, path.stat().st_mtime_ns) for path in (protected, original)]
        and original.read_bytes() == raw, 'original permissions/ownership/bytes changed')
    # Execute the actual bootstrap creation fragment at a synthetic destination
    # and use the same UID/GID/cleared-groups prefix as the real device probe.
    marker_child = '''import hashlib,json,os,sys
from pathlib import Path
path=Path(sys.argv[1]);raw=path.read_bytes()
denied=False
try:
    with path.open('wb') as stream:stream.write(b'UNEXPECTED WRITE')
except PermissionError:denied=True
print(json.dumps({'uid':os.getuid(),'gid':os.getgid(),'groups':os.getgroups(),
    'marker_sha256':hashlib.sha256(raw).hexdigest(),'write_denied':denied}))
raise SystemExit(0 if denied else 1)
'''
    # A disposable tiny fixture avoids relying on traversal of the runner's
    # private home. Original project files/permissions are never changed.
    with tempfile.TemporaryDirectory(prefix='rill-marker-permission-') as directory:
        os.chmod(directory, 0o755); marker = Path(directory) / 'marker'
        previous = os.umask(0o077)
        try: create_actual_marker_fixture(marker)
        finally: os.umask(previous)
        marker_command = nonroot(['/usr/bin/python3', '-I', '-c', marker_child, str(marker)])
        marker_result = run_marker_child(marker_command)
        require(marker_result.returncode == 0, 'actual bootstrap marker is not readable and protected for the real nonroot probe identity')
        marker_observed = json.loads(marker_result.stdout)
        check_marker(marker.lstat(), marker.read_bytes())
        require(marker_observed['uid'] == UID and marker_observed['gid'] == GID and marker_observed['groups'] == []
            and marker_observed['write_denied'] is True and marker.stat().st_uid == marker.stat().st_gid == 0
            and marker.stat().st_mode & 0o7777 == 0o444
            and marker.read_bytes() == b'owned-ephemeral-canonical-reference\n'
            and marker_observed['marker_sha256'] == hashlib.sha256(marker.read_bytes()).hexdigest(), 'actual marker/identity/permissions differ')
    record = {'status': 'PASS', 'scope': 'Actual cross-UID read permission control on tiny explicitly synthetic fixture only; no VM/native/campaign/remote upload claim',
        'root_uid': os.geteuid(), 'consumer_uid': account.pw_uid, 'consumer': account.pw_name,
        'original_read_exit_code': denied.returncode, 'export_read_exit_code': readable.returncode,
        'original_mode_unchanged': True, 'archive_sha256': result['archive_sha256'], 'reference_qualified': False,
        'denied_seconds': denied_seconds, 'readable_seconds': readable_seconds}
    record['canonical_marker_control'] = {'status': 'PASS', 'observed': marker_observed,
        'producer_umask': 0o077,
        'actual_exit_code': marker_result.returncode, 'raw_stdout': marker_result.stdout.decode(),
        'raw_stderr': marker_result.stderr.decode(), 'bootstrap_sha256': hashlib.sha256(boot.BOOTSTRAP.encode()).hexdigest(),
        'scope': 'Actual Linux creation and UID65534 read/write check of unchanged bootstrap fragment at a synthetic path; no actual guest/VM/device or allocation claim'}
    (out / 'result.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(record)); return 0


if __name__ == '__main__': raise SystemExit(main())
