"""Actual scoped Linux root-to-existing-runner read-permission control only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import archive_capture
from canonical_reference_allocation import require
from canonical_reference_host_setup import actual_controller
from export_canonical_failure import export_prefix


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
    record = {'status': 'PASS', 'scope': 'Actual cross-UID read permission control on tiny explicitly synthetic fixture only; no VM/native/campaign/remote upload claim',
        'root_uid': os.geteuid(), 'consumer_uid': account.pw_uid, 'consumer': account.pw_name,
        'original_read_exit_code': denied.returncode, 'export_read_exit_code': readable.returncode,
        'original_mode_unchanged': True, 'archive_sha256': result['archive_sha256'], 'reference_qualified': False,
        'denied_seconds': denied_seconds, 'readable_seconds': readable_seconds}
    (out / 'result.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(record)); return 0


if __name__ == '__main__': raise SystemExit(main())
