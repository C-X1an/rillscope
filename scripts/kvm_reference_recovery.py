"""Read stopped full-collection disks only; missing and failed data stay FAIL."""
from pathlib import Path
import re
import shutil
import time

import archive_capture
from kvm_pilot_common import require, sha, read_json, write_json
from kvm_benchmark_pilot import debugfs_command, disk_identity
from inspect_reference_guest import TrialInterrupted
from kvm_reference_common import METHOD, STAGES
from kvm_reference_channel import inspected_manifest
from kvm_reference_common import validate_scope

ROOT = Path(__file__).resolve().parents[1]


def recover(out, checked, deadline, *, artifact=None):
    """Caller must establish stopped ownership before any read or hash."""
    image = out / 'work.raw'; artifact = artifact if artifact is not None else out / 'artifact'
    artifact.mkdir(exist_ok=True)
    record = {'status': 'FAIL', 'method': METHOD, 'read_only': True, 'disk_preserved': True,
        'files': [], 'packages': [], 'errors': [], 'reference_qualified': False,
        'scope': 'Included bytes only; no mount/write/repair/journal replay, product rerun or qualification'}
    def persist(): write_json(artifact / 'recovery.json', record)
    def run(name, command):
        remaining = deadline - time.monotonic(); require(remaining > 0, 'full read-only recovery budget exhausted')
        return checked('full-recover-' + name, command, timeout=min(120, remaining))
    def attempt(name, operation):
        try: return operation()
        except TrialInterrupted: raise
        except Exception as error:
            record['errors'].append(name + ': ' + type(error).__name__ + ': ' + str(error)[:1024])
            persist(); return None
    before = attempt('disk-before', lambda: disk_identity(image, deadline)); record['disk_before'] = before
    def state_check():
        state = run('filesystem-state', ['dumpe2fs', '-h', str(image)]).decode('utf-8', errors='strict')
        (artifact / 'filesystem-state.txt').write_text(state, encoding='utf-8')
        return re.search(r'(?m)^Filesystem state:\s+clean\s*$', state) is not None
    record['filesystem_clean'] = attempt('filesystem-state', state_check)
    base = '/c/.local-runs/kvm-reference'
    def tree(name, guest_path, destination):
        destination.mkdir(parents=True, exist_ok=False)
        run(name, debugfs_command(image, guest_path, destination, directory=True))
        nested = destination / Path(guest_path).name; actual = destination
        if nested.is_dir():
            require(list(destination.iterdir()) == [nested], 'ambiguous recovered full directory')
            actual = nested
        require(any(actual.iterdir()), 'full guest tree missing or empty: ' + guest_path)
        entries = archive_capture.scan(actual)
        record['files'].append({'guest_path': guest_path, 'host_path': actual.relative_to(artifact).as_posix(),
            'files': len(entries), 'bytes': sum(row[2] for row in entries.values())})
        return actual
    exports = attempt('exports', lambda: tree('exports', base + '/exports', artifact / 'guest'))
    for guest_name, host_name in [('setup', 'guest-owner'), ('commands', 'guest-collection-commands'),
        ('raw-receipts', 'guest-command-receipts'), ('control', 'guest-control')]:
        attempt(host_name, lambda n=guest_name, h=host_name: tree(h, base + '/' + n, artifact / h))
    configs = artifact / 'guest-config'; configs.mkdir(exist_ok=False)
    for name in ('measurement-config.json', 'export-config.json'):
        def config(n=name):
            target = configs / n
            run(n, debugfs_command(image, base + '/' + n, target))
            value = read_json(target, 8192)
            require(value['method'] == METHOD, 'recovered configuration is not the original full method')
        attempt(name, config)
    # Original packages take precedence. A partial recovery is kept separately
    # and never overwrites a host-acknowledged archive or failed owner result.
    for stage in STAGES:
        package = {'stage': stage, 'origin': 'guest-original', 'status': 'FAIL'}
        target = artifact / 'packages' / stage
        def original_package():
            require(exports is not None, 'original guest exports unavailable')
            original = exports / 'packages' / stage / 'capture.zip'
            rows, metadata = archive_capture.inspect(original)
            manifest = inspected_manifest(original, rows)
            validate_scope(manifest, stage, commit=manifest['commit'] if stage != 'cancel' else
                read_json(configs / 'measurement-config.json', 8192)['commit'],
                source_sha256=manifest['source']['sha256'])
            digest = sha(original)
            if target.exists():
                require((target / 'capture.zip').is_file() and sha(target / 'capture.zip') == digest,
                        'host-acknowledged full archive differs from original guest bytes')
            else:
                target.mkdir(parents=True); shutil.copy2(original, target / 'capture.zip')
            package.update(status='VERIFIED', archive_sha256=digest, metadata=metadata)
            return True
        if not attempt('original-package-' + stage, original_package):
            def partial():
                raw = tree('raw-' + stage, base + '/raw/' + stage, artifact / 'partial-raw' / stage)
                recovered = artifact / 'partial-packages' / stage
                run('raw-pack-' + stage, [__import__('sys').executable, str(ROOT / 'scripts/archive_capture.py'),
                    'pack', '--source', str(raw), '--out', str(recovered)])
                _, metadata = archive_capture.inspect(recovered / 'capture.zip')
                package.update(status='VERIFIED INCLUDED BYTES', origin='host-recovered-raw',
                    archive_sha256=sha(recovered / 'capture.zip'), metadata=metadata)
            attempt('partial-package-' + stage, partial)
        record['packages'].append(package); persist()
    after = attempt('disk-after', lambda: disk_identity(image, deadline)); record['disk_after'] = after
    if before is None or before != after: record['errors'].append('original work disk identity missing or changed')
    if record['filesystem_clean'] is True and not record['errors'] and all(
            row['status'] == 'VERIFIED' for row in record['packages']): record['status'] = 'PASS'
    persist(); return record
