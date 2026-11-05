"""Retain diagnostic metadata after actual owner cleanup; never promote its result."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import archive_capture
import canonical_reference_allocation as allocation
from canonical_reference_host_setup import actual_controller
from canonical_reference_reservation import fsync_directory
from evidence import source_identity, verify_receipt
from kvm_reference_common import strict_json
from kvm_pilot_common import write_json

MAX_FILES = 5000
MAX_FILE = 128 * 1024**2
MAX_BYTES = 512 * 1024**2
MAX_ARCHIVE = 128 * 1024**2
SELECTED = ('diagnostic-result.json', 'utilities', 'vm/preparation', 'vm/artifact',
    'vm/SHA256SUMS', 'vm/SHA256SUMS.gpg', 'vm/ubuntu-cloud-image.asc', 'vm/image-key.gpg')


def retain(source, owner_receipt, out, budget_seconds):
    actual_controller()
    allocation.require(type(budget_seconds) is int and 1 <= budget_seconds <= 300,
        'finite original diagnostic retention budget required')
    source, owner_receipt, out = map(archive_capture.owned, (source, owner_receipt, out))
    allocation.require(not out.exists() and not out.is_relative_to(source) and out.parent.is_dir(),
        'new separate owned diagnostic archive required')
    allocation.require(owner_receipt.name == 'receipt.json' and owner_receipt.is_file()
        and owner_receipt.stat().st_size <= 4 * 1024**2, 'bounded original diagnostic owner receipt required')
    owner = strict_json(owner_receipt.read_bytes())
    command = owner.get('command')
    allocation.require(type(command) is list and len(command) == 6
        and command[0] in ('python3', '/usr/bin/python3', sys.executable)
        and command[1:4] == ['scripts/canonical_reference_diagnostic.py', '--out', source.relative_to(ROOT).as_posix()]
        and command[4] == '--run-as' and allocation.text(command[5], 32)
        and owner.get('cwd') == str(ROOT) and type(owner.get('exit_code')) is int
        and owner.get('verification_status') in ('PASS', 'FAIL')
        and owner.get('source_before', {}).get('sha256') == source_identity(ROOT)['sha256']
        and owner.get('source_after_sha256') == owner['source_before']['sha256']
        and owner.get('process_cleanup', {}).get('status') == 'PASS'
        and type(owner['process_cleanup'].get('remaining_active_processes')) is int
        and owner['process_cleanup']['remaining_active_processes'] == 0,
        'exact terminal source-bound diagnostic owner and complete actual cleanup required before retention')
    for stream in ('stdout', 'stderr'):
        allocation.require(owner.get(stream, {}).get('file') == stream + '.txt', 'closed original owner raw stream required')
    allocation.require(verify_receipt(owner_receipt), 'original diagnostic owner raw hashes differ')
    started = time.monotonic(); deadline = started + budget_seconds
    def remaining():
        allocation.require(time.monotonic() < deadline, 'original diagnostic retention deadline exhausted')
    candidates = [('owner/' + name, owner_receipt.parent / name) for name in ('receipt.json', 'stdout.txt', 'stderr.txt')]
    missing = []; entries = 0
    for relative in SELECTED:
        selected = source / relative
        if not selected.exists(): missing.append(relative); continue
        pending = [selected]
        while pending:
            path = pending.pop(); remaining(); entries += 1
            allocation.require(entries <= 2 * MAX_FILES and not path.is_symlink()
                and not (hasattr(path, 'is_junction') and path.is_junction()), 'bounded link-free diagnostic metadata required')
            if path.is_dir(): pending.extend(sorted(path.iterdir(), reverse=True)); continue
            allocation.require(path.is_file(), 'regular diagnostic metadata required')
            candidates.append(('source/' + path.relative_to(source).as_posix(), path))
    allocation.require(len(candidates) <= MAX_FILES, 'diagnostic metadata file count exceeded')
    names = set(); inventory = []; total = 0
    pending_archive = out.with_name(out.name + '.pending')
    allocation.require(not pending_archive.exists(), 'prior failed diagnostic archive must remain untouched')
    with zipfile.ZipFile(pending_archive, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for name, path in sorted(candidates):
            remaining(); archive_capture.member(name)
            allocation.require(name not in names and path.is_file() and not path.is_symlink(), 'unique regular original metadata required')
            names.add(name); before = path.stat(); total += before.st_size
            allocation.require(before.st_size <= MAX_FILE and total <= MAX_BYTES, 'diagnostic metadata file/total byte bound exceeded')
            digest = hashlib.sha256(); count = 0
            info = zipfile.ZipInfo(name); info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            with path.open('rb') as raw, bundle.open(info, 'w') as target:
                while block := raw.read(1024**2):
                    remaining(); count += len(block)
                    allocation.require(count <= before.st_size, 'original diagnostic file grew while retaining')
                    digest.update(block); target.write(block)
            after = path.stat()
            allocation.require(count == before.st_size and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'original diagnostic file changed while retaining')
            inventory.append({'path': name, 'bytes': count, 'sha256': digest.hexdigest()})
            allocation.require(pending_archive.stat().st_size <= MAX_ARCHIVE, 'diagnostic archive compressed byte bound exceeded')
        manifest = {'schema_version': 1, 'method': allocation.METHOD, 'files': inventory, 'missing_selected_paths': missing,
            'owner_exit_code': owner['exit_code'], 'owner_verification_status': owner['verification_status'],
            'source_sha256': owner['source_before']['sha256'], 'reference_qualified': False,
            'scope': 'Available original metadata/raw bytes only; upstream failure and missing data remain. No disks, tool caches or binaries included.'}
        bundle.writestr('manifest.json', json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode('utf-8'))
    allocation.require(pending_archive.stat().st_size <= MAX_ARCHIVE, 'closed diagnostic archive exceeds compressed bound')
    with zipfile.ZipFile(pending_archive) as bundle:
        allocation.require(set(bundle.namelist()) == names | {'manifest.json'}, 'diagnostic archive member set differs')
        for row in inventory:
            remaining(); digest = hashlib.sha256(); size = 0
            with bundle.open(row['path']) as stream:
                while block := stream.read(1024**2):
                    remaining(); size += len(block); digest.update(block)
            allocation.require(size == row['bytes'] and digest.hexdigest() == row['sha256'], 'retained original diagnostic bytes differ')
    with pending_archive.open('r+b') as stream: os.fsync(stream.fileno())
    os.replace(pending_archive, out); os.chmod(out, 0o644); fsync_directory(out.parent)
    result = {'status': 'RETAINED AVAILABLE ORIGINAL BYTES', 'method': allocation.METHOD,
        'archive_sha256': hashlib.sha256(out.read_bytes()).hexdigest(), 'compressed_bytes': out.stat().st_size,
        'files': len(inventory), 'logical_bytes': total, 'missing_selected_paths': missing,
        'owner_exit_code': owner['exit_code'], 'owner_verification_status': owner['verification_status'],
        'reference_qualified': False, 'canonical': 'NOT RUN', 'elapsed_seconds': time.monotonic() - started}
    allocation.require(time.monotonic() < deadline, 'original diagnostic archive finalization deadline exhausted')
    write_json(out.with_suffix('.json'), result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--owner-receipt', type=Path, required=True); parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--budget-seconds', type=int, required=True); args = parser.parse_args(argv)
    try:
        row = retain(args.source, args.owner_receipt, args.out, args.budget_seconds)
        print(json.dumps(row, sort_keys=True)); return 0
    except (Exception, KeyboardInterrupt) as error:
        print(json.dumps({'status': 'FAIL', 'error': type(error).__name__, 'reason': str(error)[:2048]}))
        return 77 if 'BLOCKED:' in str(error) else 1


if __name__ == '__main__': raise SystemExit(main())
