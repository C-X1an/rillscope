"""Bounded readable copy of stopped original failure bytes; never qualification."""
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
from canonical_reference_allocation import require, hex_value
from canonical_reference_host_setup import actual_controller
from canonical_reference_retained_fresh import read_bounded_file
from kvm_reference_common import strict_json
from retain_canonical_reference import SELECTED, FORBIDDEN, MAX_FILES, MAX_FILE, MAX_BYTES, MAX_ARCHIVE, MAX_DEPTH

FORMAT = 'rillscope-canonical-failure-export-v1'


def export_prefix(roots, out, *, budget_seconds, owner_sha256, expected_hashes=None):
    """Copy fixed selected roots; leave original modes/ownership/bytes untouched."""
    require(type(budget_seconds) is int and 1 <= budget_seconds <= 60, 'finite failure export budget required')
    require((owner_sha256 is None and expected_hashes is None) or
        (hex_value(owner_sha256, 64) and type(expected_hashes) is dict
         and set(expected_hashes) == {'owner/receipt.json', 'owner/stdout.txt', 'owner/stderr.txt'}
         and all(hex_value(value, 64) for value in expected_hashes.values())
         and expected_hashes['owner/receipt.json'] == owner_sha256),
        'closed exact original owner/raw snapshot binding required')
    deadline = time.monotonic() + budget_seconds
    def remaining(): require(time.monotonic() < deadline, 'original failure export cutoff exhausted')
    out = archive_capture.owned(out); pending = out.with_name(out.name + '.pending'); sidecar = out.with_suffix('.json')
    require(out.suffix == '.zip' and out.parent.is_dir() and not any(p.exists() for p in (out, pending, sidecar)),
        'new separate readable failure export required')
    require(type(roots) is list and 0 < len(roots) <= len(SELECTED) + 4, 'closed failure export roots required')
    files = {}; missing = []; total = 0; entries = 0; spellings = {}
    for prefix, selected in roots:
        remaining(); archive_capture.member(prefix); selected = archive_capture.owned(selected)
        require(not out.is_relative_to(selected), 'failure export cannot overwrite selected originals')
        if not selected.exists(): missing.append(prefix); continue
        stack = [(prefix, selected)]
        while stack:
            remaining(); name, path = stack.pop(); entries += 1
            require(entries <= 2 * MAX_FILES and len(Path(name).parts) <= MAX_DEPTH, 'failure export entry/depth bound exceeded')
            archive_capture.member(name)
            require(not FORBIDDEN.intersection(Path(name).parts), 'forbidden failure export path')
            info = path.lstat()
            require(not path.is_symlink() and not (hasattr(path, 'is_junction') and path.is_junction()),
                'failure export cannot follow links')
            require(name.casefold() not in spellings or spellings[name.casefold()] == name,
                'failure export path aliases differ')
            spellings[name.casefold()] = name
            if stat.S_ISDIR(info.st_mode):
                with os.scandir(path) as children:
                    for child in children:
                        remaining(); require(entries + len(stack) < 2 * MAX_FILES, 'failure export frontier bound exceeded')
                        stack.append((name + '/' + child.name, path / child.name))
            else:
                require(stat.S_ISREG(info.st_mode) and name not in files and len(files) < MAX_FILES
                    and 0 <= info.st_size <= MAX_FILE, 'bounded unique regular failure bytes required')
                total += info.st_size; require(total <= MAX_BYTES, 'failure export aggregate bound exceeded')
                files[name] = (path, info)
    key = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid)
    def stream(path, before, target=None):
        remaining(); require(key(path.lstat()) == key(before), 'original failure path changed')
        count = 0; digest = hashlib.sha256()
        options = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
        with os.fdopen(os.open(path, options), 'rb') as handle:
            require(key(os.fstat(handle.fileno())) == key(before), 'original failure descriptor changed')
            while block := handle.read(1024**2):
                remaining(); count += len(block); require(count <= before.st_size, 'original failure bytes grew')
                digest.update(block)
                if target is not None: require(target.write(block) == len(block), 'failure export write incomplete')
            require(key(os.fstat(handle.fileno())) == key(before), 'original failure descriptor changed during copy')
        require(count == before.st_size and key(path.lstat()) == key(before), 'original failure bytes changed')
        return digest.hexdigest()
    rows = []; objects = {}
    for name, (path, info) in sorted(files.items()):
        digest = stream(path, info)
        rows.append({'path': name, 'bytes': info.st_size, 'sha256': digest, 'mode': stat.S_IMODE(info.st_mode),
                     'uid': info.st_uid, 'gid': info.st_gid})
        objects.setdefault(digest, (path, info))
    if expected_hashes is not None:
        copied_hashes = {row['path']: row['sha256'] for row in rows}
        require(all(copied_hashes.get(name) == digest for name, digest in expected_hashes.items()),
            'copied owner/raw differs from original validated stopped-owner snapshot')
    manifest = {'format': FORMAT, 'status': 'ORIGINAL BYTES FROM FAILED RETENTION; BYTE EXPORT ONLY', 'reference_qualified': False,
        'owner_receipt_sha256': owner_sha256, 'missing_selected_paths': missing, 'files': rows,
        'scope': 'Read-only original failure bytes/modes/ownership, not original execution success or a canonical validation bundle.'}
    encoded = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
    require(len(encoded) <= 8 * 1024**2, 'failure export manifest bound exceeded')
    class BoundedOutput:
        def __init__(self, handle): self.handle = handle
        def tell(self): return self.handle.tell()
        def seek(self, offset, whence=0): return self.handle.seek(offset, whence)
        def flush(self): return self.handle.flush()
        def write(self, data):
            remaining(); require(self.tell() + len(data) <= MAX_ARCHIVE, 'failure export compressed bound exceeded')
            return self.handle.write(data)
    # The uploader may retain even a failed partial output. It is readable from
    # creation and never changes traversal/read access on the original trees.
    with pending.open('xb') as handle:
        os.chmod(pending, 0o644)
        with zipfile.ZipFile(BoundedOutput(handle), 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as bundle:
            bundle.writestr('manifest.json', encoded)
            for digest, (path, info) in sorted(objects.items()):
                remaining()
                with bundle.open('objects/' + digest, 'w', force_zip64=True) as target:
                    require(stream(path, info, target) == digest, 'failure export original digest changed')
        handle.flush(); os.fsync(handle.fileno())
    for path, before in files.values():
        remaining(); require(key(path.lstat()) == key(before), 'original failure identity changed after copy')
    remaining(); os.replace(pending, out); os.chmod(out, 0o644)
    digest = hashlib.sha256()
    with out.open('rb') as handle:
        while block := handle.read(1024**2): remaining(); digest.update(block)
    result = {'status': 'EXPORTED AVAILABLE FAILED ORIGINAL BYTES', 'format': FORMAT, 'reference_qualified': False,
        'files': len(rows), 'objects': len(objects), 'logical_bytes': total, 'compressed_bytes': out.stat().st_size,
        'owner_receipt_sha256': owner_sha256, 'archive_sha256': digest.hexdigest(), 'missing_selected_paths': missing}
    with sidecar.open('x', encoding='utf-8') as handle:
        os.chmod(sidecar, 0o644); handle.write(json.dumps(result, indent=2) + '\n'); handle.flush(); os.fsync(handle.fileno())
    remaining(); return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True); parser.add_argument('--owner-receipt', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True); parser.add_argument('--budget-seconds', type=int, required=True)
    args = parser.parse_args(argv)
    try:
        actual_controller()
        source, receipt = map(archive_capture.owned, (args.source, args.owner_receipt))
        raw = read_bounded_file(receipt, 8 * 1024**2); owner = strict_json(raw)
        command = owner.get('command', [])
        require(type(command) is list and len(command) == 8 and command[0] in ('python3', '/usr/bin/python3', sys.executable)
            and (ROOT / command[1]).resolve() == ROOT / 'scripts/run_canonical_reference.py'
            and command[2::2] == ['--config', '--out', '--run-as']
            and archive_capture.owned(ROOT / command[5]) == source and owner.get('cwd') == str(ROOT)
            and type(owner.get('exit_code')) is int and owner.get('execution_outcome') in
                ('EXECUTED', 'TIMEOUT', 'INTERRUPTED', 'SOURCE_CHANGED', 'INPUT_CHANGED', 'CLEANUP_FAILED')
            and owner.get('process_cleanup', {}).get('status') == 'PASS'
            and type(owner['process_cleanup'].get('remaining_active_processes')) is int
            and owner['process_cleanup']['remaining_active_processes'] == 0,
            'original terminal collector and completed owned stop required for readable failure export')
        for label in ('stdout', 'stderr'):
            require(owner.get(label, {}).get('file') == label + '.txt'
                and hashlib.sha256(read_bounded_file(receipt.parent / (label + '.txt'), 16 * 1024**2)).hexdigest()
                    == owner[label].get('sha256'), 'original terminal collector raw hash differs')
        roots = [('attempt/' + name, source / name) for name in SELECTED]
        roots.append(('reservation', ROOT / '.local-runs/canonical-reservations'))
        roots.append(('owner', receipt.parent))
        roots.append(('input/declared-plan.json', ROOT / command[3]))
        roots.append(('retention-command', ROOT / '.local-runs/canonical-retention-command'))
        owner_sha256 = hashlib.sha256(raw).hexdigest()
        expected_hashes = {'owner/receipt.json': owner_sha256,
            'owner/stdout.txt': owner['stdout']['sha256'], 'owner/stderr.txt': owner['stderr']['sha256']}
        result = export_prefix(roots, args.out, budget_seconds=args.budget_seconds,
            owner_sha256=owner_sha256, expected_hashes=expected_hashes)
        print(json.dumps(result)); return 0
    except (Exception, KeyboardInterrupt) as error:
        print(json.dumps({'status': 'FAIL', 'reference_qualified': False, 'error': type(error).__name__, 'reason': str(error)[:2048]})); return 1


if __name__ == '__main__': raise SystemExit(main())
