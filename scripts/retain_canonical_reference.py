"""Keep available original canonical bytes after the enclosing owner has exited.

Content deduplication changes storage only. Missing/failed original records stay
missing/failed; this command never qualifies execution or reconstructs a VM.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
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
from canonical_reference_retained_fresh import read_bounded_file
from kvm_pilot_common import write_json
from kvm_reference_common import strict_json

FORMAT = 'rillscope-canonical-bundle-v1'
MAX_FILES = 20000
MAX_FILE = 1024**3
MAX_BYTES = 8 * 1024**3
MAX_ARCHIVE = 512 * 1024**2
MAX_MANIFEST = 8 * 1024**2
MAX_DEPTH = 32
SELECTED = ('declared-plan.json', 'driver-result.json', 'utilities', 'vm/preparation', 'vm/artifact',
    'vm/SHA256SUMS', 'vm/SHA256SUMS.gpg', 'vm/ubuntu-cloud-image.asc', 'vm/image-key.gpg')
FORBIDDEN = {'.git', '.codex', '.cargo', '.rustup', 'private', 'target'}


def retain(source, owner_receipt, out, budget_seconds):
    actual_controller()
    allocation.require(type(budget_seconds) is int and 1 <= budget_seconds <= 600,
        'finite original canonical retention budget required')
    started = time.monotonic(); deadline = started + budget_seconds
    def remaining(): allocation.require(time.monotonic() < deadline, 'original canonical retention deadline exhausted')
    source, owner_receipt, out = map(archive_capture.owned, (source, owner_receipt, out))
    allocation.require(out.suffix.lower() == '.zip' and not out.exists() and not out.is_relative_to(source) and out.parent.is_dir()
        and owner_receipt.name == 'receipt.json', 'new separate canonical bundle and original terminal receipt required')
    owner_raw = read_bounded_file(owner_receipt, 8 * 1024**2); owner = strict_json(owner_raw)
    command = owner.get('command') if type(owner) is dict else None
    origin = lambda value: archive_capture.owned(Path(value) if Path(value).is_absolute() else ROOT / value)
    allocation.require(type(command) is list and len(command) == 8 and all(type(item) is str for item in command)
        and command[0] in ('python3', '/usr/bin/python3', sys.executable)
        and (ROOT / command[1]).resolve() == ROOT / 'scripts/run_canonical_reference.py'
        and command[2::2] == ['--config', '--out', '--run-as'] and origin(command[5]) == source
        and re.fullmatch('[a-z_][a-z0-9_-]{0,31}', command[7])
        and owner.get('cwd') == str(ROOT) and type(owner.get('exit_code')) is int
        and type(owner.get('schema_version')) is int and owner['schema_version'] == 1
        and owner.get('verification_status') in ('PASS', 'FAIL')
        and owner.get('execution_outcome') in ('EXECUTED', 'TIMEOUT', 'INTERRUPTED', 'SOURCE_CHANGED', 'INPUT_CHANGED')
        and owner.get('process_cleanup', {}).get('status') == 'PASS'
        and type(owner['process_cleanup'].get('remaining_active_processes')) is int
        and owner['process_cleanup']['remaining_active_processes'] == 0,
        'exact terminal original collector and completed owned cleanup required before byte retention')
    config = origin(command[3])
    for label in ('stdout', 'stderr'):
        allocation.require(type(owner.get(label)) is dict and owner[label].get('file') == label + '.txt'
            and hashlib.sha256(read_bounded_file(owner_receipt.parent / (label + '.txt'), 16 * 1024**2)).hexdigest()
                == owner[label].get('sha256'), 'original collector raw output digest differs')
    remaining()
    pending_archive = out.with_name(out.name + '.pending'); result_path = out.with_suffix('.json')
    allocation.require(not pending_archive.exists() and not result_path.exists(), 'prior canonical retention evidence must remain untouched')
    missing = []; candidates = {}; identities = {}; total = 0
    progress = {'status': 'HASHING AVAILABLE ORIGINALS', 'format': FORMAT, 'method': allocation.METHOD,
        'owner_exit_code': owner['exit_code'], 'owner_verification_status': owner['verification_status'],
        'reference_qualified': False, 'all_record_validation': 'NOT RUN', 'files': []}
    write_json(result_path, progress)
    def add(name, path):
        remaining(); archive_capture.member(name); path = archive_capture.owned(path)
        allocation.require(len(Path(name).parts) <= MAX_DEPTH and not FORBIDDEN.intersection(Path(name).parts) and name not in candidates
            and path.is_file() and not path.is_symlink(), 'unique regular closed canonical evidence path required')
        allocation.require(len(candidates) < MAX_FILES, 'canonical bundle file count exceeded')
        candidates[name] = path
    for name in ('receipt.json', 'stdout.txt', 'stderr.txt'): add('owner/' + name, owner_receipt.parent / name)
    if config.exists(): add('input/declared-plan.json', config)
    else: missing.append('input/declared-plan.json')
    def tree(prefix, selected):
        if not selected.exists(): missing.append(prefix); return
        stack = [selected]; visited = 0
        while stack:
            remaining(); path = stack.pop(); visited += 1
            allocation.require(visited <= 2 * MAX_FILES and not path.is_symlink()
                and not (hasattr(path, 'is_junction') and path.is_junction()), 'bounded link-free canonical evidence tree required')
            if path.is_dir():
                children = []
                for child in path.iterdir():
                    remaining()
                    allocation.require(len(stack) + len(children) < 2 * MAX_FILES,
                        'canonical directory frontier bound exceeded before materialization')
                    children.append(child)
                stack.extend(sorted(children, reverse=True))
            else:
                relative = path.relative_to(selected).as_posix() if selected.is_dir() else ''
                add(prefix + ('/' + relative if relative else ''), path)
    for name in SELECTED: tree('attempt/' + name, source / name)
    driver = {}; driver_raw = None
    allocation.require((source / 'driver-result.json').is_file() == ('attempt/driver-result.json' in candidates),
        'original driver record appeared or disappeared during enumeration')
    if 'attempt/driver-result.json' in candidates:
        driver_raw = read_bounded_file(source / 'driver-result.json', 4 * 1024**2); driver = strict_json(driver_raw)
    vm = driver.get('vm') if type(driver) is dict else None
    channel = vm.get('channel') if type(vm) is dict else None
    slot = channel.get('reservation_slot') if type(channel) is dict else None
    if slot is not None:
        allocation.require(type(slot) is str and re.fullmatch(r'\.local-runs/canonical-reservations/vm-[0-9]+-[0-9]+', slot),
            'original external reservation slot path differs')
        tree('reservation', archive_capture.owned(ROOT / slot))
    else: missing.append('reservation')
    def stream(path, sink=None, expected=None):
        remaining(); before = path.lstat()
        allocation.require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= MAX_FILE,
            'bounded regular canonical original required')
        key = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns)
        value = hashlib.sha256(); count = 0
        with path.open('rb') as original:
            allocation.require(key(os.fstat(original.fileno())) == key(before), 'original descriptor changed before retention')
            while block := original.read(1024**2):
                remaining(); count += len(block); allocation.require(count <= before.st_size, 'canonical original grew during retention')
                value.update(block)
                if sink is not None:
                    allocation.require(sink.write(block) == len(block), 'canonical retained object write incomplete')
                    allocation.require(pending_archive.stat().st_size <= MAX_ARCHIVE, 'canonical compressed byte bound exceeded')
            allocation.require(key(os.fstat(original.fileno())) == key(before), 'canonical original descriptor changed during retention')
        allocation.require(count == before.st_size and key(path.lstat()) == key(before)
            and (expected is None or value.hexdigest() == expected), 'canonical original changed or retained digest differs')
        return value.hexdigest(), count, key(before)
    rows = []; unique = {}
    for name, path in sorted(candidates.items()):
        digest, count, identity = stream(path); total += count
        allocation.require(total <= MAX_BYTES, 'canonical original aggregate byte bound exceeded')
        row = {'path': name, 'bytes': count, 'sha256': digest}; rows.append(row); identities[name] = identity
        unique.setdefault(digest, path)
    hashes = {row['path']: row['sha256'] for row in rows}
    allocation.require(hashes['owner/receipt.json'] == hashlib.sha256(owner_raw).hexdigest()
        and all(hashes['owner/' + name + '.txt'] == owner[name]['sha256'] for name in ('stdout', 'stderr')),
        'retained owner snapshot differs from original validated receipt/raw bytes')
    if driver_raw is not None:
        allocation.require(hashes['attempt/driver-result.json'] == hashlib.sha256(driver_raw).hexdigest(),
            'retained driver snapshot differs from original reservation selection record')
    manifest = {'schema_version': 1, 'format': FORMAT, 'method': allocation.METHOD, 'files': rows,
        'missing_selected_paths': missing, 'owner_exit_code': owner['exit_code'],
        'owner_verification_status': owner['verification_status'], 'owner_receipt_sha256': hashlib.sha256(owner_raw).hexdigest(),
        'original_reservation_slot': slot, 'reference_qualified': False, 'all_record_validation': 'NOT RUN',
        'scope': 'Available original terminal-owner/input/attempt/reservation bytes only, including failures. Disks/tool caches excluded; no execution, source repair, allocation or reference qualification.'}
    manifest_raw = json.dumps(manifest, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    allocation.require(len(manifest_raw) <= MAX_MANIFEST, 'canonical bundle manifest exceeds bound')
    progress.update(status='COPYING ORIGINAL OBJECTS', files=rows, missing_selected_paths=missing); write_json(result_path, progress)
    with zipfile.ZipFile(pending_archive, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as bundle:
        bundle.writestr('manifest.json', manifest_raw)
        for digest, path in sorted(unique.items()):
            remaining(); info = zipfile.ZipInfo('objects/' + digest); info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            with bundle.open(info, 'w', force_zip64=True) as target: stream(path, target, digest)
    allocation.require(pending_archive.stat().st_size <= MAX_ARCHIVE, 'closed canonical bundle exceeds compressed bound')
    with zipfile.ZipFile(pending_archive) as bundle:
        allocation.require(len(bundle.infolist()) == len(unique) + 1
            and set(bundle.namelist()) == {'manifest.json'} | {'objects/' + digest for digest in unique}
            and bundle.read('manifest.json') == manifest_raw, 'canonical bundle member/manifest set differs')
        lengths = {row['sha256']: row['bytes'] for row in rows}
        for digest, expected in lengths.items():
            remaining(); value = hashlib.sha256(); count = 0
            with bundle.open('objects/' + digest) as original:
                while block := original.read(1024**2):
                    remaining(); count += len(block); allocation.require(count <= expected, 'retained canonical object grew')
                    value.update(block)
            allocation.require(count == expected and value.hexdigest() == digest, 'retained canonical object bytes differ')
    for name, path in candidates.items():
        remaining(); row = path.lstat()
        allocation.require(identities[name] == (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns),
            'original canonical evidence changed during bundle verification')
    with pending_archive.open('r+b') as original: original.flush(); os.fsync(original.fileno())
    os.replace(pending_archive, out); os.chmod(out, 0o644); fsync_directory(out.parent)
    value = hashlib.sha256()
    with out.open('rb') as original:
        while block := original.read(1024**2): remaining(); value.update(block)
    result = {**manifest, 'status': 'RETAINED AVAILABLE ORIGINAL BYTES', 'files': len(rows),
        'objects': len(unique), 'logical_bytes': total, 'compressed_bytes': out.stat().st_size,
        'archive_sha256': value.hexdigest(), 'elapsed_seconds': time.monotonic() - started}
    write_json(result_path, result)
    if time.monotonic() >= deadline:
        result.update(status='FAIL', reason='original canonical retention deadline exhausted during terminal persistence')
        write_json(result_path, result); raise ValueError(result['reason'])
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--owner-receipt', type=Path, required=True); parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--budget-seconds', type=int, required=True); args = parser.parse_args(argv)
    try:
        result = retain(args.source, args.owner_receipt, args.out, args.budget_seconds)
        print(json.dumps({key: value for key, value in result.items() if key != 'missing_selected_paths'}, sort_keys=True)); return 0
    except (Exception, KeyboardInterrupt) as error:
        print(json.dumps({'status': 'FAIL', 'error': type(error).__name__, 'reason': str(error)[:2048]}))
        return 77 if 'BLOCKED:' in str(error) else 1


if __name__ == '__main__': raise SystemExit(main())
