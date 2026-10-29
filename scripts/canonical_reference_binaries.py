"""Keep exact post-run native executables and original build associations.

This is byte custody after execution, never a new build, query rerun or proof of
Rust correctness. Missing/failed original associations remain failed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import archive_capture
import canonical_reference_allocation as allocation
import canonical_reference_guest_allocation as guest
from canonical_reference_reservation import fsync_directory
from evidence import source_identity
from kvm_reference_common import strict_json
from kvm_pilot_common import write_json
from build import verify_build

MAX_BINARY = 256 * 1024**2
MAX_BYTES = 1024**3
MAX_METADATA = 4 * 1024**2
BUILD_FILES = ('build.json', 'cargo.stdout', 'cargo.stderr', 'compiler.stdout', 'compiler.stderr')


def actual_guest():
    allocation.require(platform.system() == 'Linux' and ROOT == Path('/work/c')
        and hasattr(os, 'geteuid') and os.geteuid() == 0,
        'BLOCKED: actual existing owned canonical Linux root guest required')
    import reference_allocation as original
    allocation.require(original.read_bounded(guest.MARKER, 128) == guest.MARKER_VALUE
        and guest.MARKER.lstat().st_uid == 0, 'original root-owned canonical guest marker required')


def document(path):
    path = archive_capture.owned(path)
    allocation.require(path.is_file() and path.stat().st_size <= MAX_METADATA,
        'bounded original native executable metadata required')
    return strict_json(path.read_bytes())


def single(parent, pattern):
    found = []
    for path in parent.glob(pattern):
        allocation.require(len(found) < 1, 'ambiguous original native attempt; never choose latest')
        found.append(archive_capture.owned(path))
    allocation.require(len(found) == 1 and found[0].is_dir(), 'one exact original native attempt required')
    return found[0]


def select(root, label):
    """Closed original pointers/layouts, never newest timestamps or free paths."""
    if label == 'functional':
        pointer = root / 'target/debug/rillscope.build.json'; row = document(pointer)
        allocation.require(set(row) == {'receipt'} and type(row['receipt']) is str
            and re.fullmatch(r'\.local-runs/build/dev-[0-9]+/build\.json', row['receipt']),
            'exact original functional build pointer required')
        return root / row['receipt'], 'rillscope', 'dev', [pointer]
    if label in ('full-grid', 'full-cancel'):
        experiment = single(root / '.local-runs', 'benchmark-*')
        name, profile = ('rillscope-measure', 'full') if label == 'full-grid' else ('rillscope', None)
        stage = 'grid' if label == 'full-grid' else 'cancel'
    else:
        allocation.require(label == 'sort-null', 'closed native executable role required')
        experiment = single(root / '.local-runs/bench', 's-*')
        name, profile, stage = 'rillscope-measure', 'sort-null-supplement', 'grid'
    receipt = experiment / 'build/build.json'; manifest = experiment / stage / 'manifest.json'
    row = document(manifest)
    build = document(receipt)
    allocation.require(row.get('build_receipt_sha256') == hashlib.sha256(receipt.read_bytes()).hexdigest()
        and row.get('binary_sha256') == build.get('bins', {}).get(name, {}).get('sha256')
        and row.get('source', {}).get('sha256') == build.get('source', {}).get('sha256')
        and row.get('build') == build and (profile is None or row.get('profile') == profile),
        'original measured manifest/build/executable association differs')
    return receipt, name, 'release', [manifest]


def native_prefix(raw):
    allocation.require(len(raw) >= 64 and raw[:6] == b'\x7fELF\x02\x01'
        and int.from_bytes(raw[18:20], 'little') == 62,
        'original native Linux x86_64 ELF64 executable required')


def retain(out, *, commit, source_sha256, cutoff_ns):
    actual_guest()
    allocation.require(allocation.hex_value(commit, 40) and allocation.hex_value(source_sha256, 64)
        and type(cutoff_ns) is int and 0 < cutoff_ns - time.monotonic_ns() <= 600 * 10**9,
        'finite original source-bound native retention cutoff required')
    out = archive_capture.owned(out)
    allocation.require(not out.exists() and out.parent.is_dir(), 'new owned native executable retention root required')
    allocation.require(source_identity(ROOT)['sha256'] == source_sha256, 'original seed source changed before native retention')
    out.mkdir(mode=0o700); fsync_directory(out.parent)
    record = {'schema_version': 1, 'method': allocation.METHOD, 'status': 'FAIL', 'commit': commit,
        'source_sha256': source_sha256, 'cutoff_monotonic_ns': cutoff_ns, 'associations': [],
        'objects': [], 'metadata': [], 'errors': [], 'bytes': 0, 'reference_qualified': False,
        'scope': 'Available exact original post-run native executable/build/manifest bytes only; no execution, semantic validation, reference qualification or failure repair.'}
    def remaining():
        allocation.require(time.monotonic_ns() < cutoff_ns, 'original native retention cutoff exhausted')
    def persist():
        write_json(out / 'binaries-result.json', record); fsync_directory(out)
    def copy(path, destination, expected=None, native=False):
        remaining(); path = archive_capture.owned(path); before = path.stat()
        limit = MAX_BINARY if native else MAX_METADATA
        allocation.require(path.is_file() and 0 <= before.st_size <= limit
            and record['bytes'] + before.st_size <= MAX_BYTES, 'native retention file/total bound exceeded')
        value = hashlib.sha256(); count = 0
        with path.open('rb') as source, destination.open('xb') as target:
            if native:
                native_prefix(source.read(64)); source.seek(0)
            while block := source.read(1024**2):
                remaining(); count += len(block)
                allocation.require(count <= before.st_size, 'original native artifact grew during retention')
                value.update(block); allocation.require(target.write(block) == len(block), 'native artifact write incomplete')
            target.flush(); os.fsync(target.fileno())
        after = path.stat()
        allocation.require(count == before.st_size and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            and (expected is None or value.hexdigest() == expected), 'original native artifact changed or digest differs')
        check = hashlib.sha256()
        with destination.open('rb') as stream:
            while block := stream.read(1024**2): remaining(); check.update(block)
        allocation.require(check.hexdigest() == value.hexdigest(), 'retained native artifact bytes differ')
        record['bytes'] += count
        return {'source': path.relative_to(ROOT).as_posix(), 'file': destination.relative_to(out).as_posix(),
            'bytes': count, 'sha256': value.hexdigest()}
    def metadata(path):
        path = archive_capture.owned(path)
        relative = path.relative_to(ROOT).as_posix()
        for row in record['metadata']:
            if row['source'] == relative:
                allocation.require(hashlib.sha256(path.read_bytes()).hexdigest() == row['sha256'], 'original metadata changed between roles')
                return row
        allocation.require(len(record['metadata']) < 32, 'native metadata count exceeded')
        destination = out / ('metadata-' + str(len(record['metadata'])))
        row = copy(path, destination); record['metadata'].append(row); return row
    persist()
    try:
        attempt = single(ROOT / '.local-runs', 'clean-*'); original = attempt / 'results.json'
        fresh = document(original)
        allocation.require(fresh.get('commit') == commit and fresh.get('source_sha256') == source_sha256
            and fresh.get('checkout') == (attempt / 'c').relative_to(ROOT).as_posix(),
            'original exact native fresh checkout/source differs')
        root = archive_capture.owned(attempt / 'c')
        allocation.require(source_identity(root)['sha256'] == source_sha256, 'original fresh native source changed')
        metadata(original); record['upstream_fresh_status'] = fresh.get('status')
        for label in ('functional', 'full-grid', 'full-cancel', 'sort-null'):
            row = {'role': label, 'status': 'FAIL'}; record['associations'].append(row); persist()
            try:
                remaining(); receipt, name, profile, extra = select(root, label)
                build = document(receipt); relative = build.get('bins', {}).get(name, {}).get('path')
                allocation.require(type(relative) is str, 'original build executable path missing')
                binary = archive_capture.owned(root / relative)
                proofs = [metadata(path) for path in [receipt.parent / name for name in BUILD_FILES] + extra]
                allocation.require(binary.is_file() and binary.stat().st_size <= MAX_BINARY,
                    'bounded original native executable required before build verification')
                build = verify_build(receipt, binary, name=name, root=root, profile=profile)
                # Verification may reread mutable originals. It must validate
                # the same snapshot already kept as this object's proof.
                kept = strict_json((out / proofs[0]['file']).read_bytes())
                allocation.require(kept == build, 'verified original build differs from retained proof snapshot')
                for proof, key in zip(proofs[1:5], ('raw_stdout_sha256', 'raw_stderr_sha256',
                    'raw_compiler_stdout_sha256', 'raw_compiler_stderr_sha256')):
                    allocation.require(proof['sha256'] == build.get(key), 'retained original build raw stream differs')
                linked = strict_json((out / proofs[-1]['file']).read_bytes())
                if label == 'functional':
                    allocation.require(linked == {'receipt': receipt.relative_to(root).as_posix()},
                        'retained original functional pointer differs')
                else:
                    allocation.require(linked.get('build_receipt_sha256') == proofs[0]['sha256']
                        and linked.get('build') == kept
                        and linked.get('binary_sha256') == kept['bins'][name]['sha256']
                        and linked.get('source') == kept['source'], 'retained original measured manifest differs')
                digest = build['bins'][name]['sha256']
                previous = next((item for item in record['objects'] if item['sha256'] == digest), None)
                if previous is None:
                    copied = copy(binary, out / ('object-' + digest), expected=digest, native=True)
                    os.chmod(out / copied['file'], 0o700); record['objects'].append(copied)
                else:
                    # Verify the second original path too; equality is never
                    # inferred merely from a matching digest in another receipt.
                    before = binary.stat(); shared = hashlib.sha256(); count = 0
                    with binary.open('rb') as stream:
                        native_prefix(stream.read(64)); stream.seek(0)
                        while block := stream.read(1024**2):
                            remaining(); count += len(block)
                            allocation.require(count <= MAX_BINARY and count <= before.st_size,
                                'shared original native artifact grew')
                            shared.update(block)
                    after = binary.stat()
                    allocation.require(shared.hexdigest() == digest and count == before.st_size
                        and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
                        'shared original native artifact differs or changed')
                    copied = previous
                for proof in proofs:
                    original = archive_capture.owned(ROOT / proof['source'])
                    allocation.require(original.stat().st_size <= MAX_METADATA
                        and hashlib.sha256(original.read_bytes()).hexdigest() == proof['sha256'],
                        'original native proof changed through object retention')
                row.update(status='RETAINED ORIGINAL BYTES', binary_name=name, profile=profile,
                    original_binary=binary.relative_to(ROOT).as_posix(), object=copied['file'],
                    sha256=digest, metadata=[item['file'] for item in proofs])
            except (Exception, KeyboardInterrupt) as error:
                record['errors'].append({'role': label, 'error': type(error).__name__, 'reason': str(error)[:2048]})
            persist()
        remaining()
        allocation.require(source_identity(ROOT)['sha256'] == source_sha256
            and source_identity(root)['sha256'] == source_sha256, 'native source changed during retention')
        if not record['errors'] and all(row['status'] == 'RETAINED ORIGINAL BYTES' for row in record['associations']):
            record['status'] = 'RETAINED ORIGINAL BYTES'
    except (Exception, KeyboardInterrupt) as error:
        record['errors'].append({'role': 'original-attempt', 'error': type(error).__name__, 'reason': str(error)[:2048]})
    finally:
        record['finished_monotonic_ns'] = time.monotonic_ns()
        if record['finished_monotonic_ns'] >= cutoff_ns:
            record['status'] = 'FAIL'
            record['errors'].append({'role': 'finalization', 'error': 'DeadlineExpired',
                'reason': 'original native retention cutoff exhausted before final record'})
        persist()
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--commit', required=True); parser.add_argument('--source-sha256', required=True)
    parser.add_argument('--cutoff-monotonic-ns', type=int, required=True); args = parser.parse_args(argv)
    try:
        result = retain(args.out, commit=args.commit, source_sha256=args.source_sha256, cutoff_ns=args.cutoff_monotonic_ns)
        print(json.dumps({'status': result['status'], 'objects': len(result['objects']), 'errors': result['errors'],
            'reference_qualified': False}, sort_keys=True))
        return 0 if result['status'] == 'RETAINED ORIGINAL BYTES' else 1
    except (Exception, KeyboardInterrupt) as error:
        print(json.dumps({'status': 'FAIL', 'error': type(error).__name__, 'reason': str(error)[:2048]}))
        return 77 if 'BLOCKED:' in str(error) else 1


if __name__ == '__main__': raise SystemExit(main())
