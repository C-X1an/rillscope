"""Bounded inspection/extraction of included canonical bytes; never execute them."""
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat
import struct
import time
import zipfile

import archive_capture
from canonical_reference_allocation import METHOD, require, hex_value
from canonical_reference_retained_fresh import relative
from kvm_reference_common import strict_json
from kvm_pilot_common import write_json
from retain_canonical_reference import FORMAT, MAX_FILES, MAX_FILE, MAX_BYTES, MAX_ARCHIVE, MAX_MANIFEST, MAX_DEPTH, FORBIDDEN

MANIFEST_FIELDS = {'schema_version', 'format', 'method', 'files', 'missing_selected_paths',
    'owner_exit_code', 'owner_verification_status', 'owner_receipt_sha256', 'original_reservation_slot',
    'reference_qualified', 'all_record_validation', 'scope'}
MAX_CENTRAL_DIRECTORY = 4 * 1024**2


class CanonicalBundle:
    """One held regular descriptor with finite ZIP/index/object bounds."""

    def __init__(self, path, deadline):
        require(type(deadline) in (int, float) and 0 < deadline - time.monotonic() <= 1800,
            'finite original canonical bundle inspection cutoff required')
        self.path = archive_capture.owned(path); self.deadline = deadline; self.stream = self.bundle = None
        self.before = self.path.lstat(); self.identity = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns)
        require(stat.S_ISREG(self.before.st_mode) and 22 <= self.before.st_size <= MAX_ARCHIVE,
            'bounded regular canonical bundle required')
        try:
            self.stream = self.path.open('rb'); require(self.identity(os.fstat(self.stream.fileno())) == self.identity(self.before),
                'canonical bundle descriptor differs from original path')
            # This format has at most20,001 flat ZIP members and is below512MiB.
            # Check its small ordinary EOCD before ZipFile can allocate a huge
            # attacker-controlled central directory. Per-object ZIP64 headers
            # written by force_zip64 remain supported within these outer bounds.
            self.stream.seek(-22, 2); footer = self.stream.read(22)
            signature, disk, central_disk, disk_count, count, size, offset, comment = struct.unpack('<4s4H2LH', footer)
            require(signature == b'PK\x05\x06' and disk == central_disk == comment == 0
                and disk_count == count and 1 <= count <= MAX_FILES + 1
                and 0 < size <= MAX_CENTRAL_DIRECTORY and offset + size == self.before.st_size - 22,
                'bounded single-disk canonical central directory required before ZIP parsing')
            self.archive_sha256 = self.digest(); self.stream.seek(0); self.bundle = zipfile.ZipFile(self.stream)
            entries = self.bundle.infolist()
            require(len(entries) == count and len({row.filename for row in entries}) == count,
                'canonical bundle members repeat or differ from original directory')
            for info in entries:
                require(not info.is_dir() and not info.flag_bits & 1 and stat.S_IFMT(info.external_attr >> 16) in (0, stat.S_IFREG)
                    and info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                    and info.file_size <= (MAX_MANIFEST if info.filename == 'manifest.json' else MAX_FILE),
                    'canonical bundle requires bounded regular unencrypted members')
            require('manifest.json' in self.bundle.namelist(), 'canonical bundle manifest missing')
            with self.bundle.open('manifest.json') as source: manifest_raw = source.read(MAX_MANIFEST + 1)
            require(len(manifest_raw) <= MAX_MANIFEST, 'canonical bundle manifest exceeds bound')
            self.manifest = strict_json(manifest_raw); value = self.manifest
            require(type(value) is dict and set(value) == MANIFEST_FIELDS and type(value['schema_version']) is int
                and value['schema_version'] == 1 and value['format'] == FORMAT and value['method'] == METHOD
                and value['reference_qualified'] is False and value['all_record_validation'] == 'NOT RUN'
                and type(value['owner_exit_code']) is int and value['owner_verification_status'] in ('PASS', 'FAIL')
                and hex_value(value['owner_receipt_sha256'], 64) and type(value['scope']) is str and len(value['scope']) <= 4096
                and type(value['missing_selected_paths']) is list and len(value['missing_selected_paths']) <= 32
                and all(type(name) is str and len(name) <= 4096 for name in value['missing_selected_paths'])
                and (value['original_reservation_slot'] is None or type(value['original_reservation_slot']) is str
                    and re.fullmatch(r'\.local-runs/canonical-reservations/vm-[0-9]+-[0-9]+', value['original_reservation_slot'])),
                'closed original canonical bundle manifest required')
            rows = value['files']; require(type(rows) is list and 0 < len(rows) <= MAX_FILES, 'bounded canonical path index required')
            self.files = {}; self.objects = {}; folded = set(); directories = set(); spellings = {}; total = 0
            for row in rows:
                require(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'} and type(row['bytes']) is int
                    and 0 <= row['bytes'] <= MAX_FILE and hex_value(row['sha256'], 64), 'closed original canonical file identity required')
                path = relative(row['path']); archive_capture.member(row['path'])
                require(path.parts[0] in ('owner', 'input', 'attempt', 'reservation') and len(path.parts) <= MAX_DEPTH
                    and not FORBIDDEN.intersection(path.parts) and row['path'].casefold() not in folded
                    and row['path'] not in directories and all(parent.as_posix() not in self.files for parent in path.parents),
                    'canonical evidence path aliases, traverses or conflicts')
                for prefix in (path, *path.parents):
                    spelling = prefix.as_posix(); key = spelling.casefold()
                    require(key not in spellings or spellings[key] == spelling, 'canonical path case aliases are forbidden')
                    spellings[key] = spelling
                folded.add(row['path'].casefold()); directories.update(parent.as_posix() for parent in path.parents)
                self.files[row['path']] = row; total += row['bytes']; require(total <= MAX_BYTES, 'canonical logical byte bound exceeded')
                require(row['sha256'] not in self.objects or self.objects[row['sha256']] == row['bytes'],
                    'shared canonical object has conflicting sizes')
                self.objects[row['sha256']] = row['bytes']
            require(list(self.files) == sorted(self.files) and 'owner/receipt.json' in self.files
                and self.files['owner/receipt.json']['sha256'] == value['owner_receipt_sha256']
                and set(self.bundle.namelist()) == {'manifest.json'} | {'objects/' + digest for digest in self.objects},
                'canonical archive/index/original owner member set differs')
            for digest, length in self.objects.items():
                require(self.bundle.getinfo('objects/' + digest).file_size == length, 'canonical object length differs')
            self.logical_bytes = total; self.unchanged()
        except BaseException:
            self.close(); raise

    def remaining(self): require(time.monotonic() < self.deadline, 'original canonical bundle cutoff exhausted')

    def digest(self):
        self.remaining(); self.stream.seek(0); value = hashlib.sha256(); count = 0
        while block := self.stream.read(1024**2):
            self.remaining(); count += len(block); require(count <= self.before.st_size, 'canonical bundle grew during inspection')
            value.update(block)
        require(count == self.before.st_size, 'canonical bundle length changed'); return value.hexdigest()

    def unchanged(self):
        require(self.identity(os.fstat(self.stream.fileno())) == self.identity(self.before)
            and self.identity(self.path.lstat()) == self.identity(self.before), 'canonical bundle identity changed')

    def copy(self, row, target=None):
        self.remaining(); value = hashlib.sha256(); count = 0
        with self.bundle.open('objects/' + row['sha256']) as source:
            while block := source.read(1024**2):
                self.remaining(); count += len(block); require(count <= row['bytes'], 'canonical object exceeds original length')
                value.update(block)
                if target is not None: require(target.write(block) == len(block), 'canonical restored file write incomplete')
        require(count == row['bytes'] and value.hexdigest() == row['sha256'], 'canonical included object digest differs')

    def verify(self):
        for digest, length in self.objects.items(): self.copy({'sha256': digest, 'bytes': length})
        require(self.digest() == self.archive_sha256, 'canonical archive changed during object verification'); self.unchanged()

    def close(self):
        try:
            if self.bundle is not None: self.bundle.close()
        finally:
            if self.stream is not None: self.stream.close()

    def __enter__(self): return self
    def __exit__(self, *_args): self.close()


MAX_PREFIXES = 128


def extract(archive, out, *, max_bytes, budget_seconds, prefixes=()):
    require(type(max_bytes) is int and 0 < max_bytes <= MAX_BYTES and type(budget_seconds) is int
        and 1 <= budget_seconds <= 1800, 'explicit finite restoration byte/time budget required')
    started = time.monotonic(); deadline = started + budget_seconds
    def remaining(): require(time.monotonic() < deadline, 'original canonical bundle cutoff exhausted')
    out = archive_capture.owned(out); remaining()
    require(not out.exists() and out.parent.is_dir(), 'new owned extraction output required')
    selected_prefixes = []; selectors = set()
    for value in prefixes:
        remaining(); require(len(selected_prefixes) < MAX_PREFIXES, 'canonical selector count exceeds bound')
        name = relative(value); require(len(name.parts) <= MAX_DEPTH, 'canonical selector depth exceeds bound')
        name = name.as_posix(); remaining()
        require(name not in selectors, 'duplicate canonical selector'); selectors.add(name); selected_prefixes.append(name)
    prefixes = tuple(selected_prefixes); remaining()
    with CanonicalBundle(archive, deadline) as bundle:
        selected = []
        for name, row in bundle.files.items():
            remaining(); path = PurePosixPath(name)
            if not selectors or name in selectors or any(parent.as_posix() in selectors for parent in path.parents):
                selected.append(row)
        total = sum(row['bytes'] for row in selected)
        require(selected and total <= max_bytes, 'selected canonical restoration exceeds explicit byte budget or is empty')
        bundle.verify(); out.mkdir(mode=0o700)
        report = {'status': 'RESTORING', 'format': FORMAT, 'archive_sha256': bundle.archive_sha256,
            'selected_files': len(selected), 'selected_bytes': total, 'prefixes': list(prefixes), 'completed_files': 0,
            'reference_qualified': False, 'all_record_validation': 'NOT RUN',
            'scope': 'Exact included selected bytes only; no captured executable is run and no missing/failed original is repaired.'}
        result_path = out / 'restore-result.json'; write_json(result_path, report)
        try:
            for row in selected:
                bundle.remaining(); destination = archive_capture.owned(out / row['path'])
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open('xb') as target:
                    bundle.copy(row, target); target.flush(); os.fsync(target.fileno())
                report['completed_files'] += 1
            bundle.verify(); report.update(status='RESTORED ORIGINAL INCLUDED BYTES', elapsed_seconds=time.monotonic() - started)
            write_json(result_path, report); bundle.remaining()
        except BaseException as error:
            report.update(status='FAIL', error=type(error).__name__, reason=str(error)[:2048]); write_json(result_path, report); raise
    return report
