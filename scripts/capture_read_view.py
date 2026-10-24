"""Read a verified capture through pathlib without expanding its raw files.

Use only in a dedicated, single-threaded inspection process. The context maps a
new synthetic directory to authenticated CAS objects and temporarily supplies
Path.open/stat/iterdir for that directory. It executes no captured code and
restores every patched method on exit. Other filesystem paths use normal I/O.
"""
from collections import defaultdict
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import stat
import threading
from types import MappingProxyType
import zipfile

import archive_capture

_ACTIVE = False


def _sha(path):
    value = hashlib.sha256()
    size = 0
    with path.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            size += len(block)
            if size > archive_capture.MAX_ARCHIVE:
                raise ValueError('archive exceeds retained artifact byte bound')
            value.update(block)
    return value.hexdigest()


class CaptureReadView:
    """One read-only, bounded capture mount; raw files are never written."""

    def __init__(self, archive, mount):
        self.archive = Path(archive)
        self.mount = Path(mount)
        self.read_calls = 0

    def __enter__(self):
        global _ACTIVE
        if _ACTIVE:
            raise ValueError('capture views cannot nest or share a process')
        if threading.active_count() != 1:
            raise ValueError('capture views require a dedicated single-threaded process')
        self.archive = self.archive.resolve(strict=True)
        self.mount = self.mount.resolve()
        if self.mount.exists() or self.archive.is_relative_to(self.mount):
            raise ValueError('capture view requires a new, non-overlapping mount')
        if self.archive.stat().st_size > archive_capture.MAX_ARCHIVE:
            raise ValueError('archive exceeds retained artifact byte bound')
        self.archive_sha256 = _sha(self.archive)
        rows, self.metadata = archive_capture.inspect(self.archive)
        self.files = MappingProxyType({row['path']: row for row in rows})
        children = defaultdict(set)
        for name in self.files:
            parts = PurePosixPath(name).parts
            for index, part in enumerate(parts):
                children['/'.join(parts[:index])].add(part)
        self.children = children
        self._open, self._stat, self._iterdir = Path.open, Path.stat, Path.iterdir

        def key(path):
            absolute = path.absolute()
            return absolute.relative_to(self.mount).as_posix() if absolute.is_relative_to(self.mount) else None

        def open_view(path, mode='r', buffering=-1, encoding=None, errors=None, newline=None):
            name = key(path)
            if name is None:
                return self._open(path, mode, buffering, encoding, errors, newline)
            if mode not in ('r', 'rb', 'rt'):
                raise PermissionError('capture views are read-only')
            if name == '.' or name in self.children:
                raise IsADirectoryError(str(path))
            if name not in self.files:
                raise FileNotFoundError(str(path))
            row = self.files[name]
            info = self._zip.getinfo('objects/' + row['sha256'])
            if info.file_size != row['bytes'] or row['bytes'] > archive_capture.MAX_FILE:
                raise ValueError('capture object size changed')
            data = self._zip.read(info)
            if len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['sha256']:
                raise ValueError('capture object bytes changed')
            self.read_calls += 1
            stream = io.BufferedReader(io.BytesIO(data))
            if mode == 'rb':
                return stream
            return io.TextIOWrapper(stream, encoding=encoding, errors=errors, newline=newline)

        def stat_view(path, *, follow_symlinks=True):
            name = key(path)
            if name is None:
                return self._stat(path, follow_symlinks=follow_symlinks)
            if name == '.' or name in self.children:
                mode, size = stat.S_IFDIR | 0o555, 0
            elif name in self.files:
                mode, size = stat.S_IFREG | 0o444, self.files[name]['bytes']
            else:
                raise FileNotFoundError(str(path))
            # Only captured type/length are represented. Zero timestamps are
            # synthetic filesystem metadata, never experimental observations.
            return os.stat_result((mode, 0, 0, 1, 0, 0, size, 0, 0, 0))

        def iterdir_view(path):
            name = key(path)
            if name is None:
                yield from self._iterdir(path)
                return
            name = '' if name == '.' else name
            if name not in self.children:
                if name in self.files:
                    raise NotADirectoryError(str(path))
                raise FileNotFoundError(str(path))
            for child in sorted(self.children[name]):
                yield path / child

        self._zip = None
        try:
            self._zip = zipfile.ZipFile(self.archive)
            Path.open, Path.stat, Path.iterdir = open_view, stat_view, iterdir_view
            _ACTIVE = True
            return self
        except BaseException:
            # A failed __enter__ never receives a context-manager __exit__.
            # Restore partial installations and release the archive here too.
            self._restore()
            raise

    def _restore_once(self):
        global _ACTIVE
        Path.open, Path.stat, Path.iterdir = self._open, self._stat, self._iterdir
        _ACTIVE = False
        if self._zip is not None:
            self._zip.close()

    def _restore(self):
        try:
            self._restore_once()
        finally:
            # The second idempotent pass completes cleanup when one interrupt
            # lands during the first pass, while preserving that exception.
            self._restore_once()

    def __exit__(self, kind, value, traceback):
        self._restore()
        if _sha(self.archive) != self.archive_sha256:
            raise ValueError('capture archive changed during inspection')
        return False

