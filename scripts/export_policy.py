#!/usr/bin/env python3
"""Reusable public boundary checks; private identifiers are supplied only by the operator."""
import hashlib
from pathlib import Path
import re
import json
import zipfile

SKIP = {'.git', '.local-runs', '__pycache__', 'target'}
PATTERNS = [re.compile(rb'gh[pousr]_[A-Za-z0-9]{30,}'), re.compile(rb'sk-[A-Za-z0-9_-]{32,}'),
            re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')]
CANARY = ('PRIVATE' + '_RELEASE_' + 'CANARY_DO_NOT_PUBLISH').encode()

def audit(root: Path, allowed: set[str], denied_values=None):
    errors, files = [], []
    pending = [root]
    regular = []
    while pending:
        directory = pending.pop()
        for path in sorted(directory.iterdir()):
            relative = path.relative_to(root)
            if path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction()):
                errors.append('symlink/reparse point forbidden: ' + relative.as_posix())
            elif any(part in SKIP for part in relative.parts): continue
            elif path.is_dir(): pending.append(path)
            elif path.is_file(): regular.append(path)
            else: errors.append('nonregular public path: ' + relative.as_posix())
    for path in sorted(regular):
        relative = path.relative_to(root)
        name = relative.as_posix()
        if name not in allowed:
            errors.append('not allowlisted: ' + name)
            continue
        data = path.read_bytes()
        if len(data) > 5_000_000: errors.append('oversized public file: ' + name)
        if CANARY in data or any(pattern.search(data) for pattern in PATTERNS): errors.append('sensitive pattern in ' + name)
        if any(value and value.encode() in data for value in denied_values or []): errors.append('private source value in ' + name)
        if (any(part.casefold() in ('private', '.codex') for part in relative.parts)
                or path.suffix.lower() in ('.docx', '.pem', '.key')
                or path.name.casefold() == '.env' or path.name.casefold().startswith('.env.')):
            errors.append('private/credential path: ' + name)
        files.append({'path': name, 'sha256': hashlib.sha256(data).hexdigest()})
    missing = allowed - {row['path'] for row in files}
    if missing: errors.append('allowlisted files missing: ' + ', '.join(sorted(missing)))
    return {'files': files, 'errors': errors, 'scan_boundary': 'positive paths and selected patterns; manual review is also required'}

def export(root: Path, allowed: set[str], destination: Path, denied_values=None):
    """Create an audited regular-file tree and deterministic ZIP outside the source root."""
    root, destination = root.resolve(), destination.resolve()
    archive_path = destination.with_name(destination.name + '.zip')
    manifest_path = destination.with_name(destination.name + '-manifest.json')
    if destination.is_relative_to(root) or any(p.exists() for p in (destination, archive_path, manifest_path)):
        raise ValueError('export requires a new destination outside the source tree')
    result = audit(root, allowed, denied_values)
    if result['errors']: raise ValueError('public export audit failed')
    destination.mkdir(parents=True)
    with zipfile.ZipFile(archive_path, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for row in result['files']:
            source = root / row['path']
            if source.is_symlink() or not source.is_file(): raise ValueError('export source is no longer regular')
            data = source.read_bytes()
            if hashlib.sha256(data).hexdigest() != row['sha256']: raise ValueError('export source changed after audit')
            target = destination / row['path']
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            member = zipfile.ZipInfo(row['path'], date_time=(1980, 1, 1, 0, 0, 0))
            member.external_attr = 0o100644 << 16
            member.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(member, data)
    with zipfile.ZipFile(archive_path) as archive:
        if set(archive.namelist()) != allowed or archive.testzip() is not None:
            raise ValueError('archive contents differ from exact allowlist')
    manifest = {'files': result['files'], 'archive_sha256': hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                'source': 'audited regular public files only', 'scope': result['scan_boundary']}
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest
