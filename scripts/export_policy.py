#!/usr/bin/env python3
"""Reusable public boundary checks; private identifiers are supplied only by the operator."""
import hashlib
from pathlib import Path
import re

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
            if any(part in SKIP for part in relative.parts): continue
            if path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction()):
                errors.append('symlink/reparse point forbidden: ' + relative.as_posix())
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
