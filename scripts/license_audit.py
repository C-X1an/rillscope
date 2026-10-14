#!/usr/bin/env python3
"""Compare actual locked metadata and preserved notice hashes; no maturity assertion."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
def audit():
    inventory = json.loads((ROOT / 'licenses/dependency-inventory.json').read_bytes())
    errors = []
    if hashlib.sha256((ROOT / 'Cargo.lock').read_bytes()).hexdigest() != inventory['lockfile_sha256']:
        errors.append('dependency lock differs from notice inventory')
    result = subprocess.run(['cargo', 'metadata', '--locked', '--format-version', '1'], cwd=ROOT,
                            capture_output=True, timeout=120)
    if result.returncode:
        raise RuntimeError('locked dependency metadata failed')
    metadata = json.loads(result.stdout)
    actual = {(p['name'], p['version'], p['license'], p['source']) for p in metadata['packages'] if p['source'] is not None}
    listed = {(p['name'], p['version'], p['declared_license'], p['source']) for p in inventory['packages']}
    if actual != listed: errors.append('resolved graph differs from notice inventory')
    for package in inventory['packages']:
        if package['selected_license'] not in ('MIT', 'MIT AND Unicode-3.0'):
            errors.append('unreviewed selected license')
        if 'MIT' not in package['declared_license']: errors.append('selected license is not declared')
        if 'AND Unicode-3.0' in package['declared_license'] and package['selected_license'] != 'MIT AND Unicode-3.0':
            errors.append('mandatory Unicode notice missing')
        if not package['notices']: errors.append('package has no notice')
        for notice in package['notices']:
            path = ROOT / notice['path']
            if not path.resolve().is_relative_to((ROOT / 'licenses').resolve()) or path.is_symlink():
                errors.append('invalid notice path'); continue
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != notice['sha256']:
                errors.append('notice missing or changed: ' + notice['path'])
    own = [p for p in metadata['packages'] if p['source'] is None]
    if len(own) != 1 or own[0]['license'] != 'MIT' or b'MIT' not in (ROOT / 'LICENSE').read_bytes():
        errors.append('first-party MIT declaration missing')
    return {'registry_packages': len(actual), 'preserved_notice_files': sum(len(p['notices']) for p in inventory['packages']),
            'lockfile_sha256': inventory['lockfile_sha256'], 'errors': errors,
            'scope': 'resolved metadata, declarations and exact preserved notice bytes; not exhaustive legal assurance'}

def main():
    try: result = audit()
    except FileNotFoundError:
        print('BLOCKED: license file or required cargo executable unavailable', file=sys.stderr); return 77
    except (RuntimeError, subprocess.TimeoutExpired):
        print('FAIL: locked dependency metadata unavailable', file=sys.stderr); return 1
    print(json.dumps(result, indent=2))
    return int(bool(result['errors']))

if __name__ == '__main__': raise SystemExit(main())
