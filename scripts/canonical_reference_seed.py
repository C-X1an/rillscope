"""Source-only seed for a newly owned native canonical guest.

No first-party executable or target is transported. The fixed archived rustup
installer is an independently hash-pinned third-party prerequisite. Its official
archive/checksum convention is documented in the rustup book, installation/other.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import stat
import time

import canonical_reference_allocation as allocation
from canonical_reference_reservation import source_check, fsync_directory
from evidence import source_identity
from kvm_pilot_common import write_json

ROOT = Path(__file__).resolve().parents[1]
INPUT_RELATIVE = '.local-runs/canonical-seed/seed.json'
INSTALLER_RELATIVE = '.local-runs/canonical-seed/rustup-init'
RUSTUP_VERSION = '1.28.2'
INSTALLER_URL = 'https://static.rust-lang.org/rustup/archive/1.28.2/x86_64-unknown-linux-gnu/rustup-init'
INSTALLER_SHA256 = '20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c'
INSTALLER_LIMIT = 32 * 1024**2
MAX_FILES, MAX_FILE, MAX_TOTAL = 4096, 32 * 1024**2, 128 * 1024**2
REQUIRED_FILES = {'.git/HEAD', '.git/config', 'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
    'scripts/canonical_reference_guest_start.py', INSTALLER_RELATIVE}
SEED_KEYS = {'schema_version', 'method', 'commit', 'source_sha256', 'files',
    'rustup_version', 'installer_sha256', 'installer_url', 'setup_seconds',
    'tail_seconds', 'retention_seconds', 'mode', 'first_party_build_transported', 'reference_qualified'}


def seed_files(root):
    """Include the exact fetched Git metadata, public source and one installer."""
    root = Path(root); pending = [root]; rows = []; total = 0; entries = 0
    while pending:
        for path in sorted(pending.pop().iterdir()):
            entries += 1; allocation.require(entries <= 2 * MAX_FILES, 'seed entry count exceeds bound')
            relative = path.relative_to(root).as_posix()
            allocation.require(not path.is_symlink()
                and not (hasattr(path, 'is_junction') and path.is_junction()), 'source-only seed cannot contain links')
            info = path.lstat()
            if relative == INPUT_RELATIVE: continue
            if relative == '.local-runs' or relative == '.local-runs/canonical-seed':
                allocation.require(stat.S_ISDIR(info.st_mode), 'owned seed prerequisite directory required')
            elif relative.startswith('.local-runs/'):
                allocation.require(relative == INSTALLER_RELATIVE, 'unexpected generated payload or prior first-party build')
            allocation.require('target' not in path.relative_to(root).parts
                and '.cargo' not in path.relative_to(root).parts and '.rustup' not in path.relative_to(root).parts,
                'first-party target or prepared tool home forbidden in source-only seed')
            if stat.S_ISDIR(info.st_mode): pending.append(path); continue
            allocation.require(stat.S_ISREG(info.st_mode) and len(rows) < MAX_FILES
                and info.st_size <= MAX_FILE, 'seed requires bounded regular source/metadata files')
            total += info.st_size; allocation.require(total <= MAX_TOTAL, 'source-only seed exceeds byte bound')
            rows.append({'path': relative, 'bytes': info.st_size, 'mode': stat.S_IMODE(info.st_mode),
                'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    return sorted(rows, key=lambda row: row['path'])


def validate_seed(row):
    allocation.require(type(row) is dict and set(row) == SEED_KEYS
        and type(row['schema_version']) is int and row['schema_version'] == 1
        and row['method'] == allocation.METHOD and allocation.hex_value(row['commit'], 40)
        and allocation.hex_value(row['source_sha256'], 64)
        and row['rustup_version'] == RUSTUP_VERSION and row['installer_sha256'] == INSTALLER_SHA256
        and row['installer_url'] == INSTALLER_URL and row['first_party_build_transported'] is False
        and row['reference_qualified'] is False and type(row['mode']) is str
        and row['mode'] in {'canonical', 'native-setup-diagnostic'},
        'closed exact source-only canonical seed required')
    allocation.require(type(row['setup_seconds']) is int and 1 <= row['setup_seconds'] <= 3600
        and type(row['tail_seconds']) is int and 1 <= row['tail_seconds'] <= 600
        and type(row['retention_seconds']) is int and 1 <= row['retention_seconds'] <= 600,
        'explicit finite native setup/finish/retention bounds required; no provider fit inference')
    files = row['files']; paths = []; total = 0
    allocation.require(type(files) is list and 0 < len(files) <= MAX_FILES, 'bounded original seed inventory required')
    for item in files:
        allocation.require(type(item) is dict and set(item) == {'path', 'bytes', 'mode', 'sha256'}
            and type(item['path']) is str, 'closed original seed file identity required')
        path = PurePosixPath(item['path'])
        allocation.require(not path.is_absolute() and path.as_posix() == item['path']
            and path.parts and all(part not in ('', '.', '..') for part in path.parts)
            and '\\' not in item['path'] and ':' not in item['path'] and item['path'] != INPUT_RELATIVE,
            'canonical relative seed file required')
        allocation.require(not {'target', '.cargo', '.rustup'} & set(path.parts)
            and (not item['path'].startswith('.local-runs/') or item['path'] == INSTALLER_RELATIVE),
            'first-party target, tool home or generated payload forbidden in source-only inventory')
        allocation.require(type(item['bytes']) is int and 0 <= item['bytes'] <= MAX_FILE
            and type(item['mode']) is int and 0 <= item['mode'] <= 0o777 and not item['mode'] & 0o022
            and allocation.hex_value(item['sha256'], 64), 'bounded seed file size/mode/hash required')
        paths.append(item['path']); total += item['bytes']
    allocation.require(paths == sorted(set(paths)) and total <= MAX_TOTAL
        and REQUIRED_FILES <= set(paths), 'unique sorted complete source-only seed inventory required')
    selected = next(item for item in files if item['path'] == INSTALLER_RELATIVE)
    allocation.require(selected['sha256'] == INSTALLER_SHA256 and 0 < selected['bytes'] <= INSTALLER_LIMIT
        and selected['mode'] == 0o555, 'actual pinned read-only installer identity required')
    return row


def prepare_seed(out, installer, *, commit, source_sha256, setup_seconds,
        tail_seconds, retention_seconds, mode, checked):
    """Fetch only the exact committed source into a new private guest disk tree."""
    allocation.require(platform.system() == 'Linux' and hasattr(os, 'geteuid') and os.geteuid() == 0,
        'BLOCKED: actual existing owned Linux root source-seed preparation required')
    import archive_capture
    out, installer = archive_capture.owned(out), archive_capture.owned(installer)
    allocation.require(out.is_dir() and not (out / 'stage').exists()
        and installer.is_file() and not installer.is_symlink()
        and 0 < installer.stat().st_size <= INSTALLER_LIMIT
        and hashlib.sha256(installer.read_bytes()).hexdigest() == INSTALLER_SHA256,
        'existing pinned installer bytes and new owned stage required')
    source_check(commit, source_sha256)
    stage = out / 'stage'; stage.mkdir(mode=0o755)
    template = out / 'empty-git-template'; template.mkdir(mode=0o700)
    clone = stage / 'c'
    checked('seed-git-init', ['git', 'init', '--quiet', '--initial-branch=seed',
        '--template=' + str(template), str(clone)], timeout=30)
    # A single exact commit fetch avoids unrelated refs, local clone hardlinks,
    # local user identity, hooks and a host path in a copied remote config.
    (clone / '.git/config').write_text('[core]\n\trepositoryformatversion = 0\n\tbare = false\n'
        '\tlogallrefupdates = false\n\tautocrlf = false\n[remote "origin"]\n'
        '\turl = https://github.com/C-X1an/rillscope.git\n'
        '\tfetch = +refs/heads/main:refs/remotes/origin/main\n', encoding='utf-8')
    checked('seed-git-fetch', ['git', '-C', str(clone), 'fetch', '--no-tags', '--depth=1', str(ROOT), commit], timeout=120)
    checked('seed-git-checkout', ['git', '-C', str(clone), '-c', 'core.logAllRefUpdates=false',
        'checkout', '--quiet', '--detach', commit], timeout=30)
    (clone / '.git/FETCH_HEAD').unlink()
    allocation.require(source_identity(clone)['sha256'] == source_sha256
        and not (clone / 'target').exists() and not (clone / '.git/logs').exists(),
        'actual exact committed source-only seed required')
    seed = clone / '.local-runs/canonical-seed'; seed.mkdir(parents=True, mode=0o755)
    shutil.copyfile(installer, clone / INSTALLER_RELATIVE); os.chmod(clone / INSTALLER_RELATIVE, 0o555)
    row = {'schema_version': 1, 'method': allocation.METHOD, 'commit': commit,
        'source_sha256': source_sha256, 'files': seed_files(clone), 'rustup_version': RUSTUP_VERSION,
        'installer_sha256': INSTALLER_SHA256, 'installer_url': INSTALLER_URL,
        'setup_seconds': setup_seconds, 'tail_seconds': tail_seconds, 'retention_seconds': retention_seconds,
        'mode': mode, 'first_party_build_transported': False, 'reference_qualified': False}
    validate_seed(row); write_json(clone / INPUT_RELATIVE, row); os.chmod(clone / INPUT_RELATIVE, 0o444)
    fsync_directory(seed)
    allocation.require(seed_files(clone) == row['files'], 'original source-only seed changed before disk preparation')
    return stage, row
