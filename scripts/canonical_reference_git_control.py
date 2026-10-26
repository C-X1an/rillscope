"""Check original source-bound guest Git controls without executing captures."""
import base64
import hashlib
import math
from pathlib import PurePosixPath
import re

from canonical_reference_allocation import require, hex_value
from canonical_reference_retained_fresh import receipt, instant
from kvm_reference_common import strict_json
import canonical_reference_git_trust as git_trust

COMMAND = ['/usr/bin/python3', '/work/c/tests/system/canonical_handoff_permissions.py', '--guest-git-only']
CAPSULE = ['/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'LC_ALL=C',
    'GIT_CONFIG_NOSYSTEM=1', 'GIT_CONFIG_SYSTEM=/dev/null', 'GIT_CONFIG_GLOBAL=/dev/null']
LITERAL = b'SYNTHETIC GIT OWNERSHIP CONTROL ONLY\n'


def setup_intervals(proofs, elapsed_seconds):
    """All six original sequential observations must fit the one setup clock."""
    require(type(proofs) is list and len(proofs) == 6 and type(elapsed_seconds) in (int, float)
        and math.isfinite(elapsed_seconds) and elapsed_seconds >= 0, 'six finite original setup intervals required')
    first = previous = None; total = 0
    for proof in proofs:
        start, end = instant(proof['started_utc']), instant(proof['finished_utc'])
        duration = proof.get('elapsed_seconds')
        require(type(duration) in (int, float) and math.isfinite(duration) and duration >= 0
            and start <= end and (previous is None or previous <= start)
            and duration <= (end - start).total_seconds() + .010, 'original setup intervals overlap, reverse or differ')
        if first is None: first = start
        previous = end; total += duration
    require(total <= elapsed_seconds + .010 and (previous - first).total_seconds() <= elapsed_seconds + .010,
        'original guest Git and all five native versions cannot fit setup interval')


def stream(row):
    require(type(row) is dict and set(row) == {'bytes', 'sha256', 'base64'}
        and type(row['bytes']) is int and 0 <= row['bytes'] <= 1024**2
        and type(row['base64']) is str and len(row['base64']) <= 1400000,
        'bounded lossless original Git stream required')
    try: raw = base64.b64decode(row['base64'], validate=True)
    except (ValueError, TypeError) as error: raise ValueError('invalid original Git stream encoding') from error
    require(len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256'],
        'original Git stream digest/size differs')
    return raw


def guest_output(raw, *, prefix_sha256):
    require(type(raw) is bytes and 0 < len(raw) <= 8 * 1024**2 and raw.endswith(b'\n')
        and hex_value(prefix_sha256, 64), 'bounded complete original guest Git output required')
    lines = raw.splitlines(); require(len(lines) == 19, 'all original guest Git observations required')
    rows = [strict_json(line) for line in lines]
    require(all(type(row) is dict and len(row) == 1 for row in rows), 'closed original Git event required')
    observations = [row['canonical_git_child_observation'] for row in rows if 'canonical_git_child_observation' in row]
    cases = ['fixture-git-version', 'source-init', 'source-add', 'source-commit', 'source-head',
        'unrelated-init', 'unrelated-add', 'unrelated-commit', 'unrelated-head', 'effective-two-entry-trust',
        'original-one-entry-clone', 'two-entry-only-clone', 'effective-protected-trust',
        'two-entry-fresh-clone', 'fresh-head', 'unrelated-root-owned-repository']
    require([row.get('case') for row in observations] == cases
        and 'canonical_git_original_fixtures' in rows[9] and 'canonical_git_protected_trust' in rows[13]
        and 'canonical_guest_git_control' in rows[-1],
        'guest transport control omitted, reordered, duplicated or substituted')
    command = observations[10].get('command')
    require(type(command) is list and len(command) >= 7 and all(type(value) is str for value in command),
        'original guest clone command required')
    source = command[-2]
    require(re.fullmatch(r'/tmp/rill-git-permission-[A-Za-z0-9_-]{1,80}/source', source) is not None,
        'original bounded synthetic guest source path required')
    workspace = source.rsplit('/', 1)[0]; consumer = workspace + '/consumer'; home = consumer + '/home'
    prefix = ['/usr/bin/setpriv', '--reuid=65534', '--regid=65534', '--clear-groups', '--', '/usr/bin/env',
        'HOME=' + home, 'CARGO_HOME=' + home + '/.cargo', 'RUSTUP_HOME=' + home + '/.rustup',
        'CARGO_INCREMENTAL=0', 'PATH=' + home + '/.cargo/bin:/usr/bin:/bin', 'GIT_OPTIONAL_LOCKS=0',
        'GIT_CONFIG_GLOBAL=' + workspace + '/canonical-git-trust/config',
        'GIT_CONFIG_COUNT=2', 'GIT_CONFIG_KEY_0=safe.directory', 'GIT_CONFIG_VALUE_0=' + source,
        'GIT_CONFIG_KEY_1=safe.directory', 'GIT_CONFIG_VALUE_1=' + source + '/.git', 'PYTHONDONTWRITEBYTECODE=1']
    old = ['GIT_CONFIG_COUNT=1' if value == 'GIT_CONFIG_COUNT=2' else value for value in prefix
        if value not in ('GIT_CONFIG_KEY_1=safe.directory', 'GIT_CONFIG_VALUE_1=' + source + '/.git')]
    expected = [['/usr/bin/git', '--version']]
    for name in ('source', 'unrelated'):
        path = workspace + '/' + name; template = workspace + '/empty-template'
        expected.extend([
            ['/usr/bin/git', 'init', '--quiet', '--initial-branch=fixture', '--object-format=sha1', '--template=' + template, path],
            ['/usr/bin/git', '-C', path, 'add', '--', 'literal.txt'],
            ['/usr/bin/env', 'GIT_AUTHOR_DATE=2000-01-01T00:00:00Z', 'GIT_COMMITTER_DATE=2000-01-01T00:00:00Z',
                '/usr/bin/git', '-C', path, '-c', 'user.name=RillScope synthetic fixture', '-c',
                'user.email=fixture@rillscope.invalid', '-c', 'commit.gpgsign=false', '-c',
                'core.hooksPath=' + template, 'commit', '--quiet', '-m', 'Synthetic permission fixture'],
            ['/usr/bin/git', '-C', path, 'rev-parse', 'HEAD']])
    expected.extend([
        prefix + ['/usr/bin/git', 'config', '--null', '--show-origin', '--show-scope', '--get-all', 'safe.directory'],
        old + ['/usr/bin/git', 'clone', '--no-local', '--config', 'core.autocrlf=false', source, consumer + '/old-clone'],
        prefix + ['/usr/bin/git', 'clone', '--no-local', '--config', 'core.autocrlf=false', source, consumer + '/two-entry-only'],
        prefix + ['/usr/bin/git', 'config', '--null', '--show-origin', '--show-scope', '--get-all', 'safe.directory'],
        prefix + ['/usr/bin/git', 'clone', '--no-local', '--config', 'core.autocrlf=false', source, consumer + '/fresh'],
        prefix + ['/usr/bin/git', '-C', consumer + '/fresh', 'rev-parse', 'HEAD'],
        prefix + ['/usr/bin/git', '-C', workspace + '/unrelated', 'rev-parse', 'HEAD']])
    outputs = []
    for index, (row, expected_command) in enumerate(zip(observations, expected)):
        require(set(row) == {'case', 'command', 'outcome', 'returncode', 'timeout_seconds', 'stdout', 'stderr',
            'prefix_source_sha256', 'scope'} and row['command'] == CAPSULE + expected_command
            and row['outcome'] == 'EXECUTED' and type(row['returncode']) is int
            and row['returncode'] == (128 if index in (10, 11, 15) else 0)
            and type(row['timeout_seconds']) is int and row['timeout_seconds'] == 10
            and row['prefix_source_sha256'] == prefix_sha256,
            'original guest command/config/UID/exit/source differs')
        outputs.append((stream(row['stdout']), stream(row['stderr'])))
    version = outputs[0][0].decode('ascii').strip()
    require(re.fullmatch(r'git version [0-9]+\.[0-9]+\.[0-9]+', version) is not None, 'actual guest Git version required')
    config = b''.join(b'command\0command line:\0' + path.encode() + b'\0' for path in (source, source + '/.git'))
    require(outputs[9][0] == config, 'guest effective trust is not exactly the two scoped entries')
    protected = git_trust.validate_observation(rows[13]['canonical_git_protected_trust'], PurePosixPath(source))
    protected_config = b''.join(b'global\0file:' + protected['path'].encode() + b'\0'
        + path.encode() + b'\0' for path in (source, source + '/.git')) + config
    require(outputs[12][0] == protected_config, 'protected file and command trust origins differ')
    for index, path in [(10, source + '/.git'), (11, source + '/.git'), (15, workspace + '/unrelated')]:
        require(b'dubious ownership' in outputs[index][1] and path.encode() in outputs[index][1],
            'original guest ownership denial was not reproduced')
    head = outputs[4][0].strip()
    require(re.fullmatch(rb'[0-9a-f]{40}', head) is not None and outputs[14][0].strip() == head,
        'original guest fresh/source commit differs')
    fixtures = rows[9]['canonical_git_original_fixtures']
    require(type(fixtures) is dict and set(fixtures) == {'source', 'unrelated'}, 'both original root-owned fixtures required')
    for entries in fixtures.values():
        require(type(entries) is list and 0 < len(entries) <= 512, 'bounded original fixture inventory required')
        seen = set(); total = 0
        for entry in entries:
            require(type(entry) is dict and set(entry) == {'path', 'uid', 'gid', 'mode', 'kind', 'bytes', 'sha256', 'base64'}
                and type(entry['uid']) is int and type(entry['gid']) is int and entry['uid'] == entry['gid'] == 0
                and type(entry['mode']) is int and 0 <= entry['mode'] <= 0o7777 and not entry['mode'] & 0o022
                and entry['kind'] in ('file', 'directory') and type(entry['path']) is str,
                'original fixture owner/mode/type differs')
            path = PurePosixPath(entry['path'])
            require(not path.is_absolute() and '..' not in path.parts and path.as_posix() == entry['path']
                and entry['path'] not in seen, 'original fixture path alias or duplicate')
            seen.add(entry['path']); value = stream({key: entry[key] for key in ('bytes', 'sha256', 'base64')})
            total += len(value); require(total <= 8 * 1024**2 and (entry['kind'] == 'file' or value == b''),
                'original fixture bytes exceed bound or directory contains data')
            if entry['path'] == 'literal.txt': require(value == LITERAL, 'original fixture literal differs')
        require({'.', '.git', 'literal.txt'} <= seen, 'required original source fixture member missing')
    final = rows[-1]['canonical_guest_git_control']
    require(type(final) is dict and set(final) == {'identity', 'control'}, 'closed original guest control result required')
    identity = final['identity']; result = final['control']
    require(type(identity) is dict and set(identity) == {'uid', 'gid', 'groups'} and type(identity['uid']) is int
        and type(identity['gid']) is int and identity['uid'] == identity['gid'] == 0
        and type(identity['groups']) is list and len(identity['groups']) <= 64
        and all(type(group) is int and group >= 0 for group in identity['groups']), 'actual owned guest root identity differs')
    require(type(result) is dict and result.get('status') == 'PASS' and type(result.get('consumer_uid')) is int
        and type(result.get('consumer_gid')) is int and result['consumer_uid'] == result['consumer_gid'] == 65534
        and type(result.get('original_one_entry_exit')) is int and result['original_one_entry_exit'] == 128
        and type(result.get('two_entry_clone_exit')) is int and result['two_entry_clone_exit'] == 0
        and type(result.get('unrelated_repository_exit')) is int and result['unrelated_repository_exit'] == 128
        and result.get('source_and_unrelated_ownership_modes_bytes_unchanged') is True
        and result.get('git_version') == version and result.get('fresh_commit') == head.decode()
        and result.get('effective_trust') == config.decode().split('\0')[:-1]
        and result.get('protected_effective_trust') == protected_config.decode().split('\0')[:-1]
        and result.get('protected_trust_before') == result.get('protected_trust_after') == protected
        and result.get('literal_sha256') == hashlib.sha256(LITERAL).hexdigest()
        and result.get('original_fixtures') == fixtures, 'original guest transport result differs from raw controls')
    return result


def validate_guest_git_proof(metadata, directory, *, source, seed, seed_raw, setup, before_utc=None):
    original_metadata = metadata
    class TextPaths:
        def raw(self, path, limit=16 * 1024**2): return original_metadata.raw(str(path), limit)
        def document(self, path, limit=16 * 1024**2): return original_metadata.document(str(path), limit)
    metadata = TextPaths()
    proof = receipt(metadata, directory, source=source, commit=seed['commit'], command=COMMAND, cwd=PurePosixPath('/work/c'))
    expected = [{'path': '/work/c/.local-runs/canonical-seed/seed.json',
        'bytes': len(seed_raw), 'sha256': hashlib.sha256(seed_raw).hexdigest()}]
    require(proof['inputs_before'] == proof['inputs_after'] == expected
        and proof['elapsed_seconds'] <= 30 and proof['elapsed_seconds'] <= setup['elapsed_seconds']
        and proof['elapsed_seconds'] <= (instant(proof['finished_utc']) - instant(proof['started_utc'])).total_seconds() + .010
        and (instant(proof['finished_utc']) - instant(proof['started_utc'])).total_seconds() <= setup['elapsed_seconds'] + .010
        and (before_utc is None or instant(proof['finished_utc']) <= instant(before_utc)),
        'original guest Git seed/deadline/chronology differs')
    owner_hashes = [row['sha256'] for row in seed['files'] if row['path'] == 'scripts/canonical_reference_guest_owner.py']
    require(len(owner_hashes) == 1, 'guest Git actual prefix source identity missing')
    result = guest_output(metadata.raw(directory / 'stdout.txt', 8 * 1024**2), prefix_sha256=owner_hashes[0])
    require(result == setup.get('git_ownership_control'), 'native setup omitted or substituted original guest Git proof')
    return proof
