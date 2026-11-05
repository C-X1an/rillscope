"""Check actual complete fresh records, never substitute diagnostics for gates."""
import hashlib
import json
from pathlib import Path

from evidence import source_identity
from verify_sequence import checked_receipt, load_ledger, owned_path, read_plan


def require(condition, reason):
    if not condition: raise ValueError(reason)


def canonical_shape(result, *, commit, source_sha256):
    require(type(result) is dict and result.get('mode') == 'fresh-committed-Rust-checkout'
        and result.get('status') == 'PASS' and result.get('commit') == commit
        and result.get('source_sha256') == source_sha256
        and result.get('source_stable') is True and result.get('target_directory_was_fresh') is True
        and result.get('cargo_target_dir_enforced_inside_fresh_clone') is True
        and result.get('same_os_and_toolchain_installation') is True,
        'complete exact native canonical fresh result required')
    commands = result.get('commands')
    require(type(commands) is list and len(commands) == 3
        and all(type(row) is dict for row in commands)
        and [row.get('target') for row in commands] == ['bootstrap', 'verify', 'demo']
        and all(row.get('role') == 'canonical' and row.get('state') == 'COMPLETED'
            and row.get('status') == 'PASS' and type(row.get('exit_code')) is int
            and row['exit_code'] == 0 for row in commands)
        and result.get('diagnostic_commands') == [] and result.get('not_run') == [],
        'three canonical commands must actually pass without diagnostic substitution')
    return commands


def check_fresh(root, *, commit, source_sha256):
    """Inspect one original attempt and every original gate receipt/raw stream.

    Receipt and source checks establish recorded execution, not allocator
    authenticity or measured target success beyond the unchanged inner gates.
    """
    root = Path(root).resolve()
    attempts = []
    for path in (root / '.local-runs').glob('clean-*'):
        require(len(attempts) < 2, 'bounded single canonical fresh attempt required')
        attempts.append(owned_path(root, path))
    require(len(attempts) == 1, 'exactly one original fresh attempt required')
    attempt = attempts[0]
    result_path = attempt / 'results.json'
    require(result_path.stat().st_size <= 1024**2, 'bounded original fresh result required')
    result = json.loads(result_path.read_bytes())
    commands = canonical_shape(result, commit=commit, source_sha256=source_sha256)
    clone = owned_path(root, root / result['checkout'])
    require(clone == attempt / 'c' and source_identity(root)['sha256'] == source_sha256
        and source_identity(clone)['sha256'] == source_sha256, 'seed and exact fresh source differ')
    preparation = result.get('preparation')
    require(type(preparation) is list and len(preparation) == 1
        and preparation[0].get('operation') == 'clone' and preparation[0].get('state') == 'COMPLETED'
        and preparation[0].get('status') == 'PASS' and type(preparation[0].get('exit_code')) is int
        and preparation[0]['exit_code'] == 0, 'original fresh clone preparation did not pass')
    original_clone = ['git', 'clone', '--no-local', '--config', 'core.autocrlf=false', str(root), str(clone)]
    directory = attempt / 'preparation/clone'
    require(root / preparation[0]['receipt'] == directory, 'original clone receipt path differs')
    proof = checked_receipt(root, directory, source_sha256, original_clone)
    require(proof['verification_status'] == 'PASS', 'actual clone preparation receipt failed')
    for row in commands:
        directory = attempt / 'commands' / row['target']
        require(root / row['receipt'] == directory, 'original canonical receipt path differs')
        proof = checked_receipt(root, directory, source_sha256, ['make', row['target']])
        require(proof['verification_status'] == 'PASS' and Path(proof['cwd']) == clone,
            'actual canonical receipt or its native checkout differs')
    ledger_path = clone / '.local-runs/verify-ledger/ledger.json'
    require(ledger_path.stat().st_size <= 1024**2, 'bounded original canonical ledger required')
    ledger = json.loads(ledger_path.read_bytes())
    steps = load_ledger(clone, ledger_path, source_sha256)
    require(ledger['status'] == 'PASS' and len(steps) == 18
        and [row['target'] for row in steps] == read_plan(clone)
        and all(row.get('state') == 'COMPLETED' and row.get('status') == 'PASS' for row in steps),
        'all eighteen unchanged authoritative gates must actually pass')
    return {'status': 'RECORDED CANONICAL PASS', 'commit': commit, 'source_sha256': source_sha256,
        'fresh_result_sha256': hashlib.sha256(result_path.read_bytes()).hexdigest(),
        'ledger_sha256': hashlib.sha256(ledger_path.read_bytes()).hexdigest(), 'gates': 18,
        'reference_qualified': False,
        'scope': 'Original complete canonical fresh receipts/streams/ledger checked; actual allocation authority, host lifetime and sample continuity remain outer validation obligations.'}
