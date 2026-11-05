"""Bind one collected attempt to its original completed enclosing process.

The validator runs after that process has exited. These are recorded execution
and byte checks, not a grant, a query rerun or independent qualification.
"""
import hashlib
import math
from pathlib import PurePosixPath
import re

import archive_capture
from canonical_reference_allocation import METHOD, require
from canonical_reference_retained_fresh import receipt, read_bounded_file
from kvm_reference_common import strict_json
from run_canonical_reference import MAX_CONFIG_BYTES, validate_plan

# The recorder samples finished_ns and elapsed in consecutive clock calls.
# More than10ms between those observations rejects qualification; it never
# repairs the timestamps or extends either original deadline.
ELAPSED_SAMPLING_TOLERANCE_SECONDS = 0.010


def native_path(value, root=None):
    require(type(value) is str and 0 < len(value) <= 4096 and '\\' not in value
        and ':' not in value and '\x00' not in value, 'closed original native owner path required')
    path = PurePosixPath(value)
    require(path.as_posix() == value and '..' not in path.parts and value != '.',
        'canonical original native owner path required')
    if not path.is_absolute():
        require(root is not None, 'absolute original native owner root required'); path = root / path
    return path


def integer(value): return type(value) is int and 0 < value < 2**63
def number(value): return type(value) in (int, float) and math.isfinite(value) and value >= 0


class OwnerBytes:
    def __init__(self, path):
        self.path = archive_capture.owned(path)
        require(self.path.name == 'receipt.json', 'exact original terminal-owner receipt required')
        self.initial = {}; self.cache = {}
        for name in ('receipt.json', 'stdout.txt', 'stderr.txt'):
            limit = 8 * 1024**2 if name == 'receipt.json' else 16 * 1024**2
            raw = read_bounded_file(self.path.parent / name, limit)
            self.initial[name] = hashlib.sha256(raw).hexdigest(); self.cache[name] = raw

    def raw(self, name, limit=16 * 1024**2):
        name = PurePosixPath(name)
        require(name.parent == PurePosixPath('original-owner') and name.name in self.cache,
            'unrelated original owner evidence path')
        raw = self.cache[name.name]; require(len(raw) <= limit, 'original owner evidence exceeds read bound')
        return raw

    def document(self, name, limit=16 * 1024**2):
        value = strict_json(self.raw(name, limit)); require(type(value) is dict, 'original owner object required')
        return value

    def unchanged(self):
        for name, digest in self.initial.items():
            require(hashlib.sha256(read_bounded_file(self.path.parent / name, 16 * 1024**2)).hexdigest() == digest,
                'original enclosing owner evidence changed during validation')


def validate_terminal_owner(artifact, owner_receipt, *, source):
    artifact = archive_capture.owned(artifact); original = OwnerBytes(owner_receipt)
    plan_raw = read_bounded_file(artifact / 'declared-plan.json', MAX_CONFIG_BYTES)
    plan = validate_plan(strict_json(plan_raw)); commit = plan['commit']
    require(plan['source_sha256'] == source['sha256'], 'original collection plan source differs from validator')
    proof = original.document('original-owner/receipt.json', 8 * 1024**2)
    root = native_path(proof.get('cwd')); command = proof.get('command')
    require(type(command) is list and len(command) == 8 and all(type(item) is str for item in command)
        and native_path(command[0]).is_absolute() and native_path(command[1], root) == root / 'scripts/run_canonical_reference.py'
        and command[2::2] == ['--config', '--out', '--run-as']
        and re.fullmatch('[a-z_][a-z0-9_-]{0,31}', command[7]),
        'original canonical collector command/identity differs')
    config, output = native_path(command[3], root), native_path(command[5], root)
    require(config.is_relative_to(root / '.local-runs') and output.is_relative_to(root / '.local-runs')
        and not config.is_relative_to(output) and config != output,
        'original collector configuration/output ownership differs')
    proof = receipt(original, 'original-owner', source=source, commit=commit, command=command, cwd=root)
    expected_input = [{'path': str(config), 'bytes': len(plan_raw), 'sha256': hashlib.sha256(plan_raw).hexdigest()}]
    require(proof['inputs_before'] == proof['inputs_after'] == expected_input,
        'original collector owner must fingerprint its exact declared plan input')
    require(0 <= proof['elapsed_seconds'] < plan['whole_seconds'],
        'actual enclosing process exceeded original whole-owner budget')
    result_raw = read_bounded_file(artifact / 'driver-result.json', 4 * 1024**2)
    result = strict_json(result_raw)
    require(type(result) is dict and type(result.get('schema_version')) is int and result['schema_version'] == 1
        and result.get('method') == METHOD and result.get('mode') == 'canonical'
        and result.get('status') == 'COLLECTED CANONICAL ATTEMPT' and result.get('commit') == commit
        and result.get('source_sha256') == source['sha256'] and result.get('plan_sha256') == hashlib.sha256(plan_raw).hexdigest()
        and result.get('reference_qualified') is False and result.get('all_record_validation') == 'NOT RUN'
        and result.get('provider_fit') == 'NOT ESTABLISHED', 'complete original unqualified collector result required')
    times = [result.get(name) for name in ('started_monotonic_ns', 'result_persistence_completed_monotonic_ns',
        'finished_monotonic_ns', 'deadline_monotonic_ns')]
    require(all(integer(value) for value in times) and times[0] <= times[1] <= times[2] < times[3]
        and abs(times[3] - times[0] - plan['whole_seconds'] * 10**9) <= 1000
        and number(result.get('elapsed_seconds'))
        and result['elapsed_seconds'] < proof['elapsed_seconds'] < plan['whole_seconds'],
        'original collector clocks/persistence/enclosing terminal interval differ')
    span_seconds = (times[2] - times[0]) / 10**9
    require(abs(result['elapsed_seconds'] - span_seconds) <= ELAPSED_SAMPLING_TOLERANCE_SECONDS
        and span_seconds <= proof['elapsed_seconds'] + ELAPSED_SAMPLING_TOLERANCE_SECONDS,
        'original collector elapsed/monotonic span cannot fit its actual enclosing terminal duration')
    cleanup = result.get('cleanup')
    require(type(cleanup) is dict and cleanup.get('status') == 'PASS'
        and type(cleanup.get('remaining_active_processes')) is int and cleanup['remaining_active_processes'] == 0,
        'original completed collector cleanup required')
    recovery = result.get('recovery_budget')
    require(type(recovery) is dict and recovery.get('status') == 'DECLARED BUDGET AVAILABLE'
        and type(recovery.get('declared_seconds')) is int and recovery['declared_seconds'] == plan['recovery_seconds']
        and number(recovery.get('available_preservation_seconds'))
        and abs(recovery['available_preservation_seconds'] - plan['recovery_seconds']) <= 1e-6,
        'failed-prefix preservation cannot satisfy original declared recovery stage')
    recovery_times = [recovery.get(name) for name in ('started_monotonic_ns', 'completed_monotonic_ns',
        'actual_deadline_monotonic_ns', 'declared_deadline_monotonic_ns')]
    require(all(integer(value) for value in recovery_times)
        and times[0] < recovery_times[0] <= recovery_times[1] < recovery_times[2] == recovery_times[3]
        and recovery_times[1] <= times[2]
        and abs(recovery_times[2] - recovery_times[0] - plan['recovery_seconds'] * 10**9) <= 1000
        and recovery_times[2] < times[3] - plan['cleanup_reserve_seconds'] * 10**9,
        'original stopped-recovery return/deadline/cleanup reserve differs')
    original.unchanged()
    require(read_bounded_file(artifact / 'declared-plan.json', MAX_CONFIG_BYTES) == plan_raw
        and read_bounded_file(artifact / 'driver-result.json', 4 * 1024**2) == result_raw,
        'original collector input/result changed during terminal validation')
    return {'status': 'CHECKED ORIGINAL TERMINAL OWNER', 'commit': commit, 'source_sha256': source['sha256'],
        'owner_receipt_sha256': original.initial['receipt.json'], 'driver_result_sha256': hashlib.sha256(result_raw).hexdigest(),
        'plan_sha256': hashlib.sha256(plan_raw).hexdigest(), 'actual_enclosing_seconds': proof['elapsed_seconds'],
        'original_root': str(root), 'original_output': str(output), 'plan': plan, 'collector': result,
        'reference_qualified': False,
        'scope': 'Original enclosing terminal receipt/streams/plan and original collector/recovery clocks checked after process exit. Allocation authority, stopped inventories, every raw benchmark record and independent reference qualification remain separate.'}
