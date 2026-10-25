#!/usr/bin/env python3
"""Bounded offline replay of one complete original canonical retention bundle.

The parent owns a stoppable subprocess and one original deadline. No captured
executable is run. Even complete recorded checks require independent review
before reference qualification or any public performance claim.
"""
import argparse
import datetime as dt
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import archive_capture
import canonical_reference_allocation as protocol
from canonical_reference_bundle import extract, MAX_BYTES
from canonical_reference_terminal_owner import validate_terminal_owner
from canonical_reference_recovered_records import validate_prerequisites, OriginalRecords
from canonical_reference_continuity import (validate_reservation, validate_guest_allocation,
    validate_controls, validate_resources)
from canonical_reference_retained_fresh import (RetainedMetadata, validate_fresh, receipt, read_bounded_file, instant)
from canonical_reference_attempt_check import canonical_shape
from canonical_reference_retained_binaries import validate_binaries
from canonical_reference_campaigns import validate_campaigns
from evidence import source_identity, run_owned
from kvm_pilot_common import write_json
from kvm_reference_common import strict_json

require = protocol.require
STEPS = ('bundle', 'terminal-owner', 'recovered-prerequisites', 'prior-reservation', 'guest-allocation',
    'measurement-controls', 'sample-continuity', 'canonical-receipts', 'fresh-receipts', 'native-binaries', 'campaigns', 'final-stability')
RESULT = 'CHECKED COMPLETE ORIGINAL CANONICAL RECORDS'
# Correlation of recorded UTC with the same guest's monotonic clock is a
# recording validity condition, never a benchmark latency target or lease grant.
UTC_CORRELATION_TOLERANCE_NS = 1_000_000_000
MAX_CANONICAL_STDOUT = 16 * 1024**2
MAX_CLEAN_REPORT = 1024**2


def clean_output(raw):
    """Read the fixed final pretty JSON after unchanged child progress output.

    clean_verify forwards nested evidence/make output, then prints its own report
    with indent=2 at EOF. Nested members of that report have leading spaces. Keep
    all original progress bytes in the hashed stream; parse only that final report.
    """
    require(type(raw) is bytes and 0 < len(raw) <= MAX_CANONICAL_STDOUT, 'bounded original canonical stdout required')
    position = raw.rfind(b'\n{\n')
    final = raw[position + 1:] if position >= 0 else raw
    require(len(final) <= MAX_CLEAN_REPORT, 'final original clean report exceeds bound')
    value = strict_json(final); require(type(value) is dict, 'fixed clean_verify stdout must end in one original JSON object')
    return value


class OwnerCommands:
    def __init__(self, recovered): self.recovered = recovered
    def raw(self, path, limit=16 * 1024**2):
        path = PurePosixPath(path)
        require(path.parts and path.parts[0] == 'native-owner', 'unrelated original native command record')
        name = PurePosixPath(*path.parts[1:]).as_posix()
        require(name in self.recovered.members['owner'], 'original native owner command raw member missing')
        return self.recovered.raw(self.recovered.members['owner'][name], limit)
    def document(self, path, limit=16 * 1024**2):
        row = strict_json(self.raw(path, limit)); require(type(row) is dict, 'original native owner command object required'); return row


def check_canonical_commands(prerequisites, allocation, controls, *, source):
    owner = prerequisites['owner']; identity = {'commit': prerequisites['seed']['commit'], 'source': source}
    metadata = OwnerCommands(prerequisites['recovered']); root = PurePosixPath('/work/c')
    budget = owner.get('canonical_budget_seconds')
    require(type(budget) is int and budget >= 60, 'original explicit canonical command budget required')
    prefix = prerequisites['version_proofs'][0]['command'][:-2]
    command = prefix + ['/usr/bin/python3', '/work/c/scripts/clean_verify.py', '--budget-seconds', str(budget)]
    canonical = receipt(metadata, 'native-owner/commands/canonical', command=command, cwd=root, **identity)
    clean_output(metadata.raw('native-owner/commands/canonical/stdout.txt', MAX_CANONICAL_STDOUT))
    canonical_wall = (instant(canonical['finished_utc']) - instant(canonical['started_utc'])).total_seconds()
    config_names = [('reference-host-receipt.json', allocation['receipt_sha256'],
        len(prerequisites['recovered'].raw(prerequisites['recovered'].members['allocation']['reference-host-receipt.json'], 65536))),
        ('measurement-config.json', controls['config_sha256'],
            len(prerequisites['recovered'].raw(prerequisites['recovered'].members['owner']['measurement-config.json'], 8192))),
        ('export-config.json', controls['export_sha256'],
            len(prerequisites['recovered'].raw(prerequisites['recovered'].members['owner']['export-config.json'], 8192)))]
    expected = []
    for name, digest, size in config_names:
        path = '/work/c/.local-runs/' + ('canonical-allocation/' if name == 'reference-host-receipt.json' else 'canonical-attempt/') + name
        expected.append({'path': path, 'sha256': digest, 'bytes': size})
    require(canonical['inputs_before'] == canonical['inputs_after'] == sorted(expected, key=lambda row: row['path'])
        and canonical['elapsed_seconds'] <= budget
        and canonical['elapsed_seconds'] <= canonical_wall + .010
        and canonical_wall <= (owner['canonical_finished_monotonic_ns'] - owner['canonical_started_monotonic_ns']) / 10**9 + .010,
        'original canonical direct command/input/time binding differs')
    retained = owner['native_retention']; previous = instant(canonical['finished_utc']); proofs = [canonical]; first_retained_utc = None
    for name, command in [('retain-native-binaries', ['/usr/bin/python3', '/work/c/scripts/canonical_reference_binaries.py',
        '--out', '/work/c/.local-runs/canonical-attempt/native-binaries', '--commit', identity['commit'],
        '--source-sha256', source['sha256'], '--cutoff-monotonic-ns', str(retained['cutoff_monotonic_ns'])]),
        ('retain-canonical', ['/usr/bin/python3', '/work/c/scripts/retain_release.py', '--out', '/work/c/.local-runs/canonical-attempt/retained'])]:
        proof = receipt(metadata, 'native-owner/commands/' + name, command=command, cwd=root, **identity)
        require(proof['inputs_before'] == proof['inputs_after'] == [expected[0]]
            and previous <= instant(proof['started_utc'])
            and proof['elapsed_seconds'] <= (instant(proof['finished_utc']) - instant(proof['started_utc'])).total_seconds() + .010,
            'original shared retention command/input/order/UTC span differs')
        if first_retained_utc is None: first_retained_utc = instant(proof['started_utc'])
        previous = instant(proof['finished_utc']); proofs.append(proof)
    require(sum(proof['elapsed_seconds'] for proof in proofs[1:])
        <= (retained['finished_monotonic_ns'] - retained['started_monotonic_ns']) / 10**9 + .010
        and (previous - first_retained_utc).total_seconds()
            <= (retained['finished_monotonic_ns'] - retained['started_monotonic_ns']) / 10**9 + .010,
        'original retention commands cannot fit actual shared retention interval')
    return proofs


def utc_ns(value):
    delta = instant(value) - dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 10**9 + delta.microseconds * 1000


def check_recorded_utc_intervals(prerequisites, controls, proofs):
    """Use one original guest event to correlate, never mix host clock epochs."""
    event = controls['events'][0]
    require(event['phase'] == 'prefix-start' and all(protocol.integer(event.get(key)) for key in ('utc_ns', 'monotonic_ns')),
        'original guest UTC/monotonic correlation event required')
    offset = event['utc_ns'] - event['monotonic_ns']; tolerance = UTC_CORRELATION_TOLERANCE_NS
    owner, setup = prerequisites['owner'], prerequisites['setup']
    periods = [(proofs[:1], owner['canonical_started_monotonic_ns'], owner['canonical_finished_monotonic_ns']),
        (proofs[1:], owner['native_retention']['started_monotonic_ns'], owner['native_retention']['finished_monotonic_ns']),
        (prerequisites['version_proofs'], setup['started_monotonic_ns'], setup['finished_monotonic_ns'])]
    for group, begin, end in periods:
        require(group and protocol.integer(begin) and protocol.integer(end) and begin < end, 'original guest command interval required')
        for proof in group:
            require(begin + offset - tolerance <= utc_ns(proof['started_utc']) <= utc_ns(proof['finished_utc']) <= end + offset + tolerance,
                'original command UTC interval is outside its correlated guest monotonic interval')


def bind_clean_output(prerequisites, proofs, metadata, fresh, *, source):
    """Associate exact parsed stdout and all22 receipts with the selected result."""
    stdout = OwnerCommands(prerequisites['recovered']).raw('native-owner/commands/canonical/stdout.txt', MAX_CANONICAL_STDOUT)
    parsed = clean_output(stdout); canonical_shape(parsed, commit=fresh['commit'], source_sha256=source['sha256'])
    clone = PurePosixPath(fresh['fresh_checkout']); attempt = clone.parent
    result_name = attempt / 'results.json'; original_raw = metadata.raw(result_name, 1024**2); original = strict_json(original_raw)
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')
    require(hashlib.sha256(original_raw).hexdigest() == fresh['fresh_result_sha256'] and canonical(parsed) == canonical(original),
        'original clean_verify stdout differs from selected retained fresh result')
    paths = [attempt / 'preparation/clone'] + [attempt / 'commands' / name for name in ('bootstrap', 'verify', 'demo')]
    ledger = metadata.document(clone / '.local-runs/verify-ledger/ledger.json', 1024**2)
    require(type(ledger.get('commands')) is list and len(ledger['commands']) == 18, 'all eighteen original fresh gates required for containment')
    paths.extend(clone / row['receipt'] for row in ledger['commands'])
    require(len(paths) == 22 and len(set(paths)) == 22, 'exact22 original fresh command intervals required')
    begin, end = instant(proofs[0]['started_utc']), instant(proofs[0]['finished_utc'])
    for path in paths:
        proof = metadata.document(path / 'receipt.json', 8 * 1024**2)
        require(begin <= instant(proof['started_utc']) <= instant(proof['finished_utc']) <= end,
            'original fresh command interval is outside original canonical direct receipt')
    metadata.unchanged()
    return {'status': 'CHECKED ORIGINAL CLEAN STDOUT AND22 INTERVALS',
        'fresh_result_sha256': fresh['fresh_result_sha256'], 'stdout_sha256': hashlib.sha256(stdout).hexdigest(),
        'reference_qualified': False}


def inspect_originals(archive, out, *, max_bytes, deadline_ns):
    def remaining():
        value = (deadline_ns - time.monotonic_ns()) / 10**9
        require(value > 0, 'original complete-validation deadline exhausted'); return value
    source = source_identity(ROOT); remaining()
    report = {'schema_version': 1, 'method': protocol.METHOD, 'status': 'RUNNING',
        'source_sha256': source['sha256'], 'steps': [{'name': name, 'status': 'NOT RUN'} for name in STEPS],
        'reference_qualified': False, 'independent_review': 'REQUIRED', 'provider_fit': 'NOT ESTABLISHED',
        'scope': 'Original byte custody and recorded canonical execution/all-record replay only; no captured executable runs, inferred allocation, physical exclusivity or automatic qualification.'}
    result = out / 'record-inspection.json'; write_json(result, report)
    def stage(name, action):
        remaining(); entry = next(row for row in report['steps'] if row['name'] == name)
        entry.update(status='RUNNING'); write_json(result, report); remaining()
        value = action(); remaining(); entry.update(status='PASS'); write_json(result, report); remaining(); return value
    try:
        restored = out / 'original'
        restoration = stage('bundle', lambda: extract(archive, restored, max_bytes=max_bytes,
            budget_seconds=min(1800, math.floor(remaining()))))
        require(restoration['prefixes'] == [], 'complete original canonical bundle restoration required')
        terminal = stage('terminal-owner', lambda: validate_terminal_owner(restored / 'attempt', restored / 'owner/receipt.json', source=source))
        commit = terminal['plan']['commit']; original = OriginalRecords(restored, deadline_ns / 10**9)
        require(original.raw('input/declared-plan.json', 16384) == original.raw('attempt/declared-plan.json', 16384),
            'retained original input differs from collected declared plan')
        prerequisites = stage('recovered-prerequisites', lambda: validate_prerequisites(restored / 'attempt', terminal,
            source=source, deadline=deadline_ns / 10**9))
        reservation = stage('prior-reservation', lambda: validate_reservation(restored / 'reservation', prerequisites,
            terminal, original.document('owner/receipt.json', 8 * 1024**2), deadline=deadline_ns / 10**9))
        allocation = stage('guest-allocation', lambda: validate_guest_allocation(prerequisites, reservation))
        controls = stage('measurement-controls', lambda: validate_controls(prerequisites, reservation))
        continuity = stage('sample-continuity', lambda: validate_resources(prerequisites, reservation, allocation, controls))
        def canonical_commands():
            proofs = check_canonical_commands(prerequisites, allocation, controls, source=source)
            check_recorded_utc_intervals(prerequisites, controls, proofs); return proofs
        commands = stage('canonical-receipts', canonical_commands)
        recovered = prerequisites['recovered']; owner_tree = recovered.path(recovered.trees['owner'])
        metadata = RetainedMetadata(owner_tree / 'retained')
        def fresh_records():
            checked = validate_fresh(metadata, commit=commit, source=source, validator_root=ROOT)
            binding = bind_clean_output(prerequisites, commands, metadata, checked, source=source)
            return checked, binding
        fresh, clean_binding = stage('fresh-receipts', fresh_records)
        observed = prerequisites['owner'].get('canonical_records')
        require(type(observed) is dict and observed.get('status') == 'RECORDED CANONICAL PASS'
            and observed.get('commit') == commit and observed.get('source_sha256') == source['sha256']
            and observed.get('reference_qualified') is False and observed.get('gates') == fresh['gates'] == 18
            and all(observed.get(key) == fresh[key] for key in ('fresh_result_sha256', 'ledger_sha256')),
            'original native canonical summary differs from complete retained fresh records')
        clone_proof = metadata.document(PurePosixPath(fresh['fresh_checkout']).parent / 'preparation/clone/receipt.json')
        require(instant(prerequisites['version_proofs'][-1]['finished_utc']) <= instant(commands[0]['started_utc'])
            <= instant(clone_proof['started_utc']), 'original native tool/canonical/fresh command UTC ordering differs')
        native_root = owner_tree / 'native-binaries'
        native = stage('native-binaries', lambda: validate_binaries(native_root, commit=commit, source=source, fresh=fresh, validator_root=ROOT))
        native_record = strict_json(read_bounded_file(native_root / 'binaries-result.json', 4 * 1024**2))
        reserve = prerequisites['owner']['native_retention']
        require(native_record['cutoff_monotonic_ns'] == reserve['cutoff_monotonic_ns']
            and reserve['started_monotonic_ns'] <= native_record['finished_monotonic_ns'] <= reserve['finished_monotonic_ns'],
            'original native object retention escaped original shared reserve')
        campaigns = stage('campaigns', lambda: validate_campaigns(restored / 'attempt', metadata, native,
            commit=commit, source=source, export_config_sha256=controls['export_sha256'], out=out / 'campaigns'))
        def stable():
            original.unchanged(); prerequisites['outer'].unchanged(); recovered.unchanged(); reservation['files'].unchanged(); metadata.unchanged()
            require(source_identity(ROOT) == source, 'validator source changed during complete original record replay')
        stage('final-stability', stable)
        report.update(status=RESULT, commit=commit, archive_sha256=restoration['archive_sha256'],
            original_owner_sha256=terminal['owner_receipt_sha256'], complete_fresh=fresh, native_binaries=native,
            clean_output_binding=clean_binding,
            sampled_continuity=continuity, campaigns=campaigns,
            actual_enclosing_collection_seconds=terminal['actual_enclosing_seconds'])
        write_json(result, report); remaining()
    except BaseException as error:
        for entry in report['steps']:
            if entry['status'] == 'RUNNING': entry['status'] = 'FAIL'
        report.update(status='FAIL', error=type(error).__name__, reason=str(error)[:2048]); write_json(result, report); raise
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True); parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--max-expanded-bytes', type=int, required=True); parser.add_argument('--budget-seconds', type=int, required=True)
    parser.add_argument('--_worker-deadline-monotonic-ns', type=int, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    started = time.monotonic_ns()
    try:
        require(1 <= args.budget_seconds <= 3600 and 0 < args.max_expanded_bytes <= MAX_BYTES,
            'explicit complete-validation byte/time budgets required')
        deadline = started + args.budget_seconds * 10**9
        archive, out = map(archive_capture.owned, (args.archive, args.out))
        if args._worker_deadline_monotonic_ns is not None:
            require(out.is_dir() and 0 < args._worker_deadline_monotonic_ns - time.monotonic_ns() <= args.budget_seconds * 10**9,
                'original parent validation deadline required')
            row = inspect_originals(archive, out, max_bytes=args.max_expanded_bytes, deadline_ns=args._worker_deadline_monotonic_ns)
            print(json.dumps({'status': row['status'], 'reference_qualified': False})); return 0
        require(not out.exists() and out.parent.is_dir() and not archive.is_relative_to(out), 'new separate owned complete-validation output required')
        out.mkdir(mode=0o700); before = source_identity(ROOT)
        command = [sys.executable, str(ROOT / 'scripts/verify_canonical_reference.py'), '--archive', str(archive), '--out', str(out),
            '--max-expanded-bytes', str(args.max_expanded_bytes), '--budget-seconds', str(args.budget_seconds),
            '--_worker-deadline-monotonic-ns', str(deadline)]
        seconds = (deadline - time.monotonic_ns()) / 10**9; require(seconds > 0, 'original validation budget exhausted before worker')
        code, stdout, stderr, outcome, stopped = run_owned(command, cwd=ROOT, timeout=seconds, stdin_data=None)
        (out / 'stdout.txt').write_bytes(stdout); (out / 'stderr.txt').write_bytes(stderr)
        after = source_identity(ROOT); finished = time.monotonic_ns()
        record = {'status': 'FAIL', 'method': protocol.METHOD, 'command': command, 'exit_code': code, 'execution_outcome': outcome,
            'process_cleanup': stopped, 'started_monotonic_ns': started, 'finished_monotonic_ns': finished, 'deadline_monotonic_ns': deadline,
            'source_sha256': before['sha256'], 'source_after_sha256': after['sha256'],
            'stdout_sha256': hashlib.sha256(stdout).hexdigest(), 'stderr_sha256': hashlib.sha256(stderr).hexdigest(),
            'reference_qualified': False, 'independent_review': 'REQUIRED', 'provider_fit': 'NOT ESTABLISHED'}
        if code == 0 and outcome == 'EXECUTED' and stopped.get('status') == 'PASS' and type(stopped.get('remaining_active_processes')) is int \
            and stopped['remaining_active_processes'] == 0 and before == after and finished < deadline:
            row = strict_json(read_bounded_file(out / 'record-inspection.json', 16 * 1024**2))
            require(row.get('status') == RESULT and row.get('reference_qualified') is False
                and row.get('source_sha256') == before['sha256'] and row.get('steps') == [{'name': name, 'status': 'PASS'} for name in STEPS],
                'original complete worker report missing or incomplete')
            record['status'] = RESULT
        write_json(out / 'validation-owner.json', record)
        if time.monotonic_ns() >= deadline:
            record.update(status='FAIL', reason='original validation deadline exhausted during terminal persistence'); write_json(out / 'validation-owner.json', record)
        print(json.dumps({'status': record['status'], 'reference_qualified': False, 'independent_review': 'REQUIRED'}, sort_keys=True))
        return 0 if record['status'] == RESULT and time.monotonic_ns() < deadline else 1
    except (Exception, KeyboardInterrupt) as error:
        print(json.dumps({'status': 'FAIL', 'reference_qualified': False, 'error': type(error).__name__, 'reason': str(error)[:2048]})); return 1


if __name__ == '__main__': raise SystemExit(main())
