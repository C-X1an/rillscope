#!/usr/bin/env python3
"""Selected real Rust PASS-FAIL-PASS controls in disposable committed clones."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CONTROLS = [
    ('tenant_barrier', 'src/operators/stream.rs', 'if data.text_matches(row, grant.tenant_column, &context.tenant)? {', 'if true {', 'execute::tests::duplicate_join_and_scalar_aggregate_are_exact'),
    ('forbidden_reference', 'src/bind.rs', 'Expr::Col(name) => {', 'Expr::Col(name) => {\n                if self.hidden.contains(name) { return Ok(TypedExpr { kind: ExprKind::Literal(Value::I64(0)), data_type: DataType::I64, nullable: false }); }', 'verify::tests::denied_filter_is_bound_before_execution'),
    ('forged_provenance', 'src/verify.rs', 'if schema.len() > 256 || schema != node.schema {', 'if schema.len() > 256 {', 'verify::tests::reject_forged_provenance_grant_source_and_snapshot'),
    ('work_cap', 'src/budget.rs', 'if next > self.limits.max_work {', 'if false {', 'budget::tests::charge_never_exceeds_limit_and_cancel_precedes_allocation'),
    ('expression_temporaries', 'src/operators/stream.rs', 'pub(crate) fn expr_temporary_bytes(expr: &TypedExpr, row: &[Value]) -> Result<usize> {', 'pub(crate) fn expr_temporary_bytes(expr: &TypedExpr, row: &[Value]) -> Result<usize> {\n    if matches!(expr.kind, crate::types::ExprKind::Binary(..)) { return Ok(std::mem::size_of::<Value>()); }', 'execute::tests::expression_string_temporaries_reserve_before_allocation'),
    ('sort_reorder_checkpoint', 'src/operators/stream.rs', 'budget.observe("sort_reorder_output")?;\n            budget.charge(1)?;', '/* Intentionally removed reorder cancellation/work checkpoint. */', 'operators::stream::review_tests::reorder_observes_mid_loop_cancellation_and_work_limit'),
    ('binding_identity_anchor', 'src/verify.rs', '!plan.binding_identity_matches()', 'false', 'verify::tests::reject_context_and_snapshot_substitution_before_verification'),
    ('retained_schema_reservation', 'src/execute.rs', 'let schema_reservation = budget.reserve(schema_bytes(plan.root())?)?;', 'let schema_reservation = budget.reserve(0)?;', 'execute::tests::empty_result_schema_is_reserved_and_retained'),
    ('batch_conversion_checkpoint', 'src/operators/stream.rs', 'budget.observe("batch_conversion_chunk")?;', '/* Intentionally removed conversion checkpoint. */', 'operators::stream::review_tests::batch_conversion_observes_mid_column_cancellation'),
    ('repeated_join_probe_keys', 'src/operators/blocking.rs', 'let _key_temporary = budget.reserve(key_bytes)?;', 'let _key_temporary = budget.reserve(0)?;', 'execute::tests::repeated_text_join_probe_keys_reserve_every_copy'),
]

def run(command, cwd, out, env):
    result = subprocess.run(command, cwd=cwd, capture_output=True, env=env, timeout=300)
    out.with_suffix('.stdout.txt').write_bytes(result.stdout)
    out.with_suffix('.stderr.txt').write_bytes(result.stderr)
    row = {'command': command, 'exit_code': result.returncode,
           'stdout_sha256': hashlib.sha256(result.stdout).hexdigest(), 'stderr_sha256': hashlib.sha256(result.stderr).hexdigest()}
    out.with_suffix('.json').write_text(json.dumps(row, indent=2) + '\n')
    return result, row

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists(): parser.error('mutation evidence directory must be new')
    args.out.mkdir(parents=True)
    status = subprocess.run(['git', 'status', '--porcelain'], cwd=ROOT, capture_output=True, text=True, check=True)
    if status.stdout.strip(): raise RuntimeError('commit the audited public candidate before mutation verification')
    commit = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    reports = []
    for control, relative, old, new, test in CONTROLS:
        with tempfile.TemporaryDirectory(prefix='rillscope-control-') as folder:
            clone = Path(folder) / 'repo'
            subprocess.run(['git', 'clone', '--no-local', '--config', 'core.autocrlf=false', str(ROOT), str(clone)], capture_output=True, check=True)
            if not clone.resolve().is_relative_to(Path(folder).resolve()): raise RuntimeError('disposable clone boundary failure')
            env = os.environ.copy()
            env['CARGO_TARGET_DIR'] = str(Path(folder) / 'target')
            command = ['cargo', 'test', '--locked', '--lib', test, '--', '--exact']
            path = clone / relative
            original = path.read_bytes()
            text = original.decode()
            if text.count(old) != 1: raise RuntimeError('mutation anchor must identify exactly one operation')
            baseline, before = run(command, clone, args.out / (control + '-before'), env)
            if baseline.returncode or b'running 1 test' not in baseline.stdout: raise RuntimeError('selected baseline did not execute and pass')
            path.write_text(text.replace(old, new), encoding='utf-8', newline='\n')
            mutant_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            mutant, broken = run(command, clone, args.out / (control + '-mutant'), env)
            path.write_bytes(original)
            restored, after = run(command, clone, args.out / (control + '-restored'), env)
            detected = mutant.returncode != 0 and b'running 1 test' in mutant.stdout and b'FAILED' in mutant.stdout and b'assertion' in mutant.stdout + mutant.stderr
            healthy = restored.returncode == 0 and b'running 1 test' in restored.stdout and path.read_bytes() == original
            report = {'control': control, 'source_commit': commit, 'path': relative, 'test': test,
                      'original_sha256': hashlib.sha256(original).hexdigest(), 'mutant_sha256': mutant_hash,
                      'restored_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                      'baseline': before, 'mutant': broken, 'restored': after, 'status': 'PASS' if detected and healthy else 'FAIL'}
            reports.append(report)
            print(json.dumps({'control': control, 'sequence': [baseline.returncode, mutant.returncode, restored.returncode], 'status': report['status']}), flush=True)
    summary = {'source_commit': commit, 'controls': reports, 'status': 'PASS' if all(r['status'] == 'PASS' for r in reports) else 'FAIL',
               'scope': str(len(CONTROLS)) + ' selected Rust controls; no broad mutation-coverage percentage is claimed'}
    (args.out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    return int(summary['status'] != 'PASS')

if __name__ == '__main__': raise SystemExit(main())
