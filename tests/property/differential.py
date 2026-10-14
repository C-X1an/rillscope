"""1,000 reproducible Rust optimization comparisons against physically scoped SQLite."""
import argparse
import hashlib
import json
from pathlib import Path
import random
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests/acceptance_locked'))
from product_helpers import Client, BINARY, fixture, oracle, column as col, literal as lit, binary as expr, scan, project, filtered, ordered, compare_rows, digest

SEED = 610103

def cases(rng, family, threshold):
    s = scan()
    if family == 0:
        plan = {'op': 'limit', 'count': 9, 'input': ordered(project(filtered(s, expr('gt', col('s.amount'), lit(threshold))), [('id', col('s.id')), ('amount', col('s.amount'))]), ['id', 'amount'])}
        return plan, f'SELECT id, amount FROM sales WHERE amount>{threshold} ORDER BY id NULLS LAST, amount NULLS LAST LIMIT 9', ['i64', 'i64'], [True, True], True
    if family == 1:
        join = {'op': 'join', 'left': s, 'right': scan('lookup', 'l'), 'on': [{'left': col('s.id'), 'right': col('l.key')}]}
        plan = project(filtered(join, expr('eq', col('l.flag'), lit(True))), [('id', col('s.id')), ('amount', col('s.amount')), ('flag', col('l.flag'))])
        return plan, 'SELECT s.id, s.amount, l.flag FROM sales s JOIN lookup l ON s.id=l.key WHERE l.flag=TRUE', ['i64', 'i64', 'bool'], [True, True, True], False
    if family == 2:
        plan = {'op': 'aggregate', 'input': s, 'keys': [{'name': 'grp', 'expr': col('s.grp')}], 'aggregates': [{'name': 'n', 'kind': 'count_all'}, {'name': 'present', 'kind': 'count', 'expr': col('s.amount')}, {'name': 'total', 'kind': 'sum', 'expr': col('s.amount')}]}
        return plan, 'SELECT grp, COUNT(*) AS n, COUNT(amount) AS present, SUM(amount) AS total FROM sales GROUP BY grp', ['text', 'i64', 'i64', 'i64'], [True, False, False, True], False
    if family == 3:
        pred = expr('and', expr('ne', col('s.id'), lit(threshold)), expr('or', col('s.enabled'), {'lit': None, 'type': 'bool'}))
        plan = {'op': 'aggregate', 'input': filtered(s, pred), 'keys': [], 'aggregates': [{'name': 'n', 'kind': 'count_all'}, {'name': 'total', 'kind': 'sum', 'expr': col('s.amount')}]}
        return plan, f'SELECT COUNT(*) AS n, SUM(amount) AS total FROM sales WHERE id<>{threshold} AND (enabled OR NULL)', ['i64', 'i64'], [False, True], False
    if family == 4:
        plan = project(s, [('v', expr('sub', col('s.amount'), lit(threshold))), ('unknown', expr('eq', col('s.amount'), {'lit': None, 'type': 'i64'})), ('label', lit('é'))])
        return plan, f"SELECT amount-({threshold}) AS v, amount=NULL AS unknown, 'é' AS label FROM sales", ['i64', 'bool', 'text'], [True, True, False], False
    if family == 5:
        plan = filtered(project(s, [('x', col('s.id')), ('y', col('s.amount'))]), expr('le', col('y'), lit(threshold)))
        return plan, f'SELECT id AS x, amount AS y FROM sales WHERE amount<={threshold}', ['i64', 'i64'], [True, True], False
    if family == 6:
        join = {'op': 'join', 'left': s, 'right': scan('lookup', 'l'), 'on': [{'left': col('s.id'), 'right': col('l.key')}]}
        plan = {'op': 'aggregate', 'input': filtered(join, expr('ge', col('s.amount'), lit(threshold))), 'keys': [], 'aggregates': [{'name': 'n', 'kind': 'count_all'}, {'name': 'total', 'kind': 'sum', 'expr': col('s.amount')}]}
        return plan, f'SELECT COUNT(*) AS n, SUM(s.amount) AS total FROM sales s JOIN lookup l ON s.id=l.key WHERE s.amount>={threshold}', ['i64', 'i64'], [False, True], False
    if family == 7:
        direction = rng.choice(['asc', 'desc'])
        nulls = rng.choice(['first', 'last'])
        plan = ordered(project(s, [('grp', col('s.grp')), ('id', col('s.id')), ('amount', col('s.amount'))]), ['grp', 'id', 'amount'], direction, nulls)
        return plan, f'SELECT grp, id, amount FROM sales ORDER BY grp {direction} NULLS {nulls}, id {direction} NULLS {nulls}, amount {direction} NULLS {nulls}', ['text', 'i64', 'i64'], [True, True, True], True
    if family == 8:
        plan = {'op': 'aggregate', 'input': s, 'keys': [{'name': 'enabled', 'expr': col('s.enabled')}], 'aggregates': [{'name': 'n', 'kind': 'count', 'expr': col('s.id')}, {'name': 'total', 'kind': 'sum', 'expr': col('s.amount')}]}
        return plan, 'SELECT enabled, COUNT(id) AS n, SUM(amount) AS total FROM sales GROUP BY enabled', ['bool', 'i64', 'i64'], [True, False, True], False
    plan = project(filtered(s, expr('or', expr('eq', col('s.grp'), lit('é')), {'op': 'is_null', 'expr': col('s.amount')})), [('id', col('s.id')), ('amount', col('s.amount'))])
    return plan, "SELECT id, amount FROM sales WHERE grp='é' OR amount IS NULL", ['i64', 'i64'], [True, True], False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--cases', type=int, default=1000)
    args = parser.parse_args()
    if args.cases < 1000: parser.error('the locked criterion requires at least 1000 cases')
    if args.out.exists(): parser.error('preserve existing verdicts; choose a fresh output directory')
    args.out.mkdir(parents=True)
    rng = random.Random(SEED)
    failures = 0
    start = time.perf_counter()
    with tempfile.TemporaryDirectory() as folder, (args.out / 'verdicts.jsonl').open('w', encoding='utf-8') as output:
        for case in range(args.cases):
            rows = [[rng.choice(['alpha', 'alpha', 'beta']), rng.choice([None, 0, 1, 2, 3]), rng.choice([None, -20, -1, 0, 2, 19, 30]), rng.choice([None, 'é', 'Z', 'x']), rng.choice([None, True, False]), 999, 'SYNTHETIC_HIDDEN_CANARY'] for _ in range(rng.randrange(41))]
            lookup = [[rng.choice(['alpha', 'alpha', 'beta']), rng.choice([None, 0, 1, 2, 3]), rng.choice([None, True, False]), 'SYNTHETIC_LOOKUP_CANARY'] for _ in range(rng.randrange(31))]
            catalog = fixture(rows, lookup)
            client = Client(folder, catalog)
            connection = oracle(catalog, 'alpha')
            plan, sql, types, nullable, is_ordered = cases(rng, case % 10, rng.randrange(-20, 31))
            verdict = {'case': case, 'seed': SEED, 'family': case % 10, 'input_sha256': digest([catalog, plan]), 'status': 'FAIL'}
            try:
                expected = connection.execute(sql).fetchall()
                values = []
                for optimize in (False, True):
                    code, value = client.call(plan, optimize=optimize)
                    if code != 0: raise AssertionError(value)
                    if [f['type'] for f in value['schema']] != types or [f['nullable'] for f in value['schema']] != nullable: raise AssertionError('independent schema mismatch')
                    compare_rows(value['rows'], expected, value['schema'], is_ordered)
                    values.append(value)
                if values[0]['schema'] != values[1]['schema']: raise AssertionError('optimization changed schema')
                compare_rows(values[0]['rows'], values[1]['rows'], values[0]['schema'], is_ordered)
                if case % 10 == 0:
                    code, sql_value = client.call(sql, format='sql')
                    if code != 0: raise AssertionError(sql_value)
                    compare_rows(sql_value['rows'], expected, sql_value['schema'], is_ordered)
                verdict.update(status='PASS', result_digests=[digest([v['schema'], sorted(v['rows'], key=lambda row: json.dumps(row, ensure_ascii=False))]) for v in values])
            except Exception as error:
                failures += 1
                verdict['error'] = str(error)
                (args.out / f'failure-{case}.json').write_text(json.dumps({'catalog': catalog, 'query': plan, 'sql': sql}, ensure_ascii=False, indent=2), encoding='utf-8')
            finally: connection.close()
            output.write(json.dumps(verdict, ensure_ascii=False) + '\n')
            output.flush()
            if (case + 1) % 100 == 0: print(json.dumps({'executed': case + 1, 'failures': failures}), flush=True)
    summary = {'seed': SEED, 'cases': args.cases, 'failures': failures, 'status': 'PASS' if not failures else 'FAIL',
               'binary_sha256': hashlib.sha256(BINARY.read_bytes()).hexdigest(), 'elapsed_seconds': time.perf_counter() - start,
               'verdicts_sha256': hashlib.sha256((args.out / 'verdicts.jsonl').read_bytes()).hexdigest()}
    (args.out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary))
    return int(bool(failures))

if __name__ == '__main__': raise SystemExit(main())
