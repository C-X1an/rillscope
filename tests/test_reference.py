import copy
import json
import random
import sqlite3
from contextlib import closing
import unittest
from collections import Counter
from tools.reference.engine import Limits, QueryError, Reference, evaluate, strict_loads


def fixture(rows=None):
    cols = [{'name': 'tenant', 'type': 'text', 'nullable': False},
            {'name': 'id', 'type': 'i64', 'nullable': False},
            {'name': 'amount', 'type': 'i64', 'nullable': True},
            {'name': 'secret', 'type': 'text', 'nullable': False}]
    catalog = {'version': 1, 'snapshot': 'synthetic-v1', 'tables': {
        'sales': {'columns': cols, 'rows': rows if rows is not None else [
            ['alpha', 1, 20, 'private-a'], ['beta', 2, 999, 'private-b'],
            ['alpha', 3, None, 'private-c'], ['alpha', 4, 20, 'private-d']]}}}
    context = {'version': 1, 'policy_revision': 'synthetic-r1', 'tenant': 'alpha',
               'tables': {'sales': {'tenant_column': 'tenant', 'columns': ['id', 'amount']}}}
    return catalog, context


def scan(alias='s'):
    return {'op': 'scan', 'table': 'sales', 'alias': alias}


def col(name): return {'col': name}


def lit(val, dtype='i64'):
    return {'lit': val, 'type': dtype} if val is None else {'lit': val}


def binary(op, left, right): return {'op': op, 'left': left, 'right': right}


def project(node, *names):
    return {'op': 'project', 'input': node, 'columns': [{'name': n.rsplit('.', 1)[-1], 'expr': col(n)} for n in names]}


def query(node): return {'version': 1, 'plan': node}


def bag(rows): return Counter(json.dumps(list(r), separators=(',', ':')) for r in rows)


class ReferenceTests(unittest.TestCase):
    def run_node(self, node, rows=None, limits=None):
        cat, ctx = fixture(rows)
        return evaluate(cat, ctx, query(node), limits)

    def test_tenant(self):
        self.assertEqual(self.run_node(project(scan(), 'id'))['rows'], [[1], [3], [4]])

    def test_unknown_fields(self):
        for node in [dict(scan(), policy=True), {'op': 'policy_scan', 'table': 'sales', 'alias': 's'}]:
            self.assertEqual(self.run_node(node)['status'], 'error')

    def test_forbidden_columns_in_all_positions(self):
        nodes = [project(scan(), 'secret'),
                 {'op': 'filter', 'input': scan(), 'predicate': binary('eq', col('secret'), lit('x'))},
                 {'op': 'sort', 'input': scan(), 'keys': [{'expr': col('secret'), 'direction': 'asc', 'nulls': 'last'}]},
                 {'op': 'aggregate', 'input': scan(), 'keys': [{'name': 'x', 'expr': col('secret')}],
                  'aggregates': [{'name': 'c', 'kind': 'count_all'}]},
                 {'op': 'aggregate', 'input': scan(), 'keys': [],
                  'aggregates': [{'name': 'c', 'kind': 'count', 'expr': col('secret')}]},
                 {'op': 'join', 'left': scan('a'), 'right': scan('b'),
                  'on': [{'left': col('a.secret'), 'right': col('b.secret')}]}]
        for node in nodes:
            with self.subTest(op=node['op']):
                self.assertEqual(self.run_node(node)['error']['code'], 'E_FORBIDDEN')

    def test_bind_empty_relation(self):
        for rows in ([], [['beta', 1, 0, 'hidden']]):
            self.assertEqual(self.run_node(project(scan(), 'secret'), rows)['error']['code'], 'E_FORBIDDEN')
            self.assertEqual(self.run_node(project(scan(), 'missing'), rows)['error']['code'], 'E_BIND')

    def test_bool_int_not_interchangeable(self):
        node = {'op': 'filter', 'input': scan(), 'predicate': binary('eq', col('id'), lit(True))}
        self.assertEqual(self.run_node(node)['error']['code'], 'E_TYPE')

    def test_three_valued_logic(self):
        expected_and = [[False, False, False], [False, True, None], [False, None, None]]
        expected_or = [[False, True, None], [True, True, True], [None, True, None]]
        vals = [False, True, None]
        for op, expected in [('and', expected_and), ('or', expected_or)]:
            for i, a in enumerate(vals):
                for j, b in enumerate(vals):
                    node = {'op': 'project', 'input': scan(), 'columns': [
                        {'name': 'v', 'expr': binary(op, lit(a, 'bool'), lit(b, 'bool'))}]}
                    out = self.run_node(node, [['alpha', 1, 0, 'x']])
                    self.assertEqual(out['rows'], [[expected[i][j]]], (op, a, b))

    def test_null_filter(self):
        node = {'op': 'filter', 'input': scan(), 'predicate': binary('eq', col('amount'), lit(None))}
        self.assertEqual(self.run_node(node)['rows'], [])

    def test_null_and_duplicate_join(self):
        rows = [['alpha', 1, 5, 'x'], ['alpha', 2, 5, 'y'], ['alpha', 3, None, 'z']]
        node = {'op': 'join', 'left': scan('a'), 'right': scan('b'),
                'on': [{'left': col('a.amount'), 'right': col('b.amount')}]}
        out = self.run_node(node, rows)
        self.assertEqual(len(out['rows']), 4)
        self.assertEqual(bag(out['rows']), bag([[1, 5, 1, 5], [1, 5, 2, 5], [2, 5, 1, 5], [2, 5, 2, 5]]))

    def test_identical_duplicate_join(self):
        rows = [['alpha', 1, 5, 'x'], ['alpha', 1, 5, 'x']]
        node = {'op': 'join', 'left': scan('a'), 'right': scan('b'),
                'on': [{'left': col('a.id'), 'right': col('b.id')}]}
        self.assertEqual(self.run_node(node, rows)['rows'], [[1, 5, 1, 5]] * 4)

    def test_ambiguous_join(self):
        join = {'op': 'join', 'left': scan('a'), 'right': scan('b'),
                'on': [{'left': col('a.id'), 'right': col('b.id')}]}
        self.assertEqual(self.run_node(project(join, 'id'))['error']['code'], 'E_BIND')

    def test_scalar_empty_aggregate(self):
        node = {'op': 'aggregate', 'input': scan(), 'keys': [], 'aggregates': [
            {'name': 'c', 'kind': 'count_all'}, {'name': 'n', 'kind': 'count', 'expr': col('amount')},
            {'name': 's', 'kind': 'sum', 'expr': col('amount')}]}
        self.assertEqual(self.run_node(node, [])['rows'], [[0, 0, None]])

    def test_group_null(self):
        node = {'op': 'aggregate', 'input': scan(), 'keys': [{'name': 'v', 'expr': col('amount')}],
                'aggregates': [{'name': 'c', 'kind': 'count_all'}]}
        self.assertEqual(bag(self.run_node(node)['rows']), bag([[20, 2], [None, 1]]))

    def test_sort_nulls_both_directions(self):
        for direction, nulls, expected in [('asc', 'last', [1, 2, None]), ('desc', 'last', [2, 1, None]),
                                           ('asc', 'first', [None, 1, 2]), ('desc', 'first', [None, 2, 1])]:
            node = {'op': 'sort', 'input': project(scan(), 'amount'), 'keys': [
                {'expr': col('amount'), 'direction': direction, 'nulls': nulls}]}
            rows = [['alpha', i, val, 'x'] for i, val in enumerate([2, None, 1])]
            self.assertEqual(self.run_node(node, rows)['rows'], [[v] for v in expected])

    def test_overflow_and_hidden_row_order(self):
        node = {'op': 'project', 'input': scan(), 'columns': [
            {'name': 'v', 'expr': binary('add', col('amount'), lit(1))}]}
        self.assertEqual(self.run_node(node, [['alpha', 1, 2**63-1, 'x']])['error']['code'], 'E_OVERFLOW')
        rows = [['beta', 1, 2**63-1, 'hidden'], ['alpha', 2, 1, 'x']]
        self.assertEqual(self.run_node(node, rows)['rows'], [[2]])

    def test_no_partial_success(self):
        out = self.run_node(scan(), limits=Limits(work=2))
        self.assertEqual(out['error']['code'], 'E_BUDGET')
        self.assertNotIn('rows', out)

    def test_output_limits(self):
        for limits in [Limits(output_rows=1), Limits(output_bytes=50)]:
            self.assertEqual(self.run_node(scan(), limits=limits)['error']['code'], 'E_OUTPUT_LIMIT')

    def test_structural_limit(self):
        node = scan()
        for _ in range(40): node = {'op': 'limit', 'input': node, 'count': 1}
        self.assertEqual(self.run_node(node)['error']['code'], 'E_LIMIT')

    def test_invalid_catalog(self):
        cat, ctx = fixture(); cat['tables']['sales']['rows'][0][1] = True
        self.assertEqual(evaluate(cat, ctx, query(scan()))['error']['code'], 'E_CATALOG')

    def test_snapshot_is_copied(self):
        cat, ctx = fixture(); engine = Reference(cat, ctx)
        cat['tables']['sales']['rows'][0][0] = 'beta'; ctx['tenant'] = 'beta'
        self.assertEqual(engine.run(query(project(scan(), 'id')))['rows'], [[1], [3], [4]])

    def test_input_unchanged(self):
        cat, ctx = fixture(); before = copy.deepcopy((cat, ctx))
        evaluate(cat, ctx, query(scan()), Limits(work=0))
        self.assertEqual((cat, ctx), before)

    def test_json_strict(self):
        for raw in ['{"a":1,"a":2}', '{"x":NaN}', '[' * 10000, 'x' * 65537]:
            with self.assertRaises(QueryError): strict_loads(raw)

    def test_closed_version(self):
        cat, ctx = fixture()
        for version in [True, 0, 2, '1']:
            self.assertEqual(evaluate(cat, ctx, {'version': version, 'plan': scan()})['status'], 'error')

    def test_duplicate_output_names(self):
        node = {'op': 'project', 'input': scan(), 'columns': [{'name': 'x', 'expr': col('id')}] * 2}
        self.assertEqual(self.run_node(node)['error']['code'], 'E_BIND')

    def test_unavailable_table(self):
        node = {'op': 'scan', 'table': 'other', 'alias': 'x'}
        self.assertEqual(self.run_node(node)['error']['code'], 'E_FORBIDDEN')

    def test_projection_changes_scope(self):
        self.assertEqual(self.run_node(project(project(scan(), 'id'), 's.id'))['error']['code'], 'E_BIND')

    def test_limit_zero(self):
        self.assertEqual(self.run_node({'op': 'limit', 'input': scan(), 'count': 0})['rows'], [])

    def test_unknown_function(self):
        node = {'op': 'project', 'input': scan(), 'columns': [{'name': 'x', 'expr': {'op': 'read_file', 'path': '/etc/passwd'}}]}
        self.assertEqual(self.run_node(node)['error']['code'], 'E_UNSUPPORTED')

    def test_reference_is_not_product(self):
        out = self.run_node(scan())
        self.assertEqual(out['implementation'], 'python-reference')
        self.assertNotIn('peak_reserved_bytes', out['metrics'])

    def test_malformed_null_type_and_shape(self):
        for value in [[], {}, 0, True, None, 'unknown']:
            node = {'op': 'project', 'input': scan(), 'columns': [
                {'name': 'x', 'expr': {'lit': None, 'type': value}}]}
            self.assertEqual(self.run_node(node)['status'], 'error')
        for value in [None, [], 3, 'scan', {'op': None}, {'op': []}]:
            cat, ctx = fixture()
            self.assertEqual(evaluate(cat, ctx, query(value))['status'], 'error')

    def test_sqlite_differential_1000(self):
        # Oracle tables are physically authorized here, independently from Reference.
        # No host policy rewrite is passed to SQLite and no reference evaluator is used.
        for seed in range(1000):
            rng = random.Random(seed)
            rows = [[rng.choice(['alpha', 'beta']), rng.randrange(6), rng.choice([None, -2, 0, 1, 4]), 'hidden']
                    for _ in range(rng.randrange(0, 24))]
            authorized = [(row[1], row[2]) for row in rows if row[0] == 'alpha']
            with closing(sqlite3.connect(':memory:')) as db:
                db.execute('CREATE TABLE t(id INTEGER NOT NULL, amount INTEGER)')
                db.executemany('INSERT INTO t VALUES (?, ?)', authorized)
                mode, threshold = seed % 5, rng.randrange(-3, 5)
                if mode == 0:
                    node = project({'op': 'filter', 'input': scan(), 'predicate': binary('gt', col('amount'), lit(threshold))}, 'id', 'amount')
                    sql, params = 'SELECT id,amount FROM t WHERE amount>?', (threshold,)
                elif mode == 1:
                    node = {'op': 'aggregate', 'input': scan(), 'keys': [{'name': 'a', 'expr': col('amount')}],
                            'aggregates': [{'name': 'c', 'kind': 'count_all'}, {'name': 's', 'kind': 'sum', 'expr': col('id')}]}
                    sql, params = 'SELECT amount,COUNT(*),SUM(id) FROM t GROUP BY amount', ()
                elif mode == 2:
                    node = {'op': 'join', 'left': scan('a'), 'right': scan('b'),
                            'on': [{'left': col('a.amount'), 'right': col('b.amount')}]}
                    sql, params = 'SELECT a.id,a.amount,b.id,b.amount FROM t a JOIN t b ON a.amount=b.amount', ()
                elif mode == 3:
                    node = {'op': 'aggregate', 'input': scan(), 'keys': [], 'aggregates': [
                        {'name': 'c', 'kind': 'count_all'}, {'name': 'n', 'kind': 'count', 'expr': col('amount')},
                        {'name': 's', 'kind': 'sum', 'expr': col('amount')}]}
                    sql, params = 'SELECT COUNT(*),COUNT(amount),SUM(amount) FROM t', ()
                else:
                    node = {'op': 'sort', 'input': project(scan(), 'amount', 'id'), 'keys': [
                        {'expr': col('amount'), 'direction': 'desc', 'nulls': 'last'},
                        {'expr': col('id'), 'direction': 'asc', 'nulls': 'last'}]}
                    sql, params = 'SELECT amount,id FROM t ORDER BY amount DESC NULLS LAST,id ASC', ()
                actual = self.run_node(node, rows)
                self.assertEqual(actual['status'], 'ok', (seed, actual))
                expected = db.execute(sql, params).fetchall()
                self.assertEqual(actual['rows'], [list(x) for x in expected], seed) if mode == 4 else self.assertEqual(bag(actual['rows']), bag(expected), seed)


if __name__ == '__main__': unittest.main()
