"""Locked behavior exercised through the actual Rust CLI, never the reference executor."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import subprocess
import time
from product_helpers import Client, BINARY, fixture, context, oracle, column, literal, binary, scan, project, filtered, ordered, compare_rows, digest

class ProductTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.catalog = fixture()
        self.client = Client(self.temp.name, self.catalog)

    def success(self, query, sql, ordered=False, format='json'):
        code, value = self.client.call(query, format=format)
        self.assertEqual(code, 0, value)
        connection = oracle(self.catalog, 'alpha')
        self.addCleanup(connection.close)
        expected = connection.execute(sql).fetchall()
        compare_rows(value['rows'], expected, value['schema'], ordered)
        return value

    def denied(self, query, codes=('E_FORBIDDEN',), format='json'):
        code, value = self.client.call(query, format=format)
        self.assertNotEqual(code, 0)
        self.assertEqual(value['status'], 'error')
        self.assertIn(value['error']['code'], codes)
        self.assertNotIn('rows', value)
        for canary in ['B_TENANT_CANARY', 'A_HIDDEN_CANARY', 'B_HIDDEN_CANARY', 'FAKE_CONFIG_CANARY']:
            self.assertNotIn(canary, json.dumps(value))

    def test_ac001_closed_input_and_duplicates(self):
        for data in [b'{"version":1,"version":1,"plan":{"op":"scan","table":"sales","alias":"s"}}',
                     b'{"version":2,"plan":{"op":"scan","table":"sales","alias":"s"}}',
                     b'{"version":1,"tenant":"beta","plan":{"op":"scan","table":"sales","alias":"s"}}']:
            self.denied(data, ('E_INPUT', 'E_UNSUPPORTED'))
        self.denied({'op': 'policy_scan', 'table': 'sales'}, ('E_INPUT', 'E_UNSUPPORTED'))

    def test_frontend_and_binding_denials_have_zero_actual_scans(self):
        counter = Path(self.temp.name) / 'scan-counter.txt'
        self.client.env['RILLSCOPE_TEST_SCAN_COUNTER_FILE'] = str(counter)
        code, _ = self.client.call(project(scan(), [('id', column('s.id'))]))
        self.assertEqual(code, 0)
        self.assertEqual(counter.read_text().strip(), '1')
        denied = [(b'{"version":2,"plan":{"op":"scan","table":"sales","alias":"s"}}', ('E_INPUT', 'E_UNSUPPORTED')),
                  (b'{"version":1,"plan":{"op":"scan","table":"sales","alias":"s"},"extra":1}', ('E_INPUT',)),
                  ({'op': 'policy_scan', 'table': 'sales'}, ('E_INPUT', 'E_UNSUPPORTED')),
                  (project(scan(), [('missing', column('s.unknown'))]), ('E_BIND',)),
                  (filtered(scan(), binary('eq', column('s.grp'), literal(1))), ('E_TYPE',)),
                  (project(scan(), [('salary', column('s.salary'))]), ('E_FORBIDDEN',))]
        for query, codes in denied:
            self.denied(query, codes)
            self.assertEqual(counter.read_text().strip(), '0')

    def test_ac002_sql_json_typed_ordered_equivalence(self):
        sql = 'SELECT id, amount FROM sales WHERE amount > 10 ORDER BY id LIMIT 10'
        plan = {'op': 'limit', 'count': 10, 'input': ordered(project(filtered(scan(), binary('gt', column('s.amount'), literal(10))), [('id', column('s.id')), ('amount', column('s.amount'))]), ['id'])}
        json_result = self.success(plan, sql, ordered=True)
        sql_result = self.success(sql, sql, ordered=True, format='sql')
        self.assertEqual(sql_result['schema'], json_result['schema'])
        self.assertEqual(sql_result['rows'], json_result['rows'])

    def test_ac003_binding_and_types(self):
        self.denied(project(scan(), [('bad', column('s.unknown'))]), ('E_BIND',))
        self.denied(filtered(scan(), binary('eq', column('s.grp'), literal(1))), ('E_TYPE',))
        join = {'op': 'join', 'left': scan(alias='a'), 'right': scan(alias='b'), 'on': [{'left': column('a.id'), 'right': column('b.id')}]}
        self.denied(project(join, [('id', column('id'))]), ('E_BIND',))

    def test_ac004_join_duplicates_and_aggregate(self):
        sql = 'SELECT s.id AS key, COUNT(*) AS n, COUNT(s.amount) AS present, SUM(s.amount) AS total FROM sales s INNER JOIN lookup l ON s.id=l.key GROUP BY s.id ORDER BY key'
        self.success(sql, sql, ordered=True, format='sql')

    def test_ac005_three_valued_nullable_and_empty(self):
        for predicate in [binary('and', column('s.enabled'), {'lit': None, 'type': 'bool'}), binary('or', column('s.enabled'), {'lit': None, 'type': 'bool'})]:
            op = predicate['op'].upper()
            query = project(scan(), [('v', predicate)])
            self.success(query, f'SELECT enabled {op} NULL FROM sales')
        for where in ['amount IS NULL', 'amount = NULL', 'FALSE', 'NULL']:
            sql = f'SELECT COUNT(*) AS n, COUNT(amount) AS present, SUM(amount) AS total FROM sales WHERE {where}'
            self.success(sql, sql, format='sql')
        sql = 'SELECT grp, COUNT(*) AS n, SUM(amount) AS total FROM sales GROUP BY grp ORDER BY grp NULLS FIRST'
        self.success(sql, sql, ordered=True, format='sql')

    def test_ac007_ac014_explain_and_error_redaction(self):
        plan = project(filtered(scan(), binary('gt', column('s.amount'), literal(0))), [('id', column('s.id'))])
        code, value = self.client.call(plan, command='explain')
        self.assertEqual(code, 0)
        self.assertIn('PolicyScan', value['operators'])
        for canary in ['A_HIDDEN_CANARY', 'B_TENANT_CANARY', 'FAKE_CONFIG_CANARY', 'salary', 'secret']:
            self.assertNotIn(canary, json.dumps(value))
        self.assertNotIn('row_count', value)
        self.assertNotIn('rows', value)
        self.denied(filtered(scan(), binary('gt', column('s.secret'), literal(0))))

    def test_ac009_bad_catalog_rejected(self):
        for transform in ['width', 'type', 'duplicate', 'nullable']:
            catalog = copy.deepcopy(self.catalog)
            if transform == 'width': catalog['tables']['sales']['rows'][0].pop()
            if transform == 'type': catalog['tables']['sales']['rows'][0][1] = True
            if transform == 'duplicate': catalog['tables']['sales']['columns'][1]['name'] = 'tenant'
            if transform == 'nullable': catalog['tables']['sales']['rows'][0][0] = None
            self.client.catalog.write_text(json.dumps(catalog))
            self.denied(scan(), ('E_CATALOG',))

    def test_ac010_two_tenants_nested_operator_paths(self):
        query = 'SELECT s.id AS id, COUNT(*) AS n, SUM(s.amount) AS total FROM sales s INNER JOIN lookup l ON s.id=l.key WHERE l.flag IS NULL OR l.flag=TRUE GROUP BY s.id ORDER BY id'
        self.success(query, query, ordered=True, format='sql')
        beta_catalog = copy.deepcopy(self.catalog)
        for row in beta_catalog['tables']['sales']['rows']:
            if row[0] == 'beta': row[2] = 1000
        beta = Client(self.temp.name, beta_catalog, 'beta')
        code, value = beta.call('SELECT id, amount FROM sales ORDER BY id', format='sql')
        self.assertEqual(code, 0)
        self.assertEqual(value['rows'], [[1, 1000]])

    def test_ac011_forbidden_column_in_all_six_contexts(self):
        counter = Path(self.temp.name) / 'denial-matrix-scan-counter.txt'
        self.client.env['RILLSCOPE_TEST_SCAN_COUNTER_FILE'] = str(counter)
        queries = [project(scan(), [('salary', column('s.salary'))]),
                   filtered(scan(), binary('gt', column('s.salary'), literal(0))),
                   {'op': 'join', 'left': scan(), 'right': scan('lookup', 'l'), 'on': [{'left': column('s.salary'), 'right': column('l.key')}]},
                   {'op': 'aggregate', 'input': scan(), 'keys': [{'name': 'k', 'expr': column('s.salary')}], 'aggregates': []},
                   {'op': 'aggregate', 'input': scan(), 'keys': [], 'aggregates': [{'name': 'v', 'kind': 'sum', 'expr': column('s.salary')}]},
                   ordered(scan(), ['s.salary'])]
        for query in queries:
            self.denied(query)
            self.assertEqual(counter.read_text().strip(), '0')

    def test_ac013_sql_has_no_effectful_constructs(self):
        for sql in ["COPY sales TO 'canary'", "ATTACH 'canary'", 'CREATE TABLE canary(id int)', 'UPDATE sales SET id=9',
                    "SELECT read_csv('canary') FROM sales", "SELECT http('canary') FROM sales", 'SELECT extension(1) FROM sales',
                    'SELECT udf(1) FROM sales', 'SELECT id FROM sales; SELECT id FROM sales']:
            self.denied(sql, ('E_UNSUPPORTED',), format='sql')

    def test_ac015_input_depth_and_bytes(self):
        self.denied(b' ' * 65537, ('E_LIMIT',))
        deep = scan()
        for _ in range(40): deep = {'op': 'limit', 'count': 1, 'input': deep}
        self.denied(deep, ('E_LIMIT',))

    def test_ac019_ten_repeat_digests_and_optimizer_toggle(self):
        query = 'SELECT id, amount FROM sales ORDER BY id, amount NULLS FIRST'
        values = [self.client.call(query, format='sql')[1] for _ in range(10)]
        digests = [digest([value['schema'], value['rows']]) for value in values]
        self.assertEqual(len(set(digests)), 1)
        _, disabled = self.client.call(query, format='sql', optimize=False)
        self.assertEqual([disabled['schema'], disabled['rows']], [values[0]['schema'], values[0]['rows']])

    def test_cli_duplicate_unknown_flags_and_no_required_keys(self):
        for extra in [['--tenant', 'beta'], ['--query', '-'], ['--max-work', '999999999']]:
            self.denied_bytes(extra)
        self.assertFalse(any('KEY' in key or 'TOKEN' in key for key in self.client.env))

    def test_unterminated_block_comment_is_invalid(self):
        self.denied('SELECT id FROM sales /*', ('E_INPUT', 'E_UNSUPPORTED'), format='sql')

    def test_ac018_actual_cli_cancel_before_publication(self):
        self.client.env['RILLSCOPE_TEST_CANCEL_BEFORE_PUBLISH'] = '1'
        code, value = self.client.call(project(scan(), [('id', column('s.id'))]))
        self.assertEqual(code, 4)
        self.assertEqual(value['error']['code'], 'E_CANCELLED')
        self.assertNotIn('rows', value)

    def test_ac018_actual_cli_row_and_byte_caps(self):
        rows = [['alpha', i, 1, 'x', True, 1, 'SYNTHETIC_HIDDEN'] for i in range(10001)]
        self.client = Client(self.temp.name, fixture(rows))
        self.denied(scan(), ('E_OUTPUT_LIMIT',))
        self.client = Client(self.temp.name, fixture(rows[:100]))
        self.denied(project(scan(), [('label', literal('\x01' * 4096))]), ('E_OUTPUT_LIMIT',))

    def test_four_scan_occurrences_preserve_scope_and_bags(self):
        joined = scan()
        for alias in ['l', 'm', 'n']:
            joined = {'op': 'join', 'left': joined, 'right': scan('lookup', alias), 'on': [{'left': column('s.id'), 'right': column(alias + '.key')}]}
        query = {'op': 'aggregate', 'input': joined, 'keys': [], 'aggregates': [{'name': 'n', 'kind': 'count_all'}, {'name': 'total', 'kind': 'sum', 'expr': column('s.amount')}]}
        self.success(query, 'SELECT COUNT(*) AS n, SUM(s.amount) AS total FROM sales s JOIN lookup l ON s.id=l.key JOIN lookup m ON s.id=m.key JOIN lookup n ON s.id=n.key')

    def test_signed_64_bit_values_are_exact_json_integers(self):
        values = project(scan(), [('max', literal(9223372036854775807)), ('min', literal(-9223372036854775808))])
        code, result = self.client.call(values)
        self.assertEqual(code, 0)
        self.assertEqual(result['rows'], [[9223372036854775807, -9223372036854775808]] * 3)

    def test_ac020_kill_actual_cli_after_join_checkpoint(self):
        rows = [['alpha', 1, 1, 'x', True, 1, 'SYNTHETIC_HIDDEN'] for _ in range(10000)]
        lookup = [['alpha', 1, True, 'SYNTHETIC_HIDDEN'] for _ in range(10000)]
        client = Client(self.temp.name, fixture(rows, lookup))
        marker = Path(self.temp.name) / 'join-stage.txt'
        client.env['RILLSCOPE_TEST_PHASE_FILE'] = str(marker)
        catalog_hash = hashlib.sha256(client.catalog.read_bytes()).hexdigest()
        query = Path(self.temp.name) / 'query.sql'
        query.write_text('SELECT COUNT(*) AS n FROM sales s JOIN lookup l ON s.id=l.key')
        args = [str(BINARY), 'run', '--catalog', str(client.catalog), '--context', str(client.context), '--query', str(query), '--format', 'sql']
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=client.env)
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)
        deadline = time.monotonic() + 20
        while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertTrue(marker.is_file(), 'no real join checkpoint observed')
        self.assertEqual(marker.read_text(), 'join_inner\n')
        self.assertIsNone(process.poll(), 'process must be running when terminated')
        process.kill()
        stdout, stderr = process.communicate(timeout=10)
        self.assertNotEqual(process.returncode, 0)
        self.assertNotIn(b'"status":"ok"', stdout)
        self.assertEqual(stderr, b'')
        after_hash = hashlib.sha256(client.catalog.read_bytes()).hexdigest()
        self.assertEqual(after_hash, catalog_hash)
        client.env.pop('RILLSCOPE_TEST_PHASE_FILE')
        code, result = client.call('SELECT COUNT(*) AS n FROM sales', format='sql')
        self.assertEqual(code, 0)
        self.assertEqual(result['rows'], [[10000]])
        print(json.dumps({'criterion':'AC-020','pid':process.pid,'observed_stage':'join_inner','termination_exit':process.returncode,
                          'catalog_before_sha256':catalog_hash,'catalog_after_sha256':after_hash,'rerun_rows':result['rows']}))

    def denied_bytes(self, extra):
        code, value = self.client.call(scan(), extra=extra)
        self.assertEqual(code, 2)
        self.assertEqual(value['error']['code'], 'E_INPUT')

if __name__ == '__main__': unittest.main()
