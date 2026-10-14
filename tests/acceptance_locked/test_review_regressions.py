"""Independent review counterexamples; expectations follow the locked contract."""
import tempfile
import unittest
from product_helpers import Client, fixture, scan, project, filtered, column, binary, oracle

class ReviewRegressions(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.client = Client(self.folder.name, fixture())

    def test_projection_substitution_does_not_reject_valid_input(self):
        for count in (4, 15):
            plan = scan()
            for i in range(count):
                value = column('s.enabled' if i == 0 else 'x')
                pair = binary('or', value, value)
                plan = project(plan, [('x', binary('or', pair, pair))])
            plan = filtered(plan, column('x'))
            for mode in (False, True):
                code, result = self.client.call(plan, optimize=mode)
                self.assertEqual(code, 0)
                self.assertEqual(result['schema'], [{'name': 'x', 'type': 'bool', 'nullable': True}])
                self.assertEqual(result['rows'], [[True]])

    def test_optimizer_pass_limit_preserves_valid_query(self):
        plan = scan()
        for i in range(20):
            plan = project(plan, [('x', column('s.enabled' if i == 0 else 'x'))])
        for mode in (False, True):
            code, result = self.client.call(filtered(plan, column('x')), optimize=mode)
            self.assertEqual(code, 0)
            self.assertEqual(result['rows'], [[True]])

    def test_sql_postfix_nesting_rejects_with_typed_limit(self):
        source = 'SELECT id' + ' IS NOT NULL' * 2700 + ' FROM sales'
        self.assertLess(len(source.encode()), 65536)
        code, result = self.client.call(source, format='sql')
        self.assertEqual(code, 3)
        self.assertEqual(result['error']['code'], 'E_LIMIT')

    def test_grouped_column_qualification_resolves_same_identity(self):
        queries = ['SELECT id AS k, COUNT(*) AS n FROM sales s GROUP BY s.id ORDER BY k NULLS FIRST',
                   'SELECT s.id AS k, COUNT(*) AS n FROM sales s GROUP BY id ORDER BY k NULLS FIRST']
        with oracle(fixture(), 'alpha') as database:
            expected = [list(row) for row in database.execute(queries[0])]
        self.assertEqual(expected, [[None, 1], [1, 2]])
        for source in queries:
            code, result = self.client.call(source, format='sql')
            self.assertEqual(code, 0)
            self.assertEqual(result['rows'], expected)

    def test_group_resolution_preserves_ambiguity_and_forbidden_errors(self):
        sources = [('SELECT id AS k, COUNT(*) AS n FROM sales s JOIN sales t ON s.id=t.id GROUP BY s.id', 'E_BIND'),
                   ('SELECT s.id AS k, COUNT(*) AS n FROM sales s JOIN sales t ON s.id=t.id GROUP BY id', 'E_BIND'),
                   ('SELECT salary, COUNT(*) FROM sales GROUP BY id', 'E_FORBIDDEN')]
        for source, expected in sources:
            code, result = self.client.call(source, format='sql')
            self.assertEqual(code, 2)
            self.assertEqual(result['error']['code'], expected)
        code, result = self.client.call('SELECT key AS k, COUNT(*) AS n FROM sales s JOIN lookup l ON s.id=l.key GROUP BY l.key ORDER BY k', format='sql')
        self.assertEqual(code, 0)
        self.assertEqual(result['rows'], [[1, 4]])

    def test_sql_order_is_output_column_or_alias_only(self):
        for expression in ('1', 'id + 1', 'id IS NULL'):
            code, result = self.client.call('SELECT id FROM sales ORDER BY ' + expression, format='sql')
            self.assertEqual(code, 2)
            self.assertEqual(result['error']['code'], 'E_UNSUPPORTED')

if __name__ == '__main__': unittest.main()
