"""Literal independent SQLite expectations; these are not benchmark observations."""
import contextlib
import gc
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'benchmarks'))
import sqlite_worker as worker


def fixture():
    fields = [
        {'name': 'tenant', 'type': 'text', 'nullable': False},
        {'name': 'n', 'type': 'i64', 'nullable': True},
        {'name': 'label', 'type': 'text', 'nullable': True},
        {'name': 'flag', 'type': 'bool', 'nullable': True},
        {'name': 'hidden', 'type': 'text', 'nullable': False},
    ]
    rows = [
        ['beta', 999, 'OTHER_TENANT', True, 'SECRET_B'],
        ['alpha', 3, None, True, 'SECRET_A'],
        ['alpha', 3, None, True, 'SECRET_A'],
        ['alpha', -2, 'visible', False, 'SECRET_A'],
        ['alpha', None, 'last', None, 'SECRET_A'],
    ]
    catalog = {'version': 1, 'snapshot': 'synthetic-unit', 'tables': {'sales': {'columns': fields, 'rows': rows}}}
    context = {'version': 1, 'tenant': 'alpha', 'tables': {'sales': {'tenant_column': 'tenant', 'columns': ['flag', 'label', 'n']}}}
    spec = {'sql': 'SELECT flag, label, n FROM sales ORDER BY rowid', 'schema': [
        {'name': 'flag', 'type': 'bool', 'nullable': True},
        {'name': 'label', 'type': 'text', 'nullable': True},
        {'name': 'n', 'type': 'i64', 'nullable': True},
    ]}
    return catalog, context, spec


def write_case(folder, catalog, context, spec):
    for name, value in [('catalog', catalog), ('context', context), ('case', spec)]:
        (folder / (name + '.json')).write_text(json.dumps(value), encoding='utf-8')


class SQLiteMaterialization(unittest.TestCase):
    def test_physical_authorization_column_order_nulls_and_duplicate_bag(self):
        catalog, context, _ = fixture()
        with sqlite3.connect(':memory:') as database:
            worker.materialize_catalog(database, catalog, context)
            self.assertEqual([(r[1], r[2]) for r in database.execute('PRAGMA table_info(sales)')],
                             [('flag', 'INTEGER'), ('label', 'TEXT'), ('n', 'INTEGER')])
            self.assertEqual(list(database.execute('SELECT * FROM sales ORDER BY rowid')),
                             [(1, None, 3), (1, None, 3), (0, 'visible', -2), (None, 'last', None)])
            with self.assertRaises(sqlite3.OperationalError):
                database.execute('SELECT tenant, hidden FROM sales')

    def test_single_visible_column_keeps_parameter_tuple_arity(self):
        catalog, context, _ = fixture()
        context['tables']['sales']['columns'] = ['n']
        with sqlite3.connect(':memory:') as database:
            worker.materialize_catalog(database, catalog, context)
            self.assertEqual(list(database.execute('SELECT n FROM sales ORDER BY rowid')),
                             [(3,), (3,), (-2,), (None,)])

    def test_empty_visible_schema_preserves_sqlite_rejection(self):
        catalog, context, _ = fixture()
        context['tables']['sales']['columns'] = []
        with sqlite3.connect(':memory:') as database:
            with self.assertRaises(sqlite3.OperationalError):
                worker.materialize_catalog(database, catalog, context)

    def test_success_restores_prior_gc_state_and_decodes_all_inputs_in_scope(self):
        prior = gc.isenabled()
        original_loads = json.loads
        try:
            with tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary)
                write_case(folder, *fixture())
                for enabled in (True, False):
                    with self.subTest(enabled=enabled):
                        (gc.enable if enabled else gc.disable)()
                        observed = []
                        def decode(value):
                            observed.append(gc.isenabled())
                            return original_loads(value)
                        with patch.object(worker.json, 'loads', side_effect=decode):
                            database, spec = worker.load_authorized_database(folder)
                        try:
                            self.assertEqual(gc.isenabled(), enabled)
                            self.assertEqual(observed, [False, False, False])
                            self.assertEqual(list(database.execute(spec['sql'])),
                                             [(1, None, 3), (1, None, 3), (0, 'visible', -2), (None, 'last', None)])
                        finally:
                            database.close()
        finally:
            (gc.enable if prior else gc.disable)()

    def test_json_failure_restores_both_prior_gc_states(self):
        prior = gc.isenabled()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary)
                write_case(folder, *fixture())
                (folder / 'catalog.json').write_bytes(b'{"tables":')
                for enabled in (True, False):
                    with self.subTest(enabled=enabled):
                        (gc.enable if enabled else gc.disable)()
                        with self.assertRaises(json.JSONDecodeError):
                            worker.load_authorized_database(folder)
                        self.assertEqual(gc.isenabled(), enabled)
        finally:
            (gc.enable if prior else gc.disable)()

    def test_setup_failure_closes_owned_connection_and_restores_gc(self):
        prior = gc.isenabled()
        connect = sqlite3.connect
        opened = []
        def observed_connect(*args, **kwargs):
            database = connect(*args, **kwargs)
            opened.append(database)
            return database
        try:
            with tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary)
                catalog, context, spec = fixture()
                context['tables']['sales']['columns'] = ['missing']
                write_case(folder, catalog, context, spec)
                for enabled in (True, False):
                    with self.subTest(enabled=enabled):
                        (gc.enable if enabled else gc.disable)()
                        with patch.object(worker.sqlite3, 'connect', side_effect=observed_connect):
                            with self.assertRaises(KeyError):
                                worker.load_authorized_database(folder)
                        self.assertEqual(gc.isenabled(), enabled)
                        with self.assertRaises(sqlite3.ProgrammingError):
                            opened[-1].execute('SELECT 1')
        finally:
            for database in opened:
                database.close()
            (gc.enable if prior else gc.disable)()

    def run_worker(self, folder, connect=None):
        out = io.StringIO()
        arguments = ['sqlite_worker.py', '--case', str(folder), '--measurement', str(folder / 'measurement.json')]
        with patch.object(sys, 'argv', arguments), contextlib.redirect_stdout(out):
            if connect is None:
                code = worker.main()
            else:
                with patch.object(worker.sqlite3, 'connect', side_effect=connect):
                    code = worker.main()
        raw = out.getvalue().rstrip('\n').encode()
        measurement = json.loads((folder / 'measurement.json').read_bytes())
        self.assertEqual(code, 0)
        self.assertEqual(measurement['result_sha256'], hashlib.sha256(raw).hexdigest())
        return json.loads(raw), measurement

    def test_worker_preserves_boolean_and_null_output_scalars(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            write_case(folder, *fixture())
            result, measured = self.run_worker(folder)
            self.assertEqual(result['rows'], [[True, None, 3], [True, None, 3], [False, 'visible', -2], [None, 'last', None]])
            self.assertEqual(measured['emitted_rows'], 4)

    def test_row_cap_still_collects_the_entire_real_sql_result(self):
        connect = sqlite3.connect
        seen = []
        def observe(value):
            seen.append(value)
            return value
        def observed_connect(*args, **kwargs):
            database = connect(*args, **kwargs)
            database.create_function('seen', 1, observe)
            return database
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            catalog, context, spec = fixture()
            catalog['tables']['sales']['rows'] = [['alpha', i, None, None, 'SECRET'] for i in range(10005)]
            context['tables']['sales']['columns'] = ['n']
            spec.update(sql='SELECT seen(n) AS n FROM sales', schema=[{'name': 'n', 'type': 'i64', 'nullable': True}])
            write_case(folder, catalog, context, spec)
            result, measured = self.run_worker(folder, observed_connect)
            self.assertEqual(seen, list(range(10005)))
            self.assertEqual(result['status'], 'error')
            self.assertEqual(result['error']['code'], 'E_OUTPUT_LIMIT')
            self.assertNotIn('rows', result)
            self.assertIsNone(measured['emitted_rows'])

    def test_byte_cap_retains_existing_failure_envelope(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            catalog, context, spec = fixture()
            catalog['tables']['sales']['rows'] = [['alpha', i, 'x' * 4096, None, 'SECRET'] for i in range(300)]
            context['tables']['sales']['columns'] = ['label']
            spec.update(sql='SELECT label FROM sales', schema=[{'name': 'label', 'type': 'text', 'nullable': True}])
            write_case(folder, catalog, context, spec)
            result, measured = self.run_worker(folder)
            self.assertEqual(result['status'], 'error')
            self.assertEqual(result['error']['code'], 'E_OUTPUT_LIMIT')
            self.assertNotIn('rows', result)
            self.assertIsNone(measured['emitted_rows'])


if __name__ == '__main__':
    unittest.main()

