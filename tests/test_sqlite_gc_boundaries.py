"""Independent literal controls, including one-shot GC interruption boundaries.

Only tiny owned fixtures/SQLite connections; not benchmark observations.
"""
import gc
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

OWN = Path(__file__).resolve().parent
ROOT = OWN.parent
CANDIDATE = ROOT
sys.path.insert(0, str(CANDIDATE / 'benchmarks'))
import sqlite_worker as worker

ENABLE, DISABLE, CONNECT = gc.enable, gc.disable, sqlite3.connect


def write_case(folder):
    columns = [{'name': 'tenant', 'type': 'text'}, {'name': 'n', 'type': 'i64'},
               {'name': 'txt', 'type': 'text'}, {'name': 'b', 'type': 'bool'}]
    rows = [['other', 99, 'HIDDEN', True], ['a', -(2**63), 'é\u0000末', True],
            ['a', 2**63-1, None, False], ['a', 2**63-1, None, False]]
    objects = {'catalog': {'tables': {'t': {'columns': columns, 'rows': rows}}},
               'context': {'tenant': 'a', 'tables': {'t': {'tenant_column': 'tenant', 'columns': ['b', 'txt', 'n']}}},
               'case': {'sql': 'SELECT * FROM t ORDER BY rowid'}}
    for name, obj in objects.items():
        (folder / (name + '.json')).write_bytes(json.dumps(obj, ensure_ascii=False).encode())


class IndependentGC(unittest.TestCase):
    def setUp(self):
        self.prior = gc.isenabled()
        self.opened = []
        self.temp = tempfile.TemporaryDirectory(prefix='rill-gc-')
        self.folder = Path(self.temp.name)
        write_case(self.folder)

    def tearDown(self):
        for db in self.opened:
            db.close()
        (ENABLE if self.prior else DISABLE)()
        self.temp.cleanup()

    def track_connect(self, *args, **kwargs):
        db = CONNECT(*args, **kwargs)
        self.opened.append(db)
        return db

    def test_pause_interruption_restores_prior_gc(self):
        ENABLE()
        def interrupted_pause():
            DISABLE()
            raise KeyboardInterrupt('one-shot interruption after actual GC pause')
        with patch.object(worker.gc, 'disable', side_effect=interrupted_pause):
            with self.assertRaises(KeyboardInterrupt):
                worker.load_authorized_database(self.folder)
        print(json.dumps({'control': 'pause-interruption', 'gc_enabled_after': gc.isenabled()}))
        self.assertTrue(gc.isenabled(), 'GC prior enabled state must survive pause interruption')

    def test_restore_interruption_closes_unreturned_connection(self):
        ENABLE()
        calls = 0
        def interrupted_restore():
            nonlocal calls
            calls += 1
            if calls == 1:
                raise KeyboardInterrupt('one-shot interruption before actual GC restore')
            ENABLE()
        with patch.object(worker.sqlite3, 'connect', side_effect=self.track_connect), \
             patch.object(worker.gc, 'enable', side_effect=interrupted_restore):
            with self.assertRaises(KeyboardInterrupt):
                worker.load_authorized_database(self.folder)
        self.assertEqual(len(self.opened), 1)
        try:
            self.opened[0].execute('SELECT 1')
            closed = False
        except sqlite3.ProgrammingError:
            closed = True
        print(json.dumps({'control': 'restore-interruption', 'gc_enabled_after': gc.isenabled(),
                          'connection_closed': closed, 'restore_calls': calls}))
        self.assertEqual((gc.isenabled(), closed), (True, True),
                         'Failed handoff must restore GC and close its unreturned connection')

    def test_independent_extrema_unicode_nul_bag_and_projection(self):
        db, spec = worker.load_authorized_database(self.folder)
        self.opened.append(db)
        self.assertEqual(list(db.execute(spec['sql'])),
                         [(1, 'é\u0000末', -(2**63)), (0, None, 2**63-1), (0, None, 2**63-1)])
        self.assertEqual([row[1] for row in db.execute('PRAGMA table_info(t)')], ['b', 'txt', 'n'])
        with self.assertRaises(sqlite3.OperationalError):
            db.execute('SELECT tenant FROM t')

    def test_body_interruption_closes_connection_and_restores_both_states(self):
        materialize = worker.materialize_catalog
        for enabled in (True, False):
            (ENABLE if enabled else DISABLE)()
            def interrupted_body(db, catalog, context):
                materialize(db, catalog, context)
                raise KeyboardInterrupt('interruption after actual insertion')
            with patch.object(worker.sqlite3, 'connect', side_effect=self.track_connect), \
                 patch.object(worker, 'materialize_catalog', side_effect=interrupted_body):
                with self.assertRaises(KeyboardInterrupt):
                    worker.load_authorized_database(self.folder)
            self.assertEqual(gc.isenabled(), enabled)
            with self.assertRaises(sqlite3.ProgrammingError):
                self.opened[-1].execute('SELECT 1')


if __name__ == '__main__':
    unittest.main(verbosity=2)
