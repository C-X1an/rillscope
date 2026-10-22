"""Literal relation checks under real SQLite connection limits."""
from pathlib import Path
import json
import sqlite3
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'benchmarks'))
import sqlite_worker as worker
from test_sqlite_materialization import fixture

class InsertBatches(unittest.TestCase):
    def materialize(self, *, variables=None, sql_length=None, empty=False):
        catalog,context,_=fixture()
        # Three authorized rows include a duplicate; a fourth is another tenant.
        cycle=[['alpha',None,'v',False,'SECRET_A'],['alpha',-2,None,True,'SECRET_A'],
               ['alpha',-2,None,True,'SECRET_A'],['beta',999,'OTHER',True,'SECRET_B']]
        catalog['tables']['sales']['rows']=[] if empty else cycle*90
        context['tables']['sales']['columns']=['n','label','flag']
        expected=[] if empty else [(None,'v',0),(-2,None,1),(-2,None,1)]*90
        with sqlite3.connect(':memory:') as database:
            if variables is not None:database.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER,variables)
            if sql_length is not None:database.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH,sql_length)
            worker.materialize_catalog(database,catalog,context)
            self.assertEqual(list(database.execute('SELECT * FROM sales ORDER BY rowid')),expected)
            self.assertEqual(database.execute('SELECT COUNT(*) FROM sales').fetchone()[0],len(expected))
            with self.assertRaises(sqlite3.OperationalError):database.execute('SELECT tenant,hidden FROM sales')

    def test_variable_limit_preserves_all_rows_order_nulls_and_duplicate_bag(self):
        self.materialize(variables=7)

    def test_sql_length_limit_preserves_all_authorized_cells(self):
        self.materialize(sql_length=256)

    def test_empty_authorized_relation_remains_empty(self):
        self.materialize(variables=7,empty=True)

    def test_insufficient_bind_limit_preserves_rejection_even_for_empty_relation(self):
        for empty in [False,True]:
            with self.subTest(empty=empty),self.assertRaises(sqlite3.OperationalError):
                self.materialize(variables=0,empty=empty)

class Regressions(unittest.TestCase):
    def test_finite_reiterable_must_not_restart_or_duplicate(self):
        class StoppedList(list):
            calls=0
            def __iter__(self):
                self.calls+=1
                if self.calls>2: raise RuntimeError('bounded third-iteration stop')
                return super().__iter__()
        rows=StoppedList([(7,),(9,)])
        with sqlite3.connect(':memory:') as db:
            db.execute('CREATE TABLE t(n INTEGER)')
            error=None
            try: worker.insert_authorized_rows(db,'t',['n'],rows)
            except RuntimeError as caught: error=str(caught)
            actual=list(db.execute('SELECT * FROM t ORDER BY rowid'))
            print(json.dumps({'control':'reiterable','rows':actual,'error':error,'iterations':rows.calls}))
            self.assertEqual((error,actual),(None,[(7,),(9,)]))

    def test_low_real_opcode_limit_does_not_create_new_prepare_rejection(self):
        rows=[(i,) for i in range(129)]
        with sqlite3.connect(':memory:') as old:
            old.execute('CREATE TABLE t(n INTEGER)')
            old.setlimit(sqlite3.SQLITE_LIMIT_VDBE_OP,80)
            old.executemany('INSERT INTO t VALUES (?)',iter(rows))
            self.assertEqual(list(old.execute('SELECT * FROM t ORDER BY rowid')),rows)
        with sqlite3.connect(':memory:') as db:
            db.execute('CREATE TABLE t(n INTEGER)')
            default=db.getlimit(sqlite3.SQLITE_LIMIT_VDBE_OP)
            db.setlimit(sqlite3.SQLITE_LIMIT_VDBE_OP,80)
            error=None
            try: worker.insert_authorized_rows(db,'t',['n'],iter(rows))
            except MemoryError: error='MemoryError'
            print(json.dumps({'control':'opcode-limit','default':default,'lowered':80,'candidate_error':error}))
            self.assertIsNone(error)
            self.assertEqual(list(db.execute('SELECT * FROM t ORDER BY rowid')),rows)

class PrepareSafety(unittest.TestCase):
    def test_plain_list_and_tuple_are_consumed_exactly_once(self):
        for rows in ([(7,), (9,)], ((7,), (9,))):
            with self.subTest(container=type(rows).__name__), sqlite3.connect(':memory:') as db:
                db.execute('CREATE TABLE t(n INTEGER)')
                worker.insert_authorized_rows(db, 't', ['n'], rows)
                self.assertEqual(list(db.execute('SELECT * FROM t ORDER BY rowid')), [(7,), (9,)])

    def test_low_opcode_fallback_preserves_prior_uncommitted_rows_and_empty_relation(self):
        for empty in (False, True):
            with self.subTest(empty=empty), sqlite3.connect(':memory:') as db:
                db.execute('CREATE TABLE prior(n INTEGER)')
                db.execute('CREATE TABLE t(n INTEGER)')
                db.execute('INSERT INTO prior VALUES (41)')
                db.setlimit(sqlite3.SQLITE_LIMIT_VDBE_OP, 80)
                rows = [] if empty else [(7,), (9,)] * 65
                worker.insert_authorized_rows(db, 't', ['n'], iter(rows))
                self.assertEqual(list(db.execute('SELECT * FROM prior')), [(41,)])
                self.assertEqual(list(db.execute('SELECT * FROM t ORDER BY rowid')), rows)
                self.assertEqual(db.getlimit(sqlite3.SQLITE_LIMIT_VDBE_OP), 80)
                self.assertTrue(db.in_transaction)

    def test_data_execution_memory_error_is_propagated_without_retry(self):
        class FailAfterInsert(sqlite3.Connection):
            def execute(self, sql, parameters=(), /):
                cursor = super().execute(sql, parameters)
                if sql.startswith('INSERT INTO t '):
                    raise MemoryError('fault after actual data execution')
                return cursor
        with sqlite3.connect(':memory:', factory=FailAfterInsert) as db:
            db.execute('CREATE TABLE t(n INTEGER)')
            with self.assertRaisesRegex(MemoryError, 'after actual data execution'):
                worker.insert_authorized_rows(db, 't', ['n'], iter([(7,)] * 129))
            self.assertEqual(list(db.execute('SELECT n FROM t')), [(7,)] * 128)
            self.assertEqual(db.total_changes, 128)

    def test_prepare_failure_that_loses_prior_transaction_is_not_retried(self):
        class RollbackAtPrepare(sqlite3.Connection):
            def executemany(self, sql, parameters, /):
                if sql.count('?') > 1 and parameters == ():
                    self.rollback()
                    raise MemoryError('fault rolls back prior transaction')
                return super().executemany(sql, parameters)
        with sqlite3.connect(':memory:', factory=RollbackAtPrepare) as db:
            db.execute('CREATE TABLE prior(n INTEGER)')
            db.execute('CREATE TABLE t(n INTEGER)')
            db.execute('INSERT INTO prior VALUES (41)')
            with self.assertRaisesRegex(MemoryError, 'rolls back prior transaction'):
                worker.insert_authorized_rows(db, 't', ['n'], iter([(7,)] * 129))
            self.assertEqual(list(db.execute('SELECT * FROM t')), [])
            self.assertFalse(db.in_transaction)

    def test_empty_relation_keeps_original_prepare_and_transaction_behavior(self):
        with sqlite3.connect(':memory:') as db:
            db.execute('CREATE TABLE t(n INTEGER)')
            worker.insert_authorized_rows(db, 't', ['n'], iter(()))
            self.assertTrue(db.in_transaction)
            self.assertEqual(db.total_changes, 0)
            with self.assertRaises(sqlite3.OperationalError):
                worker.insert_authorized_rows(db, 't', ['n', 'wrong'], iter(()))


if __name__=='__main__':unittest.main()
