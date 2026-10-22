"""Literal SQLite batch, preparation, transaction and cleanup boundaries."""
import atexit
import gc
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'benchmarks'))
import sqlite_worker as worker

CONNECT=sqlite3.connect
_fixtures=tempfile.TemporaryDirectory(prefix='rillscope-sqlite-')
atexit.register(_fixtures.cleanup)
OWN=Path(_fixtures.name)

class RecordingConnection(sqlite3.Connection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.inserts = []
    def execute(self, sql, parameters=(), /):
        if sql.startswith('INSERT INTO'):
            self.inserts.append((sql, tuple(parameters)))
        return super().execute(sql, parameters)

class Independent(unittest.TestCase):
    def test_bounded_chunks_literal_cells_order_and_bags(self):
        rows = [(None, 'é\x00末', True), (-(2**63), None, False), (2**63-1, 'z', None)]*85 + [(7, '', False)]*2
        expected = [(None, 'é\x00末', 1), (-(2**63), None, 0), (2**63-1, 'z', None)]*85 + [(7, '', 0)]*2
        with sqlite3.connect(':memory:', factory=RecordingConnection) as db:
            db.execute('CREATE TABLE t(n INTEGER,s TEXT,b INTEGER)')
            worker.insert_authorized_rows(db, 't', ['n','s','b'], iter(rows))
            self.assertEqual(list(db.execute('SELECT * FROM t ORDER BY rowid')), expected)
            self.assertEqual([len(params)//3 for _,params in db.inserts], [128,128,1])
            self.assertTrue(db.in_transaction)

    def test_utf8_sql_bytes_and_exact_variable_boundary(self):
        rows = [(i, None if i%2 else '值') for i in range(11)]
        with sqlite3.connect(':memory:', factory=RecordingConnection) as db:
            db.execute('CREATE TABLE 資料(n INTEGER,s TEXT)')
            db.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 5)
            # Fits exactly two two-column row groups; Unicode table name uses six bytes.
            cap = len('INSERT INTO 資料 VALUES (?,?),(?,?)'.encode('utf-8'))
            db.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, cap)
            worker.insert_authorized_rows(db, '資料', ['n','s'], iter(rows))
            self.assertEqual(list(db.execute('SELECT * FROM 資料 ORDER BY rowid')), rows)
            self.assertEqual([len(params)//2 for _,params in db.inserts], [2,2,2,2,2,1])
            self.assertTrue(all(len(sql.encode('utf-8')) <= cap and len(params) <= 5 for sql,params in db.inserts))

    def test_impossible_single_row_limits_reject_empty_and_nonempty(self):
        for rows in ([], [(1,2)]):
            for kind in ('variables','sql'):
                with self.subTest(rows=rows, kind=kind), sqlite3.connect(':memory:') as db:
                    db.execute('CREATE TABLE t(a INTEGER,b INTEGER)')
                    if kind == 'variables':
                        db.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER,1)
                    else:
                        db.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH,len('INSERT INTO t VALUES (?,?)')-1)
                    with self.assertRaises((sqlite3.OperationalError,sqlite3.DataError)):
                        worker.insert_authorized_rows(db,'t',['a','b'],iter(rows))

    def test_late_real_binding_error_closes_connection_and_restores_gc(self):
        connect = sqlite3.connect
        prior = gc.isenabled()
        opened = []
        def tracking(*args,**kwargs):
            db = connect(*args,**kwargs, factory=RecordingConnection)
            opened.append(db)
            return db
        try:
            for enabled in (True,False):
                (gc.enable if enabled else gc.disable)()
                with tempfile.TemporaryDirectory(prefix='bind-') as temporary:
                    folder=Path(temporary)
                    documents={'catalog':{'tables':{'t':{'columns':[{'name':'tenant','type':'text'},{'name':'n','type':'i64'}],
                        'rows':[['other',2**80]] + [['a',i] for i in range(128)] + [['a',2**80]]}}},
                        'context':{'tenant':'a','tables':{'t':{'tenant_column':'tenant','columns':['n']}}},
                        'case':{'sql':'SELECT n FROM t'}}
                    for name,value in documents.items():
                        (folder/(name+'.json')).write_text(json.dumps(value),encoding='utf-8')
                    with patch.object(worker.sqlite3,'connect',side_effect=tracking):
                        with self.assertRaises(OverflowError):
                            worker.load_authorized_database(folder)
                    self.assertEqual(gc.isenabled(),enabled)
                    self.assertEqual(len(opened[-1].inserts),2)
                    with self.assertRaises(sqlite3.ProgrammingError):
                        opened[-1].execute('SELECT 1')
        finally:
            for db in opened: db.close()
            (gc.enable if prior else gc.disable)()

    def test_authorization_happens_before_projecting_poison_hidden_values(self):
        catalog={'tables':{'t':{'columns':[{'name':'tenant','type':'text'},{'name':'n','type':'i64'},{'name':'secret','type':'text'}],
            'rows':[['x',object(),object()],['a',7,object()],['a',7,object()]]}}}
        context={'tenant':'a','tables':{'t':{'tenant_column':'tenant','columns':['n']}}}
        with sqlite3.connect(':memory:') as db:
            worker.materialize_catalog(db,catalog,context)
            self.assertEqual(list(db.execute('SELECT * FROM t ORDER BY rowid')),[(7,),(7,)])
            with self.assertRaises(sqlite3.OperationalError): db.execute('SELECT tenant,secret FROM t')

class Preparation(unittest.TestCase):
    def test_empty_preflight_has_no_data_step_and_precedes_first_iteration(self):
        events=[]
        class Observe(sqlite3.Connection):
            def executemany(self,sql,parameters,/):
                events.append(('prepare',parameters,self.total_changes))
                result=super().executemany(sql,parameters)
                events.append(('prepared',self.total_changes,self.in_transaction))
                return result
        def values():
            events.append(('first-row',))
            yield (7,)
            yield (9,)
        with CONNECT(':memory:',factory=Observe) as db:
            db.execute('CREATE TABLE t(n INTEGER)')
            worker.insert_authorized_rows(db,'t',['n'],values())
            self.assertEqual(events,[('prepare',(),0),('prepared',0,True),('first-row',)])
            self.assertEqual(list(db.execute('SELECT * FROM t ORDER BY rowid')),[(7,),(9,)])

    def test_transaction_loss_at_prepare_never_advances_or_retries_rows(self):
        consumed=[]
        calls=[]
        class Lose(sqlite3.Connection):
            def executemany(self,sql,parameters,/):
                calls.append(sql)
                self.rollback()
                raise MemoryError('injected transaction loss before rows')
        def values():
            consumed.append('row')
            yield (7,)
        with CONNECT(':memory:',factory=Lose) as db:
            db.execute('CREATE TABLE prior(n INTEGER)')
            db.execute('CREATE TABLE t(n INTEGER)')
            db.execute('INSERT INTO prior VALUES (41)')
            with self.assertRaisesRegex(MemoryError,'transaction loss'):
                worker.insert_authorized_rows(db,'t',['n'],values())
            self.assertEqual(consumed,[])
            self.assertEqual(len(calls),1)
            self.assertFalse(db.in_transaction)
            self.assertEqual(list(db.execute('SELECT * FROM prior')),[])
            self.assertEqual(list(db.execute('SELECT * FROM t')),[])

    def test_execution_failure_after_real_insert_is_not_retried(self):
        many=[]
        data=[]
        class Fail(sqlite3.Connection):
            def executemany(self,sql,parameters,/):
                many.append(sql)
                return super().executemany(sql,parameters)
            def execute(self,sql,parameters=(),/):
                result=super().execute(sql,parameters)
                if sql.startswith('INSERT INTO t '):
                    data.append(len(parameters))
                    raise MemoryError('injected after actual128-row statement')
                return result
        with CONNECT(':memory:',factory=Fail) as db:
            db.execute('CREATE TABLE t(n INTEGER)')
            with self.assertRaisesRegex(MemoryError,'actual128'):
                worker.insert_authorized_rows(db,'t',['n'],iter([(7,)]*129))
            self.assertEqual((len(many),data,db.total_changes),(1,[128],128))
            self.assertEqual(list(db.execute('SELECT * FROM t')),[(7,)]*128)

    def test_empty_relation_real_low_opcode_path_and_prior_rows_remain_intact(self):
        with CONNECT(':memory:') as db:
            db.execute('CREATE TABLE prior(n INTEGER)')
            db.execute('CREATE TABLE t(n INTEGER)')
            db.execute('INSERT INTO prior VALUES (41)')
            db.setlimit(sqlite3.SQLITE_LIMIT_VDBE_OP,80)
            worker.insert_authorized_rows(db,'t',['n'],iter(()))
            self.assertEqual(list(db.execute('SELECT * FROM prior')),[(41,)])
            self.assertEqual(list(db.execute('SELECT * FROM t')),[])
            self.assertEqual(db.getlimit(sqlite3.SQLITE_LIMIT_VDBE_OP),80)
            self.assertTrue(db.in_transaction)

class Ownership(unittest.TestCase):
    def setUp(self):
        self.prior=gc.isenabled()
        self.opened=[]
        self.fixture_parent=OWN/'fixtures-adversarial'
        self.fixture_parent.mkdir(exist_ok=True)
        self.temp=tempfile.TemporaryDirectory(dir=self.fixture_parent,prefix='c-')
        self.folder=Path(self.temp.name)
        documents={'catalog':{'tables':{'t':{'columns':[{'name':'tenant','type':'text'},{'name':'n','type':'i64'}],
                    'rows':[['other',2**80],['a',7],['a',9]]}}},
                   'context':{'tenant':'a','tables':{'t':{'tenant_column':'tenant','columns':['n']}}},
                   'case':{'sql':'SELECT n FROM t'}}
        for name,value in documents.items():
            (self.folder/(name+'.json')).write_text(json.dumps(value),encoding='utf-8')
    def tearDown(self):
        for db in self.opened: db.close()
        (gc.enable if self.prior else gc.disable)()
        self.temp.cleanup()
        self.assertFalse(list(self.fixture_parent.iterdir()))
    def connect(self,factory):
        def opened(*args,**kwargs):
            db=CONNECT(*args,**kwargs,factory=factory)
            self.opened.append(db)
            return db
        return opened
    def assert_closed(self):
        with self.assertRaises(sqlite3.ProgrammingError):self.opened[-1].execute('SELECT 1')

    def test_nonmemory_prepare_failure_and_interrupt_close_owned_db(self):
        for enabled in (True,False):
            for fault in (sqlite3.OperationalError,KeyboardInterrupt):
                with self.subTest(enabled=enabled,fault=fault.__name__):
                    calls=[]
                    class Fail(sqlite3.Connection):
                        def executemany(self,sql,parameters,/):
                            calls.append(parameters)
                            super().executemany(sql,parameters)
                            raise fault('injected after empty real prepare')
                    (gc.enable if enabled else gc.disable)()
                    with patch.object(worker.sqlite3,'connect',side_effect=self.connect(Fail)):
                        with self.assertRaises(fault):worker.load_authorized_database(self.folder)
                    self.assertEqual(calls,[()])
                    self.assertEqual(gc.isenabled(),enabled)
                    self.assert_closed()

    def test_real_single_prepare_opcode_failure_closes_owned_db(self):
        class Low(sqlite3.Connection):
            def execute(self,sql,parameters=(),/):
                cursor=super().execute(sql,parameters)
                if sql.startswith('CREATE TABLE'):self.setlimit(sqlite3.SQLITE_LIMIT_VDBE_OP,40)
                return cursor
        for enabled in (True,False):
            (gc.enable if enabled else gc.disable)()
            with patch.object(worker.sqlite3,'connect',side_effect=self.connect(Low)):
                with self.assertRaises(MemoryError):worker.load_authorized_database(self.folder)
            self.assertEqual(gc.isenabled(),enabled)
            self.assert_closed()

    def test_failed_cursor_close_never_falls_back_and_closes_owned_db(self):
        calls=[]
        class Fail(sqlite3.Connection):
            def executemany(self,sql,parameters,/):
                calls.append(parameters)
                cursor=super().executemany(sql,parameters)
                class Cursor:
                    def close(self):
                        cursor.close()
                        raise MemoryError('injected cursor release error')
                return Cursor()
        with patch.object(worker.sqlite3,'connect',side_effect=self.connect(Fail)):
            with self.assertRaisesRegex(MemoryError,'cursor release'):
                worker.load_authorized_database(self.folder)
        self.assertEqual(calls,[()])
        self.assertEqual(gc.isenabled(),self.prior)
        self.assert_closed()

if __name__=='__main__':unittest.main()
