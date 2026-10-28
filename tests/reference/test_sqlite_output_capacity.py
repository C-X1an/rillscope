"""Real SQLite row collection; discard only conversion of already rejected output."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/"scripts"),str(ROOT/"benchmarks")]
import sqlite_worker as worker


class SQLiteOutputCapacity(unittest.TestCase):
    def execute(self, count, *, large_text=False):
        parent=ROOT/".local-runs";parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="sqlite-capacity-",dir=parent) as temporary:
            case=Path(temporary); measurement=case/"measurement.json"
            columns=[{"name":"tenant","type":"text","nullable":False},
                     {"name":"flag","type":"bool","nullable":True},
                     {"name":"note","type":"text","nullable":False}]
            rows=[["alpha",None if i%3==0 else i%2,"z"*4096 if large_text else "ok"] for i in range(count)]
            (case/"catalog.json").write_text(json.dumps({"version":1,"snapshot":"capacity","tables":{"t":{"columns":columns,"rows":rows}}}))
            (case/"context.json").write_text(json.dumps({"tenant":"alpha","tables":{"t":{"columns":["flag","note"],"tenant_column":"tenant"}}}))
            schema=[{"name":"flag","type":"bool","nullable":True},{"name":"note","type":"text","nullable":False}]
            (case/"case.json").write_text(json.dumps({"sql":"SELECT flag,note FROM t","schema":schema}))
            consumed=[]; conversions=[]; connect=worker.sqlite3.connect
            class Database:
                def __init__(self):self.actual=connect(":memory:")
                def __getattr__(self,name):return getattr(self.actual,name)
                def execute(self,sql,*args):
                    cursor=self.actual.execute(sql,*args)
                    if sql=="SELECT flag,note FROM t":
                        def all_rows():
                            for row in cursor:
                                consumed.append(1)
                                yield row
                        return all_rows()
                    return cursor
            def convert(value):
                conversions.append(value)
                return bool(value)
            output=io.StringIO()
            with patch.object(worker.sqlite3,"connect",side_effect=lambda *_:Database()), \
                patch.object(worker,"bool",side_effect=convert,create=True), \
                patch.object(sys,"argv",["sqlite_worker","--case",str(case),"--measurement",str(measurement)]), \
                contextlib.redirect_stdout(output):
                self.assertEqual(worker.main(),0)
            payload=output.getvalue().strip().encode()
            metrics=json.loads(measurement.read_bytes())
            self.assertEqual(metrics["result_sha256"],hashlib.sha256(payload).hexdigest())
            self.assertEqual(len(consumed),count,"the actual SQLite query must still collect every row")
            self.assertGreaterEqual(metrics["execution_only_ns"],0)
            self.assertGreaterEqual(metrics["serialization_ns"],0)
            return json.loads(payload),metrics,conversions,rows

    def test_over_row_cap_preserves_full_query_but_does_not_normalize_discarded_cells(self):
        value,metrics,conversions,_=self.execute(10001)
        self.assertEqual(value,{"version":1,"status":"error","implementation":"sqlite-baseline",
            "error":{"code":"E_OUTPUT_LIMIT","scope":"baseline harness output cap"}})
        self.assertIsNone(metrics["emitted_rows"])
        self.assertEqual(conversions,[],"row-count rejection is already known; no discarded bool conversion is needed")

    def test_exact_row_cap_preserves_every_nullable_boolean_and_duplicate(self):
        value,metrics,conversions,rows=self.execute(10000)
        self.assertEqual(value["status"],"ok")
        self.assertEqual(value["rows"],[[None if row[1] is None else bool(row[1]),row[2]] for row in rows])
        self.assertEqual(metrics["emitted_rows"],10000)
        self.assertEqual(len(conversions),sum(row[1] is not None for row in rows))

    def test_byte_cap_still_serializes_and_rejects_in_range_rows(self):
        value,metrics,conversions,rows=self.execute(300,large_text=True)
        self.assertEqual(value["status"],"error")
        self.assertEqual(value["error"]["code"],"E_OUTPUT_LIMIT")
        self.assertIsNone(metrics["emitted_rows"])
        self.assertEqual(len(conversions),sum(row[1] is not None for row in rows))

    def test_empty_query_keeps_successful_empty_rows(self):
        value,metrics,conversions,_=self.execute(0)
        self.assertEqual(value["status"],"ok")
        self.assertEqual(value["rows"],[])
        self.assertEqual(metrics["emitted_rows"],0)
        self.assertEqual(conversions,[])


if __name__=="__main__":unittest.main()
