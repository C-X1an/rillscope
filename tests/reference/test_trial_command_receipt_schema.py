"""Producer-origin virtual helper receipts; no Linux/native runtime qualification."""
import copy
import hashlib
import io
import json
from pathlib import Path
import platform
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/"scripts"),str(ROOT/"benchmarks")]
import inspect_reference_guest as producer
import canonical_reference_retained_fresh as consumer


class TrialCommandReceiptSchema(unittest.TestCase):
    def produce(self,directory,*,launch_error=False):
        source={"sha256":"b"*64,"files":[["synthetic-test-only","c"*64]]}
        process=Mock(pid=123,returncode=0,stdout=io.BytesIO(b"original output\n"),stderr=io.BytesIO(b""))
        process.poll.return_value=0;process.wait.return_value=0
        owner=Mock();owner.terminate.return_value={"status":"PASS","remaining_active_processes":0}
        class Capture:
            def __init__(self,stream,path,limit):self.stream=stream;self.path=path;self.eof=False
            def drain(self):self.path.write_bytes(self.stream.getvalue());self.eof=True
            def close(self):pass
            def record(self):return {"eof_observed":self.eof}
        command=["synthetic-native-tool","--version"]
        with patch.object(producer,"source_identity",return_value=source), \
            patch.object(producer,"git_state",return_value={"commit":"a"*40,"dirty":False}), \
            patch.object(producer,"BoundedCapture",Capture), \
            patch.object(producer.subprocess,"Popen",side_effect=OSError("synthetic launch failure") if launch_error else None,return_value=process) as launch:
            run=producer.TrialCommands(directory,owner)
            if launch_error:
                with self.assertRaisesRegex(OSError,"synthetic launch failure"):run("version",command)
            else:run("version",command)
            self.assertEqual(launch.call_args.kwargs["stdin"],producer.subprocess.DEVNULL)
        path=directory/"commands/version";row=json.loads((path/"receipt.json").read_bytes())
        return path,row,source,command

    def test_original_producer_records_actual_environment_and_explicit_absent_stdin(self):
        parent=ROOT/".local-runs";parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="trial-schema-",dir=parent) as temp:
            path,row,_,_=self.produce(Path(temp))
            self.assertIn("environment",row,"strict consumers require the producer's actual runtime")
            self.assertEqual(row["environment"],{"python":platform.python_version(),"sqlite":sqlite3.sqlite_version,
                "system":platform.system(),"machine":platform.machine(),"cpu_count":producer.os.cpu_count()})
            self.assertIn("stdin",row,"DEVNULL must be explicitly recorded")
            self.assertIsNone(row["stdin"])
            self.assertEqual(row["verification_status"],"PASS")
            self.assertEqual(hashlib.sha256((path/"stdout.txt").read_bytes()).hexdigest(),row["stdout"]["sha256"])

    def test_virtual_linux_producer_round_trip_and_missing_field_controls(self):
        parent=ROOT/".local-runs";parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="trial-roundtrip-",dir=parent) as temp:
            with patch.object(producer.platform,"system",return_value="Linux"):
                path,row,source,command=self.produce(Path(temp))
            self.assertIn("environment",row,"producer-origin schema must satisfy strict reader")
            self.assertIn("stdin",row)
            original=copy.deepcopy(row)
            class Metadata:
                def document(self,*_):return copy.deepcopy(row)
                def raw(self,name):return (path/Path(str(name)).name).read_bytes()
            kwargs={"source":source,"commit":"a"*40,"command":command,"cwd":str(producer.ROOT)}
            checked=consumer.receipt(Metadata(),".local-runs/virtual/commands/version",**kwargs)
            self.assertEqual(checked,original)
            for key,pattern in [("environment","native runtime"),("stdin","explicit absent stdin")]:
                with self.subTest(key=key):
                    row.pop(key)
                    with self.assertRaisesRegex(ValueError,pattern):
                        consumer.receipt(Metadata(),".local-runs/virtual/commands/version",**kwargs)
                    row.clear();row.update(copy.deepcopy(original))
            for key,value,pattern in [("environment",{"system":"Windows"},"native runtime"),
                ("stdin","","explicit absent stdin"),("stdin",{},"explicit absent stdin")]:
                with self.subTest(key=key,value=value):
                    row[key]=value
                    with self.assertRaisesRegex(ValueError,pattern):
                        consumer.receipt(Metadata(),".local-runs/virtual/commands/version",**kwargs)
                    row.clear();row.update(copy.deepcopy(original))
            self.assertEqual(consumer.receipt(Metadata(),".local-runs/virtual/commands/version",**kwargs),original)

    def test_failed_launch_keeps_actual_runtime_and_absent_stdin_without_promotion(self):
        parent=ROOT/".local-runs";parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="trial-not-launched-",dir=parent) as temp:
            _,row,_,_=self.produce(Path(temp),launch_error=True)
            self.assertIn("environment",row)
            self.assertEqual(row["environment"]["system"],platform.system())
            self.assertIn("stdin",row);self.assertIsNone(row["stdin"])
            self.assertEqual(row["verification_status"],"FAIL")
            self.assertEqual(row["execution_outcome"],"NOT_LAUNCHED")


if __name__=="__main__":unittest.main()
