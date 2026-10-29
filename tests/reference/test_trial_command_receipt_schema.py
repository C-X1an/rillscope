"""Producer-origin virtual helper receipts; no Linux/native runtime qualification."""
import copy
import hashlib
import io
import itertools
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
    def test_terminal_helper_retains_the_exact_original_monotonic_samples(self):
        parent=ROOT/".local-runs";parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="trial-clock-",dir=parent) as temp:
            with patch.object(producer.time,"monotonic_ns",side_effect=[1_000_000_000,2_000_000_000]) as clock:
                _,row,_,_=self.produce(Path(temp))
            self.assertEqual(row.get("monotonic"),{"schema_version":1,"clock":"time.monotonic_ns",
                "started_ns":1_000_000_000,"finished_ns":2_000_000_000})
            self.assertEqual(row["elapsed_seconds"],1.0)
            self.assertEqual(clock.call_count,2)

    def produce(self,directory,*,launch_error=False,inputs=(),large_inputs=()):
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
                with self.assertRaisesRegex(OSError,"synthetic launch failure"):
                    run("version",command,inputs=inputs,large_inputs=large_inputs)
            else:run("version",command,inputs=inputs,large_inputs=large_inputs)
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
            self.assertEqual(set(row["monotonic"]),{"schema_version","clock","started_ns","finished_ns"})
            self.assertEqual(row["monotonic"]["clock"],"time.monotonic_ns")
            self.assertIs(type(row["monotonic"]["started_ns"]),int)
            self.assertIs(type(row["monotonic"]["finished_ns"]),int)
            self.assertLessEqual(row["monotonic"]["started_ns"],row["monotonic"]["finished_ns"])

    def test_every_caller_permutation_records_the_same_exact_sorted_inputs(self):
        parent=ROOT/".local-runs";parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="trial-input-order-",dir=parent) as temp:
            root=Path(temp);data={"a-input":b"first literal\n","m-input":b"middle literal\n","z-input":b"last literal\n"}
            for name,value in data.items():(root/name).write_bytes(value)
            expected=[{"path":str(root/name),"bytes":len(data[name]),"sha256":hashlib.sha256(data[name]).hexdigest()}
                for name in ("a-input","m-input","z-input")]
            for number,order in enumerate(itertools.permutations(("z-input","a-input","m-input"))):
                with self.subTest(order=order):
                    destination=root/("case-"+str(number));destination.mkdir()
                    _,row,_,_=self.produce(destination,inputs=tuple(root/name for name in order))
                    self.assertEqual(row["inputs_before"],expected)
                    self.assertEqual(row["inputs_after"],expected)

    def test_sorting_keeps_ordinary_and_explicit_image_limits_with_their_own_files(self):
        parent=ROOT/".local-runs";parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="trial-input-limits-",dir=parent) as temp:
            root=Path(temp);ordinary=root/"z-ordinary";image=root/"a-image"
            ordinary.write_bytes(b"ordinary");image.write_bytes(b"explicit image")
            expected=[(str(image),800*1024**2),(str(ordinary),256*1024**2)]
            with patch.object(producer,"bounded_identity",wraps=producer.bounded_identity) as identity:
                _,row,_,_=self.produce(root,inputs=(ordinary,),large_inputs=(image,))
            self.assertEqual([(str(call.args[0]),call.args[1]) for call in identity.call_args_list],expected+expected)
            self.assertEqual([item["path"] for item in row["inputs_before"]],[str(image),str(ordinary)])
            self.assertEqual(row["inputs_before"],row["inputs_after"])

    def test_failed_launch_preserves_the_same_sorted_input_identities(self):
        parent=ROOT/".local-runs";parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="trial-failed-input-order-",dir=parent) as temp:
            root=Path(temp);first=root/"a-input";last=root/"z-input"
            first.write_bytes(b"first");last.write_bytes(b"last")
            _,row,_,_=self.produce(root,launch_error=True,inputs=(last,first))
            self.assertEqual([item["path"] for item in row["inputs_before"]],[str(first),str(last)])
            self.assertEqual(row["inputs_before"],row["inputs_after"])
            self.assertEqual(row["verification_status"],"FAIL")
            self.assertEqual(row["execution_outcome"],"NOT_LAUNCHED")


if __name__=="__main__":unittest.main()
