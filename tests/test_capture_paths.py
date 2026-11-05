"""Actual tiny-child evidence faults; these controls measure no product latency."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'benchmarks'))
from capture_paths import CASE_LAYOUT,case_folder,case_folders,preflight_prefix
from workloads import descriptors,sort_null_descriptors,SEEDS
import process_metrics


class CapturePaths(unittest.TestCase):
    def windows_prefix(self, root, units, *, non_bmp=False):
        # Construct the full independent filename boundary on either OS. A
        # fixed padding length depends on the actual temporary-directory path.
        parent=root.resolve()/'envelope'
        base_units=len(str(parent).encode('utf-16-le'))//2+1
        padding=units-base_units-len('.measurement.json')-(2 if non_bmp else 0)
        self.assertGreater(padding,0,'fixture parent must leave room for padding')
        prefix=parent/(('\U0001f600' if non_bmp else '')+'p'*padding)
        actual=str(prefix.with_suffix('.measurement.json').absolute())
        self.assertEqual(len(actual.encode('utf-16-le'))//2,units)
        if non_bmp: self.assertEqual(len(actual),units-1)
        return prefix

    def test_all_410_logical_cases_remain_unique_and_short(self):
        manifest={'chosen_workloads':descriptors(),'seeds':list(SEEDS),'case_directory_layout':CASE_LAYOUT}
        mapped=case_folders(manifest)
        self.assertEqual(len(mapped),410)
        self.assertEqual(set(mapped),{(row['id'],seed) for row in descriptors() for seed in SEEDS})
        self.assertTrue(all(len(path)==18 and path.startswith('c-') for path in mapped.values()))
        self.assertEqual(len(set(mapped.values())),410)
        for row in sort_null_descriptors():
            for seed in SEEDS:
                short=case_folder(row['id'],seed,CASE_LAYOUT)
                self.assertNotIn(str(seed),short)
                self.assertEqual(len(short),18)

    def test_legacy_paths_and_reduced_control_identity_are_preserved(self):
        self.assertEqual(case_folder('B04-n10000-equal',20261014),'B04-n10000-equal-seed20261014')
        # Independently computed with .NET SHA256/ASCII; fixed wire-format vector.
        self.assertEqual(case_folder('B04-n10000-equal',20261014,CASE_LAYOUT),'c-9eda16746cf827da')
        workload=descriptors()[0]['id'];seed=SEEDS[0]
        full=case_folders({'chosen_workloads':descriptors(),'seeds':list(SEEDS),'case_directory_layout':CASE_LAYOUT})
        selected=case_folders({'chosen_workloads':[descriptors()[0]],'seeds':[seed],'case_directory_layout':CASE_LAYOUT})
        self.assertEqual(full[workload,seed],selected[workload,seed])

    def test_duplicate_escaping_and_unknown_case_layouts_fail(self):
        for workload,seed,layout in [('../escape',1,CASE_LAYOUT),('valid',True,CASE_LAYOUT),
                                     ('valid',1,'unknown')]:
            with self.assertRaises(ValueError): case_folder(workload,seed,layout)
        for manifest in ({'chosen_workloads':[{'id':'same'},{'id':'same'}],'seeds':[1]},
                         {'chosen_workloads':[{'id':'valid'}],'seeds':[1,1]}):
            with self.assertRaises(ValueError): case_folders(manifest)
        with patch('capture_paths.case_folder',return_value='c-collision'):
            with self.assertRaisesRegex(ValueError,'collision'):
                case_folders({'chosen_workloads':[{'id':'a'},{'id':'b'}],'seeds':[1]})

    def test_complete_windows_filename_envelope_is_checked(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve()
            for non_bmp in (False,True):
                with self.subTest(non_bmp=non_bmp):
                    accepted=self.windows_prefix(root,259,non_bmp=non_bmp)
                    self.assertEqual(max(len(str(path).encode('utf-16-le'))//2
                        for path in preflight_prefix(accepted,windows=True)),259)
                    rejected=self.windows_prefix(root,260,non_bmp=non_bmp)
                    with self.assertRaisesRegex(OSError,'Windows envelope'):
                        preflight_prefix(rejected,windows=True)
            paths=preflight_prefix(root/'short',windows=True)
            self.assertEqual({path.suffix for path in paths},{'.stdout','.stderr','.json'})
            self.assertTrue(any(path.name=='short.measurement.json' for path in paths))

    def test_long_path_is_rejected_before_child_launch_with_failure_record(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();marker=root/'child-ran'
            command=[sys.executable,'-c',"from pathlib import Path;Path("+repr(str(marker))+").write_bytes(b'ran')"]
            # Exercise the Windows envelope on every CI host; the process itself
            # must never launch. On Windows this is also the native path check.
            prefix=self.windows_prefix(root,260)
            with patch.object(process_metrics,'preflight_prefix',side_effect=lambda prefix:preflight_prefix(prefix,windows=True),create=True), \
                    patch.object(process_metrics.subprocess,'Popen') as launch:
                with self.assertRaises(OSError) as error:
                    process_metrics.measured_child(command,cwd=root,prefix=prefix,timeout=5)
            launch.assert_not_called()
            self.assertFalse(marker.exists(),'path preflight must precede child creation')
            saved=json.loads((error.exception.failure_directory/'process.json').read_bytes())
            self.assertIsNone(saved['process']['pid'])
            self.assertIsNone(saved['process']['exit_code'])
            self.assertEqual(saved['process']['process_outcome'],'NOT STARTED')

    def capture_fault(self,suffix,*,break_fallback=False):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();prefix=root/'raw/sample'
            command=[sys.executable,'-c',"import sys;sys.stdout.buffer.write(b'actual-out');sys.stderr.buffer.write(b'actual-err')"]
            original_bytes=Path.write_bytes;original_text=Path.write_text
            def bytes_write(path,data):
                if path==prefix.with_suffix(suffix) or break_fallback: raise OSError('deliberate unit storage fault')
                return original_bytes(path,data)
            def text_write(path,data,*args,**kwargs):
                if path==prefix.with_suffix(suffix) or break_fallback: raise OSError('deliberate unit storage fault')
                return original_text(path,data,*args,**kwargs)
            captured_stderr=io.StringIO()
            with patch.object(Path,'write_bytes',bytes_write),patch.object(Path,'write_text',text_write),contextlib.redirect_stderr(captured_stderr):
                with self.assertRaises(OSError) as error:
                    process_metrics.measured_child(command,cwd=root,prefix=prefix,timeout=5)
            if break_fallback:
                self.assertIsNone(error.exception.failure_directory)
                report=json.loads(captured_stderr.getvalue().strip())
                self.assertEqual(report['status'],'FAIL')
                self.assertEqual(report['stdout']['bytes'],10)
                self.assertIn('fallback_error',report)
                return
            out=error.exception.failure_directory
            self.assertEqual((out/'stdout').read_bytes(),b'actual-out')
            self.assertEqual((out/'stderr').read_bytes(),b'actual-err')
            record=json.loads((out/'process.json').read_bytes())
            self.assertEqual(record['status'],'FAIL')
            self.assertEqual(record['process']['exit_code'],0)
            self.assertGreater(record['process']['pid'],0)
            self.assertEqual(record['stdout']['sha256'],hashlib.sha256(b'actual-out').hexdigest())
            self.assertFalse(record['reference_qualified'])

    def test_stdout_write_fault_keeps_actual_child_bytes_elsewhere(self): self.capture_fault('.stdout')
    def test_process_write_fault_keeps_actual_child_bytes_elsewhere(self): self.capture_fault('.process.json')
    def test_unwritable_fallback_never_returns_success(self): self.capture_fault('.stdout',break_fallback=True)


if __name__=='__main__': unittest.main()
