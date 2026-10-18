"""Real small archive controls around simulated reference orchestration, not benchmarks."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts')); sys.path.insert(0,str(ROOT/'benchmarks'))
import archive_capture
import reference_gate


class ReferenceRetention(unittest.TestCase):
    def invoke(self,*,collection_code=0,archive_limit=None):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); out=root/'.local-runs/reference-unit'
            host=root/'host.json'; host.write_bytes(b'{}')
            proof={'bins':{'rillscope-measure':{'path':'unit-no-executable'},'rillscope':{'path':'unit-no-executable'}}}
            calls=[]
            def call(command,**kwargs):
                name=Path(command[1]).name; calls.append(name)
                if name in {'run.py','cancellation.py'}:
                    path=Path(command[command.index('--out')+1]); path.mkdir(parents=True)
                    (path/'raw-failure.txt').write_bytes(b'unit retained error bytes\n')
                    return collection_code if name=='run.py' else 0
                if name=='verify.py':
                    self.assertTrue((out/'capture-grid/capture.zip').is_file(),
                        'grid raw bytes must be retained before the long validator starts')
                    self.assertTrue((out/'capture-cancel/capture.zip').is_file(),
                        'cancellation raw bytes must be retained before validation')
                    return 29
                raise AssertionError('unexpected unit orchestration command: '+name)
            with patch.object(reference_gate,'ROOT',root), \
                    patch.object(archive_capture,'ROOT',root), \
                    patch.object(archive_capture,'MAX_ARCHIVE',archive_capture.MAX_ARCHIVE if archive_limit is None else archive_limit), \
                    patch.object(reference_gate,'environment',return_value={'unit':'no actual allocation'}), \
                    patch.object(reference_gate,'host_reasons',return_value=[]), \
                    patch.object(reference_gate,'build_release',return_value=proof), \
                    patch.object(reference_gate.subprocess,'call',side_effect=call), \
                    patch.object(sys,'argv',['reference_gate.py','--out',str(out),'--host-receipt',str(host)]), \
                    contextlib.redirect_stdout(io.StringIO()):
                code=reference_gate.main()
            packed=out/'capture-grid/capture.zip'
            contents=None
            if packed.exists() and archive_limit is None:
                with patch.object(archive_capture,'ROOT',root):
                    restored=root/'.local-runs/restored'; archive_capture.restore(packed,restored)
                contents=(restored/'raw-failure.txt').read_bytes()
            return code,calls,contents,list(out.glob('reference-results.json'))

    def test_complete_raw_packages_exist_before_validation_failure(self):
        code,calls,contents,verdicts=self.invoke()
        self.assertEqual((code,calls),(29,['run.py','cancellation.py','verify.py']))
        self.assertEqual(contents,b'unit retained error bytes\n')
        self.assertEqual(verdicts,[],'failed validation must not produce a successful reference report')

    def test_failed_collection_is_packaged_and_keeps_its_original_failure(self):
        code,calls,contents,_=self.invoke(collection_code=19)
        self.assertEqual((code,calls),(19,['run.py']))
        self.assertEqual(contents,b'unit retained error bytes\n')

    def test_archive_bound_failure_stops_the_reference_attempt(self):
        code,calls,_,_=self.invoke(archive_limit=1)
        self.assertNotEqual(code,0)
        self.assertEqual(calls,['run.py'])


if __name__=='__main__': unittest.main()
