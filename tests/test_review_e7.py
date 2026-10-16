"""Independent e7 review counterexamples; synthetic metadata is not measurement."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'),str(ROOT / 'benchmarks')]
from evidence_coverage import required_sources
import run


class ReviewE7(unittest.TestCase):
    def test_fresh_release_binds_the_actual_verification_procedure(self):
        self.assertLessEqual({'Makefile','scripts/clean_verify.py','scripts/required_gate.py',
                              'scripts/evidence.py','scripts/owned_process.py',
                              'scripts/release_audit.py','scripts/evidence_coverage.py'},
                             required_sources('AC-024', ROOT))

    def test_process_metric_types_are_rejected_before_summary_recording(self):
        # A producer regression is injected at the instrument interface. These
        # bytes/integers are a unit fixture, never an executed process observation.
        value = {'version':1,'implementation':'rust-benchmark','status':'ok',
                 'schema':[{'name':'x','type':'i64','nullable':False}],'rows':[[7]]}
        stdout = json.dumps(value).encode()
        hashes = {name + '.json':'a' * 64 for name in ('catalog','context','query','case')}
        measurement = {'implementation':'rust-benchmark','synthetic_only':True,'optimize':True,'batch_rows':128,
                       'error':None,'result_sha256':hashlib.sha256(stdout).hexdigest(),
                       **{name + '_sha256':'a'*64 for name in ('catalog','context','query')},
                       **{name:1 for name in ('load_ns','compile_ns','execution_call_wall_ns',
                                              'consumed_work','visible_work','peak_reserved_bytes',
                                              'execution_only_ns','serialization_ns')}}
        valid = {'wall_ns':1,'cpu_user_ns':1,'cpu_system_ns':1,'peak_rss_bytes':1,
                 'cpu_rss_status':'MEASURED','process_outcome':'EXECUTED','timed_out':False,'exit_code':0,'pid':1}
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            usage = dict(valid)
            def instrument(command, *, cwd, prefix):
                prefix.with_suffix('.process.json').write_text(json.dumps(usage))
                Path(command[command.index('--measurement')+1]).write_text(json.dumps(measurement))
                return usage,stdout,b''
            def sample():
                with patch.object(run,'measured_child',side_effect=instrument):
                    return run.sample('rust-on',Path('unit-only'),root,{'batch_rows':128},
                                      {'ordered':False,'schema':value['schema']},root,
                                      'measured',0,0,hashes)[0]
            self.assertEqual(sample()['problems'],[])
            for name in ('wall_ns','cpu_user_ns','cpu_system_ns','peak_rss_bytes'):
                for wrong in (False,1.5,-1,None):
                    with self.subTest(metric=name,value=wrong):
                        usage = dict(valid,**{name:wrong})
                        self.assertTrue(sample()['problems'],'malformed owned-process metric accepted')

    def test_successful_parent_stops_new_session_worker_before_receipt(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source = root / 'synthetic-input'; ready = root / 'ready'
            source.write_text('stable synthetic input')
            worker = ('import time; from pathlib import Path; Path(' + repr(str(ready))
                      + ').write_text("ready"); time.sleep(1.5); Path(' + repr(str(source))
                      + ').write_text("new-session worker survived")')
            parent = ('import subprocess,sys,time; from pathlib import Path; '
                      'subprocess.Popen([sys.executable,"-c",' + repr(worker)
                      + '],start_new_session=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); '
                      'deadline=time.monotonic()+5\n'
                      'while not Path(' + repr(str(ready)) + ').exists() and time.monotonic()<deadline: time.sleep(.01)\n'
                      'assert Path(' + repr(str(ready)) + ').exists(); print("owned new-session worker started")')
            out = root / 'receipt'
            result = subprocess.run([sys.executable,str(ROOT / 'scripts/evidence.py'),'--out',str(out),
                                     '--input',str(source),'--timeout','10','--',sys.executable,'-c',parent],
                                    cwd=ROOT,capture_output=True,timeout=20)
            self.assertEqual(result.returncode,0,result.stderr)
            receipt = json.loads((out / 'receipt.json').read_bytes())
            self.assertEqual(receipt['verification_status'],'PASS')
            time.sleep(2)
            self.assertEqual(source.read_text(),'stable synthetic input','new-session worker survived a PASS receipt')
            self.assertEqual(receipt['process_cleanup']['status'],'PASS')


if __name__ == '__main__': unittest.main()
