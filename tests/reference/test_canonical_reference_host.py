"""Literal new-method resource/deadline controls, not a QEMU execution."""
from pathlib import Path
from contextlib import ExitStack
import io
import json
import os
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import canonical_reference_host as host
import kvm_reference_budget as old
import archive_capture
from kvm_reference_channel import PORT_NAME


class CanonicalHostControls(unittest.TestCase):
    def test_prefilled_execution_record_cannot_authorize_an_original_process(self):
        for slot in ({'process': {'pid': 12345}}, [], {'cleanup': {'status': 'PASS'}}):
            with self.subTest(slot=slot), \
                patch.object(host.platform, 'system', return_value='Linux'), \
                patch.object(host.os, 'geteuid', return_value=0, create=True), \
                patch.dict(os.environ, {'GITHUB_REPOSITORY': 'C-X1an/rillscope', 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'}), \
                patch.object(host, 'source_check') as source, patch.object(host.subprocess, 'Popen') as launch:
                with self.assertRaisesRegex(ValueError, 'empty in-process execution slot'):
                    host.run_vm(Path('unused'), image=Path('unused-image'), run_as='runner', port=12345,
                        commit='a' * 40, source_sha256='b' * 64, vm_seconds=100, setup_seconds=10,
                        ownership=None, execution=slot)
                source.assert_not_called(); launch.assert_not_called()

    def test_observation_spends_original_vm_cutoff_without_renewal(self):
        with patch.object(host.time, 'monotonic_ns', return_value=100), \
            patch.object(host, 'AllocationDeadline') as deadline:
            expected = {'actual': 'synthetic sampler result only'}
            deadline.return_value.snapshot.return_value = expected
            self.assertEqual(host.snapshot_before_cutoff(201, 12345, 150), expected)
            self.assertEqual(deadline.call_args.args[0], 150)
            self.assertIs(deadline.call_args.args[1](), False)
            deadline.return_value.snapshot.assert_called_once_with(201, 12345)

    def test_persisted_stop_cannot_report_pass_when_allocator_cleanup_failed(self):
        """Independent finding's synthetic finalization control; no VM exists."""
        class Process:
            pid = 12345; returncode = 0
            def __init__(self): self.stdout = io.BytesIO(); self.stderr = io.BytesIO()
            def poll(self): return None
            def wait(self, timeout): return 0
        class Capture:
            eof = True; exceeded = False
            def __init__(self, source, path, limit): self.path = path; path.write_bytes(b'')
            def drain(self): pass
            def close(self): pass
            def record(self): return {'synthetic': True, 'file': self.path.name}
        class Channel:
            receiver_process = exchange_record = None
            def __init__(self, *args, **kwargs):
                self.done = SimpleNamespace(is_set=lambda: False)
                self.thread = SimpleNamespace(start=lambda: None, is_alive=lambda: True)
                self.report = {'status': 'FAIL', 'synthetic_live_thread': True}
            def close(self): raise ValueError('synthetic original allocator did not stop')
        class Readiness:
            """Finalization fixture only; process identity has separate controls."""
            def __init__(self,*args,**kwargs):pass
            def poll(self):return True
            def fail(self,error):pass
        created = Process(); execution = {}
        local = ROOT / '.local-runs'; local.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='host-finalize-', dir=local) as directory:
            out = Path(directory); (out / 'artifact').mkdir(); (out / 'runtime').mkdir()
            for name in ('seed.iso', 'disk.qcow2', 'work.raw', 'image', 'runtime/capture.sock'):
                (out / name).write_bytes(b'SYNTHETIC ONLY')
            fake_pwd = SimpleNamespace(getpwnam=lambda name: SimpleNamespace(pw_uid=1001))
            stopped = {'errors': [], 'cleanup': {'status': 'PASS', 'synthetic_process_cleanup_only': True},
                'receiver_exit_observed_before_stop': None}
            with patch.dict(sys.modules, {'pwd': fake_pwd}), \
                patch.dict(os.environ, {'GITHUB_REPOSITORY': 'C-X1an/rillscope', 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'}), \
                patch.object(host.platform, 'system', return_value='Linux'), \
                patch.object(host.os, 'geteuid', return_value=0, create=True), \
                patch.object(archive_capture, 'owned', side_effect=lambda path: Path(path)), \
                patch.object(host, 'source_check'), patch.object(host, 'sha', return_value=host.IMAGE_SHA), \
                patch.object(host.shutil, 'which', return_value='SYNTHETIC'), \
                patch.object(host, 'qemu_command', return_value=['SYNTHETIC NO PROCESS']), \
                patch.object(host.subprocess, 'Popen', return_value=created), \
                patch.object(host, 'BoundedCapture', Capture), patch.object(host, 'CanonicalChannel', Channel), \
                patch.object(host, 'ProcessReadiness', Readiness), \
                patch.object(host.stat, 'S_ISSOCK', return_value=True), \
                patch.object(host, 'snapshot_before_cutoff', side_effect=lambda *args: {'monotonic_ns': time.monotonic_ns()}), \
                patch.object(host, 'fsync_directory'), patch.object(host, 'stop_vm', return_value=stopped), \
                patch.object(host.time, 'sleep', side_effect=RuntimeError('synthetic loop stop')):
                result = host.run_vm(out, image=out / 'image', run_as='runner', port=12345,
                    commit='a' * 40, source_sha256='b' * 64, vm_seconds=100, setup_seconds=10,
                    ownership=None, execution=execution)
            stop_record = json.loads((out / 'artifact/vm-stop.json').read_bytes())
            self.assertEqual(result['status'], 'FAIL')
            self.assertEqual(result['cleanup']['status'], 'FAIL')
            self.assertIs(result['channel_thread_stopped'], False)
            self.assertEqual(stop_record['cleanup']['status'], 'FAIL',
                'persisted vm-stop.json reports PASS for a known-live allocator')
            self.assertIs(execution['process'], created)
            self.assertEqual(execution['cleanup']['status'], 'FAIL')
            self.assertIsNone(execution['qemu_exit_observed_before_owned_stop'])

    def test_explicit_lifetime_is_never_renewed_from_receiver_start(self):
        self.assertEqual(host.finite_lifetime(100, 20000, 2000), 20_000_000_000_100)
        for start, seconds, setup in [(True, 20000, 2000), (100, 21601, 1),
            (100, 20000, 20000), (100, 20000, False), (0, 20000, 1)]:
            with self.subTest(start=start, seconds=seconds, setup=setup):
                with self.assertRaises(ValueError): host.finite_lifetime(start, seconds, setup)
        self.assertEqual((old.VM_SECONDS, old.OWNER_SECONDS), (18000, 19500))

    def test_socket_does_not_connect_or_start_a_channel_before_same_child_readiness(self):
        """Synthetic host loop only; all processes, resources and UID facts are literal."""
        for reaches_ready in (False,True):
            with self.subTest(reaches_ready=reaches_ready):
                state={'polls':0,'connections':0,'starts':0}
                process=SimpleNamespace(pid=12345,returncode=0,stdout=io.BytesIO(),stderr=io.BytesIO(),
                    poll=lambda:None,wait=lambda timeout:0)
                class Capture:
                    eof=True;exceeded=False
                    def __init__(self,source,path,limit):self.path=path;path.write_bytes(b'')
                    def drain(self):pass
                    def close(self):pass
                    def record(self):return {'synthetic':True,'file':self.path.name}
                class Readiness:
                    def __init__(self,*args,**kwargs):state['identity']=self
                    def poll(self):state['polls']+=1;return reaches_ready and state['polls']==2
                    def fail(self,error):pass
                class Channel:
                    receiver_process=exchange_record=None
                    def __init__(self,*args,**kwargs):
                        self_identity=kwargs['identity']
                        if state['polls']!=2 or self_identity is not state['identity']:
                            raise AssertionError('channel connected before original child readiness')
                        state['connections']+=1
                        self.done=SimpleNamespace(is_set=lambda:False)
                        self.thread=SimpleNamespace(start=lambda:state.update(starts=state['starts']+1),is_alive=lambda:False)
                        self.report={'status':'SYNTHETIC ONLY'}
                    def close(self):pass
                def sleep(seconds):
                    if state['polls']==1:
                        self.assertEqual((state['connections'],state['starts']),(0,0))
                        if reaches_ready:return
                    raise RuntimeError('synthetic host loop stop')
                local=ROOT/'.local-runs';local.mkdir(exist_ok=True)
                with tempfile.TemporaryDirectory(prefix='host-readiness-',dir=local) as directory,ExitStack() as stack:
                    out=Path(directory);(out/'artifact').mkdir();(out/'runtime').mkdir()
                    for name in ('seed.iso','disk.qcow2','work.raw','image','runtime/capture.sock'):
                        (out/name).write_bytes(b'SYNTHETIC ONLY')
                    stopped={'errors':[],'cleanup':{'status':'PASS','synthetic_only':True},'receiver_exit_observed_before_stop':None}
                    stack.enter_context(patch.dict(sys.modules,{'pwd':SimpleNamespace(getpwnam=lambda name:SimpleNamespace(pw_uid=1001))}))
                    stack.enter_context(patch.dict(os.environ,{'GITHUB_REPOSITORY':'C-X1an/rillscope','GITHUB_RUN_ID':'123','GITHUB_RUN_ATTEMPT':'1'}))
                    stack.enter_context(patch.object(host.platform,'system',return_value='Linux'))
                    stack.enter_context(patch.object(host.os,'geteuid',return_value=0,create=True))
                    stack.enter_context(patch.object(archive_capture,'owned',side_effect=lambda path:Path(path)))
                    patches=[(host,'source_check',{}),(host,'sha',{'return_value':host.IMAGE_SHA}),
                        (host.shutil,'which',{'return_value':'SYNTHETIC'}),(host,'qemu_command',{'return_value':['SYNTHETIC NO PROCESS']}),
                        (host.subprocess,'Popen',{'return_value':process}),(host,'BoundedCapture',{'new':Capture}),
                        (host,'CanonicalChannel',{'new':Channel}),(host,'ProcessReadiness',{'new':Readiness}),
                        (host.stat,'S_ISSOCK',{'return_value':True}),
                        (host,'snapshot_before_cutoff',{'side_effect':lambda *args:{'monotonic_ns':time.monotonic_ns()}}),
                        (host,'fsync_directory',{}),(host,'stop_vm',{'return_value':stopped}),(host.time,'sleep',{'side_effect':sleep})]
                    for target,name,kwargs in patches:stack.enter_context(patch.object(target,name,**kwargs))
                    result=host.run_vm(out,image=out/'image',run_as='runner',port=12345,commit='a'*40,
                        source_sha256='b'*64,vm_seconds=100,setup_seconds=10,ownership=None,execution={})
                    self.assertEqual(result['status'],'FAIL')
                    self.assertEqual(result['failure']['reason'],'synthetic host loop stop')
                    self.assertEqual(state['polls'],2 if reaches_ready else 1)
                    self.assertEqual((state['connections'],state['starts']),(1,1) if reaches_ready else (0,0))

    def test_qemu_template_retains_kvm_resources_and_exact_inner_capture_port(self):
        command = host.qemu_command(Path('/owned'), Path('/image'), 'runner', 12345)
        self.assertEqual(command[command.index('-name') + 1], 'RillScope-controller-owned-canonical-reference')
        self.assertEqual(command[command.index('-accel') + 1], 'kvm')
        self.assertEqual(command[command.index('-smp') + 1], '4,sockets=1,cores=4,threads=1')
        self.assertEqual(command[command.index('-m') + 1], '8192')
        self.assertIn('memory-backend-ram,id=ram0,size=8G,prealloc=on,merge=off', command)
        self.assertIn('virtserialport,chardev=capture,name=' + PORT_NAME, command)
        self.assertIn('tcp:127.0.0.1:12345,server=on,wait=off', command)

    def test_missing_actual_linux_root_stops_before_accounts_disks_or_processes(self):
        with patch.object(host.platform, 'system', return_value='Windows'):
            with patch.object(host, 'source_check') as source:
                with self.assertRaisesRegex(ValueError, 'actual existing scoped Linux root'):
                    host.run_vm(Path('out'), image=Path('image'), run_as='runner', port=12345,
                        commit='a' * 40, source_sha256='b' * 64, vm_seconds=20000, setup_seconds=2000, ownership=None)
                source.assert_not_called()


if __name__ == '__main__': raise SystemExit(unittest.main())
