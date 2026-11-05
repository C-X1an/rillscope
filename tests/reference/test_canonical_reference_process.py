"""Synthetic procfs/readiness controls only; no process, UID, QEMU or VM run."""
import base64
from contextlib import contextmanager
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'benchmarks')]
import canonical_reference_reservation as reservation

COMMAND=['qemu-system-x86_64','-runas','runner']
PID=4001; UID=1001
PAYLOAD=b'SYNTHETIC EXECUTABLE IDENTITY ONLY; NEVER EXECUTED\n'


class ProcessReadinessControls(unittest.TestCase):
    def module(self):
        self.assertTrue((ROOT/'scripts/canonical_reference_process.py').is_file(),
            'source-bound process readiness and original identity retention required')
        return importlib.import_module('canonical_reference_process')

    @contextmanager
    def fixture(self, module):
        local=ROOT/'.local-runs';local.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='process-readiness-',dir=local) as directory:
            directory=Path(directory);binary=directory/'qemu-system-x86_64';binary.write_bytes(PAYLOAD)
            state={'uids':[UID]*4,'parent':os.getpid(),'start':123456,'argv':COMMAND[:],
                'now':200,'cancelled':False,'read_error':None,'reads':0,'record_reads':0,'exe':binary}
            process=subprocess.Popen.__new__(subprocess.Popen);process._child_created=False
            process.pid=PID;process.args=COMMAND;process.poll=Mock(return_value=None)
            actual_resolve=Path.resolve
            def resolve(path,*args,**kwargs):
                if path==Path('/proc')/str(PID)/'exe':return state['exe']
                return actual_resolve(path,*args,**kwargs)
            def read(path,limit):
                if path.is_relative_to(Path('/proc')/str(PID)):state['reads']+=1
                if state['read_error']==path.name:raise OSError('literal vanished '+path.name)
                if path==Path('/proc')/str(PID)/'stat':
                    return (str(PID)+' (synthetic qemu) '+' '.join(['S',str(state['parent'])]+['0']*17+[str(state['start'])])).encode()
                if path==Path('/proc')/str(PID)/'status':
                    return b'Name:\tqemu\nUid:\t'+b'\t'.join(str(v).encode() for v in state['uids'])+b'\n'
                if path==Path('/proc')/str(PID)/'cmdline':return b'\0'.join(os.fsencode(x) for x in state['argv'])+b'\0'
                if path==binary:return binary.read_bytes()
                if path.is_relative_to(directory/'identity'):
                    state['record_reads']+=1
                    data=path.read_bytes()
                    self.assertLessEqual(len(data),limit)
                    return data
                raise AssertionError('No actual procfs read authorized: '+str(path))
            def process_read(path,limit,check,prefix):
                check();data=read(path,limit);prefix(data,True);check();return data
            with patch.object(reservation,'read_bounded',side_effect=read), \
                patch.object(reservation.shutil,'which',return_value=str(binary)), \
                patch.object(module,'read_process_bytes',side_effect=process_read), \
                patch.object(Path,'resolve',resolve),patch.object(reservation,'fsync_directory'), \
                patch.object(module.time,'monotonic_ns',side_effect=lambda:state['now']):
                ready=module.ProcessReadiness(process,COMMAND,UID,out=directory/'identity',
                    commit='a'*40,source_sha256='b'*64,started_ns=100,
                    setup_deadline_ns=1000000,vm_deadline_ns=2000000,
                    cancelled=lambda:state['cancelled'])
                yield ready,state,directory,process,binary

    def load(self,directory,name):return json.loads((directory/'identity'/name).read_bytes())

    def test_same_original_root_child_waits_then_final_uid_passes_strict_admission(self):
        module=self.module()
        with self.fixture(module) as (ready,state,directory,process,binary):
            state['uids']=[0]*4
            self.assertIs(ready.poll(),False);self.assertIs(ready.ready,False)
            with self.assertRaises(ValueError):ready.verify('channel')
            first=self.load(directory,'startup-first.json')
            self.assertEqual(first['actual']['uids'],[0]*4)
            self.assertEqual(first['mismatches'],['uids'])
            self.assertFalse(first['reference_qualified'])
            state['uids']=[UID]*4
            self.assertIs(ready.poll(),True);self.assertIs(ready.ready,True)
            row=ready.verify('channel')
            self.assertEqual((row['pid'],row['start_ticks'],row['uid']),(PID,123456,UID))
            self.assertEqual(row['executable_sha256'],hashlib.sha256(PAYLOAD).hexdigest())
            self.assertEqual(ready.budget.deadline_ns,1000000)
            self.assertEqual(self.load(directory,'startup-ready.json')['mismatches'],[])

    def test_permanent_root_and_cancellation_spend_the_original_cutoff_without_grant(self):
        module=self.module()
        for stop in ('deadline','cancelled'):
            with self.subTest(stop=stop),self.fixture(module) as (ready,state,directory,process,binary):
                state['uids']=[0]*4;self.assertFalse(ready.poll());before=state['reads'];records_before=state['record_reads']
                if stop=='deadline':state['now']=1000000
                else:state['cancelled']=True
                with self.assertRaises(ValueError):ready.poll()
                self.assertFalse(ready.ready);self.assertEqual(state['reads'],before)
                self.assertGreater(state['record_reads'],records_before)
                failure=self.load(directory,'terminal.json')
                self.assertEqual(failure['status'],'REJECTED')
                self.assertEqual(failure['source_sha256'],'b'*64)
                self.assertFalse(failure['reference_qualified'])

    def test_foreign_mixed_parent_and_command_states_fail_closed_with_distinct_fields(self):
        module=self.module()
        for key,value,field in [('uids',[UID,0,UID,UID],'uids'),('uids',[UID+1]*4,'uids'),
            ('parent',os.getpid()+1,'parent'),('start',0,'start_ticks'),('argv',COMMAND+['--foreign'],'command')]:
            with self.subTest(key=key,value=value),self.fixture(module) as (ready,state,directory,process,binary):
                state[key]=value
                with self.assertRaises(ValueError):ready.poll()
                record=self.load(directory,'terminal.json')
                self.assertIn(field,record['mismatches']);self.assertFalse(ready.ready)
                raw=record['raw']['cmdline'];data=base64.b64decode(raw['base64'],validate=True)
                self.assertEqual(data,b'\0'.join(os.fsencode(x) for x in state['argv'])+b'\0')
                self.assertEqual((len(data),hashlib.sha256(data).hexdigest()),(raw['bytes'],raw['sha256']))

    def test_replaced_start_or_executable_hash_cannot_use_an_earlier_root_observation(self):
        module=self.module()
        for changed in ('start','binary'):
            with self.subTest(changed=changed),self.fixture(module) as (ready,state,directory,process,binary):
                state['uids']=[0]*4;self.assertFalse(ready.poll());state['uids']=[UID]*4
                if changed=='start':state['start']+=1
                else:binary.write_bytes(PAYLOAD+b'CHANGED')
                with self.assertRaises(ValueError):ready.poll()
                record=self.load(directory,'terminal.json')
                self.assertIn('start_ticks' if changed=='start' else 'executable_hash',record['mismatches'])
                self.assertFalse(ready.ready)

    def test_bounded_reader_retains_oversize_and_read_error_prefixes(self):
        module=self.module();observed=[]
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'literal';payload=b'x'*65537;path.write_bytes(payload)
            with self.assertRaisesRegex(ValueError,'byte bound'):
                module.read_process_bytes(path,65536,lambda:None,lambda raw,complete:observed.append((raw,complete)))
            self.assertEqual(observed[-1],(payload,False))
        class Broken(io.BytesIO):
            def read(self,size):
                if self.tell():raise OSError('literal partial read')
                return super().read(size)
        observed=[]
        with patch.object(Path,'open',return_value=Broken(b'ORIGINAL PREFIX')):
            with self.assertRaisesRegex(OSError,'partial read'):
                module.read_process_bytes(Path('unused'),65536,lambda:None,
                    lambda raw,complete:observed.append((raw,complete)))
        self.assertEqual(observed,[(b'ORIGINAL PREFIX',False)])

    def test_wrong_executable_path_or_name_never_becomes_readiness(self):
        module=self.module()
        for name in ('other/qemu-system-x86_64','foreign'):
            with self.subTest(name=name),self.fixture(module) as (ready,state,directory,process,binary):
                state['exe']=directory/name
                with self.assertRaises(ValueError):ready.poll()
                record=self.load(directory,'terminal.json')
                self.assertIn('executable_path',record['mismatches'])
                if name=='foreign':self.assertIn('executable_name',record['mismatches'])
                self.assertFalse(ready.ready)

    def test_ready_identity_is_rechecked_before_channel_and_each_grant_boundary(self):
        module=self.module()
        with self.fixture(module) as (ready,state,directory,process,binary):
            self.assertTrue(ready.poll())
            original=ready.verify('channel');self.assertEqual(ready.verify('grant-before'),original)
            state['uids']=[0]*4
            with self.assertRaises(ValueError):ready.verify('grant-after')
            self.assertIn('uids',self.load(directory,'grant-after.json')['mismatches'])
            self.assertFalse(ready.ready)

    def test_in_process_binding_cannot_be_relabelled_for_another_source_child_or_clock(self):
        module=self.module()
        with self.fixture(module) as (ready,state,directory,process,binary):
            valid=(process,COMMAND,UID,'a'*40,'b'*64,100,2000000)
            ready.bind(*valid)
            for index,value in [(0,object()),(1,COMMAND+['foreign']),(2,UID+1),
                (3,'c'*40),(4,'d'*64),(5,101),(6,2000001)]:
                changed=list(valid);changed[index]=value
                with self.subTest(index=index),self.assertRaises(ValueError):ready.bind(*changed)

    def test_deadline_or_cancellation_during_retention_cannot_finish_admission(self):
        module=self.module()
        for stage in ('channel','grant-before','grant-after'):
            for stop in ('deadline','cancelled'):
                with self.subTest(stage=stage,stop=stop),self.fixture(module) as (ready,state,directory,process,binary):
                    self.assertTrue(ready.poll())
                    budget=None if stage=='channel' else module.AllocationDeadline(500000,lambda:state['cancelled'])
                    cutoff=ready.budget.deadline_ns if budget is None else budget.deadline_ns
                    original=reservation.write_original
                    def retain(path,raw,**kwargs):
                        result=original(path,raw,**kwargs)
                        if path.name==stage+'.json':
                            if stop=='deadline':state['now']=cutoff
                            else:state['cancelled']=True
                        return result
                    with patch.object(reservation,'write_original',side_effect=retain):
                        with self.assertRaisesRegex(ValueError,'cutoff|deadline|cancelled'):
                            ready.verify(stage,budget=budget)
                    self.assertFalse(ready.ready)
                    self.assertEqual(self.load(directory,'terminal.json')['status'],'REJECTED')

    def test_cancellation_after_a_successful_read_preserves_that_original_prefix(self):
        module=self.module();observed=[];stopped={'value':False}
        def check():
            if stopped['value']:raise ValueError('literal cancellation')
        def prefix(raw,complete):observed.append((raw,complete));stopped['value']=True
        with patch.object(Path,'open',return_value=io.BytesIO(b'ORIGINAL BEFORE CANCEL')):
            with self.assertRaisesRegex(ValueError,'cancellation'):
                module.read_process_bytes(Path('unused'),65536,check,prefix)
        self.assertEqual(observed,[(b'ORIGINAL BEFORE CANCEL',False)])

    def test_disappearance_retains_original_partial_bytes_before_rejection(self):
        module=self.module()
        with self.fixture(module) as (ready,state,directory,process,binary):
            state['read_error']='status'
            with self.assertRaisesRegex(OSError,'literal vanished'):ready.poll()
            record=self.load(directory,'terminal.json')
            self.assertIn('stat',record['raw']);self.assertNotIn('status',record['raw'])
            self.assertEqual(record['error']['type'],'OSError')
            self.assertFalse(ready.ready)

    def test_exit_before_or_during_inspection_cannot_admit_or_discard_diagnostics(self):
        module=self.module()
        for states in ([1],[None,1]):
            with self.subTest(states=states),self.fixture(module) as (ready,state,directory,process,binary):
                process.poll=Mock(side_effect=states)
                with self.assertRaises(ValueError):ready.poll()
                self.assertIn('poll',self.load(directory,'terminal.json')['mismatches'])
                self.assertFalse(ready.ready)


if __name__=='__main__':unittest.main()
