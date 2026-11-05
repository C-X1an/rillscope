"""Original QEMU identity observations and bounded, ungranted startup readiness."""
import base64
import hashlib
import os
from pathlib import Path
import time

import archive_capture
import canonical_reference_allocation as protocol
import canonical_reference_reservation as reservation
from canonical_reference_deadline import AllocationDeadline

REASON='live QEMU parent/start/UID/command/executable differs'
MAX_RECORD_BYTES=512*1024
STAGES={'startup-first','startup-ready','terminal','channel','grant-before','grant-after'}
PIN_FIELDS=('pid','ppid','start_ticks','command_sha256','executable_sha256')


class IdentityDeadline(AllocationDeadline):
    """Spend the supplied original setup cutoff, without an inspection-time reset."""
    def check(self):
        stopped=self.cancelled()
        protocol.require(type(stopped) is bool and not stopped,'original process readiness cancelled')
        remaining=self.deadline_ns-time.monotonic_ns()
        protocol.require(0<remaining<=protocol.MAX_LEASE_NS,'original process readiness cutoff exhausted')
        return remaining/10**9


def read_process_bytes(path,limit,check,prefix):
    """Keep each bounded original prefix even if a read or cutoff check fails."""
    protocol.require(type(limit) is int and 0<limit<=reservation.MAX_PROCESS_BYTES,
        'fixed process observation read bound required')
    raw=bytearray();check()
    with Path(path).open('rb') as stream:
        while True:
            check();block=stream.read(min(4096,limit+1-len(raw)))
            if not block:
                prefix(bytes(raw),True);check();return bytes(raw)
            raw.extend(block);prefix(bytes(raw),False)
            protocol.require(len(raw)<=limit,'original process observation exceeds byte bound')
            check()


def inspect_child(process,command,uid,*,budget=None,pin=None,capture=None):
    """Observe only. Even a complete diagnostic snapshot is never admission."""
    expected_raw=b''
    snapshot={'observed_monotonic_ns':time.monotonic_ns(),'actual':{},'expected':{},
        'raw':{},'mismatches':[],'error':None}
    row=None
    def check():
        if budget is not None:budget.check()
    def read(name):
        def prefix(raw,complete):
            snapshot['raw'][name]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                'base64':base64.b64encode(raw).decode('ascii'),'complete':complete}
        return read_process_bytes(Path('/proc')/str(process.pid)/name,
            reservation.MAX_PROCESS_BYTES,check,prefix)
    try:
        check()
        if type(process) is not reservation.subprocess.Popen or process.poll() is not None:
            snapshot['mismatches']=['poll']
            raise ValueError('original live owned QEMU Popen child required')
        protocol.require(protocol.integer(process.pid) and process.pid>0,'original positive QEMU PID required')
        protocol.require(type(command) is list and 0<len(command)<=256
            and all(protocol.text(item,4096) for item in command)
            and sum(len(item.encode('utf-8'))+1 for item in command)<=reservation.MAX_PROCESS_BYTES,
            'bounded original QEMU command required')
        protocol.require(process.args==command and protocol.integer(uid) and uid>0,
            'original command and existing nonroot QEMU identity required')
        if pin is not None:
            protocol.require(type(pin) is dict and set(pin)==set(PIN_FIELDS)
                and all(protocol.integer(pin[key]) and pin[key]>0 for key in ('pid','ppid','start_ticks'))
                and all(protocol.hex_value(pin[key],64) for key in ('command_sha256','executable_sha256')),
                'closed original process identity pin required')
        expected_raw=b'\0'.join(os.fsencode(item) for item in command)+b'\0'
        snapshot['expected']={'pid':process.pid,'parent':os.getpid(),'uids':[uid]*4,
            'command_base64':base64.b64encode(expected_raw).decode('ascii'),'pin':pin}
        row=reservation.parse_stat(read('stat'),process.pid)
        snapshot['actual'].update(row)
        uids=reservation.parse_uids(read('status'));snapshot['actual']['uids']=uids
        command_raw=read('cmdline');snapshot['actual']['command_sha256']=hashlib.sha256(command_raw).hexdigest()
        # Only this kernel-owned identity link is intentionally resolved.
        executable=(Path('/proc')/str(process.pid)/'exe').resolve(strict=True)
        selected=reservation.shutil.which(command[0])
        selected_path=Path(selected).resolve(strict=True) if selected is not None else None
        snapshot['actual'].update(executable=str(executable),selected_executable=str(selected_path) if selected_path else None)
        fields=[]
        if row['ppid']!=os.getpid():fields.append('parent')
        if row['start_ticks']<=0 or pin is not None and row['start_ticks']!=pin['start_ticks']:fields.append('start_ticks')
        if uids!=[uid]*4:fields.append('uids')
        if command_raw!=expected_raw:fields.append('command')
        if selected_path!=executable:fields.append('executable_path')
        if executable.name!='qemu-system-x86_64':fields.append('executable_name')
        snapshot['mismatches']=fields
        # A wrong executable path never becomes a candidate for admission.
        digest=None
        if not any(field in fields for field in ('executable_path','executable_name')):
            check()
            digest=(hashlib.sha256(reservation.read_bounded(executable,reservation.MAX_EXECUTABLE_BYTES)).hexdigest()
                if budget is None else budget.digest(executable,reservation.MAX_EXECUTABLE_BYTES))
            check();snapshot['actual']['executable_sha256']=digest
            if pin is not None and digest!=pin['executable_sha256']:fields.append('executable_hash')
        row.update(command_sha256=hashlib.sha256(command_raw).hexdigest(),executable_sha256=digest)
        if pin is not None and (row['pid']!=pin['pid'] or row['ppid']!=pin['ppid']):
            if 'parent' not in fields:fields.append('parent')
        if pin is not None and row['command_sha256']!=pin['command_sha256'] and 'command' not in fields:fields.append('command')
        if process.poll() is not None:
            if 'poll' not in fields:fields.append('poll')
            raise ValueError('owned QEMU exited during original identity inspection')
        check()
    except BaseException as error:
        snapshot['error']={'type':type(error).__name__,'reason':str(error)[:2048]}
        if not snapshot['mismatches']:snapshot['mismatches']=['inspection_error']
        snapshot['finished_monotonic_ns']=time.monotonic_ns()
        if capture is not None:capture(snapshot)
        raise
    snapshot['finished_monotonic_ns']=time.monotonic_ns()
    if capture is not None:capture(snapshot)
    return row,snapshot


def strict_child(process,command,uid,*,budget=None,pin=None,capture=None):
    row,snapshot=inspect_child(process,command,uid,budget=budget,pin=pin,capture=capture)
    protocol.require(not snapshot['mismatches'],REASON)
    row['uid']=uid
    return row


class ProcessReadiness:
    """Retain first startup, final readiness and failures; intermediate probes are not a trace."""
    def __init__(self,process,command,uid,*,out,commit,source_sha256,started_ns,
            setup_deadline_ns,vm_deadline_ns,cancelled=lambda:False):
        protocol.require(all(protocol.integer(value) for value in (started_ns,setup_deadline_ns,vm_deadline_ns))
            and started_ns<setup_deadline_ns<=vm_deadline_ns
            and 0<vm_deadline_ns-started_ns<=protocol.MAX_LEASE_NS,'original finite process setup/VM cutoffs required')
        protocol.require(protocol.hex_value(commit,40) and protocol.hex_value(source_sha256,64),'exact process observation source required')
        protocol.require(type(command) is list and 0<len(command)<=256
            and all(protocol.text(item,4096) for item in command)
            and sum(len(item.encode('utf-8'))+1 for item in command)<=reservation.MAX_PROCESS_BYTES
            and protocol.integer(uid) and uid>0,'bounded original process command and positive target UID required')
        self.process,self.command,self.uid=process,list(command),uid
        self.commit,self.source_sha256=commit,source_sha256
        self.started_ns,self.vm_deadline_ns=started_ns,vm_deadline_ns
        self.budget=IdentityDeadline(setup_deadline_ns,cancelled)
        self.out=archive_capture.owned(out);reservation.durable_mkdir(self.out,mode=0o700)
        self.pin=None;self.ready=False;self.last=None;self.emitted=set();self.attempts=0

    def _capture(self,snapshot):self.last=snapshot

    def bind(self,process,command,uid,commit,source_sha256,started_ns,deadline_ns):
        protocol.require(self.process is process and self.command==command and self.uid==uid
            and self.commit==commit and self.source_sha256==source_sha256
            and self.started_ns==started_ns and self.vm_deadline_ns==deadline_ns,
            'same original process/source/lifetime readiness object required')

    def _retain(self,stage,status):
        protocol.require(stage in STAGES and len(self.emitted)<=len(STAGES),'closed bounded process observation stage required')
        if stage in self.emitted:return
        value={'schema_version':1,'method':protocol.METHOD,'commit':self.commit,'source_sha256':self.source_sha256,
            'reference_qualified':False,'status':status,'original_vm_started_ns':self.started_ns,
            'original_setup_deadline_ns':self.budget.deadline_ns,'original_vm_deadline_ns':self.vm_deadline_ns,
            'readiness_probes':self.attempts,'recorded_monotonic_ns':time.monotonic_ns(),
            'scope':'Original first-startup, final strict identity or failure observation only; no grant, complete startup trace, resource or reference qualification.'}
        if self.last is not None:value.update(self.last)
        raw=reservation.canonical_bytes(value,MAX_RECORD_BYTES)
        reservation.write_original(self.out/(stage+'.json'),raw)
        self.emitted.add(stage)

    def fail(self,error):
        self.ready=False
        if self.last is None:
            self.last={'observed_monotonic_ns':time.monotonic_ns(),'actual':{},'expected':{},'raw':{},'mismatches':['inspection_error']}
        self.last=dict(self.last)
        self.last['error']={'type':type(error).__name__,'reason':str(error)[:2048]}
        self._retain('terminal','REJECTED')

    def poll(self):
        if self.ready:
            self.budget.check();return True
        self.attempts+=1
        try:
            row,snapshot=inspect_child(self.process,self.command,self.uid,budget=self.budget,pin=self.pin,capture=self._capture)
            pending=snapshot['mismatches']==['uids'] and snapshot['actual']['uids']==[0]*4
            protocol.require(not snapshot['mismatches'] or pending,REASON)
            if self.pin is None:self.pin={key:row[key] for key in PIN_FIELDS}
            if pending:
                self._retain('startup-first','WAITING_FOR_UID')
                self.budget.check();return False
            self._retain('startup-ready','STRICT_IDENTITY_ONLY')
            self.budget.check();self.ready=True
            return True
        except BaseException as error:
            self.fail(error);raise

    def verify(self,stage,*,budget=None):
        protocol.require(self.ready and self.pin is not None,'startup identity is not admitted')
        protocol.require(stage in {'channel','grant-before','grant-after'},'closed original process admission stage required')
        try:
            active_budget=self.budget if budget is None else budget
            row,snapshot=inspect_child(self.process,self.command,self.uid,
                budget=active_budget,pin=self.pin,capture=self._capture)
            self._retain(stage,'REJECTED' if snapshot['mismatches'] else 'STRICT_IDENTITY_ONLY')
            protocol.require(not snapshot['mismatches'],REASON)
            active_budget.check()
            row['uid']=self.uid
            return row
        except BaseException as error:
            self.fail(error);raise
