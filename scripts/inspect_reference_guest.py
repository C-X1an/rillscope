"""Boot one signed-image4CPU8GiB KVM trial; never certify reference dedication.

Requires existing Linux root permission and an existing non-root QEMU identity.
No permission, account, feature, service or billing changes. No network or host
filesystem is exposed to the guest. Only selected observation files are public
CI artifacts; images, overlays and the isolated GPG home are excluded.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request
import datetime as dt

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
sys.path.insert(0,str(ROOT/'benchmarks'))
from run import environment
from owned_process import LinuxOwnedChildren
from evidence import source_identity,git_state

IMAGE_BASE='https://cloud-images.ubuntu.com/noble/20260926/'
IMAGE='noble-server-cloudimg-amd64.img'
IMAGE_SHA='6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2'
FINGERPRINT='D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81'
PREFIX='RILLSCOPE_GUEST_PROBE_V1 '
IMAGE_LIMIT=800*1024**2
SERIAL_LIMIT=4*1024**2
GUEST_FILES=('scripts/guest_resource_probe.py','scripts/evidence.py','scripts/owned_process.py',
             'benchmarks/run.py','benchmarks/build.py','benchmarks/workloads.py',
             'benchmarks/process_metrics.py','benchmarks/envelopes.py','benchmarks/capture_paths.py')


def require(condition,message):
    if not condition: raise ValueError(message)


class TrialInterrupted(Exception):
    pass


def interrupted(number,frame):
    # Preserve the bounded cleanup window after the first handled interruption.
    for selected in (signal.SIGTERM,signal.SIGINT): signal.signal(selected,signal.SIG_IGN)
    raise TrialInterrupted('owned guest trial interrupted by signal '+str(number))


def sha(path):
    digest=hashlib.sha256()
    with path.open('rb') as source:
        while block:=source.read(1024*1024): digest.update(block)
    return digest.hexdigest()


def bounded_identity(path,limit):
    digest=hashlib.sha256();size=0
    with path.open('rb') as source:
        while block:=source.read(min(1024*1024,limit-size+1)):
            size+=len(block);require(size<=limit,'external input exceeds explicit byte bound')
            digest.update(block)
    return {'path':str(path),'bytes':size,'sha256':digest.hexdigest()}


def bounded_bytes(path,limit):
    with path.open('rb') as source: data=source.read(limit+1)
    require(len(data)<=limit,'capture exceeds bound')
    return data


def bounded_text(path,limit):
    return bounded_bytes(path,limit).decode('utf-8',errors='replace')


class BoundedCapture:
    """Backpressure through an owned pipe; disk bytes never exceed the cap."""
    def __init__(self,source,path,limit):
        self.source=source;self.path=path;self.limit=limit
        self.size=0;self.eof=False;self.exceeded=False
        os.set_blocking(source.fileno(),False)
        self.target=path.open('xb',buffering=0)

    def drain(self):
        if self.eof or self.exceeded: return
        for _ in range(64):
            try: block=os.read(self.source.fileno(),min(65536,self.limit-self.size+1))
            except BlockingIOError: return
            if not block: self.eof=True;return
            retained=block[:self.limit-self.size]
            self.target.write(retained);self.size+=len(retained)
            if len(retained)!=len(block):
                self.exceeded=True;raise ValueError('capture exceeds bound: '+self.path.name)

    def close(self):
        self.target.close()

    def record(self):
        return {'file':self.path.name,'bytes_retained':self.size,'byte_limit':self.limit,
                'limit_exceeded':self.exceeded,'eof_observed':self.eof}


def download(url,path,limit):
    request=urllib.request.Request(url,headers={'User-Agent':'RillScope-signed-guest-trial'})
    size=0
    with urllib.request.urlopen(request,timeout=60) as response,path.open('xb') as target:
        require(response.url.startswith('https://'),'HTTPS image/key transport required')
        while block:=response.read(1024*1024):
            size+=len(block);require(size<=limit,'download exceeds bound');target.write(block)


class TrialCommands:
    """Direct helper receipts inside the enclosing scripts/evidence.py run.

    Stream raw bytes before interruption instead of buffering them in a nested
    evidence process. Only explicitly selected image inputs get800MiB; general
    evidence.py inputs retain their256MiB limit. Every input is fully rehashed.
    """
    def __init__(self,out,ownership):
        self.out=out;self.ownership=ownership

    def __call__(self,name,command,timeout=60,inputs=(),large_inputs=()):
        directory=self.out/'commands';directory.mkdir(exist_ok=True)
        destination=directory/name;destination.mkdir()
        state={'schema_version':1,'command':command,'cwd':str(ROOT),
               'started_utc':dt.datetime.now(dt.timezone.utc).isoformat(),
               'verification_status':'FAIL','execution_outcome':'NOT_LAUNCHED',
               'input_limits_bytes':{'ordinary':256*1024**2,'explicit_image':IMAGE_LIMIT},
               'scope':'actual direct guest helper; enclosed in scripts/evidence.py trial receipt'}
        process=None;error=None;captures=[];started=time.monotonic()
        selected=[(path,256*1024**2) for path in inputs]+[(path,IMAGE_LIMIT) for path in large_inputs]
        try:
            state.update(source_before=source_identity(),git=git_state())
            state['inputs_before']=[bounded_identity(path,limit) for path,limit in selected]
            process=subprocess.Popen(command,cwd=ROOT,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,bufsize=0,start_new_session=True)
            state.update(pid=process.pid,execution_outcome='EXECUTED')
            captures.append(BoundedCapture(process.stdout,destination/'stdout.txt',4*1024**2))
            captures.append(BoundedCapture(process.stderr,destination/'stderr.txt',4*1024**2))
            deadline=time.monotonic()+timeout
            while process.poll() is None:
                for capture in captures: capture.drain()
                if time.monotonic()>=deadline:
                    state['execution_outcome']='TIMEOUT'
                    raise subprocess.TimeoutExpired(command,timeout)
                time.sleep(.01)
            state['exit_code']=process.returncode
            require(process.returncode==0,'command failed: '+name)
        except (Exception,KeyboardInterrupt) as caught:
            error=caught;state.update(error=type(caught).__name__,reason=str(caught))
            if isinstance(caught,TrialInterrupted): state['execution_outcome']='INTERRUPTED'
        finally:
            cleanup=self.ownership.terminate(process.pid if process is not None else None)
            state['process_cleanup']=cleanup
            if process is not None:
                try: state['exit_code']=process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    cleanup.update(status='FAIL',error='owned helper failed to exit after cleanup')
            try:
                for capture in captures:
                    capture.drain()
                    require(capture.eof,'owned helper capture did not close')
                state['inputs_after']=[bounded_identity(path,limit) for path,limit in selected]
                require(state['inputs_after']==state.get('inputs_before'),'input bytes changed during helper')
                state['source_after_sha256']=source_identity()['sha256']
                require(state['source_after_sha256']==state.get('source_before',{}).get('sha256'),'source changed during helper')
                require(cleanup['status']=='PASS','owned helper cleanup failed')
                if error is None: state['verification_status']='PASS'
            except (OSError,ValueError) as caught:
                if error is None: error=caught
                state.update(error=type(caught).__name__,reason=str(caught))
            for capture in captures: capture.close()
            for label in ('stdout','stderr'):
                path=destination/(label+'.txt')
                if not path.exists(): path.write_bytes(b'')
                state[label]={'file':path.name,'sha256':sha(path)}
            state.update(finished_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
                         elapsed_seconds=time.monotonic()-started,captures=[capture.record() for capture in captures])
            (destination/'receipt.json').write_text(json.dumps(state,indent=2)+'\n')
            if process is not None:
                process.stdout.close();process.stderr.close()
        if error is not None: raise error
        return bounded_bytes(destination/'stdout.txt',4*1024**2)


def qmp(port,command):
    with socket.create_connection(('127.0.0.1',port),timeout=2) as connection:
        handle=connection.makefile('rwb')
        def reply():
            for _ in range(50):
                line=handle.readline(1024*1024+1)
                require(line and len(line)<=1024*1024,'invalid QMP framing')
                value=json.loads(line)
                if 'event' not in value: return value
            raise ValueError('QMP event bound exceeded')
        require('QMP' in reply(),'QMP greeting missing')
        handle.write(b'{"execute":"qmp_capabilities"}\n');handle.flush()
        require('return' in reply(),'QMP capabilities failed')
        handle.write(json.dumps({'execute':command}).encode()+b'\n');handle.flush()
        return reply()


def parse_guest(serial):
    rows=[]
    for line in serial.splitlines():
        # The owned serial device may include a kernel timestamp before output.
        if PREFIX not in line: continue
        body=line.split(PREFIX,1)[1].strip()
        require(len(body)<=90000,'guest record exceeds bound')
        value=json.loads(base64.b64decode(body,validate=True))
        require(isinstance(value,dict) and value.get('phase') in ('guest-start','guest-end'), 'invalid guest phase')
        require(set(value)=={'phase','environment','boot_id','utc_ns','monotonic_ns','clock_source',
                            'clock_properties','online_cpus','cpu_stat','vmstat','swaps','pressure',
                            'virtio_devices','reference_qualified','scope'},'invalid guest record fields')
        require(isinstance(value['environment'],dict) and value['reference_qualified'] is False
                and re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',value.get('boot_id','')) is not None
                and all(type(value[key]) is int and value[key]>0 for key in ('utc_ns','monotonic_ns')),
                'invalid guest identity/clock fields')
        rows.append(value);require(len(rows)<=2,'duplicate guest records')
    require([row['phase'] for row in rows]==['guest-start','guest-end'],'complete actual guest observations missing')
    require(rows[0]['boot_id']==rows[1]['boot_id'],'guest rebooted during trial')
    require(all(rows[1][key]>rows[0][key] for key in ('utc_ns','monotonic_ns')),'guest clocks failed to advance')
    return rows


def host_snapshot(pid,port):
    fields={}
    for line in Path('/proc',str(pid),'status').read_text().splitlines():
        key,_,value=line.partition(':');fields[key]=value.strip()
    cpus=qmp(port,'query-cpus-fast')
    threads=cpus.get('return',[])
    return {'utc_ns':time.time_ns(),'monotonic_ns':time.monotonic_ns(),'environment':environment(),
            'qemu_pid':pid,'process_status':fields,'qemu_affinity':sorted(os.sched_getaffinity(pid)),
            'vcpu_threads':[{'thread_id':row['thread-id'],'affinity':sorted(os.sched_getaffinity(row['thread-id']))} for row in threads],
            'kvm':qmp(port,'query-kvm'),'run_status':qmp(port,'query-status'),
            'memory':qmp(port,'query-memory-size-summary'),'hotplug_memory':qmp(port,'query-memory-devices'),
            'smaps_rollup':Path('/proc',str(pid),'smaps_rollup').read_text(),
            'vmstat':{line.split()[0]:int(line.split()[1]) for line in Path('/proc/vmstat').read_text().splitlines()
                      if line.split()[0] in ('pswpin','pswpout','pgmajfault')},
            'pressure':{name:Path('/proc/pressure',name).read_text() for name in ('cpu','memory','io')},
            'clock_properties':str(time.get_clock_info('monotonic')),
            'clock_source':Path('/sys/devices/system/clocksource/clocksource0/current_clocksource').read_text().strip()}


def trial(out,run_as,ownership):
    import fcntl
    import pwd
    account=pwd.getpwnam(run_as)
    checked=TrialCommands(out,ownership)
    require(account.pw_uid>0,'existing non-root QEMU identity required')
    initial=environment()
    require(initial.get('effective_cpu_capacity')==4 and initial.get('process_affinity_cpu_count')==4,'actual four-CPU host capacity required')
    require(type(initial.get('available_memory_bytes')) is int and initial['available_memory_bytes']>=10*1024**3,'actual host memory headroom insufficient')
    with Path('/dev/kvm').open('r+b',buffering=0) as device:
        require(fcntl.ioctl(device.fileno(),0xae00,0)==12,'existing KVMAPI12 required')
    for tool in ('qemu-system-x86_64','qemu-img','cloud-localds','gpg','gpgv'):
        require(shutil.which(tool) is not None,'required installed tool missing: '+tool)
    qemu=Path(shutil.which('qemu-system-x86_64')).resolve()
    version=checked('qemu-version',[str(qemu),'--version'],inputs=(qemu,))
    help_text=checked('qemu-help',[str(qemu),'-help'],inputs=(qemu,))
    require(b'-runas' in help_text,'installed QEMU lacks explicit privilege-drop option')
    (out/'gnupg').mkdir(mode=0o700)
    key=out/'ubuntu-cloud-image.asc';keyring=out/'image-key.gpg'
    download('https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x'+FINGERPRINT,key,256*1024)
    listed=checked('key-fingerprint',['gpg','--no-options','--homedir',str(out/'gnupg'),'--batch','--no-tty',
        '--with-colons','--show-keys',str(key)],inputs=(key,))
    lines=listed.decode().splitlines()
    require(sum(line.startswith('pub:') for line in lines)==1,'one pinned public signing key required')
    first=next(line.split(':')[9] for line in lines if line.startswith('fpr:'))
    require(first==FINGERPRINT,'official public signing fingerprint differs')
    checked('key-dearmor',['gpg','--no-options','--homedir',str(out/'gnupg'),'--batch','--no-tty','--output',str(keyring),'--dearmor',str(key)],inputs=(key,))
    download(IMAGE_BASE+'SHA256SUMS',out/'SHA256SUMS',65536)
    download(IMAGE_BASE+'SHA256SUMS.gpg',out/'SHA256SUMS.gpg',65536)
    signed=checked('image-signature',['gpgv','--homedir',str(out/'gnupg'),'--keyring',str(keyring),'--status-fd','1',str(out/'SHA256SUMS.gpg'),str(out/'SHA256SUMS')],inputs=(keyring,out/'SHA256SUMS',out/'SHA256SUMS.gpg'))
    valid=[line.split() for line in signed.decode().splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
    require(any(row[2]==FINGERPRINT or row[-1]==FINGERPRINT for row in valid),'detached signature primary identity differs')
    expected=[line.split()[0] for line in (out/'SHA256SUMS').read_text().splitlines() if len(line.split())==2 and line.split()[1].lstrip('*')==IMAGE]
    require(expected==[IMAGE_SHA],'signed pinned image checksum differs')
    image=out/IMAGE;download(IMAGE_BASE+IMAGE,image,IMAGE_LIMIT)
    require(sha(image)==IMAGE_SHA,'actual complete image digest differs')
    files=[];source_hashes={}
    for name in GUEST_FILES:
        data=(ROOT/name).read_bytes();require(len(data)<=256*1024,'guest source file exceeds bound')
        source_hashes[name]=hashlib.sha256(data).hexdigest()
        files.append({'path':'/opt/rillscope/'+name,'permissions':'0644','encoding':'b64','content':base64.b64encode(data).decode('ascii')})
    config={'package_update':False,'package_upgrade':False,'ssh_pwauth':False,'disable_root':True,'users':[],
            'write_files':files,'runcmd':[['/bin/sh','-c','/usr/bin/python3 /opt/rillscope/scripts/guest_resource_probe.py > /dev/ttyS0 2>&1'],['/usr/sbin/shutdown','-h','now']]}
    (out/'user-data').write_text('#cloud-config\n'+json.dumps(config)+'\n')
    (out/'meta-data').write_text('instance-id: rillscope-inspection\nlocal-hostname: rillscope-inspection\n')
    checked('seed-create',['cloud-localds',str(out/'seed.iso'),str(out/'user-data'),str(out/'meta-data')],inputs=(out/'user-data',out/'meta-data'))
    checked('overlay-create',['qemu-img','create','-f','qcow2','-F','qcow2','-b',str(image),str(out/'disk.qcow2'),'20G'],large_inputs=(image,))
    with socket.socket() as available:
        available.bind(('127.0.0.1',0));port=available.getsockname()[1]
    command=[str(qemu),'-name','RillScope-guest-inspection','-machine','q35,memory-backend=ram0,mem-merge=off',
        '-accel','kvm','-cpu','host','-smp','4,sockets=1,cores=4,threads=1','-m','8192',
        '-object','memory-backend-ram,id=ram0,size=8G,prealloc=on,merge=off','-runas',run_as,
        '-display','none','-chardev','stdio,id=serial0,signal=off,mux=off','-serial','chardev:serial0',
        '-monitor','none','-no-reboot','-nic','none',
        '-qmp',f'tcp:127.0.0.1:{port},server=on,wait=off',
        '-drive','file='+str(out/'disk.qcow2')+',if=virtio,format=qcow2',
        '-drive','file='+str(out/'seed.iso')+',media=cdrom,format=raw,readonly=on']
    metadata={'command':command,'qemu_sha256':sha(qemu),'qemu_version':version.decode(),
              'image_sha256':IMAGE_SHA,'signing_primary':FINGERPRINT,'guest_source_files':source_hashes,
              'host_before':initial,'qemu_run_as_uid':account.pw_uid,'reference_qualified':False}
    (out/'configuration.json').write_text(json.dumps(metadata,indent=2)+'\n')
    samples=[];process=None;captures=[];started=time.monotonic()
    try:
        process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0,cwd=ROOT)
        captures.append(BoundedCapture(process.stdout,out/'serial.txt',SERIAL_LIMIT))
        captures.append(BoundedCapture(process.stderr,out/'qemu.stderr',256*1024))
        (out/'process.json').write_text(json.dumps({'status':'RUNNING','pid':process.pid,'utc_ns':time.time_ns()})+'\n')
        while process.poll() is None and time.monotonic()-started<600:
            for capture in captures: capture.drain()
            try:
                value=host_snapshot(process.pid,port);samples.append(value)
                with (out/'host-samples.jsonl').open('a') as stream: stream.write(json.dumps(value)+'\n')
            except (OSError,ValueError) as error:
                with (out/'host-observation-errors.jsonl').open('a') as stream:
                    stream.write(json.dumps({'utc_ns':time.time_ns(),'error':type(error).__name__})+'\n')
            time.sleep(.5)
        for capture in captures: capture.drain()
        require(process.poll() is not None,'actual guest trial exceeded600seconds')
        require(process.returncode==0,'actual QEMU guest trial failed')
    finally:
        if process is not None and process.poll() is None:
            try: qmp(port,'system_powerdown');process.wait(timeout=5)
            except (OSError,ValueError,subprocess.TimeoutExpired):
                process.terminate()
                try: process.wait(timeout=3)
                except subprocess.TimeoutExpired: process.kill();process.wait(timeout=2)
        if process is not None:
            (out/'process.json').write_text(json.dumps({'status':'EXITED','pid':process.pid,'exit_code':process.poll(),'utc_ns':time.time_ns()})+'\n')
        for capture in captures: capture.close()
        (out/'capture.json').write_text(json.dumps([capture.record() for capture in captures],indent=2)+'\n')
        if process is not None:
            process.stdout.close();process.stderr.close()
    serial=bounded_text(out/'serial.txt',SERIAL_LIMIT)
    guest=parse_guest(serial)
    (out/'guest-snapshots.json').write_text(json.dumps(guest,indent=2)+'\n')
    require(samples,'actual host observations missing')
    require(all(row['environment'].get('effective_cpu_capacity')==4 and row['environment'].get('process_affinity_cpu_count')==4
                and 7.5*1024**3<=row['environment'].get('physical_memory_bytes',0)<=8.5*1024**3 for row in guest),'actual guest resources differ')
    observed=[row for row in samples if row['kvm'].get('return',{}).get('enabled') is True
              and row['memory'].get('return',{}).get('base-memory')==8*1024**3
              and len(row['vcpu_threads'])==4 and all(len(thread['affinity'])==4 for thread in row['vcpu_threads'])
              and int(row['process_status'].get('VmRSS','0 kB').split()[0])*1024>=7.5*1024**3
              and row['process_status'].get('Uid','').split()==[str(account.pw_uid)]*4]
    require(observed,'actual KVM, privilege drop, backing memory and four vCPU threads not observed together')
    require(all(row['process_status'].get('VmSwap','')=='0 kB' for row in samples),'QEMU swap or missing swap observations')
    return {'status':'OBSERVED','guest_snapshots':len(guest),'host_snapshots':len(samples),
            'configuration_observed':True,'reference_qualified':False,
            'scope':'actual signed-image KVM4CPU8GiB boot/resource trial; no benchmark, dedication, full continuity or reference certification'}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,required=True);parser.add_argument('--run-as',required=True)
    args=parser.parse_args()
    if platform.system()!='Linux' or not hasattr(os,'geteuid') or os.geteuid()!=0:
        print(json.dumps({'status':'BLOCKED','reason':'requires existing Linux root permission','reference_qualified':False}));return 77
    require(re.fullmatch('[a-z_][a-z0-9_-]{0,31}',args.run_as) is not None,'closed existing user name required')
    out=args.out.absolute()
    for path in (out,*out.parents):
        require(not path.is_symlink(),'owned output cannot traverse links')
        if path==ROOT: break
    out=out.resolve();require(out.is_relative_to(ROOT/'.local-runs'),'owned .local-runs output required')
    require(',' not in str(out),'QEMU output path cannot include commas')
    out.mkdir(parents=True,exist_ok=False)
    for number in (signal.SIGTERM,signal.SIGINT): signal.signal(number,interrupted)
    ownership=None
    try:
        # This process has root's existing permission to stop its descendants,
        # including helpers adopted after a nested evidence runner is stopped.
        ownership=LinuxOwnedChildren()
        result=trial(out,args.run_as,ownership);code=0
    except (OSError,ValueError,KeyError,TypeError,StopIteration,subprocess.SubprocessError,TrialInterrupted) as error:
        result={'status':'FAIL','error':type(error).__name__,'reason':str(error),'reference_qualified':False};code=1
    finally:
        for number in (signal.SIGTERM,signal.SIGINT): signal.signal(number,signal.SIG_IGN)
        cleanup=ownership.finish(None) if ownership is not None else {'status':'NOT LAUNCHED'}
        (out/'cleanup.json').write_text(json.dumps(cleanup,indent=2)+'\n')
    if cleanup['status']!='PASS':
        result.update(status='FAIL',cleanup=cleanup);code=1
    (out/'results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2));return code


if __name__=='__main__': raise SystemExit(main())
