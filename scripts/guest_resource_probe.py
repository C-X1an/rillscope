"""Observe an actual booted guest; this never certifies a reference allocation."""
import base64
import json
import os
from pathlib import Path
import platform
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'benchmarks'))
from run import environment

PREFIX='RILLSCOPE_GUEST_PROBE_V1 '


def kernel_text(path,limit=1024):
    """Bounded diagnostics preserve missing/truncated states, never invent0."""
    try:
        with path.open('rb') as source: data=source.read(limit+1)
        retained=data[:limit]
        try: text=retained.decode('utf-8');valid='VALID'
        except UnicodeDecodeError: text=None;valid='INVALID'
        return {'path':str(path),'status':'READ' if len(data)<=limit else 'TRUNCATED',
                'prefix_base64':base64.b64encode(retained).decode('ascii'),
                'bytes_retained':len(retained),'utf8':valid,'text':text}
    except OSError as error:
        return {'path':str(path),'status':'UNAVAILABLE','error':type(error).__name__}


def cgroup_diagnostics(root=Path('/sys/fs/cgroup'),membership=Path('/proc/self/cgroup')):
    result={'scope':'actual bounded diagnostic bytes only; no effective-capacity verdict',
            'membership':kernel_text(membership),'levels':[]}
    try:
        result['affinity']={'status':'MEASURED','cpus':sorted(os.sched_getaffinity(0))}
    except (OSError,AttributeError) as error:
        result['affinity']={'status':'NOT MEASURED','error':type(error).__name__}
    try:
        if result['membership']['status']!='READ' or result['membership']['utf8']!='VALID':
            raise ValueError('complete valid UTF8 membership unavailable')
        lines=result['membership']['text'].splitlines()
        names=[line[3:] for line in lines if line.startswith('0::')]
        if len(names)!=1: raise ValueError('one actual unified membership required')
        parts=Path(names[0].lstrip('/')).parts
        if '..' in parts or len(parts)>16: raise ValueError('diagnostic cgroup path/depth bound exceeded')
        base=root.resolve();current=base.joinpath(*parts).resolve()
        if not current.is_relative_to(base): raise ValueError('diagnostic path escaped hierarchy')
        while True:
            result['levels'].append({'path':str(current),'files':{
                name:kernel_text(current/name) for name in ('cgroup.controllers','cgroup.subtree_control',
                    'cgroup.type','cpu.max','memory.max','memory.high')}})
            if current==base: break
            current=current.parent
        result['status']='CAPTURED'
    except (OSError,ValueError) as error:
        result.update(status='NOT MEASURED',error=type(error).__name__,reason=str(error))
    return result


def kernel_counters(path):
    wanted={'pswpin','pswpout','pgmajfault'};result={}
    try:
        for line in path.read_text().splitlines():
            fields=line.split()
            if fields and fields[0] in wanted:
                if len(fields)!=2 or fields[0] in result or not fields[1].isdigit():
                    raise ValueError('invalid kernel counter')
                result[fields[0]]=int(fields[1])
        if set(result)!=wanted: raise ValueError('missing kernel counter')
        return {'status':'MEASURED','values':result}
    except (OSError,ValueError) as error:
        return {'status':'NOT MEASURED','error':type(error).__name__,'values':None}


def snapshot(phase):
    clock=time.get_clock_info('monotonic')
    actual=environment();actual['inspection_diagnostics']=cgroup_diagnostics()
    return {'phase':phase,'environment':actual,'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'utc_ns':time.time_ns(),'monotonic_ns':time.monotonic_ns(),
            'clock_source':Path('/sys/devices/system/clocksource/clocksource0/current_clocksource').read_text().strip(),
            'clock_properties':{'implementation':clock.implementation,'monotonic':clock.monotonic,
                                'adjustable':clock.adjustable,'resolution_seconds':clock.resolution},
            'online_cpus':Path('/sys/devices/system/cpu/online').read_text().strip(),
            'cpu_stat':Path('/proc/stat').read_text().splitlines()[0],
            'vmstat':kernel_counters(Path('/proc/vmstat')),
            'swaps':Path('/proc/swaps').read_text(),
            'pressure':{name:Path('/proc/pressure',name).read_text() for name in ('cpu','memory','io')},
            'virtio_devices':[path.read_text() for path in sorted(Path('/sys/bus/virtio/devices').glob('*/uevent'))],
            'reference_qualified':False,'scope':'actual guest observation only; no benchmark, dedication or qualification'}


def main():
    if platform.system()!='Linux':
        print(json.dumps({'status':'BLOCKED','reason':'actual guest probe requires Linux','reference_qualified':False}))
        return 77
    for phase in ('guest-start','guest-end'):
        if phase=='guest-end': time.sleep(5)
        body=json.dumps(snapshot(phase),separators=(',',':')).encode()
        if len(body)>65536: raise ValueError('guest observation exceeds bound')
        print(PREFIX+base64.b64encode(body).decode('ascii'),flush=True)
    return 0


if __name__=='__main__': raise SystemExit(main())
