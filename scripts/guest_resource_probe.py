"""Observe an actual booted guest; this never certifies a reference allocation."""
import base64
import json
from pathlib import Path
import platform
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'benchmarks'))
from run import environment

PREFIX='RILLSCOPE_GUEST_PROBE_V1 '


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
    return {'phase':phase,'environment':environment(),'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
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
