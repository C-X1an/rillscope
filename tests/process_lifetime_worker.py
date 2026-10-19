"""Isolated real-process fixtures; no Rust workload or performance claim."""
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from unittest.mock import patch

ROOT = Path(sys.argv[1]).resolve()
PREFIX = Path(sys.argv[2]).resolve()
MODE = sys.argv[3]
if MODE not in ('held-pipe', 'closed-pipe', 'delayed-launch', 'interrupt-capture',
                'exit-capture', 'interrupt-setup') or not PREFIX.is_relative_to(ROOT / '.local-runs'):
    raise ValueError('owned process fixture required')
sys.path[:0] = [str(ROOT / 'benchmarks'), str(ROOT / 'scripts')]
import process_metrics as subject


def alive(pid):
    if os.name == 'nt':
        from ctypes import wintypes
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x00100000, False, pid)
        if not handle:
            if ctypes.get_last_error() == 87: return False
            raise ctypes.WinError(ctypes.get_last_error())
        try: return kernel.WaitForSingleObject(handle, 0) == 0x102
        finally: kernel.CloseHandle(handle)
    try: os.kill(pid, 0)
    except ProcessLookupError: return False
    return True


if MODE in ('interrupt-capture', 'exit-capture', 'interrupt-setup'):
    marker = PREFIX.with_suffix('.ready')
    child = ('import os,sys,time;from pathlib import Path;'
        'print("actual-before-interrupt",flush=True);'
        'print("actual-stderr-before-interrupt",file=sys.stderr,flush=True);'
        'Path(sys.argv[1]).write_text(str(os.getpid()));time.sleep(5)')
    original_launch = subprocess.Popen
    original_communicate = subprocess.Popen.communicate
    launched = []; raised = False; propagated = None
    def launch(*args, **kwargs):
        process = original_launch(*args, **kwargs); launched.append(process)
        return process
    def interrupt_once(process, *args, **kwargs):
        global raised
        if raised: return original_communicate(process, *args, **kwargs)
        end = time.monotonic() + 3
        while not marker.is_file() and process.poll() is None and time.monotonic() < end:
            time.sleep(.005)
        if not marker.is_file(): raise AssertionError('actual child did not emit its readiness marker')
        raised = True
        if MODE == 'exit-capture': raise SystemExit(29)
        raise KeyboardInterrupt('controlled interruption after actual output')
    def interrupt_setup(job, process):
        raise KeyboardInterrupt('controlled interruption before job assignment')
    if MODE == 'interrupt-setup' and os.name != 'nt':
        raise ValueError('the suspended Windows job-assignment fixture requires Windows')
    target = patch.object(subject.WindowsJob, 'assign_and_resume', interrupt_setup) if MODE == 'interrupt-setup' else patch.object(subprocess.Popen, 'communicate', interrupt_once)
    try:
        with patch.object(subject.subprocess, 'Popen', side_effect=launch), target:
            try:
                subject.measured_child([sys.executable, '-u', '-c', child, str(marker)],
                    cwd=ROOT, prefix=PREFIX, timeout=4)
            except (KeyboardInterrupt, SystemExit) as error:
                propagated = {'type': type(error).__name__, 'code': getattr(error, 'code', None)}
        metadata = PREFIX.with_suffix('.process.json')
        stdout = PREFIX.with_suffix('.stdout'); stderr = PREFIX.with_suffix('.stderr')
        report = {'mode': MODE, 'propagated': propagated,
            'child_alive_at_return': any(process.poll() is None for process in launched),
            'usage': json.loads(metadata.read_text()) if metadata.is_file() else None,
            'stdout_hex': stdout.read_bytes().hex() if stdout.is_file() else None,
            'stderr_hex': stderr.read_bytes().hex() if stderr.is_file() else None}
    finally:
        # The old implementation leaves the pre-assignment suspended child
        # alive. End only the process whose actual Popen handle we retain.
        for process in launched:
            if process.poll() is None: process.kill()
            process.wait(timeout=3)
elif MODE == 'delayed-launch':
    original = subject.subprocess.Popen
    def delayed(*args, **kwargs):
        time.sleep(.3)  # Explicit injected startup delay, outside child execution.
        return original(*args, **kwargs)
    with patch.object(subject.subprocess, 'Popen', side_effect=delayed):
        usage, out, err = subject.measured_child([sys.executable, '-c', 'print("quick-child")'],
            cwd=ROOT, prefix=PREFIX, timeout=.2)
    report = {'mode': MODE, 'usage': usage, 'stdout_hex': out.hex(), 'stderr_hex': err.hex()}
else:
    marker = PREFIX.with_suffix('.child-pid')
    child = 'import os,sys,time;from pathlib import Path;Path(sys.argv[1]).write_text(str(os.getpid()));print("child-ready",flush=True);time.sleep(5)'
    parent = ('import os,subprocess,sys,time; from pathlib import Path; c=[sys.executable,"-c",' + repr(child) + ',sys.argv[1]]; '
        'options={"creationflags":subprocess.CREATE_NO_WINDOW|subprocess.CREATE_NEW_PROCESS_GROUP} if os.name=="nt" else {"start_new_session":True}; '
        'stream=sys.stdout if sys.argv[2]=="held-pipe" else subprocess.DEVNULL; '
        'subprocess.Popen(c,stdout=stream,stderr=stream,**options)\n'
        'end=time.monotonic()+3\n'
        'while not Path(sys.argv[1]).is_file() and time.monotonic()<end: time.sleep(.005)\n'
        'if not Path(sys.argv[1]).is_file(): raise RuntimeError("fixture child did not start")\n'
        'print("root-ready",flush=True)')
    usage, out, err = subject.measured_child([sys.executable, '-c', parent, str(marker), MODE],
        cwd=ROOT, prefix=PREFIX, timeout=.75)
    pid = int(marker.read_text())
    report = {'mode': MODE, 'usage': usage, 'stdout_hex': out.hex(), 'stderr_hex': err.hex(),
              'child_alive_at_return': alive(pid)}
    # Older defective implementations can leave this finite fixture alive. Let
    # it exit naturally; never signal a process by an unheld numeric PID.
    end = time.monotonic() + 6
    while alive(pid) and time.monotonic() < end: time.sleep(.02)
    if alive(pid): raise RuntimeError('finite owned fixture did not exit')
print(json.dumps(report, separators=(',', ':')))
