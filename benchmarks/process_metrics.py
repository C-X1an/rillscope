"""Measure only an owned child process; CPU/RSS boundaries cover its entire lifetime."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from capture_paths import preflight_prefix
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from owned_process import LinuxOwnedChildren, WindowsJob, terminate_posix_group

ENVIRONMENT_KEYS = ('SYSTEMROOT', 'SystemRoot', 'WINDIR', 'TEMP', 'TMP',
                    'SystemDrive', 'SYSTEMDRIVE', 'ProgramData', 'PROGRAMDATA')


class CaptureArtifactError(OSError):
    def __init__(self,reason,failure_directory):
        self.failure_directory=failure_directory
        super().__init__('benchmark artifact capture failed: '+reason+'; failure_directory='+str(failure_directory))


def capture_failure(command,cwd,prefix,captured,stdout,stderr,error):
    """Preserve an actual failed attempt away from its failing long/raw path."""
    record={'status':'FAIL','kind':'benchmark-harness-failure','reference_qualified':False,
        'command':[os.fsdecode(value) for value in command],'requested_prefix':str(prefix),
        'process':captured,'reason':type(error).__name__+': '+str(error),
        'scope':'actual harness attempt and retained child bytes; no replacement sample or measurement success'}
    for name,data in (('stdout',stdout),('stderr',stderr)):
        record[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
    destination=None
    try:
        if max(len(stdout),len(stderr))>16*1024**2: raise OSError('failure raw stream exceeds16MiB retention bound')
        body=json.dumps(record,separators=(',',':'))+'\n'
        if len(body.encode('utf-8'))>65536: raise OSError('failure metadata exceeds64KiB retention bound')
        local=Path(cwd).resolve()/'.local-runs'
        if local.is_symlink() or (hasattr(local,'is_junction') and local.is_junction()):
            raise OSError('failure location cannot traverse a link')
        local.mkdir(exist_ok=True)
        out=Path(tempfile.mkdtemp(prefix='pf-',dir=local))
        if (out/'stdout').write_bytes(stdout)!=len(stdout) or (out/'stderr').write_bytes(stderr)!=len(stderr):
            raise OSError('short failure raw write')
        if (out/'process.json').write_text(body,encoding='utf-8')!=len(body): raise OSError('short failure metadata write')
        destination=out
    except (OSError,ValueError) as fallback:
        # If storage itself is unavailable, the enclosing evidence owner keeps
        # this bounded diagnostic. Never say missing raw bytes were retained.
        summary={key:record[key] for key in ('status','kind','stdout','stderr','reference_qualified','process')}
        detail=type(fallback).__name__+': '+str(fallback)
        summary['fallback_error']=detail[:1024]
        summary['fallback_error_truncated']=len(detail)>1024
        print(json.dumps(summary,separators=(',',':')),file=sys.stderr,flush=True)
    raise CaptureArtifactError(record['reason'],destination) from error

def windows_usage(process):
    from ctypes import wintypes
    class FileTime(ctypes.Structure):
        _fields_ = [('low', wintypes.DWORD), ('high', wintypes.DWORD)]
    class MemoryCounters(ctypes.Structure):
        _fields_ = [('cb', wintypes.DWORD), ('faults', wintypes.DWORD),
                    ('peak_working_set', ctypes.c_size_t), ('working_set', ctypes.c_size_t),
                    ('peak_paged', ctypes.c_size_t), ('paged', ctypes.c_size_t),
                    ('peak_nonpaged', ctypes.c_size_t), ('nonpaged', ctypes.c_size_t),
                    ('pagefile', ctypes.c_size_t), ('peak_pagefile', ctypes.c_size_t)]
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    times = kernel.GetProcessTimes
    times.argtypes = [wintypes.HANDLE, ctypes.POINTER(FileTime), ctypes.POINTER(FileTime), ctypes.POINTER(FileTime), ctypes.POINTER(FileTime)]
    times.restype = wintypes.BOOL
    memory = kernel.K32GetProcessMemoryInfo
    memory.argtypes = [wintypes.HANDLE, ctypes.POINTER(MemoryCounters), wintypes.DWORD]
    memory.restype = wintypes.BOOL
    created, exited, system, user = (FileTime() for _ in range(4))
    counters = MemoryCounters(); counters.cb = ctypes.sizeof(counters)
    # CPython owns this handle until the Popen object is closed. No other PID is inspected.
    handle = wintypes.HANDLE(int(process._handle))
    cpu_ok = times(handle, ctypes.byref(created), ctypes.byref(exited), ctypes.byref(system), ctypes.byref(user))
    rss_ok = memory(handle, ctypes.byref(counters), ctypes.sizeof(counters))
    value = lambda item: ((int(item.high) << 32) | int(item.low)) * 100
    return {'cpu_user_ns': value(user) if cpu_ok else None, 'cpu_system_ns': value(system) if cpu_ok else None,
            'peak_rss_bytes': int(counters.peak_working_set) if rss_ok else None,
            'cpu_rss_instrument': 'Windows GetProcessTimes/K32GetProcessMemoryInfo on owned process handle',
            'cpu_rss_status': 'MEASURED' if cpu_ok and rss_ok else 'NOT MEASURED'}

def process_problems(usage, *, require_process_fields=True):
    """Reject malformed instrumentation before it can enter distributions."""
    problems = []
    for name in ('wall_ns','cpu_user_ns','cpu_system_ns','peak_rss_bytes'):
        value = usage.get(name)
        if type(value) is not int or value < 0 or (name in ('wall_ns','peak_rss_bytes') and value == 0):
            problems.append('invalid owned process metric: ' + name)
    if usage.get('cpu_rss_status') != 'MEASURED': problems.append('CPU/RSS instrument unavailable')
    if require_process_fields:
        if usage.get('process_outcome') != 'EXECUTED': problems.append('process/instrument attempt failed')
        if usage.get('timed_out') is not False: problems.append('process timeout or invalid timeout flag')
        if type(usage.get('exit_code')) is not int or usage['exit_code'] < 0:
            problems.append('invalid owned process exit code')
        if type(usage.get('pid')) is not int or usage['pid'] <= 0: problems.append('invalid owned process PID')
        if usage.get('instrument_problem') is not None: problems.append('instrument reports a failure')
        if 'process_cleanup' in usage:
            cleanup = usage['process_cleanup']
            if (type(cleanup) is not dict or cleanup.get('status') != 'PASS'
                    or type(cleanup.get('remaining_active_processes')) is not int
                    or cleanup['remaining_active_processes'] != 0):
                problems.append('owned process cleanup not confirmed')
        if 'capture_complete' in usage and usage['capture_complete'] is not True:
            problems.append('owned process capture incomplete')
    return problems


def measured_child(command, *, cwd, prefix: Path, timeout=120):
    env = {key: os.environ[key] for key in ENVIRONMENT_KEYS if key in os.environ}
    clock = time.perf_counter_ns()
    timed_out = False; process = None; stdout = b''; stderr = b''; elapsed = None
    usage = {'cpu_user_ns': None, 'cpu_system_ns': None, 'peak_rss_bytes': None,
             'cpu_rss_status': 'NOT MEASURED', 'cpu_rss_instrument': 'unavailable'}
    outcome = 'NOT STARTED'; problem = None; job = None; linux = None; job_ready = False
    interrupted = None; interrupted_traceback = None
    cleanup = {'status': 'NOT LAUNCHED'}; capture_complete = True; cleanup_wall_ns = 0
    def stop_owned():
        nonlocal cleanup_wall_ns
        started = time.perf_counter_ns()
        try:
            if job:
                try: result = job.terminate()
                except OSError as error:
                    result = {'status': 'FAIL', 'method': 'Windows owned job object', 'error': type(error).__name__}
                # An interruption can occur after Popen created its suspended
                # root but before assignment. An empty job proves nothing about
                # that root; use its held handle even when job termination passes.
                try:
                    if process.poll() is None: process.kill()
                    process.wait(timeout=5)
                    result.update(owned_root_reaped=True, job_setup_completed=job_ready)
                except (OSError, subprocess.TimeoutExpired) as error:
                    result.update(status='FAIL', owned_root_reaped=False,
                                  held_root_error=type(error).__name__, job_setup_completed=job_ready)
                return result
            if linux:
                # The reaped root cannot produce more descendants. Avoid a
                # per-sample polling delay when no owned child remains.
                if process.poll() is not None and not linux.children():
                    return {'status': 'PASS', 'method': 'Linux owned subreaper children', 'remaining_active_processes': 0}
                return linux.terminate(process.pid)
            return terminate_posix_group(process.pid)
        except OSError as error:
            return {'status': 'FAIL', 'error': type(error).__name__}
        finally: cleanup_wall_ns += time.perf_counter_ns() - started

    def drain(expired=None):
        nonlocal capture_complete, problem
        try: return process.communicate(timeout=5)
        except subprocess.TimeoutExpired as error:
            capture_complete = False; problem = 'bounded capture drain timed out'
            # These are only bytes actually exposed by communicate. Missing
            # bytes remain incomplete; never block again on inherited pipes.
            return error.stdout or (expired.stdout if expired else None) or b'', error.stderr or (expired.stderr if expired else None) or b''
    try: preflight_prefix(prefix)
    except (OSError,ValueError) as error:
        capture_failure(command,cwd,prefix,{'exit_code':None,'pid':None,'wall_ns':None,
            'timed_out':False,'process_outcome':outcome,'instrument_problem':'path preflight: '+type(error).__name__,
            **usage},b'',b'',error)
    try:
        prefix.parent.mkdir(parents=True, exist_ok=True)
        if os.name == 'nt':
            actual_command = command
            job = WindowsJob()
        else:
            time_binary = Path('/usr/bin/time')
            if not time_binary.is_file():
                outcome = 'INSTRUMENT UNAVAILABLE'; raise RuntimeError('GNU time required')
            usage_path = prefix.with_suffix('.usage.json')
            actual_command = [str(time_binary), '-f', '{"user_s":%U,"system_s":%S,"max_rss_kib":%M}', '-o', str(usage_path), '--', *command]
            if sys.platform.startswith('linux'): linux = LinuxOwnedChildren()
        outcome = 'LAUNCH FAILED'
        options = {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP | WindowsJob.CREATE_SUSPENDED} if job else {'start_new_session': True}
        clock = time.perf_counter_ns(); deadline = time.monotonic() + timeout
        process = subprocess.Popen(actual_command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   stdin=subprocess.DEVNULL, **options)
        if job:
            job.assign_and_resume(process)
            job_ready = True
        outcome = 'EXECUTED'
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise subprocess.TimeoutExpired(actual_command, timeout)
            stdout, stderr = process.communicate(timeout=remaining)
        except subprocess.TimeoutExpired as expired:
            timed_out = True; outcome = 'TIMEOUT'
            cleanup = stop_owned()
            if cleanup['status'] != 'PASS' and process.poll() is None: process.kill()
            stdout, stderr = drain(expired)
        elapsed = time.perf_counter_ns() - clock
        if elapsed > timeout * 1e9:
            timed_out = True; outcome = 'TIMEOUT'
        if cleanup['status'] == 'NOT LAUNCHED': cleanup = stop_owned()
        if cleanup['status'] != 'PASS' and outcome == 'EXECUTED': outcome = 'CLEANUP FAILED'
        if not capture_complete: outcome = 'CAPTURE FAILED'
        if os.name == 'nt': usage = windows_usage(process)
        else:
            lines = usage_path.read_text().splitlines() if usage_path.is_file() else []
            parsed = next((json.loads(line) for line in reversed(lines) if line.startswith('{')), None)
            if parsed is None: raise ValueError('GNU time result missing')
            import math
            if any(type(parsed.get(key)) not in (int,float) or not math.isfinite(parsed[key]) or parsed[key] < 0
                   for key in ('user_s','system_s')):
                raise ValueError('GNU time CPU metric is not finite nonnegative numeric data')
            if type(parsed.get('max_rss_kib')) is not int or parsed['max_rss_kib'] <= 0:
                raise ValueError('GNU time RSS metric is not a positive integer')
            usage = {'cpu_user_ns': round(parsed['user_s'] * 1e9), 'cpu_system_ns': round(parsed['system_s'] * 1e9),
                     'peak_rss_bytes': parsed['max_rss_kib'] * 1024, 'cpu_rss_instrument': 'GNU time on owned command; Linux max RSS KiB converted to bytes',
                     'cpu_rss_status': 'MEASURED'}
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
        problem = type(error).__name__
        if process is not None:
            cleanup = stop_owned()
            if cleanup['status'] != 'PASS' and process.poll() is None: process.kill()
            stdout, stderr = drain()
        if outcome == 'EXECUTED': outcome = 'INSTRUMENT FAILED'
    except BaseException as error:
        # Retain the failed attempt before propagating cancellation/SystemExit.
        # This must never return an interrupted attempt as a benchmark sample.
        interrupted = error; interrupted_traceback = error.__traceback__
        problem = type(error).__name__; outcome = 'INTERRUPTED'
        if process is not None:
            cleanup = stop_owned()
            stdout, stderr = drain()
    finally:
        if process is not None and cleanup['status'] != 'PASS':
            # Retry unconfirmed cleanup before closing the ownership scope.
            cleanup = stop_owned()
            if cleanup['status'] != 'PASS' and process.poll() is None: process.kill()
        if linux:
            restored = linux.close()
            if restored['status'] != 'PASS': cleanup.update(status='FAIL', subreaper_attribute_restored=False)
        if job: job.close()
    if elapsed is None: elapsed = time.perf_counter_ns() - clock
    captured = {'exit_code': None if process is None else process.returncode,
            'pid': None if process is None else process.pid, 'wall_ns': elapsed, 'timed_out': timed_out,
            'process_outcome': outcome, 'instrument_problem': problem, 'process_cleanup': cleanup,
            'cleanup_wall_ns': cleanup_wall_ns, 'capture_complete': capture_complete, **usage}
    try:
        try:
            if prefix.with_suffix('.stdout').write_bytes(stdout)!=len(stdout) or prefix.with_suffix('.stderr').write_bytes(stderr)!=len(stderr):
                raise OSError('short process raw write')
            body=json.dumps(captured,separators=(',',':'))
            if prefix.with_suffix('.process.json').write_text(body,encoding='utf-8')!=len(body): raise OSError('short process metadata write')
        except OSError as error:
            captured['child_outcome_before_artifact_failure']=captured['process_outcome']
            captured.update(process_outcome='ARTIFACT WRITE FAILED',instrument_problem='artifact write: '+type(error).__name__)
            capture_failure(command,cwd,prefix,captured,stdout,stderr,error)
        if cleanup['status'] == 'FAIL' or not capture_complete:
            capture_failure(command,cwd,prefix,captured,stdout,stderr,OSError('owned cleanup or capture unconfirmed; campaign stopped'))
    except CaptureArtifactError:
        if interrupted is not None: raise interrupted.with_traceback(interrupted_traceback)
        raise
    if interrupted is not None: raise interrupted.with_traceback(interrupted_traceback)
    return captured, stdout, stderr
