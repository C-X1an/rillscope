"""Measure only an owned child process; CPU/RSS boundaries cover its entire lifetime."""
import ctypes
import json
import os
from pathlib import Path
import subprocess
import time

ENVIRONMENT_KEYS = ('SYSTEMROOT', 'SystemRoot', 'WINDIR', 'TEMP', 'TMP',
                    'SystemDrive', 'SYSTEMDRIVE', 'ProgramData', 'PROGRAMDATA')

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
    return problems


def measured_child(command, *, cwd, prefix: Path, timeout=120):
    env = {key: os.environ[key] for key in ENVIRONMENT_KEYS if key in os.environ}
    clock = time.perf_counter_ns()
    timed_out = False; process = None; stdout = b''; stderr = b''; elapsed = None
    usage = {'cpu_user_ns': None, 'cpu_system_ns': None, 'peak_rss_bytes': None,
             'cpu_rss_status': 'NOT MEASURED', 'cpu_rss_instrument': 'unavailable'}
    outcome = 'NOT STARTED'; problem = None
    try:
        prefix.parent.mkdir(parents=True, exist_ok=True)
        clock = time.perf_counter_ns()
        if os.name == 'nt':
            actual_command = command
        else:
            time_binary = Path('/usr/bin/time')
            if not time_binary.is_file():
                outcome = 'INSTRUMENT UNAVAILABLE'; raise RuntimeError('GNU time required')
            usage_path = prefix.with_suffix('.usage.json')
            actual_command = [str(time_binary), '-f', '{"user_s":%U,"system_s":%S,"max_rss_kib":%M}', '-o', str(usage_path), '--', *command]
        outcome = 'LAUNCH FAILED'
        process = subprocess.Popen(actual_command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=os.name != 'nt')
        outcome = 'EXECUTED'
        try: stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True; outcome = 'TIMEOUT'
            if os.name == 'nt': process.kill()
            else:
                import signal
                os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
        elapsed = time.perf_counter_ns() - clock
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
        if process is not None and process.poll() is None:
            process.kill(); stdout, stderr = process.communicate()
        if outcome == 'EXECUTED': outcome = 'INSTRUMENT FAILED'
    if elapsed is None: elapsed = time.perf_counter_ns() - clock
    try:
        prefix.with_suffix('.stdout').write_bytes(stdout)
        prefix.with_suffix('.stderr').write_bytes(stderr)
    except OSError as error:
        problem = 'artifact write: ' + type(error).__name__; outcome = 'ARTIFACT WRITE FAILED'
    captured = {'exit_code': None if process is None else process.returncode,
            'pid': None if process is None else process.pid, 'wall_ns': elapsed, 'timed_out': timed_out,
            'process_outcome': outcome, 'instrument_problem': problem, **usage}
    prefix.with_suffix('.process.json').write_text(json.dumps(captured, separators=(',', ':')), encoding='utf-8')
    return captured, stdout, stderr
