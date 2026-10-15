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

def measured_child(command, *, cwd, prefix: Path, timeout=120):
    env = {key: os.environ[key] for key in ENVIRONMENT_KEYS if key in os.environ}
    prefix.parent.mkdir(parents=True, exist_ok=True)
    clock = time.perf_counter_ns()
    timed_out = False
    if os.name == 'nt':
        process = subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try: stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True; process.kill(); stdout, stderr = process.communicate()
        elapsed = time.perf_counter_ns() - clock
        usage = windows_usage(process)
        code, pid = process.returncode, process.pid
    else:
        time_binary = Path('/usr/bin/time')
        if not time_binary.is_file(): raise RuntimeError('required external GNU time CPU/RSS instrument unavailable')
        usage_path = prefix.with_suffix('.usage.json')
        wrapped = [str(time_binary), '-f', '{"user_s":%U,"system_s":%S,"max_rss_kib":%M}', '-o', str(usage_path), '--', *command]
        process = subprocess.Popen(wrapped, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try: stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            import signal
            timed_out = True; os.killpg(process.pid, signal.SIGKILL); stdout, stderr = process.communicate()
        elapsed = time.perf_counter_ns() - clock
        lines = usage_path.read_text().splitlines() if usage_path.is_file() else []
        parsed = next((json.loads(line) for line in reversed(lines) if line.startswith('{')), None)
        usage = {'cpu_user_ns': None if parsed is None else round(parsed['user_s'] * 1e9),
                 'cpu_system_ns': None if parsed is None else round(parsed['system_s'] * 1e9),
                 'peak_rss_bytes': None if parsed is None else parsed['max_rss_kib'] * 1024,
                 'cpu_rss_instrument': 'GNU time on owned command; Linux max RSS converted KiB to bytes',
                 'cpu_rss_status': 'MEASURED' if parsed is not None else 'NOT MEASURED'}
        code, pid = process.returncode, process.pid
    prefix.with_suffix('.stdout').write_bytes(stdout)
    prefix.with_suffix('.stderr').write_bytes(stderr)
    return {'exit_code': code, 'pid': pid, 'wall_ns': elapsed, 'timed_out': timed_out, **usage}, stdout, stderr
