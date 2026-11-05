"""Establish process ownership before captured commands can create descendants."""
import ctypes
from ctypes import wintypes
import time
import os
from pathlib import Path
import signal


class LinuxOwnedChildren:
    """Adopt session-changing descendants in an isolated single-command runner.

    PR_SET_CHILD_SUBREAPER changes this calling process only, without privileges:
    https://man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html
    pidfds signal only currently owned children. This is lifetime management,
    not an adversarial process sandbox or a change to system security policy.
    """
    def __init__(self):
        self.active = False
        if not hasattr(os,'pidfd_open') or not hasattr(signal,'pidfd_send_signal'):
            raise OSError('Linux pidfd ownership unavailable')
        if self.children(): raise OSError('owned command runner must start without other children')
        self.libc = ctypes.CDLL(None,use_errno=True)
        self.libc.prctl.restype = ctypes.c_int
        previous = ctypes.c_int()
        self.control(37,ctypes.byref(previous))  # PR_GET_CHILD_SUBREAPER
        self.previous = previous.value
        self.control(36,ctypes.c_ulong(1))  # PR_SET_CHILD_SUBREAPER
        self.active = True

    def control(self,option,value):
        if self.libc.prctl(ctypes.c_int(option),value,ctypes.c_ulong(0),ctypes.c_ulong(0),ctypes.c_ulong(0)) != 0:
            raise OSError(ctypes.get_errno(),'owned child subreaper operation failed')

    @staticmethod
    def children():
        result = set()
        # Include children of any thread; refuse a shared runner at entry.
        for thread in (Path('/proc') / str(os.getpid()) / 'task').iterdir():
            try: result.update(int(value) for value in (thread / 'children').read_text().split())
            except (FileNotFoundError,ProcessLookupError): continue
        return result

    def terminate(self,root_pid):
        record = {'status':'PASS','method':'Linux owned subreaper children with pidfd SIGKILL',
                  'owned_root_pid':root_pid,'signalled_children':0,'reaped_descendants':0}
        deadline = time.monotonic()+5; quiet = 0
        try:
            while time.monotonic() < deadline:
                active = 0
                for pid in self.children():
                    handle = None
                    try:
                        handle = os.pidfd_open(pid,0)
                        fields = (Path('/proc') / str(pid) / 'stat').read_text().rsplit(')',1)[1].split()
                        if int(fields[1]) != os.getpid():
                            raise OSError('child ownership changed before termination')
                        if fields[0] not in ('Z','X'):
                            active += 1
                            signal.pidfd_send_signal(handle,signal.SIGKILL,None,0)
                            record['signalled_children'] += 1
                        if pid != root_pid:
                            reaped,_ = os.waitpid(pid,os.WNOHANG)
                            record['reaped_descendants'] += int(reaped != 0)
                    except (FileNotFoundError,ProcessLookupError): pass
                    finally:
                        if handle is not None: os.close(handle)
                # Reparenting is observed after killing intermediates. The root
                # remains for Popen to reap, preserving its actual exit status.
                quiet = quiet+1 if active == 0 else 0
                if quiet >= 2:
                    return dict(record,remaining_active_processes=0)
                time.sleep(.01)
        except (OSError,ValueError,IndexError) as error:
            return dict(record,status='FAIL',error=type(error).__name__)
        return dict(record,status='FAIL',error='owned children remained active after termination')

    def close(self):
        if not self.active: return {'status':'PASS','subreaper_attribute_restored':True}
        try:
            self.control(36,ctypes.c_ulong(self.previous))
            self.active = False
            return {'status':'PASS','subreaper_attribute_restored':True}
        except OSError as error:
            return {'status':'FAIL','subreaper_attribute_restored':False,'restore_error':type(error).__name__}

    def finish(self,root_pid):
        record = self.terminate(root_pid)
        restored = self.close()
        if restored['status'] != 'PASS': record['status'] = 'FAIL'
        record.update({key:value for key,value in restored.items() if key != 'status'})
        return record


def terminate_posix_group(pid):
    """Stop the session/group created for this command, including after root exit."""
    record = {'status':'PASS','method':'SIGKILL owned process group','owned_root_pid':pid}
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        return dict(record, remaining_active_processes=0)
    except OSError as error:
        return dict(record, status='FAIL', error=type(error).__name__)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if Path('/proc').is_dir():
            active = 0
            try:
                for path in Path('/proc').iterdir():
                    if not path.name.isdecimal(): continue
                    try:
                        fields = (path / 'stat').read_text().rsplit(')',1)[1].split()
                    except (FileNotFoundError,ProcessLookupError): continue
                    # Only the newly owned session/group can count. Zombies
                    # cannot execute or modify later gate inputs.
                    if int(fields[2]) == pid and int(fields[3]) == pid and fields[0] not in ('Z','X'):
                        active += 1
            except (OSError,ValueError,IndexError) as error:
                return dict(record, status='FAIL', error=type(error).__name__)
            if active == 0: return dict(record, remaining_active_processes=0)
        else:
            try: os.killpg(pid, 0)
            except ProcessLookupError: return dict(record, remaining_active_processes=0)
            except OSError as error: return dict(record, status='FAIL', error=type(error).__name__)
        time.sleep(.01)
    return dict(record,status='FAIL',error='owned process group remained active after termination')


class WindowsJob:
    CREATE_SUSPENDED = 0x00000004

    def __init__(self):
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        signatures = {
            'CreateJobObjectW': ([ctypes.c_void_p, wintypes.LPCWSTR], wintypes.HANDLE),
            'SetInformationJobObject': ([wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD], wintypes.BOOL),
            'AssignProcessToJobObject': ([wintypes.HANDLE, wintypes.HANDLE], wintypes.BOOL),
            'TerminateJobObject': ([wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
            'QueryInformationJobObject': ([wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p], wintypes.BOOL),
            'CreateToolhelp32Snapshot': ([wintypes.DWORD, wintypes.DWORD], wintypes.HANDLE),
            'Thread32First': ([wintypes.HANDLE, ctypes.c_void_p], wintypes.BOOL),
            'Thread32Next': ([wintypes.HANDLE, ctypes.c_void_p], wintypes.BOOL),
            'OpenThread': ([wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
            'ResumeThread': ([wintypes.HANDLE], wintypes.DWORD),
            'CloseHandle': ([wintypes.HANDLE], wintypes.BOOL),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.kernel, name); function.argtypes = arguments; function.restype = result
        class BasicLimits(ctypes.Structure):
            _fields_ = [('process_time',ctypes.c_int64),('job_time',ctypes.c_int64),('flags',wintypes.DWORD),
                        ('minimum_working_set',ctypes.c_size_t),('maximum_working_set',ctypes.c_size_t),
                        ('process_limit',wintypes.DWORD),('affinity',ctypes.c_size_t),
                        ('priority',wintypes.DWORD),('scheduling',wintypes.DWORD)]
        class IoCounters(ctypes.Structure):
            _fields_ = [(name,ctypes.c_uint64) for name in ('reads','writes','other','read_bytes','write_bytes','other_bytes')]
        class ExtendedLimits(ctypes.Structure):
            _fields_ = [('basic',BasicLimits),('io',IoCounters),('process_memory',ctypes.c_size_t),
                        ('job_memory',ctypes.c_size_t),('peak_process_memory',ctypes.c_size_t),('peak_job_memory',ctypes.c_size_t)]
        self.handle = self.kernel.CreateJobObjectW(None, None)
        if not self.handle: raise ctypes.WinError(ctypes.get_last_error())
        limits = ExtendedLimits(); limits.basic.flags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            error = ctypes.WinError(ctypes.get_last_error()); self.close(); raise error

    def assign_and_resume(self, process):
        if not self.kernel.AssignProcessToJobObject(self.handle, wintypes.HANDLE(int(process._handle))):
            raise ctypes.WinError(ctypes.get_last_error())
        class ThreadEntry(ctypes.Structure):
            _fields_ = [('size',wintypes.DWORD),('usage',wintypes.DWORD),('thread_id',wintypes.DWORD),
                        ('process_id',wintypes.DWORD),('priority',wintypes.LONG),('delta',wintypes.LONG),('flags',wintypes.DWORD)]
        snapshot = self.kernel.CreateToolhelp32Snapshot(4, 0)  # TH32CS_SNAPTHREAD
        if snapshot == ctypes.c_void_p(-1).value: raise ctypes.WinError(ctypes.get_last_error())
        owned = []
        try:
            entry = ThreadEntry(); entry.size = ctypes.sizeof(entry)
            exists = self.kernel.Thread32First(snapshot, ctypes.byref(entry))
            while exists:
                if entry.process_id == process.pid: owned.append(entry.thread_id)
                exists = self.kernel.Thread32Next(snapshot, ctypes.byref(entry))
        finally: self.kernel.CloseHandle(snapshot)
        if len(owned) != 1: raise OSError('suspended owned command did not have exactly one initial thread')
        thread = self.kernel.OpenThread(0x0002, False, owned[0])  # THREAD_SUSPEND_RESUME, owned PID only
        if not thread: raise ctypes.WinError(ctypes.get_last_error())
        try:
            previous = self.kernel.ResumeThread(thread)
            if previous != 1: raise OSError('owned initial thread suspension state differed')
        finally: self.kernel.CloseHandle(thread)

    def terminate(self):
        class Accounting(ctypes.Structure):
            _fields_ = [(name,ctypes.c_int64) for name in ('user','kernel','period_user','period_kernel')] + [
                (name,wintypes.DWORD) for name in ('faults','total_processes','active_processes','terminated_processes')]
        if not self.kernel.TerminateJobObject(self.handle, 124):
            return {'status':'FAIL','method':'Windows owned job object','error':'TerminateJobObject failed'}
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            accounting = Accounting()
            if not self.kernel.QueryInformationJobObject(self.handle, 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None):
                break
            if accounting.active_processes == 0:
                return {'status':'PASS','method':'Windows owned job object','remaining_active_processes':0}
            time.sleep(.01)
        return {'status':'FAIL','method':'Windows owned job object','error':'owned job cleanup not confirmed'}

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle); self.handle = None
