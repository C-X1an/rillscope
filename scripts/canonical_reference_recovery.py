"""Recover fixed metadata from the actual stopped owned canonical work disk.

This component retains included bytes. It does not replace the original host CAS
frames, recover native executables, validate every benchmark record or qualify a
canonical campaign. Missing/failed trees remain failed and every prefix is kept.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

import archive_capture
import canonical_reference_allocation as allocation
from canonical_reference_host_setup import actual_controller
from canonical_reference_reservation import fsync_directory
from kvm_benchmark_pilot import debugfs_command, disk_identity
from kvm_pilot_common import write_json
from inspect_reference_guest import TrialInterrupted

ROOT = Path(__file__).resolve().parents[1]
MAX_RECOVERED_BYTES = 16 * 1024**3
MAX_RECOVERED_FILES = 200000
TREES = {
    'boot': ('/c/.local-runs/canonical-boot', 'boot-result.json'),
    'setup': ('/c/.local-runs/canonical-setup', 'setup-result.json'),
    'start': ('/c/.local-runs/canonical-start', 'start-result.json'),
    'allocation': ('/c/.local-runs/canonical-allocation', 'reference-host-receipt.json'),
    'owner': ('/c/.local-runs/canonical-attempt', 'owner-result.json'),
    'control': ('/c/.local-runs/kvm-reference/control', 'grid-request.json'),
    'observer': ('/c/.local-runs/kvm-reference/exports', 'canonical-guest-samples.jsonl')}


def layout(mode):
    allocation.require(type(mode) is str and mode in ('canonical', 'native-setup-diagnostic'),
        'closed original new-method recovery mode required')
    names = ('boot', 'setup', 'start') if mode == 'native-setup-diagnostic' else tuple(TREES)
    return [(name, *TREES[name]) for name in names]


def stopped(process, command, channel, cleanup):
    """Require real original process state; a success-shaped dict alone fails."""
    allocation.require(type(cleanup) is dict and cleanup.get('status') == 'PASS'
        and type(cleanup.get('remaining_active_processes')) is int
        and cleanup['remaining_active_processes'] == 0, 'actual complete owned-process cleanup required before recovery')
    allocation.require(type(process) is subprocess.Popen and process.poll() is not None
        and type(command) is list and len(command) > 1 and process.args == command
        and type(command[0]) is str and Path(command[0]).name == 'qemu-system-x86_64',
        'actual stopped original owned QEMU process and command required')
    if channel is not None:
        allocation.require(not channel.thread.is_alive() and channel.done.is_set()
            and (channel.receiver_process is None or channel.receiver_process.poll() is not None),
            'original allocator thread or receiver is still active')
    return {'pid': process.pid, 'observed_returncode_after_owned_stop': process.returncode,
        'command_sha256': hashlib.sha256(json.dumps(command, separators=(',', ':')).encode()).hexdigest(),
        'scope': 'Stopped identity only; post-subreaper returncode never proves an independently observed successful VM exit.'}


def recover(out, *, process, command, channel, cleanup, mode, deadline, checked):
    actual_controller()
    tree_plan = layout(mode)
    stop = stopped(process, command, channel, cleanup)
    allocation.require(type(deadline) in (int, float) and 0 < deadline - time.monotonic() <= 1800,
        'explicit finite original stopped-recovery cutoff required')
    out = archive_capture.owned(out)
    image = out / 'work.raw'; artifact = out / 'artifact'
    allocation.require(image.is_file() and not image.is_symlink() and artifact.is_dir(),
        'actual owned stopped work disk and existing VM artifact root required')
    destination = artifact / 'recovery'; destination.mkdir(mode=0o700, exist_ok=False)
    fsync_directory(artifact)
    record = {'schema_version': 1, 'method': allocation.METHOD, 'status': 'FAIL', 'mode': mode,
        'read_only': True, 'disk_unchanged': None, 'stopped_original': stop, 'trees': [],
        'errors': [], 'files': 0, 'bytes': 0, 'reference_qualified': False,
        'native_executables': 'NOT RECOVERED BY THIS COMPONENT', 'all_record_validation': 'NOT RUN',
        'scope': 'Fixed original stopped-disk metadata and retained CAS bytes only; no mount, repair, journal replay, raw query rerun or qualification.'}
    def persist():
        write_json(destination / 'recovery-result.json', record); fsync_directory(destination)
    def remaining():
        value = deadline - time.monotonic()
        allocation.require(value > 0, 'original stopped-recovery budget exhausted')
        return value
    def attempt(name, action):
        try: return action()
        except TrialInterrupted: raise
        except Exception as error:
            record['errors'].append({'name': name, 'error': type(error).__name__, 'reason': str(error)[:2048]})
            persist(); return None
    def run(name, command):
        return checked('canonical-recover-' + name, command, timeout=min(120, remaining()))
    persist()
    try:
        record['disk_before'] = attempt('disk-before', lambda: disk_identity(image, deadline))
        def filesystem():
            raw = run('filesystem-state', ['dumpe2fs', '-h', str(image)])
            allocation.require(type(raw) is bytes and len(raw) <= 65536, 'bounded original filesystem state required')
            (destination / 'filesystem-state.txt').write_bytes(raw)
            return re.search(r'(?m)^Filesystem state:\s+clean\s*$', raw.decode('utf-8')) is not None
        record['filesystem_clean'] = attempt('filesystem-state', filesystem)
        for name, guest_path, required in tree_plan:
            row = {'name': name, 'guest_path': guest_path, 'status': 'FAIL'}
            record['trees'].append(row); persist()
            def tree():
                target = destination / name; target.mkdir(mode=0o700, exist_ok=False)
                run(name, debugfs_command(image, guest_path, target, directory=True))
                nested = target / Path(guest_path).name
                if nested.is_dir():
                    allocation.require(list(target.iterdir()) == [nested], 'ambiguous recovered metadata directory')
                    target = nested
                allocation.require((target / required).is_file(), 'original required guest metadata missing: ' + required)
                entries = archive_capture.scan(target)
                inventory = destination / (name + '-files.jsonl')
                count = size = 0
                with inventory.open('xb') as stream:
                    for relative, before in sorted(entries.items()):
                        remaining(); path = target / relative; value = hashlib.sha256(); total = 0
                        with path.open('rb') as source:
                            while block := source.read(1024**2):
                                remaining(); total += len(block)
                                allocation.require(total <= before[2], 'recovered original file grew while hashing')
                                value.update(block)
                        after = path.stat()
                        allocation.require(total == before[2] and before ==
                            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
                            'recovered original file changed while hashing')
                        size += total; count += 1
                        allocation.require(record['files'] + count <= MAX_RECOVERED_FILES
                            and record['bytes'] + size <= MAX_RECOVERED_BYTES,
                            'aggregate stopped recovery file/byte bound exceeded')
                        raw = json.dumps({'path': relative, 'bytes': total, 'sha256': value.hexdigest()},
                            sort_keys=True, separators=(',', ':')).encode('utf-8') + b'\n'
                        allocation.require(stream.write(raw) == len(raw), 'recovered inventory write incomplete')
                    stream.flush(); os.fsync(stream.fileno())
                allocation.require(archive_capture.scan(target) == entries, 'recovered metadata tree changed during inventory')
                row.update(status='RECOVERED INCLUDED BYTES', host_path=target.relative_to(artifact).as_posix(),
                    files=count, bytes=size, inventory=inventory.relative_to(artifact).as_posix(),
                    inventory_sha256=hashlib.sha256(inventory.read_bytes()).hexdigest())
                record['files'] += count; record['bytes'] += size
                fsync_directory(target); fsync_directory(destination)
            attempt(name, tree); persist()
    except TrialInterrupted as error:
        record['errors'].append({'name': 'interrupted', 'error': type(error).__name__, 'reason': str(error)[:2048]})
        raise
    finally:
        # Hash the exact same stopped input even after missing/failed trees.
        # Failure/expiry remains unknown or changed; never repair/relocate it.
        record['disk_after'] = attempt('disk-after', lambda: disk_identity(image, deadline))
        before, after = record.get('disk_before'), record.get('disk_after')
        if before is not None and after is not None: record['disk_unchanged'] = before == after
        if (record['disk_unchanged'] is True and record.get('filesystem_clean') is True
            and not record['errors'] and len(record['trees']) == len(tree_plan)
            and all(row['status'] == 'RECOVERED INCLUDED BYTES' for row in record['trees'])):
            record['status'] = 'RECOVERED INCLUDED BYTES'
        record['finished_monotonic_ns'] = time.monotonic_ns(); persist()
    return record
