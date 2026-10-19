"""Own an unqualified KVM feasibility trial and recover its exact disk bytes.

Public source and build proofs only. Existing root owns lifecycle; QEMU drops
to the selected existing non-root identity. No management ports, shared host
directories, SSH keys, billing, account creation or host policy changes.
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
import zipfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts')); sys.path.insert(0, str(ROOT / 'benchmarks'))
from kvm_pilot_common import (STAGES, TOTAL_SECONDS, VM_SECONDS, SETUP_SECONDS,
    RECOVERY_SECONDS, CLEANUP_SECONDS, RESERVE_SECONDS, HOST_PREP_SECONDS,
    MAX_LOG, require, sha, read_json, write_json, append_json, payload_files, parse_events)
from inspect_reference_guest import (IMAGE_BASE, IMAGE, IMAGE_SHA, IMAGE_LIMIT,
    FINGERPRINT, SERIAL_LIMIT, TrialCommands, BoundedCapture, TrialInterrupted,
    interrupted, download, bounded_bytes, host_snapshot)
from evidence import source_identity
from owned_process import LinuxOwnedChildren
from build import verify_build
from run import environment
import archive_capture
from kvm_capture_channel import PORT_NAME, fsync_directory
from kvm_boot_recovery import recover_boot_logs

DISK_BYTES = 16 * 1024**3
BOOT_PREFIX = 'RILLSCOPE_PILOT_BOOT_V1 '
BOOTSTRAP = r'''import base64,json,os,pathlib,subprocess,time
record={'worker_exit':None,'unmount_status':'NOT MOUNTED','reference_qualified':False}
mounted=False
def stage(name):
    print('RILLSCOPE_PILOT_BOOT_STAGE_V1 '+json.dumps({'stage':name,'utc_ns':time.time_ns(),
        'monotonic_ns':time.monotonic_ns(),'reference_qualified':False},separators=(',',':')),flush=True)
stage('bootstrap-enter')
try:
    pathlib.Path('/work').mkdir(exist_ok=False)
    stage('work-mount-start')
    subprocess.run(['/usr/bin/mount','-t','ext4','/dev/disk/by-id/virtio-rillwork','/work'],check=True,timeout=30)
    mounted=True
    stage('work-mount-complete')
    pathlib.Path('/run/rillscope-owned-pilot').write_text('owned-ephemeral-kvm-pilot\n')
    stage('worker-start')
    result=subprocess.run(['/usr/bin/env','PYTHONDONTWRITEBYTECODE=1','GIT_OPTIONAL_LOCKS=0',
        '/usr/bin/python3','/work/c/scripts/kvm_pilot_guest.py'],stdin=subprocess.DEVNULL)
    record['worker_exit']=result.returncode
    stage('worker-return')
except BaseException as error:
    record.update(error=type(error).__name__,reason=str(error)[:1024])
finally:
    if mounted:
        os.sync()
        try:
            stage('work-unmount-start')
            subprocess.run(['/usr/bin/umount','/work'],check=True,timeout=30,capture_output=True)
            record['unmount_status']='PASS'
            stage('work-unmount-complete')
        except BaseException as error:
            record.update(unmount_status='FAIL',unmount_error=type(error).__name__)
    record.update(utc_ns=time.time_ns(),monotonic_ns=time.monotonic_ns())
    data=json.dumps(record,separators=(',',':')).encode()
    print('RILLSCOPE_PILOT_BOOT_V1 '+base64.b64encode(data).decode('ascii'),flush=True)
    stage('shutdown-start')
    subprocess.run(['/usr/sbin/shutdown','-h','now'],check=False,timeout=15)
'''


def git(root, *arguments):
    return subprocess.check_output(['git', '--no-optional-locks', '-c',
        'safe.directory=' + str(root), *arguments], cwd=root, timeout=30, stdin=subprocess.DEVNULL)


def qmp(port, command, arguments=None, *, output=None, deadline=None):
    require(type(port) is int and 0 < port < 65536, 'owned local QMP port required')
    require(command in ('set_link', 'system_powerdown', 'query-balloon', 'query-version',
                       'query-status', 'query-block', 'info-qtree', 'info-registers', 'screendump'),
            'closed pilot QMP command required')
    if command == 'set_link':
        require(arguments == {'name': 'pilot-nic', 'up': False}, 'only owned NIC link-down is permitted')
    else: require(arguments is None, 'unexpected QMP arguments')
    request = {'execute': command}
    if command in ('info-qtree', 'info-registers'):
        request = {'execute': 'human-monitor-command', 'arguments': {
            'command-line': 'info qtree' if command == 'info-qtree' else 'info registers'}}
    elif command == 'screendump':
        require(output is not None, 'owned screenshot output required')
        destination = owned_output(output) / 'runtime/boot.ppm'
        require(not destination.exists() and not destination.is_symlink(), 'preserve earlier framebuffer bytes')
        request['arguments'] = {'filename': str(destination)}
    elif arguments is not None: request['arguments'] = arguments
    deadline = min(time.monotonic() + 6, deadline) if deadline is not None else time.monotonic() + 6
    with socket.create_connection(('127.0.0.1', port), timeout=2) as connection:
        handle = connection.makefile('rwb')
        def reply():
            for _ in range(50):
                remaining = deadline - time.monotonic()
                require(remaining > 0, 'QMP diagnostic/response deadline exhausted')
                connection.settimeout(min(2, remaining))
                line = handle.readline(1024**2 + 1)
                require(line and len(line) <= 1024**2, 'invalid bounded QMP framing')
                value = json.loads(line)
                require(type(value) is dict, 'QMP response must be an object')
                if 'event' not in value: return value
            raise ValueError('QMP event bound exceeded')
        require('QMP' in reply(), 'QMP greeting missing')
        handle.write(b'{"execute":"qmp_capabilities"}\n'); handle.flush()
        require('return' in reply(), 'QMP capabilities failed')
        handle.write(json.dumps(request).encode() + b'\n'); handle.flush()
        return reply()


def collect_boot_diagnostics(out, port):
    """Read the still-owned VM before shutdown; each failed diagnostic is retained."""
    destination = out / 'artifact/boot-diagnostics'; destination.mkdir(exist_ok=False)
    deadline = time.monotonic() + 30
    report = {'status': 'PARTIAL', 'reference_qualified': False, 'observations': [],
              'scope': 'actual pre-stop firmware/device diagnostics; no boot or benchmark success inferred'}
    for command in ('query-status', 'query-block', 'info-qtree', 'info-registers', 'screendump'):
        row = {'command': command, 'status': 'FAIL', 'utc_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns()}
        try:
            require(time.monotonic() < deadline, 'pre-stop diagnostic budget exhausted')
            row['reply'] = qmp(port, command, output=out if command == 'screendump' else None, deadline=deadline)
            require('return' in row['reply'], 'QMP diagnostic returned an error')
            if command == 'screendump':
                data = bounded_bytes(out / 'runtime/boot.ppm', 16 * 1024**2)
                header = re.match(rb'P6\s+(\d{1,5})\s+(\d{1,5})\s+255\s', data[:128])
                require(header is not None, 'unsupported framebuffer header')
                width, height = int(header[1]), int(header[2])
                require(0 < width <= 4096 and 0 < height <= 4096
                        and len(data) == header.end() + width * height * 3, 'framebuffer dimensions or size differ')
                path = destination / 'framebuffer.ppm'
                with path.open('xb') as stream: require(stream.write(data) == len(data), 'framebuffer write incomplete')
                row['framebuffer'] = {'file': path.name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                                      'width': width, 'height': height}
            row['status'] = 'PASS'
        except Exception as error:
            row.update(error=type(error).__name__, reason=str(error)[:1024])
        report['observations'].append(row)
        write_json(destination / 'results.json', report)
    if all(row['status'] == 'PASS' for row in report['observations']): report['status'] = 'COLLECTED'
    write_json(destination / 'results.json', report)
    return report


def download_bounded(url, path, limit, deadline):
    remaining = deadline - time.monotonic()
    require(remaining > 0, 'host preparation download deadline exhausted')
    request = urllib.request.Request(url, headers={'User-Agent': 'RillScope-signed-pilot'})
    size = 0
    with urllib.request.urlopen(request, timeout=min(30, remaining)) as response, path.open('xb') as stream:
        require(response.url.startswith('https://'), 'HTTPS image/key transport required')
        while block := response.read(1024 * 1024):
            require(time.monotonic() < deadline, 'download exceeded host preparation deadline')
            size += len(block); require(size <= limit, 'download exceeds explicit byte bound')
            require(stream.write(block) == len(block), 'download write incomplete')


def signed_image(out, checked, deadline):
    (out / 'gnupg').mkdir(mode=0o700)
    key = out / 'ubuntu-cloud-image.asc'; keyring = out / 'image-key.gpg'
    download_bounded('https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x' + FINGERPRINT, key, 256 * 1024, deadline)
    listed = checked('key-fingerprint', ['gpg', '--no-options', '--homedir', str(out / 'gnupg'),
        '--batch', '--no-tty', '--with-colons', '--show-keys', str(key)], inputs=(key,)).decode()
    require(sum(line.startswith('pub:') for line in listed.splitlines()) == 1, 'one pinned signing key required')
    require(next(line.split(':')[9] for line in listed.splitlines() if line.startswith('fpr:')) == FINGERPRINT,
            'pinned public signing fingerprint differs')
    checked('key-dearmor', ['gpg', '--no-options', '--homedir', str(out / 'gnupg'), '--batch', '--no-tty',
        '--output', str(keyring), '--dearmor', str(key)], inputs=(key,))
    for name in ('SHA256SUMS', 'SHA256SUMS.gpg'): download_bounded(IMAGE_BASE + name, out / name, 65536, deadline)
    signed = checked('image-signature', ['gpgv', '--homedir', str(out / 'gnupg'), '--keyring', str(keyring),
        '--status-fd', '1', str(out / 'SHA256SUMS.gpg'), str(out / 'SHA256SUMS')],
        inputs=(keyring, out / 'SHA256SUMS', out / 'SHA256SUMS.gpg')).decode()
    valid = [line.split() for line in signed.splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
    require(any(row[2] == FINGERPRINT or row[-1] == FINGERPRINT for row in valid), 'signature primary identity differs')
    expected = [line.split()[0] for line in (out / 'SHA256SUMS').read_text().splitlines()
                if len(line.split()) == 2 and line.split()[1].lstrip('*') == IMAGE]
    require(expected == [IMAGE_SHA], 'signed pinned image checksum differs')
    image = out / IMAGE; download_bounded(IMAGE_BASE + IMAGE, image, IMAGE_LIMIT, deadline)
    require(sha(image, IMAGE_LIMIT) == IMAGE_SHA, 'complete pinned image digest differs')
    return image


def prepare_payload(out, build_path, commit, checked):
    source = source_identity(ROOT)
    require(git(ROOT, 'rev-parse', 'HEAD').decode().strip() == commit
            and not git(ROOT, 'status', '--porcelain').strip(), 'exact clean public commit required')
    build = read_json(build_path)
    for name, item in build['bins'].items(): verify_build(build_path, ROOT / item['path'], name=name)
    stage = out / 'stage'; stage.mkdir()
    clone = stage / 'c'
    checked('public-clone', ['git', '-c', 'safe.directory=' + str(ROOT), 'clone', '--no-local',
        '--config', 'core.autocrlf=false', str(ROOT), str(clone)], timeout=120)
    git(clone, 'remote', 'set-url', 'origin', 'https://github.com/C-X1an/rillscope.git')
    local = git(clone, 'config', '--local', '--list').decode()
    forbidden = ('credential', 'extraheader', 'include', 'sshcommand', 'hookspath', 'fsmonitor')
    require(all(not any(word in line.split('=', 1)[0].casefold() for word in forbidden)
                for line in local.splitlines()), 'transferred Git configuration contains sensitive execution/header material')
    require(git(clone, 'rev-parse', 'HEAD').decode().strip() == commit
            and source_identity(clone) == source, 'transferred checkout differs')
    relative_build = build_path.relative_to(ROOT)
    for name in ('build.json', 'cargo.stdout', 'cargo.stderr', 'compiler.stdout', 'compiler.stderr'):
        destination = clone / relative_build.parent / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(build_path.parent / name, destination)
    for item in build['bins'].values():
        destination = clone / item['path']; destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / item['path'], destination)
        require(os.access(destination, os.X_OK) and sha(destination) == item['sha256'], 'executable copy or mode differs')
    for name, item in build['bins'].items():
        verify_build(clone / relative_build, clone / item['path'], name=name, root=clone)
    payload = {'schema_version': 1, 'mode': 'unqualified-kvm-feasibility-pilot', 'commit': commit,
        'source': source, 'bins': build['bins'], 'build_receipt': {'path': relative_build.as_posix(), 'sha256': sha(build_path)},
        'host_build_environment': environment(), 'stage_budgets': STAGES, 'reference_qualified': False}
    payload['files'] = payload_files(clone)
    write_json(clone / '.local-runs/kvm-input/payload.json', payload)
    write_json(out / 'payload.json', payload)
    return stage, payload


def debugfs_command(image, source, destination, *, directory=False):
    require(re.fullmatch(r'/[A-Za-z0-9_./-]+', source) is not None and '..' not in Path(source).parts,
            'closed guest recovery path required')
    require(re.fullmatch(r'/[A-Za-z0-9_./-]+', str(destination)) is not None,
            'closed owned native recovery path required')
    operation = 'rdump' if directory else 'dump -p'
    return ['debugfs', '-R', operation + ' ' + source + ' ' + str(destination), str(image)]


def parse_boot(serial):
    rows = []
    for line in serial.splitlines():
        if BOOT_PREFIX not in line: continue
        value = line.split(BOOT_PREFIX, 1)[1].strip()
        require(len(value) <= 4096, 'boot result exceeds bound')
        row = json.loads(base64.b64decode(value, validate=True))
        require(isinstance(row, dict) and row.get('reference_qualified') is False, 'invalid boot result')
        rows.append(row)
    require(len(rows) <= 1, 'duplicate boot result')
    return rows[0] if rows else None


def disk_identity(path, deadline):
    require(path.stat().st_size == DISK_BYTES, 'owned work disk size changed')
    digest = hashlib.sha256(); size = 0
    with path.open('rb') as stream:
        while block := stream.read(4 * 1024**2):
            require(time.monotonic() < deadline, 'work-disk hashing exceeded recovery budget')
            size += len(block); require(size <= DISK_BYTES, 'work disk exceeds declared size')
            digest.update(block)
    return {'bytes': size, 'sha256': digest.hexdigest()}


def recover(out, checked, deadline, *, artifact=None):
    """Read the stopped guest disk; never mount, repair, replay or write it."""
    image = out / 'work.raw'; artifact = artifact if artifact is not None else out / 'artifact'
    artifact.mkdir(exist_ok=True)
    record = {'status': 'FAIL', 'read_only': True, 'disk_preserved': True, 'files': [], 'packages': [], 'errors': []}
    def persist():
        try: write_json(artifact / 'recovery.json', record)
        except Exception as error:
            record['status'] = 'FAIL'
            record['errors'].append('recovery-metadata: ' + type(error).__name__ + ': ' + str(error)[:512])
            print(json.dumps({'status': 'FAIL', 'recovery_metadata_error': record['errors'][-1]}), file=sys.stderr)
    def run(name, command):
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'owned recovery budget exhausted')
        return checked('recover-' + name, command, timeout=min(120, remaining))
    def attempt(name, operation):
        try: return operation()
        except TrialInterrupted: raise
        except Exception as error:
            record['errors'].append(name + ': ' + type(error).__name__ + ': ' + str(error)[:1024])
            persist()
            return None
    before = attempt('disk-before', lambda: disk_identity(image, deadline))
    record['disk_before'] = before
    def state_check():
        state = run('filesystem-state', ['dumpe2fs', '-h', str(image)]).decode('utf-8', errors='strict')
        (artifact / 'filesystem-state.txt').write_text(state, encoding='utf-8')
        return re.search(r'(?m)^Filesystem state:\s+clean\s*$', state) is not None
    record['filesystem_clean'] = attempt('filesystem-state', state_check)
    guest_base = '/c/.local-runs/kvm-pilot'
    def tree(name, guest_path, destination):
        destination.mkdir(parents=True, exist_ok=False)
        run(name, debugfs_command(image, guest_path, destination, directory=True))
        nested = destination / Path(guest_path).name
        actual = destination
        if nested.is_dir():
            require(list(destination.iterdir()) == [nested], 'ambiguous recovered directory layout')
            actual = nested
        require(any(actual.iterdir()), 'guest tree missing or empty: ' + guest_path)
        entries = archive_capture.scan(actual)
        record['files'].append({'guest_path': guest_path, 'host_path': actual.relative_to(artifact).as_posix(),
            'files': len(entries), 'bytes': sum(row[2] for row in entries.values())})
        return actual
    # The original exports include failed/pending ZIPs and their manifests.
    exports = attempt('exports', lambda: tree('exports', guest_base + '/exports', artifact / 'guest'))
    for guest_name, host_name in (('commands', 'guest-helper-commands'), ('raw-receipts', 'guest-command-receipts')):
        attempt(host_name, lambda n=guest_name, h=host_name: tree(h, guest_base + '/' + n, artifact / h))
    for label, _, _ in STAGES:
        package = {'stage': label, 'origin': 'guest-original', 'status': 'FAIL'}
        target = artifact / 'packages' / label
        def original_package():
            require(exports is not None, 'original guest exports unavailable')
            original = exports / 'packages' / label / 'capture.zip'
            _, metadata = archive_capture.inspect(original)
            digest = sha(original)
            if target.exists():
                require((target / 'capture.zip').is_file() and sha(target / 'capture.zip') == digest,
                        'host acknowledged archive differs from original guest archive')
            else:
                target.mkdir(parents=True)
                shutil.copy2(original, target / 'capture.zip')
            package.update(status='VERIFIED', archive_sha256=digest, metadata=metadata)
            return True
        if not attempt('original-package-' + label, original_package):
            def partial_package():
                raw = tree('raw-' + label, guest_base + '/raw/' + label, artifact / 'partial-raw' / label)
                recovery = artifact / 'partial-packages' / label
                run('raw-pack-' + label, [sys.executable, str(ROOT / 'scripts/archive_capture.py'),
                    'pack', '--source', str(raw), '--out', str(recovery)])
                _, metadata = archive_capture.inspect(recovery / 'capture.zip')
                package.update(status='VERIFIED INCLUDED BYTES', origin='host-recovered-raw',
                    archive_sha256=sha(recovery / 'capture.zip'), metadata=metadata)
            attempt('partial-package-' + label, partial_package)
        record['packages'].append(package)
        persist()
    after = attempt('disk-after', lambda: disk_identity(image, deadline))
    record['disk_after'] = after
    if before is None or before != after: record['errors'].append('disk identity missing or changed during read-only recovery')
    record['status'] = 'PASS' if record['filesystem_clean'] is True and not record['errors'] and all(
        row['status'] == 'VERIFIED' for row in record['packages']) else 'FAIL'
    record['scope'] = 'verified included bytes only; missing files or unclean filesystem remain FAIL; no journal replay'
    persist()
    return record


def qemu_command(out, image, run_as, port):
    return ['qemu-system-x86_64', '-name', 'RillScope-unqualified-feasibility-pilot',
        '-machine', 'q35,memory-backend=ram0,mem-merge=off', '-accel', 'kvm', '-cpu', 'host',
        '-smp', '4,sockets=1,cores=4,threads=1', '-m', '8192',
        '-object', 'memory-backend-ram,id=ram0,size=8G,prealloc=on,merge=off', '-runas', run_as,
        '-display', 'none', '-chardev', 'stdio,id=serial0,signal=off,mux=off', '-serial', 'chardev:serial0',
        '-monitor', 'none', '-no-reboot', '-netdev', 'user,id=pilot-net',
        '-device', 'virtio-net-pci,netdev=pilot-net,id=pilot-nic',
        '-device', 'virtio-serial-pci',
        '-chardev', 'socket,id=capture,path=' + str(out / 'runtime/capture.sock') + ',server=on,wait=off',
        '-device', 'virtserialport,chardev=capture,name=' + PORT_NAME,
        '-qmp', 'tcp:127.0.0.1:' + str(port) + ',server=on,wait=off',
        '-boot', 'strict=on',
        '-drive', 'file=' + str(out / 'disk.qcow2') + ',if=none,format=qcow2,id=rillboot-disk',
        '-device', 'virtio-blk-pci,drive=rillboot-disk,bootindex=1',
        '-drive', 'file=' + str(out / 'work.raw') + ',if=none,format=raw,id=rillwork-disk',
        '-device', 'virtio-blk-pci,drive=rillwork-disk,serial=rillwork',
        '-drive', 'file=' + str(out / 'seed.iso') + ',media=cdrom,format=raw,readonly=on']


def run_vm(out, command, port, payload, uid, ownership):
    artifact = out / 'artifact'; process = None; captures = []; started = time.monotonic()
    events = []; ready_at = None; link_ack = None; snapshots = 0; post_ready_errors = 0; failure = None
    receiver_process = None; receiver_streams = []; receiver_exit = None
    try:
        process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0, start_new_session=True)
        write_json(artifact / 'process.json', {'status': 'RUNNING', 'pid': process.pid, 'utc_ns': time.time_ns()})
        captures = [BoundedCapture(process.stdout, artifact / 'serial.txt', SERIAL_LIMIT),
                    BoundedCapture(process.stderr, artifact / 'qemu.stderr', 256 * 1024)]
        while process.poll() is None:
            require(time.monotonic() - started < VM_SECONDS, 'pilot VM deadline exceeded; recover original partial bytes')
            for capture in captures: capture.drain()
            if receiver_process is None and (out / 'runtime/capture.sock').exists():
                require(stat.S_ISSOCK((out / 'runtime/capture.sock').lstat().st_mode), 'owned capture socket type differs')
                os.chmod(out / 'runtime/capture.sock', 0o600)
                receiver_streams = [(artifact / ('receiver.' + label)).open('xb') for label in ('stdout', 'stderr')]
                receiver_process = subprocess.Popen([sys.executable, str(ROOT / 'scripts/kvm_capture_receiver.py'),
                    '--socket', str(out / 'runtime/capture.sock'), '--out', str(artifact / 'packages'),
                    '--timeout', str(VM_SECONDS)], cwd=ROOT, stdin=subprocess.DEVNULL,
                    stdout=receiver_streams[0], stderr=receiver_streams[1], start_new_session=True)
            if receiver_process is not None and receiver_process.poll() is not None:
                require(receiver_process.returncode == 0, 'actual capture receiver failed')
            serial = bounded_bytes(artifact / 'serial.txt', SERIAL_LIMIT).decode('utf-8', errors='replace')
            complete = serial[:serial.rfind('\n') + 1]
            current = parse_events(complete)
            for row in current[len(events):]:
                append_json(artifact / 'received-events.jsonl', {'received_utc_ns': time.time_ns(),
                    'received_monotonic_ns': time.monotonic_ns(), 'guest': row})
                if row['phase'] == 'ready':
                    require(ready_at is None and row.get('commit') == payload['commit']
                        and row.get('source_sha256') == payload['source']['sha256']
                        and row.get('binary_sha256') == {name: item['sha256'] for name, item in payload['bins'].items()},
                        'guest readiness is duplicate or not bound to actual payload')
                    ready_at = time.monotonic()
                    require(ready_at - started < SETUP_SECONDS, 'boot/setup readiness deadline exceeded')
                    request_time = {'utc_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns()}
                    response = qmp(port, 'set_link', {'name': 'pilot-nic', 'up': False})
                    link_ack = {'requested': request_time, 'response': response,
                                'finished_utc_ns': time.time_ns(), 'finished_monotonic_ns': time.monotonic_ns()}
                    write_json(artifact / 'host-link-down.json', link_ack)
                    require('return' in response, 'actual owned NIC link-down request failed')
                if row['phase'] == 'network-down': require(link_ack is not None, 'guest network-down preceded host request')
                if row['phase'] == 'stage-start' and row.get('stage') != 'setup':
                    require(any(item['phase'] == 'network-down' for item in current[:current.index(row)]),
                            'measured campaign preceded guest network-down acknowledgement')
            events = current
            required_interval = ready_at is not None and not any(row['phase'] == 'guest-exit' for row in events)
            require(ready_at is not None or time.monotonic() - started < SETUP_SECONDS, 'guest never became ready')
            try:
                begin = time.monotonic_ns(); cpu = time.thread_time_ns()
                sample = host_snapshot(process.pid, port)
                sample.update(balloon=qmp(port, 'query-balloon'), qemu_version=qmp(port, 'query-version'),
                    ready=ready_at is not None, required_interval=required_interval,
                    observer_wall_ns=time.monotonic_ns() - begin,
                    observer_cpu_ns=time.thread_time_ns() - cpu)
                append_json(artifact / 'host-samples.jsonl', sample); snapshots += 1
                if required_interval:
                    require(sample['kvm'].get('return', {}).get('enabled') is True
                        and sample['memory'].get('return', {}).get('base-memory') == 8 * 1024**3
                        and sample['hotplug_memory'].get('return') == []
                        and sample['run_status'].get('return', {}).get('status') == 'running'
                        and len(sample['vcpu_threads']) == 4
                        and all(len(row['affinity']) == 4 for row in sample['vcpu_threads'])
                        and sample['environment'].get('effective_cpu_capacity') == 4
                        and sample['environment'].get('process_affinity_cpu_count') == 4
                        and int(sample['process_status'].get('VmRSS', '0 kB').split()[0]) * 1024 >= 7.5 * 1024**3
                        and sample['process_status'].get('Uid', '').split() == [str(uid)] * 4
                        and sample['process_status'].get('VmSwap') == '0 kB', 'post-ready allocation/lifecycle observation differs')
            except (OSError, ValueError, KeyError, TypeError) as error:
                if required_interval: post_ready_errors += 1
                append_json(artifact / 'host-observation-errors.jsonl', {'utc_ns': time.time_ns(),
                    'monotonic_ns': time.monotonic_ns(), 'after_ready': ready_at is not None,
                    'required_interval': required_interval,
                    'error': type(error).__name__, 'reason': str(error)[:1024]})
            require(snapshots <= 12000, 'host observation count exceeds bound')
            time.sleep(.5)
        require(process.returncode == 0, 'actual QEMU pilot exited unsuccessfully')
    except (Exception, KeyboardInterrupt) as error:
        failure = {'error': type(error).__name__, 'reason': str(error)[:2048]}
    finally:
        if process is not None and process.poll() is None:
            if failure is not None:
                try: collect_boot_diagnostics(out, port)
                except Exception as error:
                    # Diagnostic/storage errors must never bypass owned stop.
                    print(json.dumps({'boot_diagnostics_status': 'FAIL', 'error': type(error).__name__,
                                      'reason': str(error)[:1024]}), file=sys.stderr, flush=True)
            try: qmp(port, 'system_powerdown'); process.wait(timeout=15)
            except (OSError, ValueError, subprocess.SubprocessError):
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
        if process is not None:
            if receiver_process is not None:
                try: receiver_exit = receiver_process.wait(timeout=5)
                except subprocess.TimeoutExpired: pass
            # Stop/adopt owned descendants before any disk read or hash.
            cleanup = ownership.terminate(process.pid)
            write_json(artifact / 'vm-cleanup.json', cleanup)
            for capture in captures:
                try: capture.drain()
                except (OSError, ValueError) as error:
                    failure = failure or {'error': type(error).__name__, 'reason': str(error)}
                capture.close()
            write_json(artifact / 'process.json', {'status': 'EXITED', 'pid': process.pid,
                'exit_code': process.poll(), 'utc_ns': time.time_ns(), 'cleanup': cleanup})
            write_json(artifact / 'capture.json', [capture.record() for capture in captures])
            process.stdout.close(); process.stderr.close()
        if receiver_process is not None:
            receiver_exit = receiver_process.wait(timeout=5)
        for stream in receiver_streams: stream.close()
    serial = bounded_bytes(artifact / 'serial.txt', SERIAL_LIMIT).decode('utf-8', errors='replace')
    final_events = parse_events(serial[:serial.rfind('\n') + 1]); boot = parse_boot(serial)
    require(final_events[:len(events)] == events, 'final serial lifecycle prefix changed')
    for row in final_events[len(events):]:
        append_json(artifact / 'received-events.jsonl', {'received_utc_ns': time.time_ns(),
            'received_monotonic_ns': time.monotonic_ns(), 'terminal_capture': True, 'guest': row})
    events = final_events
    result = {'status': 'FAIL', 'events': events, 'boot_result': boot, 'host_samples': snapshots,
        'post_ready_observation_errors': post_ready_errors, 'reference_qualified': False,
        'elapsed_seconds': time.monotonic() - started, 'failure': failure}
    receiver_result = read_json(artifact / 'receiver-result.json') if (artifact / 'receiver-result.json').is_file() else {}
    result.update(host_transfers=receiver_result.get('transfers', []), receiver_exit=receiver_exit)
    if (failure is None and snapshots > 0 and ready_at is not None and post_ready_errors == 0
            and len(result['host_transfers']) == 3
            and receiver_exit == 0 and receiver_result.get('status') == 'PASS'
            and boot and boot.get('worker_exit') == 0 and boot.get('unmount_status') == 'PASS'
            and any(row['phase'] == 'guest-exit' and row.get('status') == 'COLLECTED' for row in events)):
        result['status'] = 'COLLECTED'
    write_json(artifact / 'vm-result.json', result)
    return result


def prepare_host(out, build_path, commit, run_as, ownership):
    import fcntl
    import pwd
    started = time.monotonic(); deadline = started + HOST_PREP_SECONDS
    account = pwd.getpwnam(run_as)
    require(account.pw_uid > 0, 'existing non-root QEMU identity required')
    initial = environment()
    write_json(out / 'artifact/host-before.json', initial)
    require(initial.get('effective_cpu_capacity') == 4 and initial.get('process_affinity_cpu_count') == 4,
            'actual four-CPU host capacity required')
    require(type(initial.get('available_memory_bytes')) is int and initial['available_memory_bytes'] >= 10 * 1024**3,
            'actual host memory headroom insufficient')
    with Path('/dev/kvm').open('r+b', buffering=0) as device:
        require(fcntl.ioctl(device.fileno(), 0xae00, 0) == 12, 'existing KVM API12 required')
    for tool in ('qemu-system-x86_64', 'qemu-img', 'cloud-localds', 'gpg', 'gpgv', 'mkfs.ext4', 'debugfs', 'dumpe2fs'):
        require(shutil.which(tool) is not None, 'required installed tool missing: ' + tool)
    direct = TrialCommands(out, ownership)
    def checked(name, command, timeout=60, **keywords):
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'host preparation deadline exhausted')
        return direct(name, command, timeout=min(timeout, remaining), **keywords)
    qemu = Path(shutil.which('qemu-system-x86_64')).resolve()
    version = checked('qemu-version', [str(qemu), '--version'], inputs=(qemu,)).decode()
    help_text = checked('qemu-help', [str(qemu), '-help'], inputs=(qemu,))
    require(b'-runas' in help_text and b'strict=on|off' in help_text,
            'installed QEMU lacks explicit privilege drop or strict boot support')
    image = signed_image(out, checked, deadline)
    stage, payload = prepare_payload(out, build_path, commit, checked)
    # No host mount: mkfs populates the newly owned raw disk before QEMU opens it.
    with (out / 'work.raw').open('xb') as stream: stream.truncate(DISK_BYTES)
    checked('work-format', ['mkfs.ext4', '-F', '-m', '0', '-L', 'rillwork', '-d', str(stage), str(out / 'work.raw')], timeout=120)
    config = {'package_update': False, 'package_upgrade': False, 'ssh_pwauth': False, 'disable_root': True,
        'users': [], 'write_files': [{'path': '/opt/rillscope-pilot-boot.py', 'permissions': '0644',
            'encoding': 'b64', 'content': base64.b64encode(BOOTSTRAP.encode()).decode('ascii')}],
        'runcmd': [['/bin/sh', '-c', '/usr/bin/python3 /opt/rillscope-pilot-boot.py > /dev/ttyS0 2>&1']]}
    (out / 'user-data').write_text('#cloud-config\n' + json.dumps(config) + '\n', encoding='utf-8')
    (out / 'meta-data').write_text('instance-id: rillscope-cost-pilot\nlocal-hostname: rillscope-cost-pilot\n', encoding='utf-8')
    checked('seed-create', ['cloud-localds', str(out / 'seed.iso'), str(out / 'user-data'), str(out / 'meta-data')],
        inputs=(out / 'user-data', out / 'meta-data'))
    checked('overlay-create', ['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(image),
        str(out / 'disk.qcow2'), '20G'], large_inputs=(image,))
    runtime = out / 'runtime'; runtime.mkdir(mode=0o700); os.chown(runtime, account.pw_uid, account.pw_gid)
    for name in ('work.raw', 'disk.qcow2'):
        os.chown(out / name, account.pw_uid, account.pw_gid); os.chmod(out / name, 0o600)
    with socket.socket() as available:
        available.bind(('127.0.0.1', 0)); port = available.getsockname()[1]
    command = qemu_command(out, image, run_as, port)
    write_json(out / 'artifact/configuration.json', {'command': command, 'qemu_sha256': sha(qemu),
        'original_root': str(ROOT), 'original_output': out.relative_to(ROOT).as_posix(),
        'qemu_version': version, 'image_sha256': IMAGE_SHA, 'signing_primary': FINGERPRINT,
        'qemu_run_as_uid': account.pw_uid, 'payload': payload, 'setup_elapsed_seconds': time.monotonic() - started,
        'deadlines_seconds': {'host_prep': HOST_PREP_SECONDS, 'vm': VM_SECONDS, 'recovery': RECOVERY_SECONDS,
            'cleanup': CLEANUP_SECONDS, 'reserve': RESERVE_SECONDS, 'total': TOTAL_SECONDS},
        'reference_qualified': False})
    return command, port, payload, account.pw_uid


def owned_output(path):
    path = Path(path).absolute()
    for part in (path, *path.parents):
        require(not part.is_symlink() and not (hasattr(part, 'is_junction') and part.is_junction()),
                'owned output cannot traverse links')
        if part == ROOT: break
    path = path.resolve()
    require(path.is_relative_to(ROOT / '.local-runs') and re.fullmatch(r'/[A-Za-z0-9_./-]+', str(path)),
            'closed native owned .local-runs output required')
    return path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True); parser.add_argument('--run-as', required=True)
    parser.add_argument('--build-receipt', type=Path, required=True); parser.add_argument('--commit', required=True)
    args = parser.parse_args()
    if platform.system() != 'Linux' or not hasattr(os, 'geteuid') or os.geteuid() != 0:
        print(json.dumps({'status': 'BLOCKED', 'reason': 'requires existing Linux root permission',
            'reference_qualified': False})); return 77
    require(re.fullmatch('[a-z_][a-z0-9_-]{0,31}', args.run_as), 'closed existing user name required')
    require(re.fullmatch('[0-9a-f]{40}', args.commit), 'exact public commit required')
    build_path = owned_output(args.build_receipt)
    out = owned_output(args.out)
    require(out.parent.is_dir(), 'existing owned output parent required')
    out.mkdir(exist_ok=False); fsync_directory(out.parent)
    (out / 'artifact').mkdir(); fsync_directory(out)
    started = time.monotonic(); ownership = None
    result = {'status': 'FAIL', 'reference_qualified': False, 'upstream_failure_preserved': True,
        'scope': 'three separate unqualified pilot campaigns; full410/reference/fresh release remain separate'}
    for number in (signal.SIGTERM, signal.SIGINT): signal.signal(number, interrupted)
    try:
        ownership = LinuxOwnedChildren()
        command, port, payload, uid = prepare_host(out, build_path, args.commit, args.run_as, ownership)
        result['vm'] = run_vm(out, command, port, payload, uid, ownership)
    except (Exception, KeyboardInterrupt) as error:
        result['failure'] = {'error': type(error).__name__, 'reason': str(error)[:2048]}
    finally:
        for number in (signal.SIGTERM, signal.SIGINT): signal.signal(number, signal.SIG_IGN)
        cleanup = ownership.terminate(None) if ownership is not None else {'status': 'NOT LAUNCHED'}
        write_json(out / 'artifact/pre-recovery-cleanup.json', cleanup)
        # No disk reads while any owned VM/helper can still write it.
        if cleanup['status'] == 'PASS' and (out / 'work.raw').is_file():
            try:
                remaining = min(RECOVERY_SECONDS, TOTAL_SECONDS - CLEANUP_SECONDS - RESERVE_SECONDS
                    - (time.monotonic() - started))
                require(remaining > 0, 'no recovery reserve remains')
                recovery_deadline = time.monotonic() + remaining
                try:
                    result['boot_recovery'] = recover_boot_logs(out, TrialCommands(out, ownership),
                        min(recovery_deadline, time.monotonic() + 180))
                except (Exception, KeyboardInterrupt) as error:
                    result['boot_recovery'] = {'status': 'FAIL', 'error': type(error).__name__, 'reason': str(error)[:1024]}
                # A diagnostic failure never suppresses original work-disk recovery.
                result['recovery'] = recover(out, TrialCommands(out, ownership), recovery_deadline)
            except (Exception, KeyboardInterrupt) as error:
                result['recovery'] = {'status': 'FAIL', 'error': type(error).__name__, 'reason': str(error)[:2048]}
        cleanup = ownership.finish(None) if ownership is not None else cleanup
        result['cleanup'] = cleanup
        write_json(out / 'artifact/cleanup.json', cleanup)
    if (result.get('vm', {}).get('status') == 'COLLECTED' and result.get('recovery', {}).get('status') == 'PASS'
            and cleanup['status'] == 'PASS' and 'failure' not in result): result['status'] = 'COLLECTED'
    result['elapsed_seconds'] = time.monotonic() - started
    result['work_disk_policy'] = 'owned disk retained until runner cleanup; included exports always uploaded; hard host loss can lose unexported partial bytes'
    write_json(out / 'artifact/results.json', result)
    print(json.dumps(result, indent=2)); return 0 if result['status'] == 'COLLECTED' else 1


if __name__ == '__main__': raise SystemExit(main())
