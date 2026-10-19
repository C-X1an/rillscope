"""Read selected boot logs from a stopped owned qcow2 disk without mounting it."""
import hashlib
import json
from pathlib import Path
import re
import stat
import struct
import tempfile
import time
import uuid
import zlib

from kvm_pilot_common import require, write_json
from inspect_reference_guest import IMAGE, IMAGE_LIMIT, IMAGE_SHA, TrialInterrupted, bounded_bytes

ROOT_BYTES = 20 * 1024**3
HEADER_BYTES = 1024**2
LOG_BYTES = 4 * 1024**2
LINUX_FS = '0fc63daf-8483-4772-8e79-3d69d8477de4'
BOOT_LOGS = ('/var/log/cloud-init.log', '/var/log/cloud-init-output.log',
             '/var/log/boot.log', '/var/log/dmesg', '/var/log/kern.log', '/var/log/syslog')


def root_partition(data, virtual_bytes):
    """Check the primary GPT CRCs/ranges and select exactly one Linux filesystem."""
    require(type(data) is bytes and 1024 <= len(data) <= HEADER_BYTES, 'bounded GPT header bytes required')
    require(type(virtual_bytes) is int and 1024**2 <= virtual_bytes <= ROOT_BYTES
            and virtual_bytes % 512 == 0, 'bounded aligned virtual disk size required')
    require(data[510:512] == b'\x55\xaa' and any(data[446 + 16 * i + 4] == 0xee for i in range(4)),
            'protective MBR missing')
    require(data[512:520] == b'EFI PART', 'only the pinned GPT disk layout is supported')
    revision, size, expected_crc, reserved = struct.unpack_from('<IIII', data, 520)
    require(revision == 0x10000 and 92 <= size <= 512 and reserved == 0, 'invalid GPT revision/header')
    header = bytearray(data[512:512 + size]); header[16:20] = bytes(4)
    require(zlib.crc32(header) == expected_crc, 'GPT header checksum differs')
    current, backup, first, last = struct.unpack_from('<QQQQ', data, 536)
    require(current == 1 and 34 <= first <= last < backup < virtual_bytes // 512, 'invalid GPT disk range')
    entries_lba, count, width, expected_entries_crc = struct.unpack_from('<QIII', data, 584)
    require(entries_lba >= 2 and 1 <= count <= 128 and width in (128, 256), 'invalid bounded GPT entries')
    begin = entries_lba * 512; end = begin + count * width
    require(end <= len(data) and end <= first * 512, 'GPT entry array exceeds captured header/usable range')
    require(zlib.crc32(data[begin:end]) == expected_entries_crc, 'GPT entry checksum differs')
    partitions = []; candidates = []
    for index in range(count):
        offset = begin + index * width; kind = data[offset:offset + 16]
        if kind == bytes(16): continue
        start, finish = struct.unpack_from('<QQ', data, offset + 32)
        require(first <= start <= finish <= last, 'partition lies outside the usable disk')
        require(all(finish < row['start_lba'] or start > row['end_lba'] for row in partitions), 'GPT partitions overlap')
        row = {'index': index + 1, 'type': str(uuid.UUID(bytes_le=kind)), 'start_lba': start, 'end_lba': finish}
        partitions.append(row)
        if row['type'] == LINUX_FS: candidates.append(row)
    require(len(candidates) == 1, 'exactly one Linux root filesystem required')
    row = candidates[0]
    return {**row, 'offset_bytes': row['start_lba'] * 512,
            'bytes': (row['end_lba'] - row['start_lba'] + 1) * 512}


def slice_command(image, destination, partition):
    require(all(',' not in str(path) and '\n' not in str(path) and '\r' not in str(path)
                for path in (image, destination)), 'image option delimiters are forbidden')
    offset, size = partition['offset_bytes'], partition['bytes']
    require(type(offset) is int and type(size) is int and offset >= 0 and size > 0
            and offset % 512 == size % 512 == 0 and offset + size <= ROOT_BYTES,
            'bounded aligned root slice required')
    options = (f'driver=raw,offset={offset},size={size},file.driver=qcow2,'
               f'file.file.driver=file,file.file.filename={image}')
    return ['qemu-img', 'convert', '--image-opts', '-O', 'raw', '-S', '4096', options, str(destination)]


def disk_identity(path, deadline, limit):
    require(not path.is_symlink() and stat.S_ISREG(path.stat().st_mode), 'regular owned disk input required')
    require(path.stat().st_size <= limit, 'owned disk input exceeds explicit byte bound')
    digest = hashlib.sha256(); size = 0
    with path.open('rb') as stream:
        while block := stream.read(1024**2):
            require(time.monotonic() < deadline, 'boot recovery hash deadline exhausted')
            size += len(block); require(size <= limit, 'owned disk grew beyond hash bound')
            digest.update(block)
    return {'bytes': size, 'sha256': digest.hexdigest()}


def recover_boot_logs(out, checked, deadline, *, artifact=None):
    """Caller must establish stopped ownership before any disk operation."""
    artifact = artifact if artifact is not None else out / 'artifact'
    destination = artifact / 'root-boot-logs'; destination.mkdir(parents=True, exist_ok=False)
    scratch = Path(tempfile.mkdtemp(prefix='root-inspect-', dir=out))
    require(scratch.resolve().is_relative_to(out.resolve()), 'derived disk scratch must remain owned')
    overlay = out / 'disk.qcow2'; backing = out / IMAGE
    record = {'status': 'FAIL', 'read_only': True, 'reference_qualified': False,
              'files': [], 'errors': [], 'derived_disk_uploaded': False,
              'scope': 'selected actual stopped-root boot logs; no mount, repair, journal replay, key files or boot-success inference'}
    def persist(): write_json(artifact / 'root-boot-recovery.json', record)
    def run(name, command):
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'boot recovery budget exhausted')
        return checked('boot-recover-' + name, command, timeout=min(90, remaining))
    def identities():
        return {'overlay': disk_identity(overlay, deadline, 22 * 1024**3),
                'backing': disk_identity(backing, deadline, IMAGE_LIMIT)}
    try:
        record['before'] = identities()
        require(record['before']['backing']['sha256'] == IMAGE_SHA, 'pinned backing image changed')
        info = json.loads(run('image-info', ['qemu-img', 'info', '-f', 'qcow2', '--output=json', str(overlay)]))
        require(info.get('format') == 'qcow2' and info.get('virtual-size') == ROOT_BYTES
                and info.get('backing-filename') == str(backing), 'stopped root image geometry/backing differs')
        record['image_info'] = info
        header = scratch / 'header.raw'
        run('header', ['qemu-img', 'dd', '-f', 'qcow2', '-O', 'raw', 'bs=512', 'count=2048',
                       'if=' + str(overlay), 'of=' + str(header)])
        data = bounded_bytes(header, HEADER_BYTES)
        require(len(data) == HEADER_BYTES, 'complete first MiB of stopped root disk required')
        partition = root_partition(data, ROOT_BYTES); record['partition'] = partition
        record['header'] = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        (destination / 'gpt-header.raw').write_bytes(data)
        filesystem = scratch / 'root.raw'
        run('root-slice', slice_command(overlay, filesystem, partition))
        require(filesystem.is_file() and not filesystem.is_symlink() and filesystem.stat().st_size == partition['bytes'],
                'derived root filesystem length differs')
        state = run('filesystem-state', ['dumpe2fs', '-h', str(filesystem)]).decode('utf-8', errors='strict')
        (destination / 'filesystem-state.txt').write_text(state, encoding='utf-8')
        record['filesystem_clean'] = re.search(r'(?m)^Filesystem state:\s+clean\s*$', state) is not None
        for index, guest_path in enumerate(BOOT_LOGS):
            row = {'guest_path': guest_path, 'status': 'FAIL'}
            try:
                metadata = run('log-stat-' + str(index), ['debugfs', '-R', 'stat ' + guest_path, str(filesystem)]).decode('utf-8', errors='strict')
                row['stat_stdout_sha256'] = hashlib.sha256(metadata.encode('utf-8')).hexdigest()
                size_match = re.search(r'\bSize:\s+(\d+)', metadata)
                if not size_match:
                    # debugfs can exit0 while reporting lookup/other errors on
                    # stderr. Empty stdout alone cannot prove file absence.
                    row.update(status='STAT UNAVAILABLE', reason='no file stat returned; retained helper stderr is authoritative')
                else:
                    require(re.search(r'\bType:\s+regular\b', metadata) is not None, 'boot log is not a regular file')
                    size = int(size_match[1]); row['source_bytes'] = size
                    require(size <= LOG_BYTES, 'boot log exceeds retention bound; not silently truncated')
                    path = destination / Path(guest_path).name
                    run('log-dump-' + str(index), ['debugfs', '-R', 'dump ' + guest_path + ' ' + str(path), str(filesystem)])
                    data = bounded_bytes(path, LOG_BYTES)
                    require(not path.is_symlink() and len(data) == size, 'recovered log bytes differ from source stat')
                    row.update(status='COLLECTED', file=path.name, bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
            except TrialInterrupted: raise
            except Exception as error:
                row.update(error=type(error).__name__, reason=str(error)[:1024])
                record['errors'].append('log ' + guest_path + ': ' + type(error).__name__)
            record['files'].append(row); persist()
    except TrialInterrupted as error:
        record['errors'].append('interrupted: ' + str(error)[:1024])
        raise
    except Exception as error:
        record['errors'].append(type(error).__name__ + ': ' + str(error)[:1024])
    finally:
        try:
            record['after'] = identities()
            require(record.get('before') == record['after'], 'original root/backing disk bytes changed or lack prior identity')
        except Exception as error:
            record['errors'].append('disk-after: ' + type(error).__name__ + ': ' + str(error)[:1024])
        complete_sequence = [row['guest_path'] for row in record['files']] == list(BOOT_LOGS)
        if not complete_sequence: record['errors'].append('the selected boot-log sequence is incomplete')
        if not record['errors'] and record.get('filesystem_clean') is True and complete_sequence:
            record['status'] = 'COLLECTED' if all(row['status'] == 'COLLECTED' for row in record['files']) else 'PARTIAL'
        persist()
    return record
