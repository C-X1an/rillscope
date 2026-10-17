#!/usr/bin/env python3
"""Retain every regular capture file with byte-preserving content deduplication."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MAX_FILES = 500000
MAX_BYTES = 16 * 1024**3
MAX_FILE = 256 * 1024**2
MAX_MANIFEST = 128 * 1024**2
MAX_ARCHIVE = 100 * 1024**2
FORMAT = 'rillscope-cas-capture-v1'


def require(condition, message):
    if not condition: raise ValueError(message)


def owned(path):
    path = Path(path).absolute()
    for part in (path, *path.parents):
        require(not part.is_symlink() and not (hasattr(part, 'is_junction') and part.is_junction()),
                'capture paths cannot traverse links or junctions')
        if part == ROOT: break
    path = path.resolve()
    require(path.is_relative_to(ROOT / '.local-runs'), 'capture paths must remain in owned .local-runs')
    return path


def member(name):
    path = PurePosixPath(name)
    require(isinstance(name, str) and len(name.encode('utf-8')) <= 4096 and path.parts
            and not path.is_absolute() and '..' not in path.parts and '\\' not in name and ':' not in name
            and path.as_posix() == name and not any(ord(c) < 32 for c in name), 'invalid capture member')
    # Closed portable component spelling: never rename or silently lose a file
    # through a Windows device, terminal dot/space or Unicode alias.
    for component in path.parts:
        base = component.split('.')[0].upper()
        require(len(component) <= 255 and re.fullmatch('[A-Za-z0-9_.-]+',component) is not None
                and not component.endswith('.')
                and base not in {'CON','PRN','AUX','NUL'} and re.fullmatch('(COM|LPT)[0-9]+',base) is None,
                'unsupported portable capture component')
    return path


def register(name, paths):
    parts = member(name).parts
    for length in range(1,len(parts)+1):
        prefix = '/'.join(parts[:length]); key = prefix.casefold(); directory = length < len(parts)
        value = (prefix,directory)
        require(key not in paths or paths[key] == value, 'capture path case/prefix collision')
        paths[key] = value
        require(len(paths) <= MAX_FILES, 'capture path count exceeds bound')


def scan(root):
    result = {}; pending = [root]; folded = {}; total = 0; entries = 0
    while pending:
        for path in pending.pop().iterdir():
            entries += 1; require(entries <= MAX_FILES, 'capture entry count exceeds bound')
            member(path.relative_to(root).as_posix())
            require(not path.is_symlink() and not (hasattr(path, 'is_junction') and path.is_junction()),
                    'capture cannot include links or junctions')
            if path.is_dir(): pending.append(path); continue
            require(path.is_file(), 'capture requires regular files')
            name = path.relative_to(root).as_posix(); register(name,folded)
            value = path.stat(); total += value.st_size
            require(value.st_size <= MAX_FILE and total <= MAX_BYTES and len(result) < MAX_FILES,
                    'capture file/count/byte bound exceeded')
            result[name] = (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
    return result


def stream_hash(source, destination=None):
    digest = hashlib.sha256(); size = 0
    while block := source.read(1024 * 1024):
        size += len(block); require(size <= MAX_FILE, 'capture object byte bound exceeded')
        digest.update(block)
        if destination is not None: destination.write(block)
    return digest.hexdigest(), size


def inspect(archive):
    require(Path(archive).stat().st_size <= MAX_ARCHIVE, 'archive exceeds retained artifact byte bound')
    with zipfile.ZipFile(archive) as bundle:
        infos = bundle.infolist(); names = {info.filename for info in infos}
        require(len(names) == len(infos) and 2 <= len(infos) <= MAX_FILES + 2, 'invalid archive entry count')
        require({'metadata.json','manifest.jsonl'} <= names, 'archive metadata missing')
        for info in infos:
            require(not info.is_dir() and not info.flag_bits & 1 and not stat.S_ISLNK(info.external_attr >> 16),
                    'archive requires regular unencrypted members')
            if info.filename not in {'metadata.json','manifest.jsonl'}:
                require(re.fullmatch(r'objects/[0-9a-f]{64}',info.filename) is not None, 'unexpected archive object')
                require(info.file_size <= MAX_FILE, 'archive object exceeds byte bound')
        require(bundle.getinfo('metadata.json').file_size <= 65536
                and bundle.getinfo('manifest.jsonl').file_size <= MAX_MANIFEST, 'archive metadata exceeds bound')
        metadata = json.loads(bundle.read('metadata.json'))
        require(set(metadata) == {'format','files','objects','bytes','manifest_sha256'}
                and metadata['format'] == FORMAT, 'unsupported capture format')
        rows = []; paths = {}; full_names = set(); total = 0; objects = {}; digest = hashlib.sha256()
        with bundle.open('manifest.jsonl') as handle:
            while line := handle.readline(16385):
                require(len(line) <= 16384 and line.endswith(b'\n') and len(rows) < MAX_FILES,
                        'invalid manifest line/count')
                digest.update(line); row = json.loads(line)
                require(set(row) == {'path','sha256','bytes'} and isinstance(row['path'],str), 'invalid manifest record')
                register(row['path'],paths)
                require(row['path'] not in full_names, 'duplicate capture path'); full_names.add(row['path'])
                require(isinstance(row['sha256'],str) and re.fullmatch('[0-9a-f]{64}',row['sha256']) is not None
                        and type(row['bytes']) is int and 0 <= row['bytes'] <= MAX_FILE, 'invalid capture digest/size')
                require(row['sha256'] not in objects or objects[row['sha256']] == row['bytes'], 'inconsistent object size')
                objects[row['sha256']] = row['bytes']; total += row['bytes']
                require(total <= MAX_BYTES, 'expanded capture exceeds bound'); rows.append(row)
        require(names == {'metadata.json','manifest.jsonl'} | {'objects/'+key for key in objects}, 'archive object set differs')
        require(all(type(metadata[key]) is int for key in ('files','objects','bytes'))
                and (metadata['files'],metadata['objects'],metadata['bytes'],metadata['manifest_sha256']) ==
                (len(rows),len(objects),total,digest.hexdigest()), 'capture metadata identity differs')
        for key,size in objects.items():
            with bundle.open('objects/'+key) as handle:
                actual = stream_hash(handle)
            require(actual == (key,size), 'capture object digest/size differs')
    return rows, metadata


def pack(source, out):
    source, out = owned(source), owned(out)
    require(source.is_dir() and not out.is_relative_to(source), 'output must be outside the capture')
    before = scan(source); out.mkdir(parents=True,exist_ok=False)
    manifest = out/'manifest.jsonl'; pending = out/'capture.pending.zip'; objects = {}; total = 0
    with zipfile.ZipFile(pending,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as bundle:
        with manifest.open('xb') as listing:
            for name in sorted(before):
                path = source/name
                with path.open('rb') as handle: digest,size = stream_hash(handle)
                if digest not in objects:
                    with path.open('rb') as handle, bundle.open('objects/'+digest,'w',force_zip64=True) as destination:
                        require(stream_hash(handle,destination) == (digest,size), 'capture changed during object copy')
                    objects[digest] = size
                line = json.dumps({'path':name,'sha256':digest,'bytes':size},separators=(',',':')).encode()+b'\n'
                total += len(line); require(total <= MAX_MANIFEST, 'capture manifest exceeds bound'); listing.write(line)
        with manifest.open('rb') as handle: manifest_digest,_ = stream_hash(handle)
        metadata = {'format':FORMAT,'files':len(before),'objects':len(objects),
                    'bytes':sum(value[2] for value in before.values()),'manifest_sha256':manifest_digest}
        bundle.write(manifest,'manifest.jsonl')
        bundle.writestr('metadata.json',json.dumps(metadata,separators=(',',':'))+'\n')
    require(scan(source) == before, 'capture changed during packaging')
    size = pending.stat().st_size
    result = {'status':'BLOCKED' if size > MAX_ARCHIVE else 'RECORDED',**metadata,'compressed_bytes':size,
              'scope':'every regular capture file and exact bytes; duplicate content shared, failures never filtered; no benchmark correctness or reference qualification'}
    with pending.open('rb') as handle:
        digest = hashlib.sha256()
        while block := handle.read(1024 * 1024): digest.update(block)
    result['archive_sha256'] = digest.hexdigest()
    if size <= MAX_ARCHIVE:
        inspect(pending)
        pending.rename(out/'capture.zip')
    else:
        result['reason'] = 'complete archive exceeds conservative transient upload bound; retained locally'
    (out/'archive-result.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    return result


def restore(archive, out):
    rows, metadata = inspect(archive); out = owned(out); out.mkdir(parents=True,exist_ok=False)
    with zipfile.ZipFile(archive) as bundle:
        for row in rows:
            path = out.joinpath(*member(row['path']).parts); path.parent.mkdir(parents=True,exist_ok=True)
            with bundle.open('objects/'+row['sha256']) as source, path.open('xb') as destination:
                require(stream_hash(source,destination) == (row['sha256'],row['bytes']), 'restored bytes differ')
    return {'status':'RESTORED',**metadata,'scope':'exact capture files/bytes restored; no new product execution or benchmark validation'}


def main():
    parser = argparse.ArgumentParser(); sub = parser.add_subparsers(dest='action',required=True)
    create = sub.add_parser('pack'); create.add_argument('--source',type=Path,required=True); create.add_argument('--out',type=Path,required=True)
    extract = sub.add_parser('restore'); extract.add_argument('--archive',type=Path,required=True); extract.add_argument('--out',type=Path,required=True)
    args = parser.parse_args()
    try:
        result = pack(args.source,args.out) if args.action == 'pack' else restore(args.archive,args.out)
    except (OSError,ValueError,TypeError,KeyError,zipfile.BadZipFile,NotImplementedError) as error:
        print(json.dumps({'status':'FAIL','error':type(error).__name__,'reason':str(error),
                          'scope':'capture archive operation only; no product or benchmark verification'}))
        return 1
    print(json.dumps(result,indent=2)); return 77 if result['status'] == 'BLOCKED' else 0


if __name__ == '__main__': raise SystemExit(main())
