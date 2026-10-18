#!/usr/bin/env python3
"""Retain fixed release metadata and available raw captures after cleanup."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile
import archive_capture
from verify_sequence import owned_path,write_json

ROOT=Path(__file__).resolve().parents[1]
MAX_METADATA_FILES=1024
MAX_METADATA_FILE=16*1024**2
MAX_METADATA_BYTES=64*1024**2
MAX_CAPTURES=32
ERRORS=(OSError,ValueError,TypeError,KeyError,zipfile.BadZipFile,NotImplementedError)


def bounded(values,limit):
    result=[]
    for value in values:
        if len(result)>=limit: raise ValueError('release retention entry bound exceeded')
        result.append(value)
    return sorted(result)


def copy_existing(source,destination,expected):
    if (not source.is_file() or type(expected['compressed_bytes']) is not int
            or not 0<expected['compressed_bytes']<=archive_capture.MAX_ARCHIVE):
        raise ValueError('existing CAS is not a bounded regular archive')
    before=source.stat()
    if before.st_size!=expected['compressed_bytes']: raise ValueError('existing CAS length differs')
    destination.parent.mkdir(parents=True,exist_ok=False)
    digest=hashlib.sha256(); size=0
    with source.open('rb') as original,destination.open('xb') as target:
        while block:=original.read(min(1024**2,before.st_size-size+1)):
            size+=len(block)
            if size>before.st_size: raise ValueError('existing CAS grew during copy')
            digest.update(block); target.write(block)
    after=source.stat()
    if (size!=before.st_size or digest.hexdigest()!=expected['archive_sha256']
            or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=
               (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)):
        raise ValueError('existing CAS bytes/source changed during copy')
    return digest.hexdigest()


def retain(out):
    out=owned_path(ROOT,out)
    if out.exists(): raise ValueError('release retention output must be new')
    out.mkdir(parents=True)
    result={'status':'RUNNING','metadata':[],'captures':[],'metadata_bytes':0,
        'scope':'fixed actual release metadata and available reference/NULL-sort/publication/harness-failure raw bytes; incomplete and failed attempts remain incomplete/failed; no validation or reference qualification'}
    def persist(): write_json(out/'retention.json',result)
    persist()
    clean=bounded((ROOT/'.local-runs').glob('clean-*'),2)
    if len(clean)>1: raise ValueError('one exact fresh attempt required; never select the latest')
    roots=[ROOT]
    if clean:
        checkouts=[owned_path(ROOT,clean[0]/name) for name in ('c','checkout') if (clean[0]/name).exists()]
        if len(checkouts)>1: raise ValueError('one exact fresh checkout required; never select an alias')
        if checkouts:
            if not checkouts[0].is_dir(): raise ValueError('fresh checkout must be an owned directory')
            roots.extend(checkouts)
    candidates=[]
    def include(path):
        path=owned_path(ROOT,path)
        if path.exists(): candidates.append(path)
        if len(candidates)>MAX_METADATA_FILES: raise ValueError('metadata file count exceeds bound')
    def include_build(path):
        for name in ('build.json','cargo.stdout','cargo.stderr','compiler.stdout','compiler.stderr'):
            include(path/name)
    for name in ('release-system-setup','release-setup','release-command'):
        for file in ('receipt.json','stdout.txt','stderr.txt'): include(ROOT/'.local-runs'/name/file)
    for attempt in clean:
        include(attempt/'results.json')
        for prefix in ('preparation','commands','diagnostics'):
            for command in bounded((attempt/prefix).glob('*'),64):
                for file in ('receipt.json','stdout.txt','stderr.txt'): include(command/file)
    stages=[]
    def raw_capture(path,kind):
        source=owned_path(ROOT,path)
        if not source.exists(): return
        if not source.is_dir(): raise ValueError('raw capture must be an owned directory')
        if len(stages)>=MAX_CAPTURES: raise ValueError('release capture count exceeds bound')
        row={'source':source.relative_to(ROOT).as_posix(),'kind':kind,
            'package':'capture-'+str(len(stages)),'result':{'status':'PENDING'}}
        stages.append((source,None,row));result['captures'].append(row)
    def publication_raw(path): raw_capture(path,'publication-transport')
    for root in roots:
        local=root/'.local-runs'
        for failure in bounded(local.glob('pf-*'),16): raw_capture(failure,'benchmark-harness-failure')
        # Keep every original functional build association, including failures.
        # Binaries, targets and unrelated checkout files remain outside this list.
        for build in bounded((local/'build').glob('dev-*'),64): include_build(build)
        for ledger in bounded(local.glob('verify*/ledger.json'),4):
            include(ledger)
            for command in bounded((ledger.parent/'commands').glob('*'),32):
                for file in ('receipt.json','stdout.txt','stderr.txt'): include(command/file)
        experiments=bounded(local.glob('benchmark-*'),4)+bounded((local/'bench').glob('s-*'),4)
        for experiment in experiments:
            experiment=owned_path(ROOT,experiment)
            if not experiment.is_dir(): raise ValueError('experiment must be an owned directory')
            # A build can fail before creating grid/build's redundant copy.
            include_build(experiment/'build')
            for file in ('reference-preflight.json','reference-results.json','retention-grid.json','retention-cancel.json'):
                include(experiment/file)
            for stage in ('grid','cancel'):
                source=owned_path(ROOT,experiment/stage)
                early=owned_path(ROOT,experiment/('capture-'+stage))
                if not source.exists() and not (early/'capture.zip').exists(): continue
                include(early/'archive-result.json')
                row={'source':source.relative_to(ROOT).as_posix(),
                    'package':'capture-'+str(len(stages)),'result':{'status':'PENDING'}}
                if len(stages)>=MAX_CAPTURES: raise ValueError('release capture count exceeds bound')
                stages.append((source,early,row)); result['captures'].append(row)
        for pattern in ('publication-boundary-*','publication-decision-*'):
            for experiment in bounded(local.glob(pattern),4): publication_raw(experiment)
        for control in bounded(local.glob('publication-control-*'),4):
            control=owned_path(ROOT,control)
            include(control/'summary.json')
            for source in bounded(control.glob('source.*.rs'),8): include(source)
            publication_raw(control/'commands')
            for label in ('baseline','mutant','restored'):
                publication_raw(control/'checkout/.local-runs'/label)
            for build in bounded((control/'checkout/.local-runs/build').glob('*'),16):
                include_build(build)
    # Secure small immutable command/progress bytes before any large operation.
    for path in sorted(set(candidates)):
        if not path.is_file() or path.stat().st_size>MAX_METADATA_FILE:
            raise ValueError('release metadata is nonregular or exceeds file bound')
        data=path.read_bytes(); result['metadata_bytes']+=len(data)
        if result['metadata_bytes']>MAX_METADATA_BYTES: raise ValueError('release metadata exceeds aggregate bound')
        destination=out/'metadata'/('m'+str(len(result['metadata'])))/path.name
        destination.parent.mkdir(parents=True); destination.write_bytes(data)
        result['metadata'].append({'source':path.relative_to(ROOT).as_posix(),
            'file':destination.relative_to(out).as_posix(),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
        persist()
    pending=[]; copied=[]
    # Copy every completed early CAS before spending time on new raw packaging.
    # Copied bytes are explicitly unverified until all archive objects are checked.
    for source,early,row in stages:
        if early is None:
            pending.append((source,row));continue
        archive=owned_path(ROOT,early/'capture.zip'); record=owned_path(ROOT,early/'archive-result.json')
        if not archive.exists() or not record.exists():
            pending.append((source,row)); continue
        try:
            if record.stat().st_size>65536: raise ValueError('existing archive record exceeds bound')
            value=json.loads(record.read_bytes())
            if value['status']!='RECORDED': raise ValueError('existing archive is not a completed CAS')
            row.update(mode='existing-early-CAS',result={'status':'COPYING'})
            persist()
            destination=out/row['package']
            digest=copy_existing(archive,destination/'capture.zip',value)
            write_json(destination/'archive-result.json',value)
            row['result']={'status':'COPIED_UNVERIFIED','archive_sha256':digest}
            copied.append((destination,row,value))
        except ERRORS as error:
            row['result']={'status':'FAIL','error':type(error).__name__,'reason':str(error)}
        persist()
    # Only stages with no earlier complete package need another raw traversal.
    for source,row in pending:
        row.update(mode='fallback-raw-pack',result={'status':'PACKING'}); persist()
        try: row['result']=archive_capture.pack(source,out/row['package'])
        except ERRORS as error:
            row['result']={'status':'FAIL','error':type(error).__name__,'reason':str(error)}
        persist()
    # A timeout here still leaves metadata and every copied complete CAS available.
    for destination,row,value in copied:
        try:
            _,actual=archive_capture.inspect(destination/'capture.zip')
            if any(value.get(key)!=observed for key,observed in actual.items()):
                raise ValueError('existing CAS record differs from verified objects')
            row['result']=value
        except ERRORS as error:
            row['result']={'status':'FAIL','error':type(error).__name__,'reason':str(error)}
        persist()
    if not result['metadata'] and not stages: raise ValueError('no actual release evidence available')
    result['status']='RETAINED' if all(row['result']['status']=='RECORDED' for row in result['captures']) else 'FAIL'
    persist()
    return result


def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--out',type=Path,required=True); args=parser.parse_args()
    try: result=retain(args.out)
    except ERRORS as error:
        print(json.dumps({'status':'FAIL','error':type(error).__name__,'reason':str(error)})); return 1
    print(json.dumps({'status':result['status'],'metadata_files':len(result['metadata']),
        'captures':len(result['captures']),'scope':result['scope']}))
    return 0 if result['status']=='RETAINED' else 1


if __name__=='__main__': raise SystemExit(main())
