"""Portable physical paths; logical workload identities remain in every record."""
import hashlib
import os
from pathlib import Path
import re

CASE_LAYOUT='sha256-16-v1'


def case_folder(workload,seed,layout=None):
    if (type(workload) is not str or re.fullmatch(r'[A-Za-z0-9_-]{1,128}',workload) is None
            or type(seed) is not int or not 0<=seed<2**63):
        raise ValueError('closed workload identity and integer seed required')
    if layout is None: return workload+'-seed'+str(seed)
    if layout!=CASE_LAYOUT: raise ValueError('unknown benchmark case directory layout')
    return 'c-'+hashlib.sha256((workload+':'+str(seed)).encode('ascii')).hexdigest()[:16]


def case_folders(manifest):
    descriptions=manifest['chosen_workloads'];seeds=manifest['seeds']
    if (not 0<len(descriptions)<=512 or not 0<len(seeds)<=64 or len(descriptions)*len(seeds)>4096
            or len(seeds)!=len(set(seeds))):
        raise ValueError('bounded unique case grid required')
    pairs=[(description['id'],seed) for description in descriptions for seed in seeds]
    if len(pairs)!=len(set(pairs)): raise ValueError('duplicate workload/seed identity')
    paths=[case_folder(workload,seed,manifest.get('case_directory_layout')) for workload,seed in pairs]
    if len(paths)!=len(set(paths)): raise ValueError('benchmark case directory collision')
    return dict(zip(pairs,paths))


def preflight_prefix(prefix,*,windows=None):
    """Check every process/measurement filename before an owned child starts."""
    if windows is None: windows=os.name=='nt'
    paths=[prefix.with_suffix(suffix).absolute() for suffix in
           ('.stdout','.stderr','.process.json','.measurement.json','.usage.json')]
    if windows and any(len(str(path).encode('utf-16-le'))//2>=260 for path in paths):
        raise OSError('benchmark artifact path exceeds portable Windows envelope')
    if any(any(character in str(path) for character in ('\0','\r','\n')) for path in paths):
        raise ValueError('benchmark artifact path contains a forbidden control character')
    return paths
