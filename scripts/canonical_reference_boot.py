"""Distinct source-only cloud bootstrap and closed actual boot footer parser."""
import base64

import canonical_reference_allocation as allocation
from kvm_reference_common import strict_json

BOOT_PREFIX = 'RILLSCOPE_CANONICAL_BOOT_V1 '
FOOTER_KEYS = {'schema_version', 'method', 'boot_id', 'commit', 'source_sha256', 'seed_sha256', 'mode',
    'started_monotonic_ns', 'finished_monotonic_ns', 'utc_ns', 'worker_pid', 'worker_exit',
    'worker_stopped', 'unmount_status', 'status', 'errors', 'reference_qualified'}
BOOTSTRAP = r'''import base64,hashlib,json,os,pathlib,re,signal,subprocess,time,traceback
METHOD='rillscope-controller-owned-canonical-reference-v1'
record={'schema_version':1,'method':METHOD,'boot_id':None,'commit':None,'source_sha256':None,
    'seed_sha256':None,'mode':None,'started_monotonic_ns':time.monotonic_ns(),
    'finished_monotonic_ns':None,'utc_ns':None,'worker_pid':None,'worker_exit':None,
    'worker_stopped':False,'unmount_status':'NOT MOUNTED','status':'FAIL','errors':[],
    'reference_qualified':False}
mounted=False;worker=None
def error(phase,value):
    if len(record['errors'])<8:
        record['errors'].append({'phase':phase,'error':type(value).__name__,
            'reason':str(value)[:512],'traceback':''.join(traceback.format_exception(value,limit=4))[-1024:]})
def interrupted(number,frame):raise RuntimeError('owned boot interrupted by signal '+str(number))
def persist():
    path=pathlib.Path('/work/c/.local-runs/canonical-boot/boot-result.json')
    path.parent.mkdir(mode=0o700,exist_ok=False)
    raw=json.dumps(record,sort_keys=True,separators=(',',':'),allow_nan=False).encode('ascii')
    if len(raw)>16384:raise ValueError('owned boot record exceeds bound')
    with path.open('xb') as stream:
        if stream.write(raw)!=len(raw):raise OSError('boot record write incomplete')
        stream.flush();os.fsync(stream.fileno())
    for parent in (path.parent,path.parent.parent):
        fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
for selected in (signal.SIGTERM,signal.SIGINT):signal.signal(selected,interrupted)
try:
    if os.getuid()!=0 or os.geteuid()!=0:raise ValueError('existing guest root required')
    record['boot_id']=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    pathlib.Path('/work').mkdir(exist_ok=False)
    subprocess.run(['/usr/bin/mount','-t','ext4','/dev/disk/by-id/virtio-rillwork','/work'],check=True,timeout=30)
    mounted=True
    marker=pathlib.Path('/run/rillscope-owned-canonical-reference')
    fd=os.open(marker,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    try:
        value=b'owned-ephemeral-canonical-reference\n'
        if os.write(fd,value)!=len(value):raise OSError('marker write incomplete')
        os.fsync(fd)
    finally:os.close(fd)
    seed=pathlib.Path('/work/c/.local-runs/canonical-seed/seed.json')
    with seed.open('rb') as stream:raw=stream.read(4*1024**2+1)
    if not 0<len(raw)<=4*1024**2:raise ValueError('bounded original seed required')
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise ValueError('duplicate seed key')
            result[key]=value
        return result
    row=json.loads(raw,object_pairs_hook=unique)
    if type(row)is not dict or row.get('method')!=METHOD or row.get('reference_qualified')is not False:
        raise ValueError('actual new-method seed differs')
    if not re.fullmatch('[0-9a-f]{40}',row.get('commit',''))or not re.fullmatch('[0-9a-f]{64}',row.get('source_sha256','')):
        raise ValueError('exact source identity required')
    if row.get('mode')not in ('canonical','native-setup-diagnostic'):raise ValueError('unknown new boot mode')
    record.update(commit=row['commit'],source_sha256=row['source_sha256'],mode=row['mode'],
        seed_sha256=hashlib.sha256(raw).hexdigest())
    worker=subprocess.Popen(['/usr/bin/env','PYTHONDONTWRITEBYTECODE=1','GIT_OPTIONAL_LOCKS=0',
        '/usr/bin/python3','/work/c/scripts/canonical_reference_guest_start.py'],
        stdin=subprocess.DEVNULL,start_new_session=True)
    record['worker_pid']=worker.pid
    # This independent safety ceiling never resets the actual pre-Popen host
    # VM lease. Setup and every granted command have their own stricter bounds.
    record['worker_exit']=worker.wait(timeout=21600)
except BaseException as value:error('worker',value)
finally:
    for selected in (signal.SIGTERM,signal.SIGINT):signal.signal(selected,signal.SIG_IGN)
    try:
        if worker is not None and worker.poll()is None:
            os.killpg(worker.pid,signal.SIGTERM)
            try:worker.wait(timeout=5)
            except subprocess.TimeoutExpired:os.killpg(worker.pid,signal.SIGKILL);worker.wait(timeout=5)
        record['worker_stopped']=worker is None or worker.poll()is not None
        if worker is not None:record['worker_exit']=worker.returncode
    except BaseException as value:error('worker-stop',value)
    if mounted:
        record['unmount_status']='PENDING'
        try:persist();os.sync()
        except BaseException as value:error('retain-before-unmount',value)
        try:
            subprocess.run(['/usr/bin/umount','/work'],check=True,timeout=30,capture_output=True)
            record['unmount_status']='PASS'
        except BaseException as value:record['unmount_status']='FAIL';error('unmount',value)
    record.update(finished_monotonic_ns=time.monotonic_ns(),utc_ns=time.time_ns())
    if record['worker_exit']==0 and record['worker_stopped']and record['unmount_status']=='PASS'and not record['errors']:
        record['status']='PASS'
    try:
        raw=json.dumps(record,sort_keys=True,separators=(',',':'),allow_nan=False).encode('ascii')
        if len(raw)>16384:raise ValueError('boot footer exceeds bound')
        print('RILLSCOPE_CANONICAL_BOOT_V1 '+base64.b64encode(raw).decode('ascii'),flush=True)
    finally:subprocess.run(['/usr/sbin/shutdown','-h','now'],check=False,timeout=15)
'''


def cloud_config():
    return {'package_update': False, 'package_upgrade': False, 'ssh_pwauth': False, 'disable_root': True,
        'users': [], 'bootcmd': [['/usr/bin/systemctl', 'mask', '--runtime', '--now', 'serial-getty@ttyS0.service']],
        'write_files': [{'path': '/opt/rillscope-canonical-boot.py', 'permissions': '0644',
            'encoding': 'b64', 'content': base64.b64encode(BOOTSTRAP.encode('ascii')).decode('ascii')}],
        'runcmd': [['/bin/sh', '-c', '/usr/bin/python3 /opt/rillscope-canonical-boot.py > /dev/ttyS0 2>&1']]}


def validate_footer(row):
    allocation.require(type(row) is dict and set(row) == FOOTER_KEYS
        and type(row['schema_version']) is int and row['schema_version'] == 1
        and row['method'] == allocation.METHOD and row['reference_qualified'] is False
        and allocation.boot(row['boot_id']) and row['status'] in ('PASS', 'FAIL')
        and type(row['worker_stopped']) is bool and row['unmount_status'] in ('PASS', 'FAIL', 'NOT MOUNTED'),
        'closed original new-method boot footer required')
    allocation.require(all(allocation.integer(row[key]) for key in
        ('started_monotonic_ns', 'finished_monotonic_ns', 'utc_ns'))
        and row['finished_monotonic_ns'] > row['started_monotonic_ns']
        and (row['worker_pid'] is None or allocation.integer(row['worker_pid']))
        and (row['worker_exit'] is None or type(row['worker_exit']) is int and -255 <= row['worker_exit'] <= 255),
        'actual boot clocks and worker observations required')
    allocation.require(type(row['errors']) is list and len(row['errors']) <= 8,
        'bounded original boot errors required')
    for error in row['errors']:
        allocation.require(type(error) is dict and set(error) == {'phase', 'error', 'reason', 'traceback'}
            and all(type(value) is str and len(value.encode('utf-8')) <= 4096 for value in error.values()),
            'closed bounded actual boot error required')
    if row['status'] == 'PASS':
        allocation.require(row['worker_exit'] == 0 and type(row['worker_exit']) is int
            and row['worker_stopped'] and row['unmount_status'] == 'PASS' and not row['errors']
            and allocation.integer(row['worker_pid']) and allocation.hex_value(row['commit'], 40)
            and allocation.hex_value(row['source_sha256'], 64) and allocation.hex_value(row['seed_sha256'], 64)
            and row['mode'] in ('canonical', 'native-setup-diagnostic'), 'actual complete boot success required')
    return row


def parse_boot(serial):
    allocation.require(type(serial) is str and len(serial.encode('utf-8')) <= 4 * 1024**2,
        'bounded original guest serial stream required')
    rows = []
    for line in serial.splitlines():
        if BOOT_PREFIX not in line: continue
        encoded = line.split(BOOT_PREFIX, 1)[1].strip()
        allocation.require(len(encoded) <= 24000, 'original boot footer frame exceeds bound')
        raw = base64.b64decode(encoded, validate=True)
        allocation.require(len(raw) <= 16384, 'decoded boot footer exceeds bound')
        rows.append(validate_footer(strict_json(raw)))
        allocation.require(len(rows) <= 1, 'duplicate new-method boot footer')
    allocation.require(len(rows) == 1, 'complete original new-method boot footer missing')
    return rows[0]
