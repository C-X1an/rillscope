"""Byte restoration and real malformed-archive controls; no benchmark execution."""
import hashlib
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import archive_capture


class CaptureArchive(unittest.TestCase):
    def fixture(self, root):
        source = root/'.local-runs/grid'; source.mkdir(parents=True)
        data = {'a/stdout.txt':b'{"status":"error","error":{"code":"E_BUDGET"}}\n',
                'b/stdout.txt':b'{"status":"error","error":{"code":"E_BUDGET"}}\n',
                'b/stderr.txt':b'', 'raw.bin':bytes(range(256))*17}
        for name,body in data.items():
            path = source/name; path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(body)
        return source,data

    def rewrite(self, source, target, change):
        with zipfile.ZipFile(source) as old:
            entries = [(info,old.read(info)) for info in old.infolist()]
        with zipfile.ZipFile(target,'x',compression=zipfile.ZIP_DEFLATED) as new:
            for info,data in change(entries): new.writestr(info,data)

    def test_exact_binary_empty_and_failed_outputs_restore_with_content_deduplication(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(archive_capture,'ROOT',Path(folder).resolve()):
            root = Path(folder).resolve(); source,expected = self.fixture(root); out = root/'.local-runs/packed'
            result = archive_capture.pack(source,out)
            self.assertEqual((result['status'],result['files'],result['objects']),('RECORDED',4,3))
            archive = out/'capture.zip'; original = archive.read_bytes()
            restored = root/'.local-runs/restored'; archive_capture.restore(archive,restored)
            self.assertEqual({path.relative_to(restored).as_posix():path.read_bytes()
                              for path in restored.rglob('*') if path.is_file()},expected)
            bad = root/'.local-runs/changed.zip'
            def mutate(entries):
                changed = False
                for info,data in entries:
                    if info.filename.startswith('objects/') and data and not changed:
                        data = bytes([data[0]^1])+data[1:]; changed = True
                    yield info,data
            self.rewrite(archive,bad,mutate)
            with self.assertRaisesRegex(ValueError,'digest/size'):
                archive_capture.restore(bad,root/'.local-runs/rejected')
            self.assertFalse((root/'.local-runs/rejected').exists())
            self.assertEqual(archive.read_bytes(),original)
            self.assertEqual(len(archive_capture.inspect(archive)[0]),4)
            self.assertEqual({path.relative_to(source).as_posix():path.read_bytes()
                              for path in source.rglob('*') if path.is_file()},expected)

    def test_traversal_and_case_prefix_collisions_fail_before_output_creation(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(archive_capture,'ROOT',Path(folder).resolve()):
            root = Path(folder).resolve(); source,_ = self.fixture(root); out = root/'.local-runs/packed'
            archive_capture.pack(source,out)
            for label,names in (('traversal',['../escape']),('prefix',['A','a/child'])):
                def mutate(entries):
                    data = {info.filename:(info,body) for info,body in entries}
                    one = json.loads(data['manifest.jsonl'][1].splitlines()[0])
                    rows = [dict(one,path=name) for name in names]
                    manifest = b''.join(json.dumps(row).encode()+b'\n' for row in rows)
                    metadata = {'format':'rillscope-cas-capture-v1','files':len(rows),'objects':1,
                                'bytes':sum(row['bytes'] for row in rows),
                                'manifest_sha256':hashlib.sha256(manifest).hexdigest()}
                    yield 'manifest.jsonl',manifest
                    yield 'metadata.json',json.dumps(metadata).encode()
                    yield data['objects/'+one['sha256']]
                bad = root/('.local-runs/'+label+'.zip'); self.rewrite(out/'capture.zip',bad,mutate)
                with self.assertRaises(ValueError):
                    archive_capture.restore(bad,root/('.local-runs/'+label))
                self.assertFalse((root/('.local-runs/'+label)).exists())
            self.assertFalse((root/'.local-runs/escape').exists())

    def test_archive_symlink_metadata_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(archive_capture,'ROOT',Path(folder).resolve()):
            root = Path(folder).resolve(); source,_ = self.fixture(root); out = root/'.local-runs/packed'
            archive_capture.pack(source,out)
            def mutate(entries):
                for info,data in entries:
                    if info.filename.startswith('objects/'):
                        info.create_system = 3; info.external_attr = (stat.S_IFLNK|0o777)<<16
                    yield info,data
            bad = root/'.local-runs/link.zip'; self.rewrite(out/'capture.zip',bad,mutate)
            with self.assertRaisesRegex(ValueError,'regular unencrypted'):
                archive_capture.inspect(bad)

    def test_windows_device_aliases_reject_before_restoration(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(archive_capture,'ROOT',Path(folder).resolve()):
            root = Path(folder).resolve(); source,_ = self.fixture(root); out = root/'.local-runs/packed'
            archive_capture.pack(source,out)
            names = ('NUL','nul.txt','CON','COM1.log','LPT9','COM¹','CONIN$','CONOUT$',
                     'a.','a ','a/child.','bad?name','bad|name','x'*256)
            for number,name in enumerate(names):
                with self.subTest(unfaithful_component=name):
                    def mutate(entries):
                        data = {info.filename:(info,body) for info,body in entries}
                        one = dict(json.loads(data['manifest.jsonl'][1].splitlines()[0]),path=name)
                        manifest = json.dumps(one).encode()+b'\n'
                        metadata = {'format':'rillscope-cas-capture-v1','files':1,'objects':1,'bytes':one['bytes'],
                                    'manifest_sha256':hashlib.sha256(manifest).hexdigest()}
                        yield 'manifest.jsonl',manifest
                        yield 'metadata.json',json.dumps(metadata).encode()
                        yield data['objects/'+one['sha256']]
                    bad = root/('.local-runs/alias-'+str(number)+'.zip')
                    self.rewrite(out/'capture.zip',bad,mutate)
                    # Inspect first: the failing baseline never opens a device.
                    with self.assertRaises(ValueError): archive_capture.inspect(bad)
                    destination = root/('.local-runs/rejected-'+str(number))
                    with self.assertRaises(ValueError): archive_capture.restore(bad,destination)
                    self.assertFalse(destination.exists())

    def test_upload_bound_retains_complete_pending_capture(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(archive_capture,'ROOT',Path(folder).resolve()):
            root = Path(folder).resolve(); source,_ = self.fixture(root); out = root/'.local-runs/packed'
            with patch.object(archive_capture,'MAX_ARCHIVE',1): result = archive_capture.pack(source,out)
            self.assertEqual(result['status'],'BLOCKED')
            self.assertFalse((out/'capture.zip').exists())
            self.assertEqual(len(archive_capture.inspect(out/'capture.pending.zip')[0]),4)

    def test_owning_boundary_and_recursive_output_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(archive_capture,'ROOT',Path(folder).resolve()):
            root = Path(folder).resolve(); source,_ = self.fixture(root)
            with self.assertRaises(ValueError): archive_capture.pack(source,source/'recursive')
            with self.assertRaises(ValueError): archive_capture.pack(root,root/'.local-runs/out')
            self.assertFalse((source/'recursive').exists())


if __name__ == '__main__': unittest.main()
