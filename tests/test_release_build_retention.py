"""Keep build provenance when a release gate succeeds or fails before capture."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import archive_capture
import retain_release

BUILD_FILES=('build.json','cargo.stdout','cargo.stderr','compiler.stdout','compiler.stderr')


class ReleaseBuildRetention(unittest.TestCase):
    def write_build(self,root,path,label):
        expected={}
        for name in BUILD_FILES:
            target=root/path/name;target.parent.mkdir(parents=True,exist_ok=True)
            data=('unit '+label+' '+name+' retained original bytes\n').encode()
            target.write_bytes(data);expected[(Path(path)/name).as_posix()]=data
        return expected

    def retain(self,root):
        command=root/'.local-runs/release-command';command.mkdir(parents=True,exist_ok=True)
        (command/'stdout.txt').write_bytes(b'unit release failure, no product execution\n')
        with patch.object(retain_release,'ROOT',root),patch.object(archive_capture,'ROOT',root):
            out=root/'.local-runs/retained';result=retain_release.retain(out)
        self.assertEqual(result['status'],'RETAINED')
        return {row['source']:(out/row['file']).read_bytes() for row in result['metadata']}

    def test_all_primary_functional_build_proofs_survive_exact_roots(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();expected={}
            for path,label in [('.local-runs/build/dev-first','primary first'),
                               ('.local-runs/build/dev-second','primary second'),
                               ('.local-runs/clean-unit/c/.local-runs/build/dev-primary','fresh primary')]:
                expected.update(self.write_build(root,path,label))
            hidden=root/'.local-runs/build/dev-first/target/private-canary';hidden.parent.mkdir();hidden.write_bytes(b'not selected')
            actual=self.retain(root)
            for path,data in expected.items():
                self.assertIn(path,actual,'primary functional build proof omitted')
                self.assertEqual(actual[path],data)
            self.assertFalse(any('/target/' in name for name in actual))

    def test_failed_experiment_build_without_grid_is_retained(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();expected={}
            for path,label in [('.local-runs/bench/s-failed/build','NULL-sort build failure'),
                               ('.local-runs/benchmark-failed/build','reference build failure')]:
                expected.update(self.write_build(root,path,label))
            actual=self.retain(root)
            for path,data in expected.items():
                self.assertIn(path,actual,'pre-capture build failure was omitted')
                self.assertEqual(actual[path],data)

    def test_too_many_primary_builds_fail_explicitly(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve()
            for index in range(65):
                (root/'.local-runs/build'/('dev-'+str(index))).mkdir(parents=True)
            with patch.object(retain_release,'ROOT',root),patch.object(archive_capture,'ROOT',root):
                with self.assertRaisesRegex(ValueError,'entry bound'):
                    retain_release.retain(root/'.local-runs/retained')

    def test_failed_harness_bytes_survive_separate_raw_retention(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();failure=root/'.local-runs/pf-unit';failure.mkdir(parents=True)
            expected={'stdout':b'unit original child bytes\n','stderr':b'unit child error\n',
                      'process.json':b'{"status":"FAIL","unit_fixture":true}\n'}
            for name,data in expected.items(): (failure/name).write_bytes(data)
            command=root/'.local-runs/release-command';command.mkdir()
            (command/'stdout.txt').write_bytes(b'unit failed release\n')
            with patch.object(retain_release,'ROOT',root),patch.object(archive_capture,'ROOT',root):
                out=root/'.local-runs/retained';result=retain_release.retain(out)
                self.assertEqual(result['status'],'RETAINED')
                self.assertEqual(len(result['captures']),1,'separate harness failure bytes were omitted')
                self.assertEqual(result['captures'][0]['kind'],'benchmark-harness-failure')
                restored=root/'.local-runs/restored'
                archive_capture.restore(out/result['captures'][0]['package']/'capture.zip',restored)
                for name,data in expected.items(): self.assertEqual((restored/name).read_bytes(),data)


if __name__=='__main__': unittest.main()
