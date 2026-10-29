"""Actual byte/archival controls over small synthetic failed-release fixtures."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import archive_capture
import retain_release


class ReleaseRetention(unittest.TestCase):
    def fixture(self,root,compact=False):
        command=root/'.local-runs/release-command'; command.mkdir(parents=True)
        (command/'stdout.txt').write_bytes(b'unit canonical failure, not a product run\n')
        checkout=root/'.local-runs/clean-unit'/('c' if compact else 'checkout')
        for stage in ('grid','cancel'):
            path=checkout/'.local-runs/benchmark-unit'/stage; path.mkdir(parents=True)
            (path/'actual-error.txt').write_bytes(b'unit retained failure bytes\n')
        hidden=checkout/'.git'; hidden.mkdir(); (hidden/'config').write_bytes(b'unit private canary\n')
        return checkout

    def test_every_available_failed_capture_restores_and_git_is_excluded(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); self.fixture(root)
            with patch.object(retain_release,'ROOT',root),patch.object(archive_capture,'ROOT',root):
                out=root/'.local-runs/retained'; result=retain_release.retain(out)
                self.assertEqual((result['status'],len(result['captures'])),('RETAINED',2))
                for index,row in enumerate(result['captures']):
                    restored=root/'.local-runs'/('restored-'+str(index))
                    archive_capture.restore(out/row['package']/'capture.zip',restored)
                    self.assertEqual((restored/'actual-error.txt').read_bytes(),b'unit retained failure bytes\n')
            self.assertEqual([row['source'] for row in result['metadata']],['.local-runs/release-command/stdout.txt'])
            self.assertFalse(any('.git' in str(path.relative_to(out)) for path in out.rglob('*')))

    def test_archive_cap_failure_is_explicit_and_never_reported_retained(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); self.fixture(root)
            with patch.object(retain_release,'ROOT',root),patch.object(archive_capture,'ROOT',root), \
                    patch.object(archive_capture,'MAX_ARCHIVE',1):
                out=root/'.local-runs/retained'; result=retain_release.retain(out)
            self.assertEqual(result['status'],'FAIL')
            self.assertEqual([row['result']['status'] for row in result['captures']],['BLOCKED','BLOCKED'])
            self.assertEqual(json.loads((out/'retention.json').read_bytes())['status'],'FAIL')

    def test_multiple_fresh_attempts_are_not_cherry_picked(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); self.fixture(root)
            (root/'.local-runs/clean-second').mkdir()
            with patch.object(retain_release,'ROOT',root),patch.object(archive_capture,'ROOT',root):
                with self.assertRaisesRegex(ValueError,'one exact fresh'):
                    retain_release.retain(root/'.local-runs/retained')

    def test_required_sort_null_dispatch_capture_is_retained(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); command=root/'.local-runs/release-command'; command.mkdir(parents=True)
            (command/'stdout.txt').write_bytes(b'unit release attempt\n')
            raw=root/'.local-runs/bench/s-unit/grid'; raw.mkdir(parents=True)
            (raw/'failed-observation.txt').write_bytes(b'unit sort failure retained\n')
            with patch.object(retain_release,'ROOT',root),patch.object(archive_capture,'ROOT',root):
                out=root/'.local-runs/retained'; result=retain_release.retain(out)
                self.assertEqual(len(result['captures']),1,'required NULL-sort raw capture was omitted')
                restored=root/'.local-runs/restored'
                archive_capture.restore(out/result['captures'][0]['package']/'capture.zip',restored)
                self.assertEqual((restored/'failed-observation.txt').read_bytes(),b'unit sort failure retained\n')

    def test_metadata_is_durable_before_fallback_pack_can_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); self.fixture(root); out=root/'.local-runs/retained'
            def interrupted(*args):
                self.assertTrue((out/'retention.json').is_file(),'progress metadata must exist before expensive packing')
                self.assertTrue(list((out/'metadata').glob('*/stdout.txt')),'nested/outer command bytes not yet secured')
                raise TimeoutError('unit simulated pack interruption, not an actual benchmark timeout')
            with patch.object(retain_release,'ROOT',root),patch.object(archive_capture,'ROOT',root), \
                    patch.object(archive_capture,'pack',side_effect=interrupted):
                result=retain_release.retain(out)
            self.assertEqual(result['status'],'FAIL')
            self.assertEqual(len(result['metadata']),1)

    def test_existing_complete_cas_is_copied_without_repacking_its_raw_stage(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); checkout=self.fixture(root)
            experiment=checkout/'.local-runs/benchmark-unit'; old_pack=archive_capture.pack
            with patch.object(retain_release,'ROOT',root),patch.object(archive_capture,'ROOT',root):
                early=experiment/'capture-grid'; old_pack(experiment/'grid',early)
                original=(early/'capture.zip').read_bytes()
                def remaining_only(source,out):
                    self.assertNotEqual(Path(source).name,'grid','completed early CAS was needlessly repacked')
                    return old_pack(source,out)
                with patch.object(archive_capture,'pack',side_effect=remaining_only):
                    out=root/'.local-runs/retained'; result=retain_release.retain(out)
            self.assertEqual(result['status'],'RETAINED')
            package=next(row for row in result['captures'] if row['source'].endswith('/grid'))
            self.assertEqual((out/package['package']/'capture.zip').read_bytes(),original)

    def test_compact_fresh_checkout_retains_every_failed_stage(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();self.fixture(root,compact=True)
            with patch.object(retain_release,'ROOT',root),patch.object(archive_capture,'ROOT',root):
                out=root/'.local-runs/retained';result=retain_release.retain(out)
                self.assertEqual(result['status'],'RETAINED')
                self.assertEqual(len(result['captures']),2)
                for index,row in enumerate(result['captures']):
                    restored=root/'.local-runs'/('restored-'+str(index))
                    archive_capture.restore(out/row['package']/'capture.zip',restored)
                    self.assertEqual((restored/'actual-error.txt').read_bytes(),b'unit retained failure bytes\n')

    def test_publication_transport_and_control_bytes_survive_retention(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();local=root/'.local-runs'
            command=local/'release-command';command.mkdir(parents=True)
            (command/'stdout.txt').write_bytes(b'unit canonical failure\n')
            expected={
                'publication-boundary-unit':('trace.txt',b'actual unit boundary trace\n'),
                'publication-decision-unit':('stdout.bin',b'actual unit terminal envelope\n'),
                'publication-control-unit/commands':('mutant/stderr.txt',b'actual unit mutation failure\n'),
                'publication-control-unit/checkout/.local-runs/baseline':('stdout.bin',b'unit baseline\n'),
                'publication-control-unit/checkout/.local-runs/mutant':('stdout.bin',b'unit mutant\n'),
                'publication-control-unit/checkout/.local-runs/restored':('stdout.bin',b'unit restored\n')}
            for directory,(file,data) in expected.items():
                path=local/directory/file;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
            control=local/'publication-control-unit'
            (control/'summary.json').write_bytes(b'{"unit_status":"FAIL"}\n')
            hidden=control/'checkout/.git';hidden.mkdir(parents=True)
            (hidden/'config').write_bytes(b'unrelated unit configuration must stay excluded\n')
            with patch.object(retain_release,'ROOT',root),patch.object(archive_capture,'ROOT',root):
                out=local/'retained';result=retain_release.retain(out)
                self.assertEqual(result['status'],'RETAINED')
                by_source={row['source']:row for row in result['captures']}
                self.assertEqual(len(by_source),len(expected),'a publication raw campaign was omitted')
                for index,(directory,(file,data)) in enumerate(expected.items()):
                    row=by_source['.local-runs/'+directory];restored=local/('restored-'+str(index))
                    archive_capture.restore(out/row['package']/'capture.zip',restored)
                    self.assertEqual((restored/file).read_bytes(),data)
                    self.assertFalse(any('.git' in path.parts for path in restored.rglob('*')))
            self.assertTrue(any(row['source'].endswith('/summary.json') for row in result['metadata']))

    def test_separate_system_setup_receipt_and_raw_streams_are_retained(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();setup=root/'.local-runs/release-system-setup';setup.mkdir(parents=True)
            expected={'receipt.json':b'{"unit_owner":0}\n','stdout.txt':b'unit system setup\n','stderr.txt':b'unit failure\n'}
            for name,data in expected.items(): (setup/name).write_bytes(data)
            with patch.object(retain_release,'ROOT',root),patch.object(archive_capture,'ROOT',root):
                out=root/'.local-runs/retained';result=retain_release.retain(out)
            self.assertEqual(result['status'],'RETAINED')
            self.assertEqual(len(result['metadata']),3,'separate privileged setup evidence was omitted')
            for row in result['metadata']:
                self.assertEqual((out/row['file']).read_bytes(),expected[Path(row['source']).name])

    def test_original_guest_export_result_bytes_for_all_three_stages_are_retained(self):
        with tempfile.TemporaryDirectory(prefix='rill-retention-unit-') as folder:
            root=Path(folder).resolve();checkout=self.fixture(root,compact=True)
            supplement=checkout/'.local-runs/bench/s-unit/grid';supplement.mkdir(parents=True)
            (supplement/'actual-error.txt').write_bytes(b'fixture supplement failure\n')
            expected={}
            for experiment,stage in [(checkout/'.local-runs/benchmark-unit','grid'),
                (checkout/'.local-runs/benchmark-unit','cancel'),(supplement.parent,'grid')]:
                file=experiment/('capture-'+stage)/'host-export-result.json';file.parent.mkdir()
                original=b'{"fixture":"byte custody only","status":"FAIL"}\r\n'
                file.write_bytes(original);expected[file.relative_to(root).as_posix()]=original
            with patch.object(retain_release,'ROOT',root),patch.object(archive_capture,'ROOT',root):
                out=root/'.local-runs/retained';result=retain_release.retain(out)
            actual={row['source']:(out/row['file']).read_bytes() for row in result['metadata'] if row['source'] in expected}
            self.assertEqual(actual,expected)
            self.assertEqual(len(actual),3)
            self.assertEqual(len(result['captures']),3)


if __name__=='__main__': unittest.main()
