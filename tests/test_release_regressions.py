"""Explicit validator fixtures; none establish dependency or signal execution."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT / 'scripts')); sys.path.insert(0,str(ROOT / 'benchmarks'))
import license_audit
import cancellation


class ReleaseRegressions(unittest.TestCase):
    def test_and_license_requires_each_mandatory_notice_component(self):
        package = copy.deepcopy(next(row for row in json.loads((ROOT / 'licenses/dependency-inventory.json').read_bytes())['packages'] if row['name'] == 'unicode-ident'))
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve(); (root / 'licenses').mkdir()
            (root / 'Cargo.lock').write_bytes(b'unit metadata fixture, not a resolved lock')
            (root / 'LICENSE').write_bytes((ROOT / 'LICENSE').read_bytes())
            for notice in package['notices']:
                notice['spdx_license'] = 'Unicode-3.0' if notice['path'].endswith('LICENSE-UNICODE') else 'MIT'
                target = root / notice['path']; target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes((ROOT / notice['path']).read_bytes())
                upstream = root / '.unit-source/unicode-ident' / target.name
                upstream.parent.mkdir(parents=True,exist_ok=True); upstream.write_bytes(target.read_bytes())
            inventory = {'lockfile_sha256':hashlib.sha256((root / 'Cargo.lock').read_bytes()).hexdigest(),'packages':[package]}
            path = root / 'licenses/dependency-inventory.json'; path.write_text(json.dumps(inventory))
            metadata = {'packages':[{'name':package['name'],'version':package['version'],'license':package['declared_license'],'source':package['source'],
                                     'manifest_path':str(root / '.unit-source/unicode-ident/Cargo.toml')},
                                    {'name':'unit-first-party','source':None,'license':'MIT'}]}
            with patch.object(license_audit,'ROOT',root), patch.object(license_audit.subprocess,'run',return_value=subprocess.CompletedProcess([],0,json.dumps(metadata).encode(),b'')):
                self.assertEqual(license_audit.audit()['errors'], [])
                omitted = next(item for item in package['notices'] if item['spdx_license'] == 'Unicode-3.0')
                package['notices'].remove(omitted); (root / omitted['path']).unlink()
                path.write_text(json.dumps(inventory))
                self.assertTrue(license_audit.audit()['errors'], 'mandatory Unicode component was omitted but audit stayed green')

    def test_unstable_cancellation_artifacts_cannot_validate_as_passing(self):
        # All events are synthetic metadata fixtures, never an observed cancellation.
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); build_dir = root / 'build'; build_dir.mkdir()
            for stream in ('stdout','stderr'): (build_dir / ('cargo.' + stream)).write_bytes(b'unit fixture')
            build = {'status':'PASS','source':{'sha256':'a' * 64},'source_after_sha256':'a' * 64,
                     'bins':{'rillscope':{'sha256':'b' * 64}},
                     **{'raw_' + stream + '_sha256':cancellation.sha(build_dir / ('cargo.' + stream)) for stream in ('stdout','stderr')}}
            (build_dir / 'build.json').write_text(json.dumps(build))
            (root / 'manifest.json').write_text(json.dumps({'build':build,'source':{'sha256':'a' * 64},'binary_sha256':'b' * 64}))
            payload = json.dumps({'version':1,'implementation':'rust','status':'error','error':{'code':'E_CANCELLED'}}).encode()
            rows = []
            for seed in cancellation.SEEDS:
                case = root / ('seed-' + str(seed)); case.mkdir()
                (case / 'input').write_bytes(b'unit fixture')
                for phase, count in (('warmup',5),('measured',30)):
                    for repetition in range(count):
                        tag = f'{phase}-{repetition:02d}'
                        (case / (tag + '.stdout')).write_bytes(payload); (case / (tag + '.stderr')).write_bytes(b'')
                        (case / (tag + '.phase')).write_bytes(b'join_inner\n')
                        rows.append({'seed':seed,'phase':phase,'repetition':repetition,'started_ns':0,'checkpoint_observed_ns':1,
                                     'signal_sent_ns':2,'terminal_and_exit_observed_ns':3,'cancel_upper_bound_ns':1,
                                     'exit_code':4,'problems':[],'inputs':{'input':cancellation.sha(case / 'input')},
                                     'stdout_sha256':hashlib.sha256(payload).hexdigest(),'stderr_sha256':hashlib.sha256(b'').hexdigest()})
            samples = root / 'samples.jsonl'; samples.write_text(''.join(json.dumps(row) + '\n' for row in rows))
            result = dict(cancellation.cancellation_summary(rows,False),samples_sha256=cancellation.sha(samples))
            (root / 'results.json').write_text(json.dumps(result))
            self.assertEqual(result['status'],'FAIL')
            self.assertEqual(cancellation.verify_cancellation(root)['status'],'FAIL')


if __name__ == '__main__': unittest.main()
