"""Dispatch control-flow tests; simulated subprocess returns are not product runs."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'benchmarks'))
import dispatch


class CaptureDispatch(unittest.TestCase):
    def invoke(self, arguments, outcomes):
        proof = {'bins':{'rillscope-measure':{'path':'target/fake-measure'}}}
        with patch.object(sys,'argv',['dispatch.py',*arguments]), \
                patch.object(dispatch,'build_release',return_value=proof) as build, \
                patch.object(dispatch.subprocess,'call',side_effect=outcomes) as call:
            code = dispatch.main()
        return code,build.call_count,[item.args[0] for item in call.call_args_list]

    def test_default_full_propagates_validation_failure(self):
        code,build,calls = self.invoke(['--profile','full'],[0,23])
        self.assertEqual((code,build,len(calls)),(23,1,2))
        self.assertEqual(Path(calls[0][1]).name,'run.py')
        self.assertEqual(calls[0][calls[0].index('--profile')+1],'full')
        self.assertEqual(Path(calls[1][1]).name,'verify.py')
        self.assertEqual(calls[1][2],calls[0][calls[0].index('--out')+1])

    def test_explicit_capture_collects_full_profile_without_claiming_validation(self):
        code,build,calls = self.invoke(['--profile','full','--capture-only'],[0])
        self.assertEqual((code,build,len(calls)),(0,1,1))
        self.assertEqual(Path(calls[0][1]).name,'run.py')
        self.assertEqual(calls[0][calls[0].index('--profile')+1],'full')

    def test_failed_collection_cannot_be_hidden_by_capture_only(self):
        code,_,calls = self.invoke(['--profile','full','--capture-only'],[17])
        self.assertEqual((code,len(calls)),(17,1))

    def test_capture_only_rejects_reduced_profiles_before_build(self):
        for profile in ('instrumentation-pilot','sort-null-supplement','cancellation-only'):
            with self.subTest(profile=profile), patch.object(sys,'argv',
                    ['dispatch.py','--profile',profile,'--capture-only']), \
                    patch.object(dispatch,'build_release') as build:
                with self.assertRaises(SystemExit) as error: dispatch.main()
                self.assertEqual(error.exception.code,2)
                build.assert_not_called()


if __name__ == '__main__': unittest.main()
