"""Root owns lifecycle, while only existing non-root identity builds Rust."""
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import prepare_kvm_reference as prepare


class PreparationOwnership(unittest.TestCase):
    def test_user_prefix_drops_identity_before_any_rust_or_path_lookup(self):
        account = SimpleNamespace(pw_uid=1001, pw_gid=127, pw_dir='/home/runner')
        prefix = prepare.runner_prefix(account)
        self.assertEqual(prefix[:5], ['/usr/bin/setpriv', '--reuid=1001', '--regid=127', '--clear-groups', '--'])
        self.assertEqual(prefix[5], '/usr/bin/env')
        self.assertIn('HOME=/home/runner', prefix)
        self.assertIn('CARGO_HOME=/home/runner/.cargo', prefix)
        for account in [SimpleNamespace(pw_uid=0, pw_gid=127, pw_dir='/root'),
            SimpleNamespace(pw_uid=1001, pw_gid=0, pw_dir='/home/runner'),
            SimpleNamespace(pw_uid=1001, pw_gid=127, pw_dir='/home/../root')]:
            with self.assertRaises(ValueError): prepare.runner_prefix(account)

    def run_preparation(self, fail=False):
        temp = tempfile.TemporaryDirectory(dir=ROOT / '.local-runs'); self.addCleanup(temp.cleanup)
        out = Path(temp.name) / 'new'; seen = []; owner = Mock()
        owner.finish.return_value = {'status': 'PASS', 'remaining_active_processes': 0}
        def checked(name, command, **kwargs):
            seen.append((name, command))
            if fail: raise OSError('original setup failure')
            return b''
        pwd = SimpleNamespace(getpwnam=lambda name: SimpleNamespace(pw_uid=1001, pw_gid=127, pw_dir='/home/runner'))
        with patch.object(prepare.platform, 'system', return_value='Linux'), \
             patch.object(prepare.os, 'geteuid', return_value=0, create=True), \
             patch.dict(sys.modules, {'pwd': pwd}), \
             patch.object(prepare, 'owned_output', return_value=out), \
             patch.object(prepare, 'LinuxOwnedChildren', return_value=owner), \
             patch.object(prepare, 'TrialCommands', return_value=checked), \
             patch.dict(prepare.os.environ), \
             patch.object(prepare.signal, 'signal'):
            code = prepare.main(['--out', str(out), '--run-as', 'runner'])
        return code, seen, owner, json.loads((out / 'results.json').read_bytes())

    def test_root_lifecycle_and_user_build_share_one_finite_owner(self):
        code, seen, owner, result = self.run_preparation()
        self.assertEqual(code, 0)
        self.assertEqual([name for name, _ in seen], ['system', 'pinned-rust', 'release-build', 'owned-lifecycle'])
        self.assertEqual(seen[0][1][0], '/usr/bin/python3')
        self.assertEqual(seen[-1][1][0], '/usr/bin/python3')
        for _, command in seen[1:3]: self.assertEqual(command[:3], ['/usr/bin/setpriv', '--reuid=1001', '--regid=127'])
        self.assertFalse(any('sudo' in command for _, command in seen))
        owner.finish.assert_called_once_with(None)
        self.assertEqual(result['status'], 'PREPARED')
        self.assertFalse(result['reference_qualified'])

    def test_original_preparation_failure_is_not_retried_and_owned_cleanup_runs(self):
        code, seen, owner, result = self.run_preparation(fail=True)
        self.assertEqual(code, 1); self.assertEqual(len(seen), 1)
        self.assertEqual(result['status'], 'FAIL')
        owner.finish.assert_called_once_with(None)


if __name__ == '__main__': unittest.main()
