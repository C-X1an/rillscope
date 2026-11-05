"""Literal interruption controls for archive-context acquisition and cleanup."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import capture_read_view as module


class CaptureReadViewInterruptionTests(unittest.TestCase):
    def setUp(self):
        base = ROOT / '.local-runs'
        base.mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix='view-interrupt-', dir=base)
        self.folder = Path(self.tmp.name).resolve()
        self.assertTrue(self.folder.is_relative_to(base.resolve()))
        self.archive = self.folder / 'literal.zip'
        self.literal = b'[[null,1],[null,1]]\n'
        digest = hashlib.sha256(self.literal).hexdigest()
        row = {'path': 'rows.json', 'sha256': digest, 'bytes': len(self.literal)}
        listing = json.dumps(row, separators=(',', ':')).encode() + b'\n'
        metadata = {'format': 'rillscope-cas-capture-v1', 'files': 1,
                    'objects': 1, 'bytes': len(self.literal),
                    'manifest_sha256': hashlib.sha256(listing).hexdigest()}
        with zipfile.ZipFile(self.archive, 'x', compression=zipfile.ZIP_DEFLATED) as bundle:
            bundle.writestr('objects/' + digest, self.literal)
            bundle.writestr('manifest.jsonl', listing)
            bundle.writestr('metadata.json', json.dumps(metadata))

    def tearDown(self):
        self.tmp.cleanup()

    def interrupted_context(self, phase, operation, argument, exception_type):
        self.assertIsNone(sys.gettrace(), 'literal control requires an untraced process')
        archive_before = self.archive.read_bytes()
        original = (Path.open, Path.stat, Path.iterdir)
        real_path = module.Path
        view = module.CaptureReadView(self.archive, self.folder / 'view')
        fired = body_executed = False
        caught = None
        armed = phase == 'enter'
        allowed = {'__enter__'} if phase == 'enter' else {'__exit__', '_restore', '_restore_once'}
        lines = Path(module.__file__).read_text(encoding='utf-8').splitlines()
        # Ordinary attribute-assignment faults cover every individual store.
        # The proxy forwards all reads/calls/stores to the real Path class.
        class PathAssignments:
            def __call__(self, *args, **kwargs):
                return real_path(*args, **kwargs)

            def __getattr__(self, name):
                return getattr(real_path, name)

            def __setattr__(self, name, value):
                nonlocal fired
                if name == argument and armed and not fired:
                    fired = True
                    raise exception_type('literal interruption')
                setattr(real_path, name, value)

        def trace(frame, event, arg):
            nonlocal fired
            if frame.f_globals is module.__dict__ and frame.f_code.co_name in allowed and event == 'line':
                line = lines[frame.f_lineno - 1].strip()
                matches = (('STORE_GLOBAL' in operation and line == '_ACTIVE = True')
                           or ('RETURN_VALUE' in operation and line == 'return self')
                           or ('LOAD_ATTR' in operation and line == 'self._zip.close()'))
                if matches and not fired:
                    fired = True
                    sys.settrace(None)
                    raise exception_type('literal interruption')
            return trace

        try:
            try:
                if 'STORE_ATTR' in operation:
                    module.Path = PathAssignments()
                else:
                    # Line tracing supports propagated exceptions. CPython's
                    # opcode-trace exception semantics are not used here.
                    sys.settrace(trace)
                with view:
                    body_executed = True
                    self.assertEqual((view.mount / 'rows.json').read_bytes(), self.literal)
                    armed = True
            except BaseException as error:
                caught = error
            finally:
                sys.settrace(None)
            captured = ((Path.open, Path.stat, Path.iterdir) == original,
                        getattr(view, '_zip', None) is None or view._zip.fp is None,
                        module._ACTIVE)
        finally:
            # Test isolation only: assertions use the state captured before this
            # cleanup, so a leaked method or handle remains a real test failure.
            sys.settrace(None)
            module.Path = real_path
            Path.open, Path.stat, Path.iterdir = original
            module._ACTIVE = False
            if getattr(view, '_zip', None) is not None:
                view._zip.close()
        self.assertTrue(fired, 'the requested interruption point was never reached')
        self.assertIs(type(caught), exception_type)
        self.assertEqual(str(caught), 'literal interruption')
        self.assertEqual(body_executed, phase == 'exit')
        self.assertEqual(captured, (True, True, False),
                         'methods, archive handle and active flag must recover before caller cleanup')
        self.assertEqual(self.archive.read_bytes(), archive_before)
        with module.CaptureReadView(self.archive, self.folder / 'next-view') as next_view:
            self.assertEqual((next_view.mount / 'rows.json').read_bytes(), self.literal)
        self.assertEqual((Path.open, Path.stat, Path.iterdir), original)

    def test_normal_context_retains_duplicate_null_rows_and_restores_methods(self):
        original = (Path.open, Path.stat, Path.iterdir)
        with module.CaptureReadView(self.archive, self.folder / 'view') as view:
            self.assertEqual((view.mount / 'rows.json').read_bytes(), b'[[null,1],[null,1]]\n')
        self.assertEqual((Path.open, Path.stat, Path.iterdir), original)
        self.assertIsNone(view._zip.fp)
        self.assertFalse(module._ACTIVE)

    def test_failed_enter_at_each_install_store_cleans_all_methods_and_archive(self):
        for name in ('open', 'stat', 'iterdir'):
            for kind in (KeyboardInterrupt, SystemExit):
                with self.subTest(attribute=name, exception=kind.__name__):
                    self.interrupted_context('enter', {'STORE_ATTR'}, name, kind)

    def test_failed_enter_at_active_flag_cleans_all_methods_and_archive(self):
        for kind in (KeyboardInterrupt, SystemExit, RuntimeError):
            with self.subTest(exception=kind.__name__):
                self.interrupted_context('enter', {'STORE_GLOBAL'}, '_ACTIVE', kind)

    def test_failed_enter_immediately_before_return_cleans_all_methods_and_archive(self):
        for kind in (KeyboardInterrupt, SystemExit):
            with self.subTest(exception=kind.__name__):
                self.interrupted_context('enter', {'RETURN_VALUE', 'RETURN_CONST'}, None, kind)

    def test_exit_interruption_at_each_restore_store_still_releases_every_resource(self):
        for name in ('open', 'stat', 'iterdir'):
            for kind in (KeyboardInterrupt, SystemExit):
                with self.subTest(attribute=name, exception=kind.__name__):
                    self.interrupted_context('exit', {'STORE_ATTR'}, name, kind)

    def test_exit_interruption_before_close_still_closes_archive(self):
        for kind in (KeyboardInterrupt, SystemExit):
            with self.subTest(exception=kind.__name__):
                self.interrupted_context('exit', {'LOAD_ATTR', 'LOAD_METHOD'}, 'close', kind)

    def test_body_base_exceptions_propagate_after_resources_are_released(self):
        original = (Path.open, Path.stat, Path.iterdir)
        for kind in (KeyboardInterrupt, SystemExit):
            with self.subTest(exception=kind.__name__):
                view = module.CaptureReadView(self.archive, self.folder / 'view')
                with self.assertRaisesRegex(kind, 'body interruption'):
                    with view:
                        raise kind('body interruption')
                self.assertEqual((Path.open, Path.stat, Path.iterdir), original)
                self.assertIsNone(view._zip.fp)
                self.assertFalse(module._ACTIVE)


if __name__ == '__main__':
    unittest.main(verbosity=2)
