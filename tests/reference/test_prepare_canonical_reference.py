"""No host utility installation occurs in these platform/budget controls."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'benchmarks')]
import prepare_canonical_reference as prepare


class ProvisionControls(unittest.TestCase):
    def test_unavailable_controller_precedes_output_or_package_operations(self):
        with patch.object(prepare, 'actual_controller', side_effect=ValueError('BLOCKED: scoped controller missing')), \
            patch.object(prepare.archive_capture, 'owned') as owned:
            with self.assertRaisesRegex(ValueError, 'scoped controller missing'):
                prepare.provision(Path('missing'), 900)
            owned.assert_not_called()
            self.assertEqual(prepare.main(['--out', 'missing', '--budget-seconds', '900']), 77)

    def test_invalid_original_budget_precedes_files_or_commands(self):
        for seconds in (True, 0, -1, 1801):
            with self.subTest(seconds=seconds), patch.object(prepare, 'actual_controller'), \
                patch.object(prepare.archive_capture, 'owned') as owned:
                with self.assertRaisesRegex(ValueError, 'finite original'):
                    prepare.provision(Path('missing'), seconds)
                owned.assert_not_called()


if __name__ == '__main__': unittest.main()
