"""Generated controller fixtures: no real operation, observer, host probe or child."""
import unittest

import identity_cache_observe as control
import identity_cache_capture as capture
import identity_cache_maintenance as maintenance


class ControllerTests(unittest.TestCase):
    def test_maintenance_production_approval_pins_are_absent(self):
        self.assertIsNone(maintenance.EXPECTED_APPROVAL_SHA256)
        self.assertIsNone(maintenance.EXPECTED_APPROVAL_BYTES)

    def test_fixed_operation_budgets(self):
        self.assertEqual(control.POLICY['capture']['wall_seconds'], 90)
        self.assertEqual(control.POLICY['continue']['cutoffs'], [580, 585, 590, 600])

    def test_capture_has_fixed_callable(self):
        self.assertTrue(callable(capture.run))


if __name__ == '__main__':
    unittest.main()
