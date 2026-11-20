"""The correspondence checker must reject incomplete or altered evidence."""

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "authorization_correspondence",
    ROOT / "scripts/check-authorization-correspondence.py",
)
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class AuthorizationEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Actual pinned-compiler output, not a second implementation of Cedar.
        cls.rows = (
            (ROOT / "crates/enclave-agent-runtime/tests/data/cedar-lean-4.14.0.csv")
            .read_text()
            .splitlines()
        )

    def test_complete_compiled_domain_is_accepted(self):
        self.assertEqual(CHECKER.vectors("\n".join(self.rows)), self.rows)

    def test_missing_duplicate_and_reordered_inputs_are_rejected(self):
        for changed in [
            self.rows[:-1],
            [self.rows[1], *self.rows[1:]],
            [self.rows[1], self.rows[0], *self.rows[2:]],
        ]:
            with self.assertRaises(ValueError):
                CHECKER.vectors("\n".join(changed))

    def test_decision_domain_and_field_count_are_checked(self):
        for suffix in ["2", "", "0,extra"]:
            changed = self.rows.copy()
            changed[0] = changed[0].rsplit(",", 1)[0] + "," + suffix
            with self.assertRaises(ValueError):
                CHECKER.vectors("\n".join(changed))


if __name__ == "__main__":
    unittest.main()
