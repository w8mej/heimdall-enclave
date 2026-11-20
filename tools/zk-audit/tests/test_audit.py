import copy
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "audit_chips", Path(__file__).parents[1] / "audit_chips.py"
)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class ExtractedConstraintTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.export = audit.load_constraints()

    def test_real_rust_airs_admit_distinct_outputs_for_equal_inputs(self):
        report = audit.audit(self.export)
        self.assertTrue(all(report["epoch_controls"].values()))
        for probe in report["probes"]:
            with self.subTest(chip=probe["chip"]):
                self.assertEqual(probe["outcome"], "COUNTEREXAMPLE")
                a, b = copy.deepcopy(probe["first_trace"]), copy.deepcopy(
                    probe["second_trace"]
                )
                self.assertNotEqual(
                    a[0][probe["output_column"]], b[0][probe["output_column"]]
                )
                a[0][probe["output_column"]] = b[0][probe["output_column"]]
                self.assertEqual(a, b)

    def test_compiled_deterministic_air_rejects_a_different_output(self):
        chip, p = self.export["DeterministicControl"], self.export["prime"]
        self.assertTrue(audit.satisfies(chip, [[11, 11], [0, 0]], [], p))
        self.assertFalse(audit.satisfies(chip, [[11, 12], [0, 0]], [], p))

    def test_noncanonical_or_malformed_traces_are_errors(self):
        chip, p = self.export["DeterministicControl"], self.export["prime"]
        for rows in ([[0]], [[p, p], [0, 0]], [[-1, -1], [0, 0]]):
            with self.assertRaises(ValueError):
                audit.satisfies(chip, rows, [], p)

    def test_polynomials_are_evaluated_in_the_exported_prime_field(self):
        p = self.export["prime"]
        expression = ["add", ["constant", p - 1], ["constant", 1]]
        self.assertEqual(audit.evaluate(expression, [[0], [0]], [], 0, p), 0)


if __name__ == "__main__":
    unittest.main()
