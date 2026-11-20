#!/usr/bin/env python3
"""Executable source-policy regressions; never dispatch a hardware CI job."""

import importlib.util
import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "hardware_ci", ROOT / "scripts/check-hardware-ci.py"
)
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class HardwarePolicyTests(unittest.TestCase):
    def fixture(self, transform):
        directory = tempfile.TemporaryDirectory(prefix="mcpmac-hardware-ci-")
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        workflows = root / ".github/workflows"
        workflows.mkdir(parents=True)
        for source in (ROOT / ".github/workflows").glob("*.y*ml"):
            (workflows / source.name).write_text(
                transform(source.name, source.read_text())
            )
        return root

    def reject(self, transform):
        with self.assertRaises(POLICY.PolicyError):
            POLICY.check_policy(self.fixture(transform))

    def test_current_policy_and_hosted_pr_jobs(self):
        self.assertEqual(POLICY.check_policy(ROOT), 2048)

    def test_original_variable_only_gate_exposes_pr(self):
        original = "${{ vars.ENABLE_BARE_METAL_SEP == 'true' }}"
        atoms = POLICY.condition_atoms(original)
        self.assertTrue(POLICY.permits(atoms, {"vars.ENABLE_BARE_METAL_SEP": "true"}))
        self.reject(
            lambda name, text: text.replace(
                "${{ github.event_name == 'push' && github.ref == 'refs/heads/main' && github.ref_protected && vars.ENABLE_BARE_METAL_SEP == 'true' }}",
                original,
            )
        )

    def test_either_hardware_job_losing_a_guard_is_rejected(self):
        for flag in POLICY.HARDWARE.values():
            for guard in (
                "github.event_name == 'push' && ",
                "github.ref == 'refs/heads/main' && ",
                "github.ref_protected && ",
                f" && vars.{flag} == 'true'",
            ):
                with self.subTest(flag=flag, guard=guard):
                    self.reject(
                        lambda name, text: "\n".join(
                            (
                                line.replace(guard, "")
                                if "if:" in line and flag in line
                                else line
                            )
                            for line in text.splitlines()
                        )
                    )

    def test_or_function_unknown_context_and_lookalike_ref_fail_closed(self):
        for mutation in (
            "github.ref_protected || true",
            "always()",
            "github.fake_protection",
            "github.ref_protected == 'true'",
        ):
            with self.subTest(mutation=mutation):
                self.reject(
                    lambda name, text: text.replace("github.ref_protected", mutation)
                )
        self.reject(
            lambda name, text: text.replace(
                "github.ref == 'refs/heads/main'", "github.ref == 'refs/heads/main '"
            )
        )

    def test_wrong_flag_or_ref_or_event_is_rejected(self):
        for old, new in (
            (
                "vars.ENABLE_BARE_METAL_SEP == 'true'",
                "vars.ENABLE_SELF_HOSTED_M1 == 'true'",
            ),
            ("github.event_name == 'push'", "github.event_name == 'pull_request'"),
            (
                "github.ref == 'refs/heads/main'",
                "github.ref == 'refs/heads/development'",
            ),
        ):
            with self.subTest(new=new):
                self.reject(lambda name, text: text.replace(old, new))

    def test_unreviewed_new_runner_job_is_rejected(self):
        for selection in (
            "self-hosted",
            "[self-hosted, macOS]",
            "${{ inputs.runner }}",
            "{group: bringup-macs}",
        ):
            with self.subTest(selection=selection):
                self.reject(
                    lambda name, text: (
                        text
                        + "\n  unexpected:\n    runs-on: "
                        + selection
                        + "\n    steps: []\n"
                        if name == "ci.yml"
                        else text
                    )
                )

    def test_matrix_include_cannot_sneak_in_hardware(self):
        self.reject(
            lambda name, text: re.sub(
                r"os:\s*\[\s*ubuntu-24\.04,\s*macos-14\s*\]",
                "os: [ubuntu-24.04, macos-14]\n        include:\n          - os: self-hosted",
                text,
            )
        )

    def test_duplicate_yaml_anchors_tags_and_malformed_yaml_are_rejected(self):
        for suffix in (
            "\non: {push: {}}\n",
            "\nextra: &job value\n",
            "\nextra: !!str value\n",
            "\nextra: [\n",
        ):
            with self.subTest(suffix=suffix):
                root = self.fixture(
                    lambda name, text: text + suffix if name == "ci.yml" else text
                )
                with self.assertRaises((POLICY.PolicyError, POLICY.yaml.YAMLError)):
                    POLICY.check_policy(root)

    def test_removal_of_hardware_or_hosted_pr_coverage_is_rejected(self):
        self.reject(
            lambda name, text: text.replace("  bare-metal-sep:", "  renamed-hardware:")
        )
        self.reject(
            lambda name, text: text.replace("  pull_request:", "  pull_request_target:")
        )
        self.reject(
            lambda name, text: text.replace(
                "  ci-vm-compatible:\n", "  ci-vm-compatible:\n    if: false\n"
            )
        )

    def test_hardware_dependency_and_unmasked_source_gate_are_required(self):
        self.reject(
            lambda name, text: text.replace("    needs: hardware-source-policy\n", "")
        )
        self.reject(
            lambda name, text: text.replace(
                "  hardware-source-policy:\n",
                "  hardware-source-policy:\n    continue-on-error: true\n",
            )
        )
        self.reject(
            lambda name, text: text.replace(
                "          python3 scripts/check-hardware-ci.py\n",
                "          python3 scripts/check-hardware-ci.py || true\n",
            )
        )


if __name__ == "__main__":
    unittest.main()
