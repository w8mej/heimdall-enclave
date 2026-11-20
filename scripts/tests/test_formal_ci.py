#!/usr/bin/env python3
"""Mutation tests of the actual hosted formal-workflow source contract."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "formal_ci", ROOT / "scripts/check-formal-ci.py"
)
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class FormalWorkflowTests(unittest.TestCase):
    def reject(self, target, transform):
        with tempfile.TemporaryDirectory(prefix="mcpmac-formal-ci-") as directory:
            root = Path(directory)
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            for name in ("formal.yml", "security-lint.yml"):
                text = (ROOT / ".github/workflows" / name).read_text()
                (workflows / name).write_text(
                    transform(text) if name == target else text
                )
            with self.assertRaises(
                (POLICY.READER.PolicyError, POLICY.READER.yaml.YAMLError)
            ):
                POLICY.check_policy(root)

    def test_current_workflows_install_cache_and_compile(self):
        self.assertEqual(POLICY.check_policy(ROOT), 2)

    def test_missing_installer_compiler_cache_or_regression_is_rejected(self):
        for target in ("formal.yml", "security-lint.yml"):
            for command in (
                POLICY.INSTALL,
                "lake exe cache get",
                "python3 scripts/check-lean.py",
                "python3 scripts/tests/test_lean_gate.py",
            ):
                with self.subTest(target=target, command=command):
                    self.reject(target, lambda text: text.replace(command, "true", 1))

    def test_masked_or_conditional_compiler_step_is_rejected(self):
        for target in ("formal.yml", "security-lint.yml"):
            for suffix in (" || true", "; true", " || echo ignored"):
                with self.subTest(target=target, suffix=suffix):
                    self.reject(
                        target,
                        lambda text: text.replace(
                            "python3 scripts/check-lean.py\n",
                            "python3 scripts/check-lean.py" + suffix + "\n",
                            1,
                        ),
                    )
            self.reject(
                target,
                lambda text: text.replace(
                    "      - name: Mandatory Lean compiler gate\n",
                    "      - name: Mandatory Lean compiler gate\n        continue-on-error: true\n",
                ),
            )
            self.reject(
                target,
                lambda text: text.replace(
                    "      - name: Mandatory Lean compiler gate\n",
                    "      - name: Mandatory Lean compiler gate\n        if: false\n",
                ),
            )

    def test_job_level_masking_shell_and_working_directory_changes_are_rejected(self):
        for target, job in [
            ("formal.yml", "formal"),
            ("security-lint.yml", "code-and-doc-lint"),
        ]:
            with self.subTest(target=target):
                self.reject(
                    target,
                    lambda text: text.replace(
                        f"  {job}:\n", f"  {job}:\n    continue-on-error: true\n"
                    ),
                )
                self.reject(
                    target,
                    lambda text: text.replace(
                        "        shell: bash", "        shell: bash {0}"
                    ),
                )
                self.reject(
                    target,
                    lambda text: text.replace(
                        "        working-directory: .\n",
                        "        working-directory: ignored-proof-copy\n",
                    ),
                )

    def test_compilation_cannot_precede_toolchain_installation(self):
        self.reject(
            "formal.yml",
            lambda text: text.replace(
                "        run: ./scripts/install-lean-toolchain.sh", "        run: true"
            ).replace(
                "      - name: Mandatory Lean compiler gate\n",
                "      - name: Late installer\n        shell: bash\n        working-directory: .\n"
                "        run: ./scripts/install-lean-toolchain.sh\n      - name: Mandatory Lean compiler gate\n",
            ),
        )

    def test_hosted_pr_trigger_and_process_failure_checks_are_required(self):
        self.reject(
            "formal.yml",
            lambda text: text.replace("  pull_request:", "  workflow_dispatch:"),
        )
        self.reject(
            "formal.yml",
            lambda text: text.replace(
                "python3 scripts/tests/test_lean_gate_process.py", "true"
            ),
        )


if __name__ == "__main__":
    unittest.main()
