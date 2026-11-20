#!/usr/bin/env python3
"""Adversarial compiler checks for the mandatory formal gate (Lean is required)."""

import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

if __package__:
    from .lean_fixture import copy_guard_inputs
else:
    from lean_fixture import copy_guard_inputs

ROOT = Path(__file__).resolve().parents[2]
LEAN_DIR = ROOT / "proofs/lean4"
SPEC = importlib.util.spec_from_file_location(
    "lean_gate", ROOT / "scripts/check-lean.py"
)
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class GateTests(unittest.TestCase):
    def test_changed_definition_is_rejected_even_with_unchanged_type_manifest(self):
        # Run the real gate in a private copy: changing a model definition must
        # fail before a stale object/type digest can masquerade as the contract.
        with tempfile.TemporaryDirectory(prefix="depot-lean-definition-") as directory:
            root = Path(directory)
            package = root / "proofs/lean4"
            shutil.copytree(
                LEAN_DIR, package, ignore=shutil.ignore_patterns(
                    ".lake", "__pycache__")
            )
            (root / "scripts").mkdir()
            shutil.copy2(ROOT / "scripts/check-lean.py",
                         root / "scripts/check-lean.py")
            copy_guard_inputs(ROOT, root)
            model = package / "Enclave/TransportAdmission.lean"
            source = model.read_text()
            self.assertIn("pendingMax : Nat", source)
            model.write_text(source.replace(
                "pendingMax : Nat", "pendingMax : Int", 1))
            result = subprocess.run(
                [os.sys.executable, str(root / "scripts/check-lean.py")],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "reviewed transport definition changed", result.stderr)
            self.assertFalse((root / "reports/lean-build.json").exists())

    def test_removed_definition_contract_cannot_shrink_the_inventory(self):
        import json

        with tempfile.TemporaryDirectory(prefix="depot-lean-contract-") as directory:
            root = Path(directory)
            package = root / "proofs/lean4"
            shutil.copytree(
                LEAN_DIR, package, ignore=shutil.ignore_patterns(
                    ".lake", "__pycache__")
            )
            (root / "scripts").mkdir()
            shutil.copy2(ROOT / "scripts/check-lean.py",
                         root / "scripts/check-lean.py")
            copy_guard_inputs(ROOT, root)
            manifest = json.loads(
                (package / "transport-contracts.json").read_text())
            manifest.pop("Enclave/TransportAdmission.lean")
            (package / "transport-contracts.json").write_text(json.dumps(manifest))
            report = root / "reports/lean-build.json"
            report.parent.mkdir()
            report.write_text('{"result":"PASS","stale":true}\n')
            result = subprocess.run(
                [os.sys.executable, str(root / "scripts/check-lean.py")],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("inventory changed", result.stderr)
            self.assertFalse(report.exists())

    def test_missing_compiler_fails(self):
        env = dict(os.environ, PATH="/usr/bin:/bin")
        # Fault injection must not delete the preceding real build's provenance:
        # production check-lean deliberately invalidates its own stale report.
        report = ROOT / "reports/lean-build.json"
        prior = report.read_bytes() if report.exists() else None
        with tempfile.TemporaryDirectory(
            prefix="depot-lean-no-compiler-"
        ) as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            shutil.copy2(ROOT / "scripts/check-lean.py",
                         root / "scripts/check-lean.py")
            copy_guard_inputs(ROOT, root)
            shutil.copytree(
                LEAN_DIR,
                root / "proofs/lean4",
                ignore=shutil.ignore_patterns(".lake", "__pycache__"),
            )
            result = subprocess.run(
                ["/usr/bin/python3", str(root / "scripts/check-lean.py")],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("No proof check ran", result.stderr)
        self.assertEqual(
            report.read_bytes() if report.exists() else None,
            prior,
            "compiler-fault regression destroyed the real build artifact",
        )

    def check_bad_declaration(self, declaration, expected):
        audit = (LEAN_DIR / "Audit.lean").read_text()
        body = audit[audit.index("open Lean"):]
        with tempfile.TemporaryDirectory(prefix="depot-lean-gate-") as directory:
            fixture = Path(directory) / "Attack.lean"
            fixture.write_text(
                "import Lean\nimport Enclave\nimport Test\n"
                + "namespace Enclave.GateAttack\n"
                + declaration
                + "\nend Enclave.GateAttack\n"
                + body
            )
            result = subprocess.run(
                [shutil.which("lake"), "env", "lean", str(fixture)],
                cwd=LEAN_DIR,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn(expected, result.stdout + result.stderr)

    def test_unused_custom_axiom_is_rejected(self):
        self.check_bad_declaration(
            "axiom assumed : False", "Project axiom forbidden")

    def test_sorry_is_rejected(self):
        self.check_bad_declaration(
            "theorem assumed : False := by sorry", "forbidden axiom sorryAx"
        )

    def test_admit_is_rejected(self):
        self.check_bad_declaration(
            "theorem assumed : False := by admit", "forbidden axiom sorryAx"
        )

    def test_invalid_proof_fails_compilation(self):
        self.check_bad_declaration(
            "theorem assumed : 1 = 2 := by rfl", "tactic 'rfl' failed"
        )

    def test_native_decide_is_rejected_by_kernel_dependency_audit(self):
        self.check_bad_declaration(
            "theorem assumed : True := by native_decide", "forbidden axiom"
        )

    def test_unsafe_implementation_cannot_supply_a_kernel_proof(self):
        self.check_bad_declaration(
            "unsafe def unsafeValue : Nat := 0\n"
            "theorem assumed : unsafeValue = 0 := by rfl",
            "unsafe",
        )

    def test_invalid_imported_proof_fails_actual_gate_and_removes_stale_report(self):
        # Execute the same production entrypoint in a private project fixture.
        # Existing artifacts can accelerate unchanged modules; Lake still runs
        # and must reject the newly imported module. No compiler output is faked.
        with tempfile.TemporaryDirectory(prefix="depot-lean-full-gate-") as directory:
            root = Path(directory)
            package = root / "proofs/lean4"
            shutil.copytree(
                LEAN_DIR,
                package,
                symlinks=True,
                ignore=shutil.ignore_patterns(".lake", "__pycache__"),
            )
            (package / ".lake").mkdir()
            (package / ".lake/packages").symlink_to(
                (LEAN_DIR / ".lake/packages").resolve(), target_is_directory=True
            )
            if (LEAN_DIR / ".lake/build").is_dir():
                shutil.copytree(LEAN_DIR / ".lake/build",
                                package / ".lake/build")
            (root / "scripts").mkdir()
            shutil.copy2(ROOT / "scripts/check-lean.py",
                         root / "scripts/check-lean.py")
            copy_guard_inputs(ROOT, root)
            (package / "Enclave/GateAttack.lean").write_text(
                "namespace Enclave.GateAttack\n"
                "theorem invalid : 1 = 2 := by rfl\nend Enclave.GateAttack\n"
            )
            with (package / "Enclave.lean").open("a") as stream:
                stream.write("\nimport Enclave.GateAttack\n")
            # This fixture deliberately authorizes its additional import so
            # the compiler stage is exercised. A separate mutation test proves
            # that an unauthorized definition/import change is rejected first.
            import hashlib
            import json

            contract = package / "transport-contracts.json"
            reviewed = json.loads(contract.read_text())
            reviewed["Enclave.lean"] = hashlib.sha256(
                (package / "Enclave.lean").read_bytes()
            ).hexdigest()
            contract.write_text(json.dumps(reviewed))
            report = root / "reports/lean-build.json"
            report.parent.mkdir()
            report.write_text('{"result":"PASS","stale":true}\n')
            result = subprocess.run(
                [os.sys.executable, str(root / "scripts/check-lean.py")],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=650,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("tactic 'rfl' failed", result.stdout + result.stderr)
            self.assertNotIn("PASS: compiled", result.stdout)
            self.assertFalse(
                report.exists(), "failed compilation retained stale PASS provenance"
            )

    def test_definition_cannot_replace_required_theorem(self):
        result = subprocess.run(
            [shutil.which("lake"), "env", "lean", "Audit.lean"],
            cwd=LEAN_DIR,
            capture_output=True,
            text=True,
            check=True,
        )
        output = "\n".join(
            line
            for line in result.stdout.splitlines()
            if not line.startswith('KERNEL_DECL ["Enclave.conf_le_refl",')
        )
        with self.assertRaisesRegex(RuntimeError, "missing or replaced"):
            GATE.validate_compiled(LEAN_DIR, output)

    def test_weakened_type_is_rejected(self):
        result = subprocess.run(
            [shutil.which("lake"), "env", "lean", "Audit.lean"],
            cwd=LEAN_DIR,
            capture_output=True,
            text=True,
            check=True,
        )
        import json

        output = []
        for line in result.stdout.splitlines():
            if line.startswith('KERNEL_DECL ["Enclave.conf_le_refl",'):
                line = "KERNEL_DECL " + \
                    json.dumps(["Enclave.conf_le_refl", "True"])
            output.append(line)
        with self.assertRaisesRegex(RuntimeError, "reviewed theorem type changed"):
            GATE.validate_compiled(LEAN_DIR, "\n".join(output))


if __name__ == "__main__":
    unittest.main()
