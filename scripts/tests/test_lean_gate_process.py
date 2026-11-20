#!/usr/bin/env python3
"""Test actual gate entrypoint failure propagation with controlled tool faults.

Fault executables never supply a successful theorem inventory. These tests are
process-contract evidence, not compiler/proof verification; test_lean_gate.py and
the full pinned gate supply actual Lean checks separately.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

if __package__:
    from .lean_fixture import copy_guard_inputs
else:
    from lean_fixture import copy_guard_inputs

ROOT = Path(__file__).resolve().parents[2]


class GateProcessTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(
            prefix="depot-gate-process-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "scripts").mkdir()
        shutil.copy2(
            ROOT / "scripts/check-lean.py", self.root / "scripts/check-lean.py"
        )
        copy_guard_inputs(ROOT, self.root)
        shutil.copytree(
            ROOT / "proofs/lean4",
            self.root / "proofs/lean4",
            ignore=shutil.ignore_patterns(".lake", "__pycache__"),
        )
        report = self.root / "reports/lean-build.json"
        report.parent.mkdir()
        report.write_text('{"result":"PASS","stale":true}\n')
        self.report = report

    def run_fault(self, mode, expected):
        env = dict(os.environ, PATH="/usr/bin:/bin")
        calls = self.root / "calls.jsonl"
        if mode != "absent":
            binaries = self.root / "fault-tools"
            binaries.mkdir()
            fault = binaries / "lake"
            fault.write_text(
                "#!"
                + sys.executable
                + "\n"
                + "import json,sys\nfrom pathlib import Path\n"
                + f"path=Path({str(calls)!r})\n"
                + 'with path.open("a") as out: out.write(json.dumps(sys.argv[1:])+"\\n")\n'
                + f"mode={mode!r}\n"
                + 'if sys.argv[1:]==["env","lean","--version"]:\n'
                ' print("Lean (version " + ("4.15.0" if mode=="version" else "4.14.0") + ", fault fixture)")\n'
                'elif sys.argv[1] == "build":\n'
                ' print("controlled build failure" if mode=="build" else "controlled build stage")\n'
                ' sys.exit(71 if mode=="build" else 0)\n'
                "else:\n"
                ' print("controlled audit failure" if mode=="audit" else "no kernel inventory")\n'
                ' sys.exit(72 if mode=="audit" else 0)\n'
            )
            fault.chmod(0o755)
            (binaries / "lean").symlink_to("lake")
            env["PATH"] = str(binaries) + ":/usr/bin:/bin"
        result = subprocess.run(
            [sys.executable, str(self.root / "scripts/check-lean.py")],
            cwd=self.root,
            env=env,
            text=True,
            capture_output=True,
            timeout=20,
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(expected, result.stdout + result.stderr)
        self.assertNotIn("PASS: compiled", result.stdout)
        self.assertFalse(
            self.report.exists(), "failed gate retained stale successful provenance"
        )
        return (
            [json.loads(line) for line in calls.read_text().splitlines()]
            if calls.exists()
            else []
        )

    def test_absent_compiler_never_uses_static_fallback(self):
        self.assertEqual(self.run_fault("absent", "No proof check ran"), [])

    def test_wrong_version_never_reaches_build(self):
        self.assertEqual(
            self.run_fault("version", "wrong Lean compiler"),
            [["env", "lean", "--version"]],
        )

    def test_build_failure_stops_before_audit_and_invalidates_stale_report(self):
        calls = self.run_fault("build", "returned non-zero exit status 71")
        self.assertEqual(
            calls,
            [
                ["env", "lean", "--version"],
                ["build", "Enclave", "Test", "enclave_verifier"],
            ],
        )

    def test_audit_failure_is_not_a_build_success(self):
        calls = self.run_fault(
            "audit", "kernel declaration / transitive axiom audit failed"
        )
        self.assertEqual(calls[-1], ["env", "lean", "Audit.lean"])

    def test_success_exit_without_kernel_inventory_fails(self):
        calls = self.run_fault(
            "inventory", "compiler did not produce the kernel audit inventory"
        )
        self.assertEqual(calls[-1], ["env", "lean", "Audit.lean"])


if __name__ == "__main__":
    unittest.main()
