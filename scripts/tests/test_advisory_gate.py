"""Run actual gate and extracted master-linter stage against inert tool exits."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class AdvisoryGateTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        (root / "scripts").mkdir()
        (root / ".cargo").mkdir()
        shutil.copy(ROOT / "scripts/check-advisories.py", root / "scripts")
        shutil.copy(ROOT / "deny.toml", root)
        shutil.copy(ROOT / ".cargo/audit.toml", root / ".cargo")
        binaries = root / "bin"
        binaries.mkdir()
        (binaries / "python3").symlink_to(sys.executable)
        cargo = binaries / "cargo"
        cargo.write_text("""#!/bin/sh
printf '%s\\n' "$*" >> "$ADVISORY_CALLS"
case "$1 $2" in
  'deny --version') exit 127;;
  'deny check') exit "$DENY_EXIT";;
  'audit --deny') exit "$AUDIT_EXIT";;
  'audit --ignore') exit "$AUDIT_EXIT";;
  'clippy --workspace'|'fmt --all') exit 0;;
  *) exit 98;;
esac
""")
        cargo.chmod(0o755)
        legacy_audit = binaries / "cargo-audit"
        legacy_audit.write_text("#!/bin/sh\nexit 0\n")
        legacy_audit.chmod(0o755)
        env = dict(
            os.environ,
            PATH=f"{binaries}:/usr/bin:/bin",
            ADVISORY_CALLS=str(root / "calls"),
            DENY_EXIT="0",
            AUDIT_EXIT="0",
        )
        return root, env

    def stage(self, root, env):
        source = (ROOT / "scripts/lint-all.sh").read_text()
        start = source.index("STAGE3_STATUS=0")
        end = source.index("# 4. Semantic SAST", start)
        script = 'TOTAL_STAGES=9\nrecord_result() { exit "$3"; }\n' + source[start:end]
        return subprocess.run(
            ["/bin/bash", "-c", script],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
        )

    def test_master_linter_propagates_audit_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root, env = self.fixture(directory)
            env["AUDIT_EXIT"] = "31"
            result = self.stage(root, env)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            calls = (root / "calls").read_text()
            self.assertIn("deny check advisories", calls)
            self.assertIn("audit --deny warnings", calls)

    def test_master_linter_requires_both_tools_and_accepts_both_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            root, env = self.fixture(directory)
            result = self.stage(root, env)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            calls = (root / "calls").read_text()
            self.assertIn("deny check advisories", calls)
            self.assertIn("audit --deny warnings", calls)
            env["DENY_EXIT"] = "32"
            self.assertNotEqual(self.stage(root, env).returncode, 0)

    def test_mismatched_exceptions_stop_before_either_tool(self):
        with tempfile.TemporaryDirectory() as directory:
            root, env = self.fixture(directory)
            (root / "deny.toml").write_text("[advisories]\nignore=[]\n")
            result = subprocess.run(
                [sys.executable, "scripts/check-advisories.py"],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("exception lists differ", result.stderr)
            self.assertFalse((root / "calls").exists())


if __name__ == "__main__":
    unittest.main()
