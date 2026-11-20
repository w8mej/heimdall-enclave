#!/usr/bin/env python3
"""Run actual non-mutating installer entry paths against hostile tool lookup."""

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ("install.sh", "uninstall.sh", "verify-install.sh")


class DirectScriptTools(unittest.TestCase):
    def run_script(self, name, help_only):
        with tempfile.TemporaryDirectory(prefix="mcpmac-f90-direct-") as tmp:
            directory = Path(tmp)
            marker = directory / "executed"
            for tool in ("sed", "uname"):
                executable = directory / tool
                executable.write_text(
                    "#!/bin/sh\nprintf injected > "
                    + shlex.quote(str(marker))
                    + '\nprintf "not-Darwin\\n"\n'
                )
                executable.chmod(0o755)
            env = dict(
                os.environ,
                PATH=str(directory) + ":/usr/bin:/bin:/usr/sbin:/sbin",
                MCPMAC_DIST=str(directory / "missing-distribution"),
            )
            args = ["/bin/sh", str(ROOT / "packaging/macos" / name)]
            # verify-install has no --help branch. Its platform/UID/missing-file
            # refusal precedes all operations; install/uninstall --help use sed.
            if help_only:
                args.append("--help")
            result = subprocess.run(
                args, env=env, cwd=directory, capture_output=True, text=True, timeout=10
            )
            return result, marker.exists()

    def test_help_does_not_execute_a_caller_path_tool(self):
        for name in SCRIPTS[:2]:
            with self.subTest(script=name):
                result, executed = self.run_script(name, True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(executed, "caller-controlled sed executed")
                self.assertIn("#", result.stdout)

    def test_platform_refusal_does_not_execute_a_caller_path_tool(self):
        for name in SCRIPTS:
            with self.subTest(script=name):
                result, executed = self.run_script(name, False)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(executed, "caller-controlled uname executed")


if __name__ == "__main__":
    unittest.main()
