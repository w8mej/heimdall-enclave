"""Exercise copied root wrappers with private paths; never run privileged work.

The fixed install prefix and bootstrap identity probes are relocated into a
fixture. CLI lookup, argument handling and child environment remain production.
"""

import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class RootWrapperLookup(unittest.TestCase):
    def test_lookup_refusal_and_legitimate_argument_flow(self):
        with tempfile.TemporaryDirectory(prefix="mcpmac-root-wrapper-") as tmp:
            directory = Path(tmp)
            installed = directory / "installed-cli"
            marker = directory / "hostile-executed"
            calls = directory / "calls"
            malicious = (
                "#!/bin/sh\nprintf injected > " + shlex.quote(str(marker)) + "\n"
            )
            for name in (
                "target/release/mcp-enclave",
                "target/debug/mcp-enclave",
                "bin/mcp-enclave",
                "mcp-enclave",
            ):
                path = directory / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(malicious)
                path.chmod(0o700)
            probes = {}
            for name, output in (("uname", "Darwin"), ("id", "0")):
                path = directory / ("probe-" + name)
                path.write_text('#!/bin/sh\nprintf "%s\\n" ' + output + "\n")
                path.chmod(0o700)
                probes["/usr/bin/" + name] = str(path)
            scripts = []
            for name in ("bootstrap_enclave.sh", "hydrate_model.sh"):
                source = (ROOT / "core" / name).read_text()
                source = source.replace(
                    "/opt/enterprise/enclave/bin/mcp-enclave", str(installed)
                )
                for original, replacement in probes.items():
                    source = source.replace(original, replacement)
                path = directory / name
                path.write_text(source)
                scripts.append(path)
            env = dict(
                os.environ,
                PATH=str(directory) + ":/usr/bin:/bin",
                MCPMAC_CLI=str(directory / "mcp-enclave"),
                MCPMAC_UNTRUSTED_CHILD="must-not-arrive",
            )
            for path in scripts:
                result = subprocess.run(
                    ["/bin/sh", str(path)],
                    env=env,
                    cwd=directory,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 20, result.stdout + result.stderr)
                self.assertFalse(marker.exists(), "cwd/PATH/environment CLI executed")
            # This inert CLI records exact argv/env. It cannot install anything.
            installed.write_text(
                "#!" + sys.executable + "\nimport json,os,sys\n"
                "with open(" + repr(str(calls)) + ', "a") as f:\n'
                ' f.write(json.dumps([sys.argv[1:], dict(os.environ)]) + "\\n")\n'
            )
            installed.chmod(0o700)
            target = "model;$(touch unwanted)"
            dmg = "/private/path with spaces/$(touch unwanted).dmg"
            for path, args in (
                (scripts[0], ["L3"]),
                (scripts[1], [target, "L2", "--sync", "--dmg", dmg]),
            ):
                result = subprocess.run(
                    ["/bin/sh", str(path), *args],
                    env=env,
                    cwd=directory,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            rows = [json.loads(line) for line in calls.read_text().splitlines()]
            self.assertEqual(
                [row[0] for row in rows],
                [
                    ["deploy", action, "--profile", "L3"]
                    for action in ("preflight", "install", "verify")
                ]
                + [
                    [
                        "deploy",
                        "hydrate",
                        "--profile",
                        "L2",
                        "--target",
                        target,
                        "--sync",
                        "--dmg",
                        dmg,
                    ]
                ],
            )
            for _, child_env in rows:
                self.assertNotIn("MCPMAC_UNTRUSTED_CHILD", child_env)
                self.assertNotIn("MCPMAC_CLI", child_env)
            self.assertFalse(marker.exists())
            self.assertFalse((directory / "unwanted").exists())


if __name__ == "__main__":
    unittest.main()
