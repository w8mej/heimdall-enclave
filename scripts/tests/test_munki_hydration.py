#!/usr/bin/env python3
"""Run actual Munki weight scripts with explicit portable plutil/stat fixtures.

These checks cover progress reporting and exit conventions, not model
provenance, real macOS utilities or a native management-agent installation.
"""

import html
import json
import os
import plistlib
import re
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class MunkiHydration(unittest.TestCase):
    def run_script(self, key, status, payload=b"weights", cli_exit=30):
        with tempfile.TemporaryDirectory(prefix="depot-f129-munki-") as tmp:
            base = Path(tmp)
            model = base / "model"
            if payload is not None:
                model.write_bytes(payload)
            state = base / "status.json"
            if status is not None:
                state.write_text(
                    status if isinstance(status, str) else json.dumps(status)
                )
            parser = base / "plutil"
            parser.write_text(
                "#!/usr/bin/python3\nimport json,sys\n"
                "try:\n v=json.load(sys.stdin)[sys.argv[2]]\n"
                "except (ValueError,KeyError,TypeError): sys.exit(1)\n"
                "if isinstance(v,(dict,list,bool)) or v is None: sys.exit(1)\n"
                "print(v)\n"
            )
            parser.chmod(0o755)
            stat = base / "stat"
            stat.write_text(
                "#!/usr/bin/python3\nimport os,sys\nprint(os.stat(sys.argv[-1]).st_size)\n"
            )
            stat.chmod(0o755)
            args = base / "args"
            cli = base / "cli"
            cli.write_text(
                f"#!/bin/sh\nprintf '%s\\n' \"$@\" > {shlex.quote(str(args))}\nexit {cli_exit}\n"
            )
            cli.chmod(0o755)
            raw = (ROOT / "adapters/munki/enclave-model-weights.pkginfo").read_text()
            # Preserve an executable before-fix control even when the old
            # manifest has an unescaped ampersand. Validity is tested separately.
            script = html.unescape(
                re.search(
                    r"<key>" + re.escape(key) +
                    r"</key>\s*<string>(.*?)</string>",
                    raw,
                    re.S,
                )[1]
            )
            for original, fixture in [
                ("/opt/enterprise/enclave/cas/models/llada-8b-instruct", str(model)),
                ("/var/run/enclave/jobs/hydration-status.json", str(state)),
                ("/usr/bin/plutil", str(parser)),
                ("/usr/bin/stat", str(stat)),
                ("/opt/enterprise/enclave/bin/depot-enclave", str(cli)),
            ]:
                script = script.replace(original, fixture)
            # No production path override is introduced. Only this copied
            # script names the fixtures, and no real deployment tool runs.
            result = subprocess.run(
                ["/bin/sh", "-c", script],
                capture_output=True,
                text=True,
                timeout=5,
                env=dict(os.environ),
            )
            return result.returncode, (
                args.read_text().splitlines() if args.exists() else []
            )

    def complete(self):
        return {
            "target": "llada-8b-instruct",
            "profile": "L1",
            "status": "completed",
            "bytes_synced": 7,
            "bytes_total": 7,
            "percent": 100.0,
            "bao_root": "ab" * 32,
        }

    def test_manifest_is_valid_plist(self):
        with (ROOT / "adapters/munki/enclave-model-weights.pkginfo").open("rb") as file:
            self.assertIn("installcheck_script", plistlib.load(file))

    def test_valid_complete_progress_skips_reinstallation(self):
        status = self.complete()
        for body in (status, json.dumps(status, indent=2)):
            with self.subTest(body=body):
                self.assertEqual(self.run_script(
                    "installcheck_script", body)[0], 1)

    def test_absent_malformed_wrong_target_or_incomplete_progress_needs_install(self):
        cases = [
            None,
            "{",
            {},
            dict(self.complete(), target="other-model"),
            dict(self.complete(), profile="L2"),
            dict(self.complete(), error="failed"),
            dict(self.complete(), bytes_total=0),
            dict(self.complete(), bytes_synced=6),
            dict(self.complete(), bytes_total=8),
            dict(self.complete(), percent=99),
            dict(self.complete(), bao_root="x" * 64),
        ]
        cases += [
            dict(self.complete(), status=value)
            for value in ("pending", "syncing", "failed", "invented")
        ]
        for status in cases:
            with self.subTest(status=status):
                self.assertEqual(self.run_script(
                    "installcheck_script", status)[0], 0)
        for payload in (None, b"", b"wrong size"):
            with self.subTest(payload=payload):
                self.assertEqual(
                    self.run_script(
                        "installcheck_script", self.complete(), payload=payload
                    )[0],
                    0,
                )

    def test_postinstall_accepts_pending_and_propagates_actual_failure(self):
        for code, expected in ((0, 0), (30, 0), (20, 20), (40, 40)):
            with self.subTest(code=code):
                actual, args = self.run_script(
                    "postinstall_script", None, cli_exit=code
                )
                self.assertEqual(actual, expected)
                self.assertEqual(
                    args,
                    [
                        "deploy",
                        "hydrate",
                        "--profile",
                        "L1",
                        "--target",
                        "llada-8b-instruct",
                        "--async",
                    ],
                )


if __name__ == "__main__":
    unittest.main()
