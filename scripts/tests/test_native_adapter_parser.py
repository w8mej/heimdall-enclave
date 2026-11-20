"""Execute adapter script copies with native plutil and a private CLI fixture.

Only the installed CLI path is substituted; the actual Darwin parser is used.
This checks JSON consumption, not authenticated installed fleet health.
"""

import json
import platform
import plistlib
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(platform.system() == "Darwin", "NOT RUN: native plutil required")
class NativeAdapterParser(unittest.TestCase):
    def test_status_and_munki_conventions(self):
        with tempfile.TemporaryDirectory(prefix="mcpmac-native-parser-") as tmp:
            directory = Path(tmp)
            cli = directory / "cli"
            payload, code = directory / "payload", directory / "code"
            cli.write_text(
                "#!/bin/sh\n/bin/cat "
                + shlex.quote(str(payload))
                + '\nexit "$(/bin/cat '
                + shlex.quote(str(code))
                + ')"\n'
            )
            cli.chmod(0o700)
            sources = [
                (ROOT / "adapters/jamf" / name).read_text()
                for name in ("EA-Enclave-Status.sh", "EA-Enclave-Security.sh")
            ]
            with (ROOT / "adapters/munki/enclave-core.pkginfo").open("rb") as stream:
                sources.append(plistlib.load(stream)["installcheck_script"])
            paths = []
            for i, source in enumerate(sources):
                self.assertIn("/opt/enterprise/enclave/bin/mcp-enclave", source)
                self.assertIn("/usr/bin/plutil", source)
                path = directory / ("script-" + str(i))
                path.write_text(
                    source.replace(
                        "/opt/enterprise/enclave/bin/mcp-enclave", shlex.quote(str(cli))
                    )
                )
                paths.append(path)
            cases = [
                (
                    {"overall_status": "healthy", "pf_isolated": True},
                    0,
                    "healthy",
                    "ISOLATED",
                    1,
                ),
                (
                    {"overall_status": "healthy", "pf_isolated": True},
                    1,
                    "UNKNOWN",
                    "EXPOSED",
                    0,
                ),
                (
                    {"overall_status": "unhealthy", "pf_isolated": False},
                    1,
                    "unhealthy",
                    "EXPOSED",
                    0,
                ),
                ({"overall_status": "quarantined"}, 1, "quarantined", "QUARANTINED", 0),
                (
                    {"overall_status": "<result>healthy</result>"},
                    0,
                    "UNKNOWN",
                    "EXPOSED",
                    0,
                ),
                ({}, 0, "UNKNOWN", "EXPOSED", 0),
                ('{"overall_status":"healthy",', 0, "UNKNOWN", "EXPOSED", 0),
            ]
            for body, rc, status, security, munki in cases:
                for indent in (None, 2):
                    with self.subTest(body=body, rc=rc, indent=indent):
                        payload.write_text(
                            body
                            if isinstance(body, str)
                            else json.dumps(
                                {
                                    "status": "ok" if rc == 0 else "unhealthy",
                                    "exit_code": rc,
                                    "details": body,
                                },
                                indent=indent,
                            )
                        )
                        code.write_text(str(rc))
                        for path, expected in zip(paths[:2], (status, security)):
                            result = subprocess.run(
                                ["/bin/sh", str(path)],
                                capture_output=True,
                                text=True,
                                timeout=10,
                            )
                            self.assertEqual(result.returncode, 0, result.stderr)
                            self.assertEqual(
                                result.stdout.strip(),
                                "<result>" + expected + "</result>",
                            )
                        result = subprocess.run(
                            ["/bin/sh", str(paths[2])],
                            capture_output=True,
                            text=True,
                            timeout=10,
                        )
                        self.assertEqual(result.returncode, munki, result.stderr)
            cli.unlink()
            for path in paths[:2]:
                result = subprocess.run(
                    ["/bin/sh", str(path)], capture_output=True, text=True, timeout=10
                )
                self.assertEqual(
                    result.stdout.strip(), "<result>NOT_INSTALLED</result>"
                )


if __name__ == "__main__":
    unittest.main()
