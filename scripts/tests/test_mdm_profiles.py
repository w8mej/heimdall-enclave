"""Exercise managed profile argv/refusal with inert CLI; native parsing on Darwin."""

import json
import os
import platform
import plistlib
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class ManagedProfileSelection(unittest.TestCase):
    def setUp(self):
        self.temp_root = ROOT / "target"
        self.temp_root.mkdir(exist_ok=True)

    def adapter_sources(self):
        sources = [
            (ROOT / "adapters/jamf" / name).read_text()
            for name in ("EA-Enclave-Status.sh", "EA-Enclave-Security.sh")
        ]
        with (ROOT / "adapters/munki/enclave-core.pkginfo").open("rb") as stream:
            sources.append(plistlib.load(stream)["installcheck_script"])
        return sources

    def fixtures(self, directory):
        calls = directory / "calls"
        cli = directory / "inert cli"
        envelope = json.dumps(
            {"details": {"overall_status": "healthy", "pf_isolated": True}}
        )
        cli.write_text(
            "#!/bin/sh\n"
            + "printf '%s\\n' \"$@\" > "
            + shlex.quote(str(calls))
            + "\n"
            + "printf '%s\\n' "
            + shlex.quote(envelope)
            + "\n"
        )
        cli.chmod(0o700)
        parser = directory / "inert parser"
        if platform.system() != "Darwin":
            # This fixture tests argv/control flow; only the Darwin run tests plutil.
            parser.write_text(
                "#!" + sys.executable + "\n"
                "import json,sys\n"
                "value=json.load(sys.stdin)\n"
                "for key in sys.argv[2].split('.'): value=value[key]\n"
                "print(str(value).lower() if isinstance(value,bool) else value)\n"
            )
            parser.chmod(0o700)
        paths = []
        for i, source in enumerate(self.adapter_sources()):
            source = source.replace(
                "/opt/enterprise/enclave/bin/mcp-enclave", shlex.quote(str(cli))
            )
            if platform.system() != "Darwin":
                source = source.replace("/usr/bin/plutil", shlex.quote(str(parser)))
            path = directory / ("adapter " + str(i))
            path.write_text(source)
            paths.append(path)
        return calls, paths

    def run_adapter(self, path, profile):
        env = dict(os.environ)
        env.pop("ENCLAVE_PROFILE", None)
        if profile is not None:
            env["ENCLAVE_PROFILE"] = profile
        return subprocess.run(
            ["/bin/sh", str(path)], env=env, capture_output=True, text=True, timeout=10
        )

    def test_all_profiles_and_unset_default_reach_health_cli(self):
        with tempfile.TemporaryDirectory(
            prefix="phase2 profiles-", dir=self.temp_root
        ) as tmp:
            calls, paths = self.fixtures(Path(tmp))
            for configured in (None, "L1", "L2", "L3"):
                for i, path in enumerate(paths):
                    with self.subTest(configured=configured, adapter=i):
                        calls.unlink(missing_ok=True)
                        result = self.run_adapter(path, configured)
                        self.assertEqual(
                            calls.read_text().splitlines(),
                            [
                                "deploy",
                                "healthcheck",
                                "--profile",
                                configured or "L2",
                                "--json",
                            ],
                        )
                        self.assertEqual(
                            result.returncode, 1 if i == 2 else 0, result.stderr
                        )
                        if i < 2:
                            self.assertEqual(
                                result.stdout.strip(),
                                (
                                    "<result>healthy</result>",
                                    "<result>ISOLATED</result>",
                                )[i],
                            )

    def test_invalid_profile_stops_before_cli_and_cannot_claim_health(self):
        with tempfile.TemporaryDirectory(
            prefix="phase2 profiles-", dir=self.temp_root
        ) as tmp:
            calls, paths = self.fixtures(Path(tmp))
            for configured in (
                "",
                "l2",
                "L4",
                "L3 --dev",
                "L1\nL2",
                "$(touch ignored)",
            ):
                for i, path in enumerate(paths):
                    with self.subTest(configured=configured, adapter=i):
                        calls.unlink(missing_ok=True)
                        result = self.run_adapter(path, configured)
                        self.assertFalse(calls.exists())
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertIn("Invalid ENCLAVE_PROFILE", result.stderr)
                        self.assertEqual(
                            result.stdout.strip(),
                            (
                                "<result>UNKNOWN</result>",
                                "<result>EXPOSED</result>",
                                "",
                            )[i],
                        )


if __name__ == "__main__":
    unittest.main()
