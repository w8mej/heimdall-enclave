"""Run real MDM shell control flow with a private inert CLI, never an install."""

import json
import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class PhaseTwoConsumers(unittest.TestCase):
    def test_required_verify_failure_stops_bootstrap_and_hydration(self):
        with tempfile.TemporaryDirectory(prefix="phase2-consumer-") as tmp:
            base = Path(tmp)
            calls = base / "calls"
            cli = base / "cli"
            cli.write_text(
                "#!/bin/sh\n"
                f"printf '%s\\n' \"$2\" >> {shlex.quote(str(calls))}\n"
                '[ "$2" != verify ] || exit 30\nexit 0\n'
            )
            cli.chmod(0o700)
            env = dict(os.environ, ENCLAVE_CLI=str(cli))
            for script, args in [
                ("adapters/lightweight-mdm/lightweight_mdm_bootstrap.sh", ["L3"]),
                (
                    "adapters/jamf/jamf_deploy_enclave.sh",
                    ["unused", "unused", "unused", "target", "L3", "bootstrap"],
                ),
            ]:
                with self.subTest(script=script):
                    calls.write_text("")
                    result = subprocess.run(
                        ["/bin/sh", str(ROOT / script), *args],
                        env=env,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    self.assertEqual(result.returncode, 30, result)
                    self.assertEqual(
                        calls.read_text().splitlines(),
                        ["preflight", "install", "verify"],
                    )

    def test_fleet_preserves_actual_result_envelope_and_exit(self):
        with tempfile.TemporaryDirectory(prefix="phase2-fleet-") as tmp:
            cli = Path(tmp) / "cli"
            for code, status in [(0, "healthy"), (50, "unhealthy")]:
                body = {
                    "verb": "healthcheck",
                    "exit_code": code,
                    "status": "ok" if code == 0 else "unhealthy",
                    "details": {
                        "overall_status": status,
                        "physical_memory": {"compliant": code == 0},
                    },
                }
                cli.write_text(
                    "#!/bin/sh\nprintf '%s\\n' "
                    + shlex.quote(json.dumps(body))
                    + f"\nexit {code}\n"
                )
                cli.chmod(0o700)
                result = subprocess.run(
                    ["/bin/sh", str(ROOT / "adapters/fleet/scripts/healthcheck.sh")],
                    env=dict(os.environ, ENCLAVE_CLI=str(cli), ENCLAVE_PROFILE="L2"),
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(result.returncode, code)
                self.assertEqual(json.loads(result.stdout), body)


if __name__ == "__main__":
    unittest.main()
