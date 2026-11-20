#!/usr/bin/env python3
"""Exercise the real direct installer ordering with inert host-command fixtures.

This does not establish Darwin platform checks or signature validity. Every
host-mutating command before provisioning is inert, and provisioning always
terminates the shell before the remainder of the installer can execute.
"""

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class InstallerPreflight(unittest.TestCase):
    def run_installer(self, profile, preflight_exit, signature_exit=0, broker=True):
        with tempfile.TemporaryDirectory(
            prefix="depot-f113-", dir=ROOT / "target"
        ) as tmp:
            base = Path(tmp)
            stage = base / "stage"
            (stage / "bin").mkdir(parents=True)
            if broker:
                asset = stage / "bin/enclave-apfs-broker"
                asset.write_text("#!/bin/sh\nexit 0\n")
                asset.chmod(0o700)
            (stage / "EnclaveCustody.app").mkdir()
            (stage / "EnclaveOIDC.app/Contents/MacOS").mkdir(parents=True)
            oidc = stage / "EnclaveOIDC.app/Contents/MacOS/enclave-oidc"
            oidc.write_text("fixture broker")
            oidc.chmod(0o700)
            (stage / "codesign-pins.json").write_text("{}")
            (stage / "fido-mds").mkdir()
            (stage / "fido-mds/yubico.json").write_text('{"entries":[]}')
            (stage / "launchd").mkdir()
            for name in (
                "supervisor",
                "zk",
                "custody",
                "cas",
                "adapter",
                "ifc",
                "browser",
                "hydrate",
                "gateway",
                "apfs-broker",
                "intent",
                "oidc-broker",
            ):
                (
                    stage / "launchd" /
                    ("com.enterprise.enclave." + name + ".plist")
                ).write_text("fixture")
            (stage / "tuf/repo").mkdir(parents=True)
            for trust_name in (
                "root.json",
                "timestamp.json",
                "snapshot.json",
                "targets.json",
                "enclave-host-config.json",
                "enclave-policy.cedar.v1.json",
                "vk_manifest.json",
                "enclave-distribution-v1.json",
            ):
                (stage / "tuf/repo" / trust_name).write_text("{}")
            log = base / "calls"
            args = base / "args"
            cli = stage / "bin/depot-enclave"
            cli.write_text(
                "#!/bin/sh\n"
                '[ "$1" = deploy ] || exit 0\n'
                f'printf \'preflight|%s|%s\\n\' "$PATH" "${{F113_CANARY-unset}}" >> {shlex.quote(str(log))}\n'
                f"printf '%s\\n' \"$@\" > {shlex.quote(str(args))}\n"
                f"exit {preflight_exit}\n"
            )
            cli.chmod(0o755)
            # The actual installer body is unchanged. These shell functions
            # substitute only unavailable/privileged host operations. The
            # provisioner exits even when preflight is missing (before-fix
            # control), so the fixture cannot reach real installation.
            fixture = f"""
uname() {{ echo Darwin; }}
id() {{ echo 0; }}
stat() {{ echo 0; }}
launchctl() {{ printf 'subdomains = {{\\n}}\\n'; }}
mktemp() {{ echo {shlex.quote(str(stage))}; }}
chown() {{ :; }}
chmod() {{ :; }}
cp() {{ :; }}
shasum() {{ echo checksum >> {shlex.quote(str(log))}; }}
codesign() {{ echo signature >> {shlex.quote(str(log))}; return {signature_exit}; }}
sh() {{ echo provision >> {shlex.quote(str(log))}; exit 73; }}
"""
            script = base / "installer.sh"
            script.write_text(
                fixture + (ROOT / "packaging/macos/install.sh").read_text()
            )
            env = dict(
                os.environ,
                depot_DIST=str(stage),
                depot_PROFILE=profile,
                F113_CANARY="must-be-cleared",
            )
            result = subprocess.run(
                ["/bin/sh", str(script)],
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
            )
            calls = log.read_text().splitlines() if log.exists() else []
            arguments = args.read_text().splitlines() if args.exists() else []
            return result, calls, arguments

    def test_failed_preflight_prevents_provisioning(self):
        result, calls, args = self.run_installer("L2", 10)
        self.assertEqual(result.returncode, 10, result.stdout + result.stderr)
        self.assertNotIn("provision", calls)
        self.assertEqual(args, ["deploy", "preflight", "--profile", "L2"])
        self.assertLess(
            calls.index("signature"),
            next(i for i, c in enumerate(calls) if c.startswith("preflight|")),
        )

    def test_valid_preflight_allows_provisioning_for_each_profile(self):
        for profile in ("L1", "L2", "L3"):
            with self.subTest(profile=profile):
                result, calls, args = self.run_installer(profile, 0)
                self.assertEqual(result.returncode, 73,
                                 result.stdout + result.stderr)
                self.assertEqual(
                    args, ["deploy", "preflight", "--profile", profile])
                self.assertEqual(calls[-1], "provision")
                self.assertIn(
                    "preflight|/usr/bin:/bin:/usr/sbin:/sbin|unset", calls)

    def test_l3_missing_broker_still_refused_before_preflight(self):
        result, calls, args = self.run_installer("L3", 0, broker=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(args)
        self.assertNotIn("provision", calls)

    def test_signature_failure_prevents_staged_cli_execution(self):
        result, calls, args = self.run_installer("L2", 0, signature_exit=1)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(args)
        self.assertNotIn("provision", calls)


if __name__ == "__main__":
    unittest.main()
