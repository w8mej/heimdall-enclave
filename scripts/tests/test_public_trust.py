"""Exercise actual bounded public inventory/copy functions in private fixtures.

These checks establish structural packaging behavior, not TUF signature validity
or organizational authority. Runtime TUF provides cryptographic admission.
"""

import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FILES = (
    "root.json",
    "timestamp.json",
    "snapshot.json",
    "targets.json",
    "enclave-host-config.json",
    "enclave-policy.cedar.v1.json",
    "vk_manifest.json",
    "enclave-distribution-v1.json",
)
HELPER = ROOT / "packaging/macos/public-trust.sh"


class PublicTrust(unittest.TestCase):
    def execute(self, repo, destination=None):
        command = ". " + shlex.quote(str(HELPER)) + "\n"
        command += (
            "copy_public_trust "
            + shlex.quote(str(repo))
            + " "
            + shlex.quote(str(destination))
            if destination
            else "require_public_trust " + shlex.quote(str(repo))
        )
        return subprocess.run(
            ["/bin/sh", "-c", command], capture_output=True, text=True, timeout=5
        )

    def fixture(self, root):
        repo = root / "repo"
        repo.mkdir()
        for name in FILES:
            (repo / name).write_text('{"fixture_public":true}')
        return repo

    def test_complete_inventory_copies_exact_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = self.fixture(root)
            destination = root / "out"
            out = self.execute(repo, destination)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertEqual(
                sorted(p.name for p in destination.iterdir()), sorted(FILES)
            )
            for name in FILES:
                self.assertEqual(
                    (destination / name).read_bytes(), (repo / name).read_bytes()
                )

    def test_missing_roles_or_payloads_refuse_before_copy(self):
        for name in FILES:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                repo = self.fixture(root)
                (repo / name).unlink()
                result = self.execute(repo, root / "out")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("PUBLIC_TRUST_REQUIRED", result.stderr)
                self.assertFalse((root / "out").exists())

    def test_empty_link_private_and_unrecognized_inputs_refuse(self):
        for bad in ("empty", "link", "seed", "pem", "extra", "directory"):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                repo = self.fixture(root)
                file = repo / "root.json"
                if bad == "empty":
                    file.write_bytes(b"")
                if bad == "link":
                    file.unlink()
                    file.symlink_to(repo / "targets.json")
                if bad == "seed":
                    file.write_text('{"seed":"fixture-only-dummy"}')
                if bad == "pem":
                    file.write_text("-----BEGIN PRIVATE KEY-----\nfixture-only\n")
                if bad == "extra":
                    (repo / "keys.json").write_text("{}")
                if bad == "directory":
                    file.unlink()
                    file.mkdir()
                result = self.execute(repo, root / "out")
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / "out").exists())

    def test_numbered_root_rotation_is_bounded_and_copied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = self.fixture(root)
            (repo / "2.root.json").write_text('{"signed":{"version":2}}')
            destination = root / "out"
            self.assertEqual(self.execute(repo, destination).returncode, 0)
            self.assertEqual(
                (destination / "2.root.json").read_bytes(),
                (repo / "2.root.json").read_bytes(),
            )
            (repo / "02.root.json").write_text("{}")
            self.assertNotEqual(self.execute(repo).returncode, 0)
            (repo / "02.root.json").unlink()
            for number in range(3, 35):
                (repo / f"{number}.root.json").write_text("{}")
            self.assertNotEqual(self.execute(repo).returncode, 0)

    def test_installer_embeds_same_verified_inventory_function(self):
        source = (ROOT / "packaging/macos/install.sh").read_text()
        embedded = source.split(
            "# BEGIN embedded public-trust inventory (kept equal to public-trust.sh)\n"
        )[1].split("# END embedded public-trust inventory")[0]
        self.assertEqual(embedded, HELPER.read_text())


if __name__ == "__main__":
    unittest.main()
