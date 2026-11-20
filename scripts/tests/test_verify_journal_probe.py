"""Execute the production shell helper on owned, nonprivileged fixtures.

This does not run verify-install, sudo, Seatbelt, launchd or any host mutation.
"""

import pathlib
import shlex
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "packaging/macos/verify-install.sh"
BEGIN = "# BEGIN exclusive journal probe helper\n"
END = "# END exclusive journal probe helper\n"


class JournalProbeOwnership(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mcpmac-probe-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.directory = self.root / "journal with spaces"
        self.directory.mkdir()
        source = SCRIPT.read_text()
        self.assertEqual(source.count(BEGIN), 1)
        self.assertEqual(source.count(END), 1)
        self.helper = source.split(BEGIN, 1)[1].split(END, 1)[0]

    def invoke(self, *prefix):
        return subprocess.run(
            [
                "/bin/sh",
                "-c",
                self.helper + '\njournal_probe_write "$@"\n',
                "probe-fixture",
                str(self.directory),
                *prefix,
            ],
            capture_output=True,
            timeout=5,
        )

    def wrapper(self, body):
        path = self.root / "owned wrapper"
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(0o700)
        return str(path)

    def test_exclusive_probe_preserves_predictable_files_and_symlink_targets(self):
        first = self.directory / ".verify"
        first.write_bytes(b"existing positive-control name")
        target = self.root / "unrelated sentinel"
        target.write_bytes(b"existing cross-write target")
        link = self.directory / ".xwrite-from-adapter"
        link.symlink_to(target)
        before = {p: p.lstat() for p in (first, target, link)}
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(set(self.directory.iterdir()), {first, link})
        self.assertEqual(first.read_bytes(), b"existing positive-control name")
        self.assertEqual(target.read_bytes(), b"existing cross-write target")
        self.assertTrue(link.is_symlink())
        for path, stat in before.items():
            after = path.lstat()
            self.assertEqual(
                (after.st_dev, after.st_ino, after.st_mode),
                (stat.st_dev, stat.st_ino, stat.st_mode),
            )

    def test_creation_refusal_never_adopts_or_deletes_existing_probe(self):
        sentinel = self.directory / ".mcpmac-verify.existing"
        sentinel.write_bytes(b"preserve on refused command")
        before = sentinel.stat()
        result = self.invoke("/usr/bin/false")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(sentinel.read_bytes(), b"preserve on refused command")
        self.assertEqual(sentinel.stat().st_ino, before.st_ino)

    def test_empty_success_output_is_incomplete(self):
        result = self.invoke("/usr/bin/true")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_foreign_success_output_cannot_authorize_cleanup(self):
        sentinel = self.root / "foreign sentinel"
        sentinel.write_bytes(b"not this probe's path")
        prefix = self.wrapper("printf '%s\\n' " + shlex.quote(str(sentinel)))
        result = self.invoke(prefix)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(sentinel.read_bytes(), b"not this probe's path")

    def test_cleanup_failure_is_incomplete_and_does_not_recursively_delete(self):
        directory = self.directory / ".mcpmac-verify.A1b2C3d4"
        directory.mkdir()
        sentinel = directory / "preserve"
        sentinel.write_bytes(b"cleanup may not recurse")
        prefix = self.wrapper("printf '%s\\n' " + shlex.quote(str(directory)))
        result = self.invoke(prefix)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(sentinel.read_bytes(), b"cleanup may not recurse")

    def test_traversal_and_multiline_outputs_cannot_authorize_cleanup(self):
        sentinel = self.root / "foreign sentinel"
        sentinel.write_bytes(b"never delete through a generated-name prefix")
        for value in [
            str(
                self.directory / ".mcpmac-verify.A1b2C3d4" / ".." / ".." / sentinel.name
            ),
            str(self.directory / ".mcpmac-verify.A1b2C3d4") + "\n" + str(sentinel),
        ]:
            prefix = self.wrapper("printf '%s\\n' " + shlex.quote(value))
            result = self.invoke(prefix)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(
                sentinel.read_bytes(), b"never delete through a generated-name prefix"
            )


if __name__ == "__main__":
    unittest.main()
