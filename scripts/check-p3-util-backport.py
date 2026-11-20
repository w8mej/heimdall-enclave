#!/usr/bin/env python3
"""Offline identity check for the narrowly scoped Rust1.89 dependency backport.

Checks reconstructed upstream bytes, inventory, license identities and unchanged
locked dependency versions. This does not replace compilation or crypto tests.
"""

import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "vendor/p3-util"
BASELINE = "338481bb17a08bfc666e70194862436c21ea2c40"
SHA = "b2deb6b0e30be32c696ab3cd443cc6f10b2ffce0faa31d37bd59e58789dd6df1"
PATCH = b"""        // depot Rust 1.89 backport: the slice MaybeUninit API stabilized later.
        // SAFETY: iter_next_chunk_erased initialized exactly the first n bytes,
        // n <= BUFLEN, and MaybeUninit<u8> has the same layout as u8. The slice
        // stays within this buffer and cannot outlive this callback.
        func(unsafe { core::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) });"""
ORIGINAL = b"        func(unsafe { buf.get_unchecked(..n).assume_init_ref() });"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def versions(text):
    result = []
    for package in text.split("[[package]]")[1:]:
        name = re.search(r'^name = "([^"]+)"$', package, re.M).group(1)
        version = re.search(r'^version = "([^"]+)"$', package, re.M).group(1)
        result.append((name, version))
    return sorted(result)


manifest = json.loads((VENDOR / "upstream-source.json").read_text())
assert manifest["archive_sha256"] == SHA
expected = set(manifest["original_files_sha256"]
               ) | set(manifest["added_files"])
actual = {str(p.relative_to(VENDOR)) for p in VENDOR.rglob("*") if p.is_file()}
assert actual == expected, (actual - expected, expected - actual)
for name, sha in manifest["original_files_sha256"].items():
    path = (VENDOR / name).resolve(strict=True)
    path.relative_to(VENDOR)
    data = path.read_bytes()
    if name == "src/lib.rs":
        assert data.count(PATCH) == 1
        data = data.replace(PATCH, ORIGINAL)
    assert digest(data) == sha, name
for name, sha in {
    "LICENSE-MIT": "d6543a1b0a0a51d10b5f8c389324c7dfeba556b7f39815efd292927bde808700",
    "LICENSE-APACHE": "3708458dee7f359ac6c9c5558023ed481be87e5372c43ebd7f2ca7ad23c12026",
}.items():
    assert digest((VENDOR / name).read_bytes()) == sha, name
old = subprocess.check_output(
    ["git", "-C", str(ROOT), "show", BASELINE + ":Cargo.lock"], text=True
)
assert versions(old) == versions((ROOT / "Cargo.lock").read_text())
print(
    json.dumps(
        {
            "status": "PASS",
            "scope": __doc__.strip(),
            "upstream_archive_sha256": SHA,
            "original_files": len(manifest["original_files_sha256"]),
            "unchanged_locked_package_versions": len(versions(old)),
        },
        indent=2,
    )
)
