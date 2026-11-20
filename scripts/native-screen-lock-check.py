#!/usr/bin/env python3
"""Build/check production helper and its separate private screen-lock relay fixture.

Does not create an application, subscribe/post notifications, connect to installed
sockets, sign/enroll keys or change any service. Requires a non-root Darwin user.
"""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


def main():
    if sys.platform != "darwin" or os.geteuid() == 0:
        print("NOT RUN: requires non-root Darwin build account", flush=True)
        return 77
    root = Path(__file__).resolve().parents[1]
    subprocess.run(
        [sys.executable, str(
            root / "scripts/native-macos-check.py"), "swift-build"],
        cwd=root,
        check=True,
    )
    scratch = root / ".native-macos" / "screen-lock"
    command = [
        "swift",
        "build",
        "--package-path",
        str(root / "helpers/enclaveintent"),
        "--scratch-path",
        str(scratch),
        "-c",
        "release",
        "-Xswiftc",
        "-Ddepot_NATIVE_TESTING",
    ]
    print(
        json.dumps(
            {
                "build_argv": command,
                "scope": "private socketpair only; no host lock event or installed socket",
            }
        ),
        flush=True,
    )
    subprocess.run(command, cwd=root, check=True)
    binary_dir = subprocess.run(
        command + ["--show-bin-path"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    helper = (Path(binary_dir) / "enclave-intent").resolve(strict=True)
    if not helper.is_relative_to(scratch.resolve()):
        raise RuntimeError("Build helper escaped private checkout scratch")
    print(
        json.dumps(
            {
                "helper": str(helper),
                "sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
            }
        ),
        flush=True,
    )
    result = subprocess.run(
        [str(helper), "--native-test", "--screen-lock-relay-self-test"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    print(result.stdout, end="", flush=True)
    print(result.stderr, end="", file=sys.stderr, flush=True)
    if (
        "screen-lock relay private fixtures PASS; no host notifications or installed sockets"
        not in result.stdout
    ):
        raise RuntimeError("Private fixture completion missing")
    print(
        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode if error.returncode > 0 else 1)
