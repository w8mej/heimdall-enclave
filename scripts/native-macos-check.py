#!/usr/bin/env python3
"""Build and identify a checkout-local native GUI test helper. Python 3.10+."""

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path


def run(argv, **kwargs):
    print("+ " + shlex.join([str(x) for x in argv]), flush=True)
    return subprocess.run([str(x) for x in argv], check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("check", choices=["intent", "swift-build"])
    args = parser.parse_args()
    if sys.platform != "darwin" or os.geteuid() == 0:
        print(
            "NOT RUN: native GUI testing requires a non-root Mac console user",
            flush=True,
        )
        return 77
    root = Path(__file__).resolve().parents[1]
    if args.check == "swift-build":
        build = [
            "swift",
            "build",
            "--package-path",
            root / "helpers/enclaveintent",
            "-c",
            "release",
        ]
        run(build, cwd=root)
        binary_dir = run(
            build + ["--show-bin-path"], cwd=root, capture_output=True, text=True
        ).stdout.strip()
        helper = Path(binary_dir) / "enclave-intent"
        refused = subprocess.run(
            [str(helper), "--native-test"], capture_output=True, text=True, timeout=10
        )
        if refused.returncode != 2 or "separately compiled" not in refused.stderr:
            raise RuntimeError(
                "Production helper did not refuse native-test mode")
        print("Production release helper correctly refuses --native-test", flush=True)
        return 0
    scratch = root / ".native-macos" / "intent"
    build = [
        "swift",
        "build",
        "--package-path",
        root / "helpers/enclaveintent",
        "--scratch-path",
        scratch,
        "-c",
        "release",
        "-Xswiftc",
        "-Ddepot_NATIVE_TESTING",
    ]
    run(build, cwd=root)
    binary_dir = run(
        build + ["--show-bin-path"], cwd=root, capture_output=True, text=True
    ).stdout.strip()
    helper = (Path(binary_dir) / "enclave-intent").resolve(strict=True)
    if not helper.is_relative_to(scratch.resolve()):
        raise RuntimeError("Swift returned a helper outside this checkout")
    run(
        [
            "codesign",
            "--force",
            "--sign",
            "-",
            "--options",
            "runtime",
            "--identifier",
            "com.enterprise.enclave.intent.native-test",
            helper,
        ],
        cwd=root,
    )
    run(["codesign", "--verify", "--strict", "--verbose=2", helper], cwd=root)
    run(["codesign", "-dv", "--verbose=2", helper], cwd=root)
    sha = hashlib.sha256(helper.read_bytes()).hexdigest()
    print(
        "NATIVE_HELPER "
        + json.dumps(
            {
                "path": str(helper),
                "sha256": sha,
                "build": "release with depot_NATIVE_TESTING",
                "coverage": "GUI and real SEP signatures; production peer authentication excluded",
            }
        ),
        flush=True,
    )
    env = dict(
        os.environ,
        depot_HW="1",
        depot_INTENT_NATIVE_TEST="1",
        depot_INTENT_HELPER=str(helper),
        depot_INTENT_HELPER_SHA256=sha,
    )
    run(
        [
            "cargo",
            "test",
            "--locked",
            "-j",
            "2",
            "-p",
            "enclave-custody-vaultd",
            "--test",
            "hw_intent",
            "--",
            "--nocapture",
            "--test-threads=1",
        ],
        cwd=root,
        env=env,
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode if error.returncode > 0 else 1)
