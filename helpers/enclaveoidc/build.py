#!/usr/bin/env python3
"""Compile the separate native broker; never install or start authentication."""

import argparse
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-test", action="store_true")
    parser.add_argument(
        "--signing-mode", choices=("local-pins", "team-id"), default="local-pins"
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    suffix = "native-test" if args.native_test else "production"
    output = (args.output or ROOT / "target" /
              ("yubikey-oidc-" + suffix)).resolve()
    if not output.is_relative_to(ROOT / "target"):
        parser.error("output must remain in this checkout target directory")
    output.parent.mkdir(parents=True, exist_ok=True)
    cache = ROOT / "target/yubikey-swift-module-cache"
    cache.mkdir(exist_ok=True)
    # Reuse wire/CBOR/display support and the context-free denial-only upgrade
    # gate. OIDC owns its selected context and peer verifier; the intent helper's
    # production context must not leak in.
    shared = ROOT / "helpers/enclaveintent/Sources/enclaveintent"
    sources = [
        shared / name
        for name in [
            "CBOR.swift",
            "SecureDisplay.swift",
            "OcclusionDetector.swift",
            "DeploymentUpgrade.swift",
        ]
    ]
    sources += sorted((ROOT / "helpers/enclaveoidc/Sources").glob("*.swift"))
    command = [
        "/usr/bin/xcrun",
        "swiftc",
        "-module-cache-path",
        str(cache),
        "-o",
        str(output),
    ]
    if args.native_test:
        command += ["-D", "depot_OIDC_NATIVE_TESTING"]
    if args.signing_mode == "team-id":
        command += ["-D", "depot_TEAM_ID_MODE"]
    command += [str(source) for source in sources]
    return subprocess.call(command, cwd=ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
