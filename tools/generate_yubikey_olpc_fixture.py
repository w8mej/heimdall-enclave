#!/usr/bin/env python3
"""Generate synthetic external TUF fixtures using pinned securesystemslib/OpenSSL.

No depot canonicalizer or signing implementation is imported. The fixed seed
is public test input, never production authority. No network or installation.
"""

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

WHEEL_SHA256 = "2e5414bbdde33155a91805b295cbedc4ae3f12b48dccc63e1089093537f43c81"
ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    wheel = args.wheel.resolve(strict=True)
    if hashlib.sha256(wheel.read_bytes()).hexdigest() != WHEEL_SHA256:
        parser.error("pinned external wheel hash mismatch")
    destination = args.output.resolve()
    if not destination.is_relative_to(ROOT) or destination.exists():
        parser.error("new repository-local output directory required")
    sys.path.insert(0, str(wheel))
    from securesystemslib.formats import encode_canonical

    def canonical(value):
        return encode_canonical(value).encode("utf-8")

    def wire(value):
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    destination.mkdir(parents=True)
    with tempfile.TemporaryDirectory(
        dir=ROOT / "target", prefix="yubikey-olpc-synthetic-"
    ) as temporary:
        temporary = Path(temporary)
        key = temporary / "public-test-seed.der"
        key.write_bytes(
            bytes.fromhex("302e020100300506032b657004220420") +
            bytes([73]) * 32
        )
        command = [
            "openssl",
            "pkey",
            "-inform",
            "DER",
            "-in",
            str(key),
            "-pubout",
            "-outform",
            "DER",
        ]
        public = subprocess.check_output(command, timeout=10)[-32:]
        tuf_key = {
            "keytype": "ed25519",
            "scheme": "ed25519",
            "keyval": {"public": public.hex()},
        }
        key_id = hashlib.sha256(canonical(tuf_key)).hexdigest()
        files = {}
        preimages = {}

        def sign(name, body):
            message = canonical(body)
            input_path = temporary / "message"
            input_path.write_bytes(message)
            signature = subprocess.check_output(
                [
                    "openssl",
                    "pkeyutl",
                    "-sign",
                    "-rawin",
                    "-keyform",
                    "DER",
                    "-inkey",
                    str(key),
                    "-in",
                    str(input_path),
                ],
                timeout=10,
            )
            assert len(signature) == 64
            result = wire(
                {
                    "signed": body,
                    "signatures": [{"keyid": key_id, "sig": signature.hex()}],
                }
            )
            files[name + ".json"] = result
            preimages[name] = message.hex()
            return result

        expires = "2035-01-01T00:00:00Z"
        common = {"version": 1, "spec_version": "1.0.31", "expires": expires}
        sign(
            "root",
            dict(
                common,
                _type="root",
                consistent_snapshot=False,
                keys={key_id: tuf_key},
                roles={
                    name: {"keyids": [key_id], "threshold": 1}
                    for name in ["root", "timestamp", "snapshot", "targets"]
                },
            ),
        )
        target = b"abc"
        targets = sign(
            "targets",
            dict(
                common,
                _type="targets",
                targets={
                    "synthetic.txt": {
                        "length": len(target),
                        "hashes": {
                            "sha256": hashlib.sha256(target).hexdigest(),
                            "blake3": "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
                        },
                        "custom": {
                            "description": 'line\nnext\t"quoted"\\path',
                            "\ue000": "BMP",
                            "\U0001f600": "astral",
                            "integer": 9007199254740991,
                        },
                    }
                },
            ),
        )

        def link(data):
            return {
                "version": 1,
                "length": len(data),
                "hashes": {"sha256": hashlib.sha256(data).hexdigest()},
            }

        snapshot = sign(
            "snapshot",
            dict(common, _type="snapshot", meta={
                 "targets.json": link(targets)}),
        )
        sign(
            "timestamp",
            dict(common, _type="timestamp", meta={
                 "snapshot.json": link(snapshot)}),
        )
        provenance = {
            "qualification": "EXTERNAL_SOFTWARE_FIXTURE_ONLY",
            "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "securesystemslib_version": "1.3.1",
            "wheel_sha256": WHEEL_SHA256,
            "openssl_version": subprocess.check_output(
                ["openssl", "version"], text=True
            ).strip(),
            "public_synthetic_seed_hex": (bytes([73]) * 32).hex(),
            "public_key_hex": public.hex(),
            "keyid": key_id,
            "signed_preimages_hex": preimages,
            "file_sha256": {
                name: hashlib.sha256(data).hexdigest() for name, data in files.items()
            },
            "exclusions": "No guarded signer, independent custodian, SEP, authenticator, production protocol approval or deployment",
        }
        for name, data in files.items():
            (destination / name).write_bytes(data)
        (destination / "provenance.json").write_text(
            json.dumps(provenance, indent=2) + "\n"
        )
    print(
        json.dumps(
            {"destination": str(destination), "files": len(
                files), "keyid": key_id}
        )
    )


if __name__ == "__main__":
    main()
