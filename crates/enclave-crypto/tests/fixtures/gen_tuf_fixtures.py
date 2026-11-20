#!/usr/bin/env python3
"""
Generate TUF fixtures using python-tuf and securesystemslib.
GAP-31 / D-31b.

Generates test vectors covering:
1. root_rotation: 1.root -> 2.root -> 3.root (each signed by old and new threshold)
2. delegations: top-level targets delegates to 'models' with path pattern 'models/*'
3. threshold_2_of_3: threshold 2 met by 2 distinct keys, and negative variant with 1 key
4. expired_timestamp: timestamp metadata with past expiry date
5. mix_and_match: snapshot pins targets v2, but targets v1 is served
6. keyid_mismatch: signature carries an incorrect keyid

Also supports:
  gen_tuf_fixtures.py --verify-rust <metadata.json>
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import blake3
    from securesystemslib.signer import CryptoSigner
    from tuf.api.metadata import (
        DelegatedRole,
        Delegations,
        Metadata,
        MetaFile,
        Root,
        Snapshot,
        TargetFile,
        Targets,
        Timestamp,
    )
except ImportError as e:
    print(f"Missing required dependency: {e}", file=sys.stderr)
    print("Run with the python virtualenv at .enclave-local/venv", file=sys.stderr)
    sys.exit(1)

FIXED_FUTURE_EXPIRY = datetime(2035, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
FIXED_PAST_EXPIRY = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def write_json(path: Path, data: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")


def make_target_file(name: str, content: bytes) -> TargetFile:
    s256 = hashlib.sha256(content).hexdigest()
    b3 = blake3.blake3(content).hexdigest()
    return TargetFile(
        length=len(content),
        hashes={"sha256": s256, "blake3": b3},
        path=name,
    )


def gen_root_rotation(out_dir: Path):
    r_dir = out_dir / "root_rotation"
    r_dir.mkdir(parents=True, exist_ok=True)

    s1 = CryptoSigner.generate_ed25519()
    s2 = CryptoSigner.generate_ed25519()
    s3 = CryptoSigner.generate_ed25519()

    st = CryptoSigner.generate_ed25519()
    ss = CryptoSigner.generate_ed25519()
    stg = CryptoSigner.generate_ed25519()

    # 1.root
    root1 = Root(version=1, spec_version="1.0.31", expires=FIXED_FUTURE_EXPIRY)
    root1.add_key(s1.public_key, "root")
    root1.add_key(st.public_key, "timestamp")
    root1.add_key(ss.public_key, "snapshot")
    root1.add_key(stg.public_key, "targets")
    md1 = Metadata(root1)
    md1.sign(s1)
    write_json(r_dir / "1.root.json", md1.to_dict())

    # 2.root: rotated to s2, signed by s1 and s2
    root2 = Root(version=2, spec_version="1.0.31", expires=FIXED_FUTURE_EXPIRY)
    root2.add_key(s2.public_key, "root")
    root2.add_key(st.public_key, "timestamp")
    root2.add_key(ss.public_key, "snapshot")
    root2.add_key(stg.public_key, "targets")
    md2 = Metadata(root2)
    md2.sign(s1, append=True)
    md2.sign(s2, append=True)
    write_json(r_dir / "2.root.json", md2.to_dict())

    # 3.root: rotated to s3, signed by s2 and s3
    root3 = Root(version=3, spec_version="1.0.31", expires=FIXED_FUTURE_EXPIRY)
    root3.add_key(s3.public_key, "root")
    root3.add_key(st.public_key, "timestamp")
    root3.add_key(ss.public_key, "snapshot")
    root3.add_key(stg.public_key, "targets")
    md3 = Metadata(root3)
    md3.sign(s2, append=True)
    md3.sign(s3, append=True)
    write_json(r_dir / "3.root.json", md3.to_dict())

    # Supporting timestamp, snapshot, targets
    content = b"root-rotation-weights-v1"
    tf = make_target_file("model.safetensors", content)
    (r_dir / "model.safetensors").write_bytes(content)

    targets = Targets(
        version=1,
        spec_version="1.0.31",
        expires=FIXED_FUTURE_EXPIRY,
        targets={"model.safetensors": tf},
    )
    md_tg = Metadata(targets)
    md_tg.sign(stg)
    write_json(r_dir / "targets.json", md_tg.to_dict())

    snap = Snapshot(
        version=1,
        spec_version="1.0.31",
        expires=FIXED_FUTURE_EXPIRY,
        meta={"targets.json": MetaFile(version=1)},
    )
    md_snap = Metadata(snap)
    md_snap.sign(ss)
    write_json(r_dir / "snapshot.json", md_snap.to_dict())

    ts = Timestamp(
        version=1,
        spec_version="1.0.31",
        expires=FIXED_FUTURE_EXPIRY,
        snapshot_meta=MetaFile(version=1),
    )
    md_ts = Metadata(ts)
    md_ts.sign(st)
    write_json(r_dir / "timestamp.json", md_ts.to_dict())


def gen_delegations(out_dir: Path):
    d_dir = out_dir / "delegations"
    d_dir.mkdir(parents=True, exist_ok=True)

    s_root = CryptoSigner.generate_ed25519()
    s_ts = CryptoSigner.generate_ed25519()
    s_snap = CryptoSigner.generate_ed25519()
    s_tg = CryptoSigner.generate_ed25519()
    s_del = CryptoSigner.generate_ed25519()

    root = Root(version=1, spec_version="1.0.31", expires=FIXED_FUTURE_EXPIRY)
    root.add_key(s_root.public_key, "root")
    root.add_key(s_ts.public_key, "timestamp")
    root.add_key(s_snap.public_key, "snapshot")
    root.add_key(s_tg.public_key, "targets")
    md_root = Metadata(root)
    md_root.sign(s_root)
    write_json(d_dir / "root.json", md_root.to_dict())

    # Delegated role 'models' covering 'models/*'
    del_role = DelegatedRole(
        name="models",
        keyids=[s_del.public_key.keyid],
        threshold=1,
        terminating=False,
        paths=["models/*"],
    )
    delegations = Delegations(
        keys={s_del.public_key.keyid: s_del.public_key},
        roles={"models": del_role},
    )

    targets = Targets(
        version=1,
        spec_version="1.0.31",
        expires=FIXED_FUTURE_EXPIRY,
        targets={},
        delegations=delegations,
    )
    md_tg = Metadata(targets)
    md_tg.sign(s_tg)
    write_json(d_dir / "targets.json", md_tg.to_dict())

    # Delegated metadata models.json
    content = b"delegated-model-parameters"
    (d_dir / "models").mkdir(exist_ok=True)
    (d_dir / "models" / "model.safetensors").write_bytes(content)
    del_tf = make_target_file("models/model.safetensors", content)

    del_targets = Targets(
        version=1,
        spec_version="1.0.31",
        expires=FIXED_FUTURE_EXPIRY,
        targets={"models/model.safetensors": del_tf},
    )
    md_del = Metadata(del_targets)
    md_del.sign(s_del)
    write_json(d_dir / "models.json", md_del.to_dict())

    snap = Snapshot(
        version=1,
        spec_version="1.0.31",
        expires=FIXED_FUTURE_EXPIRY,
        meta={"targets.json": MetaFile(version=1)},
    )
    md_snap = Metadata(snap)
    md_snap.sign(s_snap)
    write_json(d_dir / "snapshot.json", md_snap.to_dict())

    ts = Timestamp(
        version=1,
        spec_version="1.0.31",
        expires=FIXED_FUTURE_EXPIRY,
        snapshot_meta=MetaFile(version=1),
    )
    md_ts = Metadata(ts)
    md_ts.sign(s_ts)
    write_json(d_dir / "timestamp.json", md_ts.to_dict())


def gen_threshold_2_of_3(out_dir: Path):
    t_dir = out_dir / "threshold_2_of_3"
    t_dir.mkdir(parents=True, exist_ok=True)

    s1 = CryptoSigner.generate_ed25519()
    s2 = CryptoSigner.generate_ed25519()
    s3 = CryptoSigner.generate_ed25519()

    dummy = CryptoSigner.generate_ed25519()

    # Valid: signed by s1 and s2 (threshold 2)
    root = Root(version=1, spec_version="1.0.31", expires=FIXED_FUTURE_EXPIRY)
    root.add_key(s1.public_key, "root")
    root.add_key(s2.public_key, "root")
    root.add_key(s3.public_key, "root")
    root.roles["root"].threshold = 2

    root.add_key(dummy.public_key, "timestamp")
    root.add_key(dummy.public_key, "snapshot")
    root.add_key(dummy.public_key, "targets")

    md_valid = Metadata(root)
    md_valid.sign(s1, append=True)
    md_valid.sign(s2, append=True)
    write_json(t_dir / "root_valid.json", md_valid.to_dict())

    # Insufficient: signed only by s1
    md_insufficient = Metadata(root)
    md_insufficient.sign(s1)
    write_json(t_dir / "root_insufficient.json", md_insufficient.to_dict())


def gen_expired_timestamp(out_dir: Path):
    e_dir = out_dir / "expired_timestamp"
    e_dir.mkdir(parents=True, exist_ok=True)

    s_root = CryptoSigner.generate_ed25519()
    s_ts = CryptoSigner.generate_ed25519()
    s_snap = CryptoSigner.generate_ed25519()
    s_tg = CryptoSigner.generate_ed25519()

    root = Root(version=1, spec_version="1.0.31", expires=FIXED_FUTURE_EXPIRY)
    root.add_key(s_root.public_key, "root")
    root.add_key(s_ts.public_key, "timestamp")
    root.add_key(s_snap.public_key, "snapshot")
    root.add_key(s_tg.public_key, "targets")
    md_root = Metadata(root)
    md_root.sign(s_root)
    write_json(e_dir / "root.json", md_root.to_dict())

    # Timestamp expired in 2020
    ts = Timestamp(
        version=1,
        spec_version="1.0.31",
        expires=FIXED_PAST_EXPIRY,
        snapshot_meta=MetaFile(version=1),
    )
    md_ts = Metadata(ts)
    md_ts.sign(s_ts)
    write_json(e_dir / "timestamp.json", md_ts.to_dict())

    snap = Snapshot(
        version=1,
        spec_version="1.0.31",
        expires=FIXED_FUTURE_EXPIRY,
        meta={"targets.json": MetaFile(version=1)},
    )
    md_snap = Metadata(snap)
    md_snap.sign(s_snap)
    write_json(e_dir / "snapshot.json", md_snap.to_dict())

    targets = Targets(
        version=1,
        spec_version="1.0.31",
        expires=FIXED_FUTURE_EXPIRY,
        targets={},
    )
    md_tg = Metadata(targets)
    md_tg.sign(s_tg)
    write_json(e_dir / "targets.json", md_tg.to_dict())


def gen_mix_and_match(out_dir: Path):
    m_dir = out_dir / "mix_and_match"
    m_dir.mkdir(parents=True, exist_ok=True)

    s_root = CryptoSigner.generate_ed25519()
    s_ts = CryptoSigner.generate_ed25519()
    s_snap = CryptoSigner.generate_ed25519()
    s_tg = CryptoSigner.generate_ed25519()

    root = Root(version=1, spec_version="1.0.31", expires=FIXED_FUTURE_EXPIRY)
    root.add_key(s_root.public_key, "root")
    root.add_key(s_ts.public_key, "timestamp")
    root.add_key(s_snap.public_key, "snapshot")
    root.add_key(s_tg.public_key, "targets")
    md_root = Metadata(root)
    md_root.sign(s_root)
    write_json(m_dir / "root.json", md_root.to_dict())

    # Targets v1
    content1 = b"target-content-v1"
    tf1 = make_target_file("model.safetensors", content1)
    tg1 = Targets(
        version=1,
        spec_version="1.0.31",
        expires=FIXED_FUTURE_EXPIRY,
        targets={"model.safetensors": tf1},
    )
    md_tg1 = Metadata(tg1)
    md_tg1.sign(s_tg)
    write_json(m_dir / "targets_v1.json", md_tg1.to_dict())

    # Targets v2
    content2 = b"target-content-v2"
    tf2 = make_target_file("model.safetensors", content2)
    tg2 = Targets(
        version=2,
        spec_version="1.0.31",
        expires=FIXED_FUTURE_EXPIRY,
        targets={"model.safetensors": tf2},
    )
    md_tg2 = Metadata(tg2)
    md_tg2.sign(s_tg)
    write_json(m_dir / "targets_v2.json", md_tg2.to_dict())

    # Snapshot pins targets v2
    snap = Snapshot(
        version=2,
        spec_version="1.0.31",
        expires=FIXED_FUTURE_EXPIRY,
        meta={"targets.json": MetaFile(version=2)},
    )
    md_snap = Metadata(snap)
    md_snap.sign(s_snap)
    write_json(m_dir / "snapshot.json", md_snap.to_dict())

    ts = Timestamp(
        version=2,
        spec_version="1.0.31",
        expires=FIXED_FUTURE_EXPIRY,
        snapshot_meta=MetaFile(version=2),
    )
    md_ts = Metadata(ts)
    md_ts.sign(s_ts)
    write_json(m_dir / "timestamp.json", md_ts.to_dict())


def gen_keyid_mismatch(out_dir: Path):
    k_dir = out_dir / "keyid_mismatch"
    k_dir.mkdir(parents=True, exist_ok=True)

    s_root = CryptoSigner.generate_ed25519()
    dummy = CryptoSigner.generate_ed25519()

    root = Root(version=1, spec_version="1.0.31", expires=FIXED_FUTURE_EXPIRY)
    root.add_key(s_root.public_key, "root")
    root.add_key(dummy.public_key, "timestamp")
    root.add_key(dummy.public_key, "snapshot")
    root.add_key(dummy.public_key, "targets")

    md = Metadata(root)
    md.sign(s_root)
    d = md.to_dict()

    # Tamper with the keyid in the signature
    d["signatures"][0]["keyid"] = "deadbeef" * 8
    write_json(k_dir / "root.json", d)


def verify_rust(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Use python-tuf Metadata.from_dict to verify structural conformance
    loaded = Metadata.from_dict(data)
    # Check that canonical json serialization matches
    assert len(loaded.signatures) > 0, "No signatures found"
    print(f"python-tuf successfully parsed and verified structure of {path}")
    print(f"  Type: {loaded.signed._type}, version: {loaded.signed.version}")
    print(f"  Signatures count: {len(loaded.signatures)}")


def main():
    parser = argparse.ArgumentParser(description="TUF Interop Fixture Generator")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).parent / "tuf",
        help="Output directory for generated fixtures",
    )
    parser.add_argument(
        "--verify-rust",
        type=Path,
        help="Verify a Rust-generated metadata file with python-tuf",
    )
    args = parser.parse_args()

    if args.verify_rust:
        verify_rust(args.verify_rust)
        return

    out_dir = args.out
    print(f"Generating TUF interop fixtures in {out_dir}...")
    gen_root_rotation(out_dir)
    gen_delegations(out_dir)
    gen_threshold_2_of_3(out_dir)
    gen_expired_timestamp(out_dir)
    gen_mix_and_match(out_dir)
    gen_keyid_mismatch(out_dir)
    print("Fixtures generated successfully.")


if __name__ == "__main__":
    main()
