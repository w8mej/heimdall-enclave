#!/usr/bin/env python3
"""Bounded production/Lean comparison; no universal Rust refinement claim."""

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "proofs/lean4"
subprocess.run(["lake", "build", "protocol_vectors"], cwd=PACKAGE, check=True)
rust = subprocess.check_output(
    [
        "cargo",
        "run",
        "--locked",
        "-q",
        "-p",
        "enclave-tool-host",
        "--example",
        "proof-vectors",
    ],
    cwd=ROOT,
    text=True,
)
lean = subprocess.check_output(
    ["lake", "exe", "protocol_vectors"], cwd=PACKAGE, text=True
)
expected = {"T": 12288, "R": 9, "D": 324, "Q": 4251, "L": 1620, "E": 5184}


def vectors(output):
    lines = output.splitlines()
    if len(lines) != sum(expected.values()) or len(set(lines)) != len(lines):
        raise SystemExit("FAIL: unexpected/missing/duplicate vector rows")
    for tag, count in expected.items():
        actual = [line.split(",")[1] for line in lines if line.startswith(tag + ",")]
        if actual != list(map(str, range(count))):
            raise SystemExit("FAIL: incomplete vector domain " + tag)
    return lines


a, b = vectors(rust), vectors(lean)
if a != b:
    for x, y in zip(a, b):
        if x != y:
            raise SystemExit(f"FAIL: Rust {x}; Lean {y}")
    raise SystemExit("FAIL: vector count mismatch")
for row in a:
    if row.startswith("Q,"):
        _, _, k, charged = row.split(",")
        k = int(k)
        exact = 0 if k <= 1 else (pow(k, 1000) - 1).bit_length()
        if int(charged) != exact:
            raise SystemExit(
                "FAIL: exact Python integer pricing oracle disagrees: " + row
            )
print(
    "PASS: 12288 actual V2 ticket encodings, 9 durable replay steps (including reopen),"
)
print(
    "324 overflow-boundary DPoP freshness cases, 4251 exact millibit prices, and 1620 rolling-ledger steps match compiled Lean."
)
print(
    "All prices also agree with an independent Python arbitrary-precision integer oracle."
)
print(
    "Bounded translation validation only; dispatch, signatures, storage durability and URI parsing need separate evidence."
)
print(
    "Rolling comparisons include exact lazy storage, duplicate keys, global pools, clock rollback, expiry and validated restoration."
)
print(
    "All 1296 four-operation egress histories (5184 transitions) match, including both sign/release orders and epoch separation."
)
