#!/usr/bin/env python3
"""Bounded ContextDag correspondence; no semantic sanitizer guarantee."""

import argparse
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def vectors(text):
    rows = text.splitlines()
    if len(rows) != 3440:
        raise ValueError("incomplete graph correspondence corpus")
    index = 0
    for parents in range(86):
        for explicit in range(5):
            for conf in range(1, 5):
                for sanitize in range(2):
                    fields = rows[index].split(",")
                    prefix = [
                        "G",
                        *map(str, [index, parents, explicit, conf, sanitize]),
                    ]
                    if fields[:6] != prefix or len(fields) != 9:
                        raise ValueError(f"invalid graph domain row{index}")
                    if (
                        fields[6] not in ("0", "1", "2")
                        or fields[7] not in ("0", "1", "2", "3", "255")
                        or fields[8] not in ("0", "1")
                    ):
                        raise ValueError(f"invalid graph outcome row{index}")
                    index += 1
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust-output", type=Path)
    parser.add_argument("--lean-output", type=Path)
    args = parser.parse_args()
    if bool(args.rust_output) != bool(args.lean_output):
        parser.error("supply both captured outputs or neither")
    if args.rust_output:
        rust, lean = args.rust_output.read_text(), args.lean_output.read_text()
        print("Comparing captured outputs; caller retains execution provenance.")
    else:
        lean = subprocess.check_output(
            ["lake", "env", "lean", "--run", "ContextVectors.lean"],
            cwd=ROOT / "proofs/lean4",
            text=True,
        )
        rust = subprocess.check_output(
            [
                "cargo",
                "run",
                "--locked",
                "-q",
                "-p",
                "enclave-agent-runtime",
                "--example",
                "context-correspondence",
            ],
            cwd=ROOT,
            text=True,
        )
    fixture = ROOT / "crates/enclave-agent-runtime/tests/data/context-lean-4.14.0.csv"
    if lean != fixture.read_text():
        raise SystemExit("FAIL: native fixture differs from current pinned Lean output")
    for actual, model in zip(vectors(rust), vectors(lean)):
        if actual != model:
            raise SystemExit(f"FAIL: Rust {actual}; Lean {model}")
    print(
        "PASS:3440 actual graph admission/integrity/endorsement-update cases match pinned Lean."
    )
    print(
        "85 ordered parent-taint lists plus unknown parent,5 explicit-label choices,4confidentialities,2update modes."
    )
    print(
        "Finite projection only; sanitizer validity, endorsement authority, caller provenance and physical controls remain open."
    )


if __name__ == "__main__":
    main()
