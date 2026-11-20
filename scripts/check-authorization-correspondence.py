#!/usr/bin/env python3
"""Compare production Cedar decisions to the compiled abstract model.

Captured-output mode supports separate native Rust and Linux Lean execution.
The caller must retain exact revisions, command outcomes and log hashes.
"""

import argparse
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "proofs/lean4"


def vectors(output):
    rows = output.splitlines()
    if len(rows) != 7104:
        raise ValueError(f"expected7104 rows, got{len(rows)}")
    index = 0
    for policy in range(111):
        for taint in range(4):
            for conf in range(1, 5):
                for action in range(2):
                    for namespace in range(2):
                        fields = rows[index].split(",")
                        prefix = [
                            "C",
                            *map(str, [index, policy, taint, conf, action, namespace]),
                        ]
                        if fields[:-1] != prefix or fields[-1] not in ("0", "1"):
                            raise ValueError(
                                f"invalid/missing/out-of-order row{index}: {rows[index]}"
                            )
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
        rust = args.rust_output.read_text()
        lean = args.lean_output.read_text()
        print(
            "Comparing captured outputs; execution provenance remains the caller's responsibility."
        )
    else:
        subprocess.run(
            ["lake", "build", "authorization_vectors"], cwd=PACKAGE, check=True
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
                "authorization-correspondence",
            ],
            cwd=ROOT,
            text=True,
        )
        lean = subprocess.check_output(
            ["lake", "exe", "authorization_vectors"], cwd=PACKAGE, text=True
        )
    fixture = ROOT / "crates/enclave-agent-runtime/tests/data/cedar-lean-4.14.0.csv"
    if lean != fixture.read_text():
        raise SystemExit(
            "FAIL: committed native fixture differs from current compiled Lean output"
        )
    a, b = vectors(rust), vectors(lean)
    for actual, model in zip(a, b):
        if actual != model:
            raise SystemExit(f"FAIL: Rust {actual}; Lean {model}")
    print(
        "PASS:7104 actual CedarEngine policy/request decisions match compiled CedarSemantics."
    )
    print(
        "111 ordered policy lists (empty/single/pairs), permit/forbid precedence and5 predicates over64 requests."
    )
    print(
        "Bounded predicate projection; no signed-bundle/Biscuit/caller/OS authority or universal refinement claim."
    )


if __name__ == "__main__":
    main()
