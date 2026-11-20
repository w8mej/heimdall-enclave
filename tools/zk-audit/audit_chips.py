#!/usr/bin/env python3
"""Find concrete counterexamples in polynomials extracted from real Rust AIRs.

Exit 1 means a counterexample was found; 0 means these bounded fixtures found
none, NOT that the AIR is sound. Compiler/export errors exit 2. No hash axiom or
idealized Python constraint is substituted for the Rust implementation.
"""

import argparse
import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load_constraints():
    result = subprocess.run(
        [
            "cargo",
            "run",
            "--quiet",
            "-p",
            "enclave-zk-auditor",
            "--example",
            "audit-constraints",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(result.stdout)


def evaluate(expression, rows, public, row, prime):
    op, *args = expression
    if op == "constant":
        return args[0] % prime
    if op == "main":
        return rows[(row + args[0]) % len(rows)][args[1]] % prime
    if op == "public":
        return public[args[0]] % prime
    if op == "first":
        return int(row == 0)
    if op == "last":
        return int(row == len(rows) - 1)
    if op == "transition":
        return int(row != len(rows) - 1)
    operands = [evaluate(arg, rows, public, row, prime) for arg in args]
    if op == "add":
        return sum(operands) % prime
    if op == "sub":
        return (operands[0] - operands[1]) % prime
    if op == "mul":
        return (operands[0] * operands[1]) % prime
    if op == "neg":
        return -operands[0] % prime
    raise ValueError(f"unsupported exported expression: {op}")


def satisfies(chip, rows, public, prime):
    if len(rows) < 2 or any(len(row) != chip["width"] for row in rows):
        raise ValueError("invalid trace dimensions")
    if len(public) != chip["public_count"]:
        raise ValueError("invalid public-input dimensions")
    if any(not 0 <= v < prime for row in rows for v in row) or any(
        not 0 <= v < prime for v in public
    ):
        raise ValueError("noncanonical field element")
    return all(
        evaluate(e, rows, public, r, prime) == 0
        for r in range(len(rows))
        for e in chip["constraints"]
    )


def probe(name, chip, prime):
    c = chip["columns"]
    rows = [[0] * chip["width"] for _ in range(2)]
    rows[0][c["active"]] = 1
    public = [0] * chip["public_count"]
    if name == "MerkleAir":
        rows[0][c["current"]] = 1
        rows[0][c["sibling"]] = 2
    elif name == "SigAir":
        for key, value in [("key", 1), ("message", 2), ("pk", 3)]:
            rows[0][c[key]] = value
    elif name == "ImtAir":
        rows[0][c["target"]] = 1
        rows[0][c["high"]] = 2
    elif name == "LassoDfaAir":
        rows[0][c["byte"]] = ord("9")
        rows[0][c["digit"]] = 1
    else:
        assert name == "Poseidon2Air"
    rows[0][c["output"]] = 7
    other = copy.deepcopy(rows)
    other[0][c["output"]] = 8
    first_valid = satisfies(chip, rows, public, prime)
    second_valid = satisfies(chip, other, public, prime)
    return {
        "chip": name,
        "constraint_count": len(chip["constraints"]),
        "outcome": (
            "COUNTEREXAMPLE"
            if first_valid and second_valid
            else "NO COUNTEREXAMPLE IN FIXTURE"
        ),
        "first_valid": first_valid,
        "second_valid": second_valid,
        "output_column": c["output"],
        "first_trace": rows,
        "second_trace": other,
        "public": public,
    }


def epoch_controls(chip, prime):
    c = chip["columns"]
    rows = [[0] * chip["width"] for _ in range(2)]
    rows[0][c["active"]] = rows[0][c["fold"]] = 1
    for row in rows:
        for bit in range(c["bits"]):
            row[c["slack"] + bit] = (12_000 >> bit) & 1
    public = [0] * chip["public_count"]
    public[c["cap_public"]] = 12_000
    valid = satisfies(chip, rows, public, prime)
    bad_flag, bad_delta, bad_used = (copy.deepcopy(rows) for _ in range(3))
    bad_flag[0][c["fold"]] = 2
    bad_delta[0][c["delta"]] = 1 << c["bits"]
    bad_used[0][c["used"]] = 12_001
    return {
        "valid_trace_accepted": valid,
        "nonboolean_fold_rejected": not satisfies(chip, bad_flag, public, prime),
        "delta_without_bit_decomposition_rejected": not satisfies(
            chip, bad_delta, public, prime
        ),
        "overspent_fixture_rejected": not satisfies(chip, bad_used, public, prime),
    }


def audit(export):
    prime = export["prime"]
    names = ("Poseidon2Air", "MerkleAir", "SigAir", "ImtAir", "LassoDfaAir")
    return {
        "scope": "bounded concrete witnesses checked against extracted Rust AIR polynomials; no soundness proof",
        "prime": prime,
        "probes": [probe(name, export[name], prime) for name in names],
        "epoch_controls": epoch_controls(export["EpochAir"], prime),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, help="save full polynomials, witnesses and provenance"
    )
    args = parser.parse_args()
    try:
        export = load_constraints()
        report = audit(export)
        report["revision"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        report["source_sha256"] = {
            str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted((ROOT / "crates/enclave-zk-auditor/src/zk").glob("*.rs"))
        }
        report["constraints"] = export
        if args.output:
            args.output.write_text(json.dumps(report, indent=2) + "\n")
        for result in report["probes"]:
            print(
                f'{result["chip"]}: {result["outcome"]} ({result["constraint_count"]} extracted constraints)'
            )
        print(
            "Epoch bounded controls:",
            json.dumps(report["epoch_controls"], sort_keys=True),
        )
        print(report["scope"])
        if not all(report["epoch_controls"].values()):
            return 2
        return int(any(p["outcome"] == "COUNTEREXAMPLE" for p in report["probes"]))
    except (subprocess.CalledProcessError, OSError, ValueError, KeyError) as exc:
        print(f"Audit not completed: {exc}", file=sys.stderr)
        if isinstance(exc, subprocess.CalledProcessError):
            print(exc.stderr, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
