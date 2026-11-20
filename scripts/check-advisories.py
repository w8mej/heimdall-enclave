#!/usr/bin/env python3
"""Enforce one exception policy and run both independent advisory gates."""

import argparse
import subprocess
import sys
import tomllib
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--policy-only", action="store_true")
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
policies = [
    tomllib.loads((root / path).read_text())["advisories"]
    for path in ("deny.toml", ".cargo/audit.toml")
]
for key in ("unmaintained", "unsound"):
    if any(policy.get(key) == "none" for policy in policies):
        sys.exit(f"Broad advisory suppression refused: {key}")
if set(policies[0].get("ignore", [])) != set(policies[1].get("ignore", [])):
    sys.exit("Advisory exception lists differ")
print("Advisory exception policy agrees", flush=True)
if not args.policy_only:
    results = []
    # cargo-deny rejects unmaintained advisories; cargo-audit only warns by
    # default. Require warnings there too so both tools enforce the same bar.
    for command in (
        ["cargo", "deny", "check", "advisories"],
        ["cargo", "audit", "--deny", "warnings"],
    ):
        print("+ " + " ".join(command), flush=True)
        result = subprocess.run(command, cwd=root, check=False)
        results.append(result.returncode)
        print(f"{command[1]} exit: {result.returncode}", flush=True)
    sys.exit(0 if results == [0, 0] else 1)
