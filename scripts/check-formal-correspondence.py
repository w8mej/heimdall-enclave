#!/usr/bin/env python3
"""Compare real production Rust calls with compiled Lean functions exhaustively.

This covers only the finite FlowGate transition/status table and label join/order.
It does not verify callers, admission, memory wiping, external systems or hardware.
"""

import subprocess
from pathlib import Path

root = Path(__file__).resolve().parent.parent
package = root / "proofs/lean4"
subprocess.run(["lake", "build", "correspondence"], cwd=package, check=True)
rust = subprocess.check_output(
    [
        "cargo",
        "run",
        "--locked",
        "-q",
        "-p",
        "enclave-agent-runtime",
        "--example",
        "formal-correspondence",
    ],
    cwd=root,
    text=True,
)
lean = subprocess.check_output(
    ["lake", "exe", "correspondence"], cwd=package, text=True
)


def rows(output):
    lines = [line for line in output.splitlines() if line.startswith(("F,", "L,"))]
    if len(lines) != 117 + 256 or len(set(lines)) != len(lines):
        raise SystemExit("FAIL: incomplete or duplicate correspondence vectors")
    return set(lines)


a, b = rows(rust), rows(lean)
if a != b:
    raise SystemExit(f"FAIL: production-only {sorted(a-b)}; model-only {sorted(b-a)}")
print(
    "PASS: all 117 FlowGate state/event results and return statuses, plus 256 label join/order pairs agree."
)
print(
    "Bounded translation validation only. Remaining model modules have no established production correspondence."
)

# Configuration correspondence to actual renderer output. Fail on an unknown
# rule grammar; never silently interpret a new directive as an allowed policy.
rendered = [
    line.removeprefix("R,") for line in rust.splitlines() if line.startswith("R,")
]
metadata = [line.split(",")[1:] for line in lean.splitlines() if line.startswith("P,")]
if len(metadata) != 1:
    raise SystemExit("FAIL: missing compiled packet policy metadata")
iface, gid, port_a, port_b = metadata[0]
expected = [
    f'loopback_if = "{iface}"',
    'llm_group   = "_llmagent"',
    f"pass out quick on $loopback_if inet  proto tcp from any to 127.0.0.1 port {{ {port_a}, {port_b} }} group $llm_group keep state",
    f"pass out quick on $loopback_if inet6 proto tcp from any to ::1       port {{ {port_a}, {port_b} }} group $llm_group keep state",
    "block drop out log (all) quick inet  from any to any group $llm_group",
    "block drop out log (all) quick inet6 from any to any group $llm_group",
]
if rendered != expected or gid != "8701":
    raise SystemExit(
        "FAIL: production rendered pf anchor differs from the compiled Lean policy projection"
    )
print(
    "PASS: packet model interface/group/ports correspond to the exact production rendered IPv4/IPv6 anchor rules."
)
print(
    "Limits: named group must resolve to GID8701; model projects loopback-addressed outbound packets. Kernel state, routing and rule loading require macOS tests."
)
