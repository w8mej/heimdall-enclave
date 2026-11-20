#!/usr/bin/env python3
"""Refresh reviewed type hashes after intentional theorem changes; review the diff.

Requires a successful real build. This command is deliberately separate from CI:
CI compares the current kernel types to this committed review artifact.
"""

import hashlib
import importlib.util
import json
import re
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parent.parent
package = root / "proofs/lean4"
subprocess.run(
    ["lake", "build", "Enclave", "Test", "enclave_verifier"], cwd=package, check=True
)
audit = subprocess.run(
    ["lake", "env", "lean", "Audit.lean"],
    cwd=package,
    text=True,
    capture_output=True,
    check=True,
)
compiled = dict(
    json.loads(line.removeprefix("KERNEL_DECL "))
    for line in audit.stdout.splitlines()
    if line.startswith("KERNEL_DECL ")
)
expected = {}
for directory in ["Enclave", "Test"]:
    for path in sorted((package / directory).glob("*.lean")):
        source = path.read_text()
        namespace = re.search(r"^namespace\s+(\S+)", source, re.MULTILINE).group(1)
        for name in re.findall(
            r"^(?:@\[[^\n]*\]\s+)?theorem\s+([\w\']+)", source, re.MULTILINE
        ):
            full = namespace + "." + name
            if full not in compiled:
                raise SystemExit("Missing compiled theorem: " + full)
            expected[full] = hashlib.sha256(compiled[full].encode()).hexdigest()
(package / "theorem-types.json").write_text(
    json.dumps(expected, indent=2, sort_keys=True) + "\n"
)
print(
    f"Recorded {len(expected)} reviewed theorem type hashes. Review and commit this diff."
)

spec = importlib.util.spec_from_file_location(
    "lean_gate", root / "scripts/check-lean.py"
)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
contracts = {
    name: hashlib.sha256((package / name).read_bytes()).hexdigest()
    for name in gate.TRANSPORT_CONTRACT_FILES
}
(package / "transport-contracts.json").write_text(
    json.dumps(contracts, indent=2, sort_keys=True) + "\n"
)
print(
    f"Recorded {len(contracts)} transport source/test definition contracts. "
    "Review definitions and their diff before committing; hashes are not semantic review."
)
