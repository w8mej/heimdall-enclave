"""Copy the actual mandatory source checker and inputs into gate fault fixtures."""

import shutil
from pathlib import Path


def copy_guard_inputs(source_root: Path, destination_root: Path):
    # Copying complete named source files keeps private gate fixtures faithful;
    # they must reach their intended compiler/process fault, not a missing input.
    for name in (
        "scripts/check-transport-guards.py",
        "crates/enclave-crypto/src/namespace.rs",
        "crates/enclave-swarm-syncd/src/transport/ohttp_fetch.rs",
        "crates/enclave-core/src/power.rs",
        "crates/enclave-swarm-syncd/src/streaming.rs",
        "crates/enclave-swarm-syncd/src/config.rs",
    ):
        target = destination_root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_root / name, target)
