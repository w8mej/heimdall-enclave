#!/usr/bin/env python3
"""Check actual hydration artifact refuses fabricated/unsafe completion.

This is a release regression, not complete model-download or macOS validation.
Only private temporary queue/cache paths are written. No native host changes.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

binary = Path(sys.argv[1]).resolve(strict=True)
for hook in ("0", "1"):
    with tempfile.TemporaryDirectory(prefix="depot-release-hydration-") as tmp:
        base = Path(tmp)
        jobs, cas = base / "jobs", base / "cas"
        env = dict(
            os.environ, depot_TEST_TAMPER_DMG=hook, depot_INJECT_HYDRATE_FAIL=hook
        )
        for target in ("../escape", "depot-negative-release-missing-target"):
            result = subprocess.run(
                [
                    str(binary),
                    "--json",
                    "--profile",
                    "L1",
                    "deploy",
                    "hydrate",
                    "--sync",
                    "--target",
                    target,
                    "--jobs-dir",
                    str(jobs),
                    "--cas-dir",
                    str(cas),
                ],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode != 41:
                raise SystemExit(
                    f"FAIL: expected hydration refusal41: {result.returncode}: {result.stdout} {result.stderr}"
                )
            reply = json.loads(result.stdout)
            if reply["status"] != "failed":
                raise SystemExit(
                    "FAIL: hydration reported successful completion")
            if target.startswith("../"):
                if reply["details"].get("error") != "INVALID_TARGET_SLUG":
                    raise SystemExit(
                        "FAIL: unsafe target was not rejected before admission"
                    )
            elif "AUTHENTICATED_TARGET_UNAVAILABLE" not in reply.get("summary", ""):
                raise SystemExit(
                    "FAIL: missing authenticated target did not fail closed"
                )
            if cas.exists() and any(p.is_file() for p in cas.rglob("*")):
                raise SystemExit(
                    "FAIL: refused import published model/cache content")
            if (base / "escape").exists():
                raise SystemExit("FAIL: traversal wrote outside model store")
print(
    "PASS: actual hydration artifact rejects traversal and missing authority with both legacy-hook values; no fabricated model bytes"
)
