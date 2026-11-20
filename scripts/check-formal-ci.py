#!/usr/bin/env python3
"""Check the mandatory compiler path in both Lean CI workflows (F127).

This is a repository source contract, not evidence of a hosted job or required
branch check. The shared strict YAML reader is owned by F126.
"""

import argparse
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "hardware_ci_reader", ROOT / "scripts/check-hardware-ci.py"
)
READER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(READER)

INSTALL = "./scripts/install-lean-toolchain.sh"
CACHE = 'export PATH="$HOME/.elan/bin:$PATH"\nlake exe cache get'
COMPILE = (
    'export PATH="$HOME/.elan/bin:$PATH"\n'
    "python3 scripts/check-lean.py\npython3 scripts/tests/test_lean_gate.py"
)
SOURCE_CHECK = (
    "python3 -m pip install 'PyYAML==6.0.2'\n"
    "python3 scripts/check-formal-ci.py\n"
    "python3 scripts/tests/test_formal_ci.py\n"
    "python3 scripts/tests/test_lean_gate_process.py"
)


def required_step(steps, command, directory):
    matches = [
        (index, step)
        for index, step in enumerate(steps)
        if isinstance(step, dict) and step.get("run", "").strip() == command
    ]
    if len(matches) != 1:
        raise READER.PolicyError(
            f"require exactly one unmodified compiler-path step: {command!r}"
        )
    index, step = matches[0]
    if any(key in step for key in ("if", "continue-on-error")):
        raise READER.PolicyError(
            "compiler-path step must be unconditional and fail on errors"
        )
    if step.get("shell") != "bash" or step.get("working-directory") != directory:
        raise READER.PolicyError(
            "compiler-path step requires explicit bash and reviewed working directory"
        )
    return index


def check_policy(root):
    for filename, job_name in [
        ("formal.yml", "formal"),
        ("security-lint.yml", "code-and-doc-lint"),
    ]:
        workflow = READER.load_workflow(root / ".github/workflows" / filename)
        job = workflow["jobs"].get(job_name)
        if not isinstance(job, dict) or not READER.runner_is_hosted(job):
            raise READER.PolicyError(f"{filename}: missing hosted compiler job")
        if any(key in job for key in ("if", "continue-on-error")):
            raise READER.PolicyError(
                f"{filename}: compiler job must be unconditional and fail on errors"
            )
        triggers = workflow.get("on", {})
        for event in ("push", "pull_request"):
            if triggers.get(event, {}).get("branches") != ["main"]:
                raise READER.PolicyError(f"{filename}: preserve {event} main trigger")
        steps = job.get("steps", [])
        install = required_step(steps, INSTALL, ".")
        cache = required_step(steps, CACHE, "proofs/lean4")
        compile_index = required_step(steps, COMPILE, ".")
        if not install < cache < compile_index:
            raise READER.PolicyError(
                f"{filename}: install and locked cache must precede compilation"
            )
        if (
            filename == "formal.yml"
            and required_step(steps, SOURCE_CHECK, ".") >= install
        ):
            raise READER.PolicyError(
                "formal.yml: source-policy and process-failure tests must run before install"
            )
    return 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        count = check_policy(args.root)
    except (
        READER.PolicyError,
        OSError,
        READER.yaml.YAMLError,
        TypeError,
        AttributeError,
    ) as exc:
        print(f"FAIL: formal CI source policy: {exc}", file=sys.stderr)
        return 1
    print(
        f"PASS: {count} hosted workflows install pinned Lean, fetch locked math cache, and compile with unmasked failures."
    )
    print(
        "Scope: source wiring only; actual remote job and required-branch settings remain unobserved."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
