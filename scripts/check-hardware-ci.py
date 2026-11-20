#!/usr/bin/env python3
"""Fail closed on changes to the reviewed hardware-job source policy (F126).

This checks repository workflow definitions, not GitHub dispatch or runner-group
authorization. A PR can edit this policy and its workflows; server-side runner
restrictions and branch protection remain administrator-owned prerequisites.
Requires PyYAML==6.0.2; unknown YAML/condition/runner forms require policy review.
"""

import argparse
import itertools
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
HARDWARE = {
    "bare-metal-sep": "ENABLE_BARE_METAL_SEP",
    "rust-apple-silicon-hardware": "ENABLE_SELF_HOSTED_M1",
}
HOSTED = {"ubuntu-24.04", "macos-14"}
HARDWARE_LABELS = ["self-hosted", "macOS", "ARM64", "bare-metal-sep"]


class PolicyError(ValueError):
    """An unsupported or insecure workflow source definition."""


class UniqueLoader(yaml.BaseLoader):
    """Keep scalars as strings (including YAML 1.1's `on`); reject duplicates."""


def unique_mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, str) or key in result or key == "<<":
            raise PolicyError(f"duplicate/unsupported YAML key: {key!r}")
        result[key] = loader.construct_object(value_node)
    return result


UniqueLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping
)


def load_workflow(path):
    source = path.read_text()
    for token in yaml.scan(source):
        if isinstance(
            token,
            (yaml.tokens.AnchorToken, yaml.tokens.AliasToken, yaml.tokens.TagToken),
        ):
            raise PolicyError(
                f"{path.name}: YAML anchors, aliases and tags require review"
            )
    workflow = yaml.load(
        source, Loader=UniqueLoader
    )  # nosec B506: UniqueLoader subclasses yaml.BaseLoader and rejects tags/anchors/aliases
    if not isinstance(workflow, dict) or not isinstance(workflow.get("jobs"), dict):
        raise PolicyError(f"{path.name}: workflow must contain a jobs mapping")
    return workflow


def condition_atoms(condition):
    """Recognize only the reviewed conjunction grammar; never eval source text.

    No OR, functions, coercions, interpolation or unknown context is accepted.
    Whitespace inside string literals is preserved, so lookalike refs fail.
    """
    if not isinstance(condition, str):
        raise PolicyError("job condition is missing or is not a string")
    match = re.fullmatch(r"\s*\$\{\{\s*(.*?)\s*\}\}\s*", condition, re.S)
    body = match.group(1) if match else condition.strip()
    atoms = []
    for part in body.split("&&"):
        part = part.strip()
        if part == "github.ref_protected":
            atom = ("github.ref_protected", True)
        else:
            match = re.fullmatch(
                r"(github\.(?:event_name|ref)|vars\.[A-Z_][A-Z0-9_]*)\s*==\s*'([^']*)'",
                part,
            )
            if not match:
                raise PolicyError(f"unsupported job condition atom: {part!r}")
            atom = match.groups()
        if atom in atoms:
            raise PolicyError(f"duplicate job condition atom: {part!r}")
        atoms.append(atom)
    return frozenset(atoms)


def permits(atoms, context):
    """Evaluate the accepted grammar with GitHub's case-insensitive strings."""
    for name, expected in atoms:
        actual = context[name]
        if isinstance(expected, bool):
            if actual is not expected:
                return False
        elif not isinstance(actual, str) or actual.casefold() != expected.casefold():
            return False
    return True


def runner_is_hosted(job):
    runner = job.get("runs-on")
    if isinstance(runner, str) and runner in HOSTED:
        return True
    # Exhaustively resolve the only hosted matrix projection currently used.
    if runner == "${{ matrix.os }}":
        matrix = job.get("strategy", {}).get("matrix", {})
        if not isinstance(matrix, dict) or not isinstance(matrix.get("os"), list):
            return False
        options = matrix["os"]
        include = matrix.get("include", [])
        if not isinstance(include, list) or any(
            not isinstance(row, dict) for row in include
        ):
            return False
        options = options + [row["os"] for row in include if "os" in row]
        return bool(options) and all(
            isinstance(value, str) and value in HOSTED for value in options
        )
    return False


def check_policy(root):
    directory = root / ".github/workflows"
    paths = sorted(set(directory.glob("*.yml")) | set(directory.glob("*.yaml")))
    if not paths:
        raise PolicyError("no workflows found")
    seen = set()
    cases = 0
    for path in paths:
        workflow = load_workflow(path)
        for name, job in workflow["jobs"].items():
            if not isinstance(job, dict):
                raise PolicyError(f"{path.name}/{name}: job must be a mapping")
            if path.name == "ci.yml" and name in HARDWARE:
                seen.add(name)
                if job.get("runs-on") != HARDWARE_LABELS:
                    raise PolicyError(
                        f"{name}: changed hardware runner selection requires review"
                    )
                flag = HARDWARE[name]
                atoms = condition_atoms(job.get("if"))
                expected = frozenset(
                    {
                        ("github.event_name", "push"),
                        ("github.ref", "refs/heads/main"),
                        ("github.ref_protected", True),
                        ("vars." + flag, "true"),
                    }
                )
                if atoms != expected:
                    raise PolicyError(
                        f"{name}: requires push AND exact main ref AND protection AND {flag}"
                    )
                if job.get("needs") != "hardware-source-policy":
                    raise PolicyError(
                        f"{name}: hardware job must depend on the hosted source-policy gate"
                    )
                # Run the actual parsed condition, varying the other job's flag independently.
                for event, ref, protected, first, second in itertools.product(
                    [
                        "push",
                        "pull_request",
                        "pull_request_target",
                        "workflow_dispatch",
                        "workflow_run",
                        "schedule",
                        "repository_dispatch",
                        "merge_group",
                    ],
                    [
                        "refs/heads/main",
                        "refs/heads/development",
                        "refs/tags/main",
                        "refs/pull/23/merge",
                    ],
                    [False, True],
                    ["", "false", "true", "TRUE"],
                    ["", "false", "true", "TRUE"],
                ):
                    context = {
                        "github.event_name": event,
                        "github.ref": ref,
                        "github.ref_protected": protected,
                        "vars.ENABLE_BARE_METAL_SEP": first,
                        "vars.ENABLE_SELF_HOSTED_M1": second,
                    }
                    wanted = (
                        event == "push"
                        and ref == "refs/heads/main"
                        and protected
                        and context["vars." + flag].casefold() == "true"
                    )
                    if permits(atoms, context) != wanted:
                        raise PolicyError(f"{name}: event-policy mismatch: {context}")
                    cases += 1
            elif not runner_is_hosted(job):
                raise PolicyError(
                    f"{path.name}/{name}: unreviewed self-hosted/dynamic runner selection"
                )
        if path.name == "ci.yml":
            policy = workflow["jobs"].get("hardware-source-policy", {})
            if (
                not runner_is_hosted(policy)
                or "if" in policy
                or "continue-on-error" in policy
            ):
                raise PolicyError(
                    "hardware-source-policy: require an unconditional hosted gate"
                )
            checks = [
                step
                for step in policy.get("steps", [])
                if isinstance(step, dict)
                and step.get("run", "").strip()
                == "python3 scripts/check-hardware-ci.py\npython3 scripts/tests/test_hardware_ci.py"
            ]
            if (
                len(checks) != 1
                or "if" in checks[0]
                or "continue-on-error" in checks[0]
            ):
                raise PolicyError(
                    "hardware-source-policy: require an unmasked policy and regression step"
                )
            for event in ("push", "pull_request"):
                if workflow.get("on", {}).get(event, {}).get("branches") != ["main"]:
                    raise PolicyError(f"ci.yml: preserve {event} main trigger")
            for name in ("ci-vm-compatible", "rust"):
                job = workflow["jobs"].get(name, {})
                if not runner_is_hosted(job) or "if" in job:
                    raise PolicyError(
                        f"{name}: preserve unconditional hosted PR verification"
                    )
    if seen != set(HARDWARE):
        raise PolicyError("missing reviewed hardware job(s) in ci.yml")
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        cases = check_policy(args.root)
    except (PolicyError, OSError, yaml.YAMLError, TypeError, AttributeError) as exc:
        print(f"FAIL: hardware CI source policy: {exc}", file=sys.stderr)
        return 1
    print(
        f"PASS: hardware CI source policy; {cases} parsed event/ref/protection/readiness cases."
    )
    print(
        "Scope: local workflow definitions; remote runner authorization and dispatch are unverified."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
