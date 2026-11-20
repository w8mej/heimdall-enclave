#!/usr/bin/env python3
"""Read-only first-touch observations; never an enrollment/readiness authority.

Offline by default. No sockets are connected, state stores opened, services
started, keys accessed, or files repaired. Optional subprocesses are closed,
explicit config-only / codesign commands with bounded time and captured output.
Only non-secret hashes/metadata are emitted; authority scope is never printed.
"""

import argparse
import hashlib
import json
import os
import plistlib
import re
import selectors
import stat
import subprocess
import sys
import time
import unicodedata
from pathlib import PurePosixPath

MAX_DESCRIPTOR = 64 * 1024
MAX_PUBLIC = 1024 * 1024
ROOT_FIELDS = (
    "binary_dir",
    "custody_bundle",
    "sandbox_dir",
    "socket_root",
    "state_root",
    "audit_root",
    "cas_store_root",
    "staging_root",
    "support_root",
)
TARGET_FIELDS = {
    "version",
    "target_id",
    "role",
    "profile",
    "authority_config",
    "expected_artifacts_manifest",
    "codesign_pins_file",
    "signing_identity_mode",
    "layout",
    "broker",
    "shared_read_only_inputs",
}
INSTALLED = (
    "/opt/enterprise/enclave",
    "/var/run/enclave",
    "/var/db/enclave",
    "/var/log/enclave",
    "/Library/Application Support/EnterpriseEnclave",
)
DAEMONS = (
    ("adapter", 701, "_llmagent", "enclave-model-runnerd"),
    ("cas", 702, "_enclavecas", "enclave-swarm-syncd"),
    ("custody", 703, "_piivault", "enclave-custody-vaultd"),
    ("ifc", 704, "_enclaveifc", "enclave-agent-runtime"),
    ("zk", 705, "_enclavezk", "enclave-zk-auditor"),
)
INVENTORY_FIELDS = {
    "version",
    "kind",
    "target_id",
    "profile",
    "signing_identity_mode",
    "deployment_config_sha256",
    "source_git_commit",
    "source_manifest_sha256",
    "source_input_count",
    "codesign_pins_sha256",
    "staging_root",
    "external_provenance",
    "files",
}
PACKAGE_BINARIES = {
    "depot-enclave",
    "enclave-model-runnerd",
    "enclave-swarm-syncd",
    "enclave-apfs-broker",
    "enclave-agent-runtime",
    "enclave-zk-auditor",
    "enclave-cdp-browser",
    "enclave-client-gateway",
    "enclave-intent",
}
PACKAGE_JOBS = {
    "adapter",
    "cas",
    "custody",
    "ifc",
    "zk",
    "supervisor",
    "intent",
    "oidc-broker",
    "hydrate",
    "browser",
    "gateway",
    "apfs-broker",
}
CUSTODY_RUNTIME_BOUNDS = {
    "tuf/repo/fido-mds-allowlist.json": 256 * 1024,
    "tuf/repo/custody-envelope-policy-v1.json": 16 * 1024,
}


def sha256_value(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)


def package_member(path, namespace):
    """Closed packaging map, matching artifact-inventory/SCHEMA-v1.md."""
    if (
        not isinstance(path, str)
        or not path.isascii()
        or path.startswith("/")
        or not path
        or len(path) > 4096
        or any(part in ("", ".", "..") for part in path.split("/"))
        or any(unicodedata.category(c) == "Cc" or c in "'\"`$;&|<>()\\" for c in path)
    ):
        return False
    if path in {
        "codesign-pins.json",
        "SHA256SUMS",
        "custody.entitlements",
        "yubikey-transport",
        "install.sh",
        "uninstall.sh",
        "public-trust.sh",
        "fido-mds/yubico.json",
    }:
        return True
    parts = path.split("/")
    if len(parts) == 2 and parts[0] == "bin":
        return parts[1] in PACKAGE_BINARIES
    for bundle, executable in (
        ("EnclaveCustody.app", "enclave-custody-vaultd"),
        ("EnclaveOIDC.app", "enclave-oidc"),
    ):
        if path.startswith(bundle + "/"):
            return path[len(bundle) + 1:] in {
                "Contents/Info.plist",
                "Contents/PkgInfo",
                "Contents/embedded.provisionprofile",
                "Contents/_CodeSignature/CodeResources",
                "Contents/MacOS/" + executable,
            }
    if len(parts) == 2 and parts[0] == "launchd":
        return parts[1] in (
            {"provision-accounts.sh", "enclave-daemon.entitlements"}
            | {
                suffix + ".sb"
                for suffix in (
                    "adapter",
                    "cas",
                    "custody",
                    "ifc",
                    "zk",
                    "browser",
                    "gateway",
                )
            }
            | {namespace + "." + suffix + ".plist" for suffix in PACKAGE_JOBS}
        )
    if len(parts) == 3 and parts[:2] == ["tuf", "repo"]:
        name = parts[2]
        return name in {
            "root.json",
            "timestamp.json",
            "snapshot.json",
            "targets.json",
            "enclave-host-config.json",
            "enclave-policy.cedar.v1.json",
            "vk_manifest.json",
            "enclave-distribution-v1.json",
            "fido-mds-allowlist.json",
            "custody-envelope-policy-v1.json",
        } or bool(
            re.fullmatch(r"[1-9][0-9]{0,9}\.root\.json", name)
            and int(name.split(".")[0]) <= 2147483647
        )
    return False


class Refusal(Exception):
    """A redacted stable diagnostic code, never underlying file contents."""


def refuse(code):
    raise Refusal(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                refuse("DUPLICATE_JSON_FIELD")
            result[key] = value
        return result

    try:
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8")
        return json.loads(
            raw,
            object_pairs_hook=pairs,
            parse_constant=lambda _: refuse("INVALID_JSON"),
        )
    except (ValueError, UnicodeError, RecursionError):
        refuse("INVALID_JSON")


def path_value(value):
    if (
        not isinstance(value, str)
        or not value.isascii()
        or len(value.encode("utf-8")) > 4096
    ):
        refuse("DEPLOYMENT_PATH")
    if (
        not value.startswith("/")
        or value == "/"
        or str(PurePosixPath(value)) != value
        or any(p in (".", "..", "") for p in value.split("/")[1:])
        or any(unicodedata.category(c) == "Cc" or c in "'\"`$;&|<>()\\" for c in value)
    ):
        refuse("DEPLOYMENT_PATH")
    parts = value.split("/")
    if (
        parts[1].lower() in {"var", "tmp", "etc", "private"}
        and parts[1] != parts[1].lower()
        or parts[1] == "private"
        and len(parts) > 2
        and parts[2].lower() in {"var", "tmp", "etc"}
        and parts[2] != parts[2].lower()
    ):
        refuse("DEPLOYMENT_PATH_ALIAS_CASE")
    return value


def normalized(value):
    value = path_value(value)
    for alias in ("/var", "/tmp", "/etc"):
        if value == alias or value.startswith(alias + "/"):
            return "/private" + value
    return value


def below(path, parent):
    return normalized(path).casefold().startswith(normalized(parent).casefold() + "/")


def overlap(left, right):
    return (
        normalized(left).casefold() == normalized(right).casefold()
        or below(left, right)
        or below(right, left)
    )


def exact_fields(value, names):
    if not isinstance(value, dict) or set(value) != set(names):
        refuse("DEPLOYMENT_SCHEMA")


def readonly_inputs(target):
    result = [target["authority_config"],
              target["expected_artifacts_manifest"]]
    if target["broker"] is not None:
        result.append(target["broker"]["tuf_root_file"])
    return result


def outputs(target):
    result = [target["layout"][key] for key in ROOT_FIELDS]
    if target["broker"] is not None:
        result.append(target["broker"]["base_dir"])
    return result


def validate_target(target):
    """Mirror inert B1 syntax/isolation; never grants checked Rust authority."""
    exact_fields(target, TARGET_FIELDS)
    layout = target["layout"]
    exact_fields(layout, (*ROOT_FIELDS, "launchd_namespace", "mach_service"))
    if (
        type(target["version"]) is not int
        or target["version"] != 1
        or not isinstance(target["target_id"], str)
        or not re.fullmatch(r"[a-z](?:[a-z0-9-]{0,62}[a-z0-9])?", target["target_id"])
        or target["role"] not in ("dedicated-test", "existing-upgrade")
        or target["profile"] not in ("L2", "L3")
        or target["signing_identity_mode"] not in ("local-pins", "team-id")
    ):
        refuse("DEPLOYMENT_SCHEMA")
    for name, maximum in (("launchd_namespace", 112), ("mach_service", 128)):
        value = layout[name]
        if (
            not isinstance(value, str)
            or len(value) > maximum
            or "." not in value
            or not all(
                re.fullmatch(r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?", p)
                for p in value.split(".")
            )
        ):
            refuse("DEPLOYMENT_SCHEMA")
    broker = target["broker"]
    if (target["profile"] == "L3") != (broker is not None):
        refuse("DEPLOYMENT_SCHEMA")
    if broker is not None:
        exact_fields(broker, ("base_dir", "tuf_root_file"))
    shared = target["shared_read_only_inputs"]
    if not isinstance(shared, list) or len(shared) > 8:
        refuse("DEPLOYMENT_SHARED_INPUT")
    refs = readonly_inputs(target)
    roots = outputs(target)
    for path in roots + refs + [target["codesign_pins_file"]] + shared:
        path_value(path)
    for key in (
        "socket_root",
        "state_root",
        "audit_root",
        "cas_store_root",
        "staging_root",
    ):
        if any(c.isspace() for c in layout[key]):
            refuse("DEPLOYMENT_PATH")
    own_roots = [layout[key] for key in ROOT_FIELDS]
    for index, left in enumerate(own_roots):
        for right in own_roots[index + 1:]:
            bundle_exception = {left, right} == {
                layout["custody_bundle"],
                layout["support_root"],
            } and normalized(layout["custody_bundle"]).startswith(
                normalized(layout["support_root"]) + "/"
            )
            if overlap(left, right) and not bundle_exception:
                refuse("DEPLOYMENT_OUTPUT_OVERLAP")
    if len({normalized(p) for p in shared}) != len(shared) or not all(
        normalized(p) in {normalized(r) for r in refs} for p in shared
    ):
        refuse("DEPLOYMENT_SHARED_INPUT")
    for index, reference in enumerate(refs):
        if overlap(reference, target["codesign_pins_file"]):
            refuse("DEPLOYMENT_PIN_OVERLAP")
        if any(overlap(reference, other) for other in refs[index + 1:]):
            refuse("DEPLOYMENT_INPUT_OVERLAP")
    for reference in refs + [target["codesign_pins_file"]]:
        if any(
            overlap(reference, root) for root in roots if root != layout["support_root"]
        ):
            refuse("DEPLOYMENT_INPUT_OUTPUT_OVERLAP")
    if broker and normalized(broker["base_dir"]) != normalized(
        layout["state_root"] + "/apfs-broker"
    ):
        refuse("DEPLOYMENT_BROKER_LAYOUT")
    if target["role"] == "dedicated-test":
        if (
            any(
                overlap(root, installed)
                for root in roots + [target["codesign_pins_file"]]
                for installed in INSTALLED
            )
            or layout["launchd_namespace"] == "com.enterprise.enclave"
            or layout["mach_service"] == "com.enterprise.enclave.exception"
        ):
            refuse("DEPLOYMENT_INSTALLED_OVERLAP")
    return target


def validate_pair(left, right):
    validate_target(left)
    validate_target(right)
    if (
        left["target_id"] == right["target_id"]
        or left["role"] == right["role"]
        or any(
            left["layout"][k] == right["layout"][k]
            for k in ("launchd_namespace", "mach_service")
        )
        or any(overlap(a, b) for a in outputs(left) for b in outputs(right))
    ):
        refuse("DEPLOYMENT_PAIR_COLLISION")
    if overlap(left["codesign_pins_file"], right["codesign_pins_file"]) or any(
        overlap(a["codesign_pins_file"], root)
        for a, b in ((left, right), (right, left))
        for root in outputs(b)
    ):
        refuse("DEPLOYMENT_PAIR_COLLISION")
    for a, b in ((left, right), (right, left)):
        for reference in readonly_inputs(a):
            shared = normalized(reference) in {
                normalized(p) for p in readonly_inputs(b)
            } and all(
                normalized(reference)
                in {normalized(p) for p in t["shared_read_only_inputs"]}
                for t in (a, b)
            )
            for root in outputs(b) + [b["codesign_pins_file"]]:
                exception = (
                    normalized(root) == normalized(b["layout"]["support_root"])
                    and normalized(reference).startswith(normalized(root) + "/")
                    and shared
                )
                if overlap(reference, root) and not exception:
                    refuse("DEPLOYMENT_PAIR_COLLISION")
            for other in readonly_inputs(b):
                if overlap(reference, other) and (
                    normalized(reference) != normalized(other) or not shared
                ):
                    refuse("DEPLOYMENT_SHARED_INPUT")


def _protected(metadata):
    return metadata.st_uid == 0 and not metadata.st_mode & 0o022


def _read_at(parent, parts, maximum):
    """Held nofollow production walker; parent is a borrowed directory FD."""
    directory = os.dup(parent)
    try:
        for index, component in enumerate(parts):
            metadata = os.fstat(directory)
            if not stat.S_ISDIR(metadata.st_mode) or not _protected(metadata):
                refuse("PROTECTED_ANCESTOR")
            last = index == len(parts) - 1
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            fd = os.open(
                component, flags | (0 if last else os.O_DIRECTORY), dir_fd=directory
            )
            if not last:
                os.close(directory)
                directory = fd
                continue
            try:
                before = os.fstat(fd)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or not _protected(before)
                    or before.st_nlink != 1
                    or not 0 < before.st_size <= maximum
                ):
                    refuse("PROTECTED_FILE")
                chunks, total = [], 0
                while total <= maximum:
                    block = os.read(fd, min(65536, maximum + 1 - total))
                    if not block:
                        break
                    total += len(block)
                    chunks.append(block)
                after = os.fstat(fd)
                fields = (
                    "st_dev",
                    "st_ino",
                    "st_uid",
                    "st_mode",
                    "st_nlink",
                    "st_size",
                    "st_mtime_ns",
                    "st_ctime_ns",
                )
                if total != before.st_size or any(
                    getattr(before, k) != getattr(after, k) for k in fields
                ):
                    refuse("PROTECTED_CHANGED")
                return b"".join(chunks)
            finally:
                os.close(fd)
        refuse("PROTECTED_PATH")
    finally:
        os.close(directory)


def protected_read(path, maximum=MAX_PUBLIC):
    path_value(path)
    physical = normalized(path) if sys.platform == "darwin" else path
    root = None
    try:
        root = os.open("/", os.O_RDONLY | os.O_DIRECTORY |
                       os.O_NOFOLLOW | os.O_CLOEXEC)
        return _read_at(root, physical.split("/")[1:], maximum)
    except OSError:
        refuse("PROTECTED_UNAVAILABLE")
    finally:
        if root is not None:
            os.close(root)


def load_target(path, reader=protected_read):
    target = validate_target(strict_json(reader(path, MAX_DESCRIPTOR)))
    descriptor_location(target, path)
    return target


def descriptor_location(target, path):
    path_value(path)
    if any(
        overlap(path, root)
        for root in outputs(target)
        if root != target["layout"]["support_root"]
    ):
        refuse("DEPLOYMENT_CONFIG_OUTPUT_OVERLAP")


def routes(target, console):
    layout = target["layout"]
    result = {
        suffix: layout["socket_root"] + "/" + suffix + "/" + suffix + ".sock"
        for suffix, *_ in DAEMONS
    }
    result["supervisor"] = layout["socket_root"] + \
        "/supervisor/supervisor.sock"
    result["intent"] = (
        None
        if console is None
        else layout["socket_root"] + f"/intent/{console}/intent.sock"
    )
    if target["broker"] is not None:
        result["apfs-broker"] = layout["socket_root"] + \
            "/apfs-broker/broker.sock"
    return result


def daemon_argv(target, descriptor, suffix, binary):
    layout = target["layout"]
    sandbox = layout["sandbox_dir"] + "/" + suffix + ".sb"
    executable = (
        layout["custody_bundle"] + "/Contents/MacOS/" + binary
        if suffix == "custody"
        else layout["binary_dir"] + "/" + binary
    )
    args = [
        "/usr/bin/sandbox-exec",
        "-f",
        sandbox,
        executable,
        "--socket-dir",
        layout["socket_root"],
        "--audit-dir",
        layout["audit_root"],
        "--state-dir",
        layout["state_root"] + "/" + suffix,
        "--profile",
        target["profile"],
        "--sandbox-profile",
        sandbox,
    ]
    if suffix == "cas":
        tuf = (
            target["broker"]["tuf_root_file"]
            if target["broker"]
            else layout["support_root"] + "/tuf/root.json"
        )
        args += [
            "--store-dir",
            layout["cas_store_root"],
            "--tuf-root",
            tuf,
            "--tuf-repo",
            layout["state_root"] + "/cas/tuf/repo",
        ]
    if suffix == "custody":
        args += [
            "--yubikey-transport",
            "hid",
            "--mds-file",
            layout["support_root"] + "/fido-mds.json",
            "--oidc-broker-config",
            layout["support_root"] + "/oidc-broker-identity.json",
            "--custody-authority-config",
            target["authority_config"],
        ]
    if suffix == "ifc":
        args += [
            "--policy-key-file",
            layout["state_root"] + "/ifc/ifc-policy.key",
            "--depot-lock-file",
            layout["state_root"] + "/ifc/enclave-depot-lock.json",
        ]
    if suffix == "zk":
        args += ["--strike-file", layout["state_root"] + "/zk/zk-strikes.json"]
    return args + ["--deployment-target", descriptor]


def check_plists(target, descriptor, directory, reader=protected_read):
    layout = target["layout"]
    jobs = []
    for suffix, _, account, binary in DAEMONS:
        jobs.append((suffix, daemon_argv(
            target, descriptor, suffix, binary), account))
    jobs += [
        (
            "intent",
            [
                layout["binary_dir"] + "/enclave-intent",
                "--socket",
                layout["socket_root"] + "/intent/intent.sock",
                "--supervisor-socket",
                layout["socket_root"] + "/supervisor/supervisor.sock",
                "--deployment-target",
                descriptor,
            ],
            None,
        ),
        (
            "supervisor",
            [
                layout["binary_dir"] + "/depot-enclave",
                "--profile",
                target["profile"],
                "supervise",
                "--socket-dir",
                layout["socket_root"],
                "--deployment-config",
                descriptor,
            ],
            "root",
        ),
    ]
    if target["broker"] is not None:
        jobs.append(
            (
                "apfs-broker",
                [
                    layout["binary_dir"] + "/enclave-apfs-broker",
                    "--deployment-target",
                    descriptor,
                ],
                "root",
            )
        )
    result = []
    for suffix, args, account in jobs:
        label = layout["launchd_namespace"] + "." + suffix
        raw = reader(directory + "/" + label + ".plist", MAX_PUBLIC)
        value = None
        try:
            value = plistlib.loads(raw)
        except Exception:
            refuse("PLIST_SCHEMA")
        if (
            not isinstance(value, dict)
            or value.get("Label") != label
            or value.get("ProgramArguments") != args
            or value.get("UserName") != account
            or "Program" in value
            or "RootDirectory" in value
            or value.get("EnvironmentVariables", {})
            not in ({}, {"MallocNanoZone": "0"})
        ):
            refuse("PLIST_TARGET_MISMATCH")
        if suffix == "supervisor" and value.get("MachServices") != {
            layout["mach_service"]: True
        }:
            refuse("PLIST_MACH_MISMATCH")
        result.append(
            {
                "job": suffix,
                "sha256": digest(raw),
                "status": "OBSERVED_PLIST_ROUTES_MATCH",
            }
        )
    return result


def installed_plist_specs(target, descriptor):
    """Closed installed renderer contract; render-directory checks stay separate."""
    layout = target["layout"]
    jobs = {}
    for suffix, _, account, binary in DAEMONS:
        limits = dict(
            Core=0,
            ResidentSetSize={
                "adapter": 48,
                "cas": 48,
                "custody": 24,
                "ifc": 32,
                "zk": 48,
            }[suffix]
            * 1024
            * 1024,
            NumberOfFiles=256,
            NumberOfProcesses=1,
        )
        jobs[suffix] = dict(
            ProgramArguments=daemon_argv(target, descriptor, suffix, binary),
            UserName=account,
            GroupName=account,
            InitGroups=True,
            RunAtLoad=True,
            KeepAlive={"SuccessfulExit": False},
            ThrottleInterval=30,
            ProcessType="Adaptive" if suffix == "custody" else "Background",
            LowPriorityIO=True,
            Umask=63,
            SoftResourceLimits=limits,
            HardResourceLimits=limits,
            EnvironmentVariables={"MallocNanoZone": "0"},
        )
        for key in ("StandardOutPath", "StandardErrorPath"):
            jobs[suffix][key] = (
                layout["audit_root"] + "/" + suffix + "/" + suffix + ".log"
            )
    jobs["supervisor"] = dict(
        ProgramArguments=[
            layout["binary_dir"] + "/depot-enclave",
            "--profile",
            target["profile"],
            "supervise",
            "--socket-dir",
            layout["socket_root"],
            "--deployment-config",
            descriptor,
        ],
        UserName="root",
        RunAtLoad=True,
        KeepAlive=True,
        ThrottleInterval=10,
        ProcessType="Interactive",
        MachServices={layout["mach_service"]: True},
    )
    jobs["intent"] = dict(
        ProgramArguments=[
            layout["binary_dir"] + "/enclave-intent",
            "--socket",
            layout["socket_root"] + "/intent/intent.sock",
            "--supervisor-socket",
            layout["socket_root"] + "/supervisor/supervisor.sock",
            "--deployment-target",
            descriptor,
        ],
        RunAtLoad=True,
        KeepAlive=True,
        ThrottleInterval=1,
        ProcessType="Interactive",
    )
    jobs["oidc-broker"] = dict(
        ProgramArguments=[
            layout["support_root"] +
            "/EnclaveOIDC.app/Contents/MacOS/enclave-oidc",
            "--identity-config",
            layout["support_root"] + "/oidc-broker-identity.json",
            "--oauth-config",
            layout["support_root"] + "/oidc-oauth.json",
            "--deployment-target",
            descriptor,
        ],
        LimitLoadToSessionType="Aqua",
        RunAtLoad=True,
        KeepAlive=False,
        ProcessType="Interactive",
        SoftResourceLimits={"Core": 0},
        HardResourceLimits={"Core": 0},
    )
    jobs["hydrate"] = dict(
        ProgramArguments=[
            layout["binary_dir"] + "/depot-enclave",
            "deploy",
            "hydrate-worker",
            "--profile",
            target["profile"],
            "--jobs-dir",
            layout["socket_root"] + "/jobs",
            "--cas-dir",
            layout["cas_store_root"],
            "--deployment-config",
            descriptor,
        ],
        UserName="_enclavecas",
        GroupName="_enclavecas",
        WatchPaths=[layout["socket_root"] + "/jobs"],
        ThrottleInterval=2,
    )
    for suffix, account, throttle in (
        ("browser", "_cdpbrowser", 10),
        ("gateway", "_enclaveingress", 30),
    ):
        sandbox = layout["sandbox_dir"] + "/" + suffix + ".sb"
        args = (
            [
                "/usr/bin/sandbox-exec",
                "-f",
                sandbox,
                layout["binary_dir"] + "/enclave-cdp-browser",
                "--socket",
                layout["socket_root"] + "/browser/browser.sock",
                "--throwaway-dir",
                layout["state_root"] + "/browser",
                "--profile",
                target["profile"],
            ]
            if suffix == "browser"
            else [
                layout["binary_dir"] + "/enclave-client-gateway",
                "--socket-dir",
                layout["socket_root"],
                "--sandbox-profile",
                sandbox,
                "--profile",
                target["profile"],
                "--audit-dir",
                layout["audit_root"],
            ]
        )
        jobs[suffix] = dict(
            ProgramArguments=args + ["--deployment-target", descriptor],
            UserName=account,
            GroupName=account,
            InitGroups=True,
            RunAtLoad=True,
            KeepAlive={"SuccessfulExit": False},
            ThrottleInterval=throttle,
            ProcessType="Background",
            Umask=63,
            SoftResourceLimits={"Core": 0},
            HardResourceLimits={"Core": 0},
        )
        for key in ("StandardOutPath", "StandardErrorPath"):
            jobs[suffix][key] = (
                layout["audit_root"] + "/" + suffix + "/" + suffix + ".log"
            )
    if target["broker"] is not None:
        jobs["apfs-broker"] = dict(
            ProgramArguments=[
                layout["binary_dir"] + "/enclave-apfs-broker",
                "--deployment-target",
                descriptor,
            ],
            UserName="root",
            GroupName="wheel",
            RunAtLoad=True,
            KeepAlive=True,
            ThrottleInterval=10,
            WorkingDirectory="/",
            Umask=63,
            SoftResourceLimits={"Core": 0, "NumberOfFiles": 64},
            HardResourceLimits={"Core": 0, "NumberOfFiles": 128},
        )
        for key in ("StandardOutPath", "StandardErrorPath"):
            jobs["apfs-broker"][key] = layout["audit_root"] + \
                "/apfs-broker/broker.log"
    for suffix in ("supervisor", "intent", "hydrate"):
        for key in ("StandardOutPath", "StandardErrorPath"):
            jobs[suffix][key] = layout["audit_root"] + "/" + suffix + ".log"
    result = []
    for suffix, expected in jobs.items():
        label = layout["launchd_namespace"] + "." + suffix
        expected["Label"] = label
        directory = (
            "LaunchAgents" if suffix in (
                "intent", "oidc-broker") else "LaunchDaemons"
        )
        other = "LaunchDaemons" if directory == "LaunchAgents" else "LaunchAgents"
        result.append(
            (
                suffix,
                "/Library/" + directory + "/" + label + ".plist",
                "/Library/" + other + "/" + label + ".plist",
                expected,
            )
        )
    return result


INSTALLED_STAMP_FIELDS = (
    "st_dev",
    "st_ino",
    "st_uid",
    "st_gid",
    "st_mode",
    "st_nlink",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)


def installed_stamp(value):
    return tuple(getattr(value, key) for key in INSTALLED_STAMP_FIELDS)


def installed_metadata(path, value):
    return dict(
        path=path,
        device=value.st_dev,
        inode=value.st_ino,
        uid=value.st_uid,
        gid=value.st_gid,
        mode=format(stat.S_IMODE(value.st_mode), "04o"),
        links=value.st_nlink,
        size=value.st_size,
        mtime_ns=value.st_mtime_ns,
        ctime_ns=value.st_ctime_ns,
    )


def _installed_read_at(root, path, maximum=MAX_PUBLIC):
    """Observe fixed path through held FDs; private root injection is test-only."""
    if not re.fullmatch(
        r"/Library/(?:LaunchDaemons|LaunchAgents)/[a-z0-9.-]+\.plist", path
    ):
        refuse("FAIL_INSTALLED_PATH")
    held = [os.dup(root)]
    checks = []
    records = []
    absent = None
    raw = None
    status = "OBSERVED_PROTECTED_INSTALLED_FILE"
    try:
        before = os.fstat(held[0])
        if not stat.S_ISDIR(before.st_mode) or not _protected(before):
            refuse("FAIL_INSTALLED_ANCESTOR")
        checks.append((held[0], before, None, None))
        records.append(installed_metadata("/", before))
        current = ""
        parts = path.split("/")[1:]
        for index, component in enumerate(parts):
            parent = held[-1]
            current += "/" + component
            last = index == len(parts) - 1
            try:
                named = os.stat(component, dir_fd=parent,
                                follow_symlinks=False)
            except FileNotFoundError:
                absent = (parent, component)
                status = (
                    "UNKNOWN_INSTALLED_JOB_ABSENT"
                    if last
                    else "UNKNOWN_INSTALLED_DIRECTORY_ABSENT"
                )
                break
            if stat.S_ISLNK(named.st_mode):
                refuse("FAIL_INSTALLED_SYMLINK")
            if not _protected(named) or (
                not stat.S_ISREG(named.st_mode)
                if last
                else not stat.S_ISDIR(named.st_mode)
            ):
                refuse("FAIL_INSTALLED_FILE" if last else "FAIL_INSTALLED_ANCESTOR")
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            fd = os.open(
                component, flags | (0 if last else os.O_DIRECTORY), dir_fd=parent
            )
            held.append(fd)
            before = os.fstat(fd)
            if installed_stamp(named) != installed_stamp(before):
                refuse("FAIL_INSTALLED_CHANGED")
            checks.append((fd, before, parent, component))
            records.append(installed_metadata(current, before))
            if last:
                if before.st_nlink != 1 or not 0 < before.st_size <= maximum:
                    refuse("FAIL_INSTALLED_FILE")
                chunks, size = [], 0
                while size <= maximum:
                    block = os.read(fd, min(65536, maximum + 1 - size))
                    if not block:
                        break
                    chunks.append(block)
                    size += len(block)
                if size != before.st_size:
                    refuse("FAIL_INSTALLED_CHANGED")
                raw = b"".join(chunks)
        for fd, before, parent, component in reversed(checks):
            if installed_stamp(os.fstat(fd)) != installed_stamp(before):
                refuse("FAIL_INSTALLED_CHANGED")
            if parent is not None and installed_stamp(
                os.stat(component, dir_fd=parent, follow_symlinks=False)
            ) != installed_stamp(before):
                refuse("FAIL_INSTALLED_CHANGED")
        if absent is not None:
            try:
                os.stat(absent[1], dir_fd=absent[0], follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                refuse("FAIL_INSTALLED_CHANGED")
        return raw, {"status": status, "metadata": records}
    finally:
        for fd in reversed(held):
            os.close(fd)


def installed_plist_read(path, maximum=MAX_PUBLIC):
    root = None
    try:
        root = os.open("/", os.O_RDONLY | os.O_DIRECTORY |
                       os.O_NOFOLLOW | os.O_CLOEXEC)
        return _installed_read_at(root, path, maximum)
    except PermissionError:
        refuse("UNKNOWN_INSTALLED_OBSERVATION_UNAVAILABLE")
    except OSError:
        refuse("FAIL_INSTALLED_OBSERVATION_REFUSED")
    finally:
        if root is not None:
            os.close(root)


class UniquePlistDict(dict):
    def __setitem__(self, key, value):
        if key in self:
            refuse("FAIL_INSTALLED_PLIST_DUPLICATE_FIELD")
        super().__setitem__(key, value)


def exact_plist_value(value, expected):
    if isinstance(value, dict) and isinstance(expected, dict):
        return set(value) == set(expected) and all(
            exact_plist_value(value[k], expected[k]) for k in expected
        )
    if type(value) is not type(expected):
        return False
    if isinstance(value, list):
        return len(value) == len(expected) and all(
            exact_plist_value(a, b) for a, b in zip(value, expected)
        )
    return value == expected


def installed_plist_audit(
    descriptor, reader=protected_read, observer=installed_plist_read
):
    """Standalone static observation: no authority/state/socket/service queries."""
    raw = reader(descriptor, MAX_DESCRIPTOR)
    target = validate_target(strict_json(raw))
    descriptor_location(target, descriptor)
    jobs, observations = [], {}
    for suffix, path, other, expected in installed_plist_specs(target, descriptor):
        result = {"job": suffix, "path": path, "other_directory_path": other}
        try:
            content, observed = observer(path, MAX_PUBLIC)
            alternate, elsewhere = observer(other, MAX_PUBLIC)
            observations[path] = (content, observed)
            observations[other] = (alternate, elsewhere)
            result["observation"] = observed
            result["other_directory_observation"] = elsewhere
            if alternate is not None:
                refuse("FAIL_INSTALLED_PLIST_WRONG_DIRECTORY")
            if content is None:
                result["status"] = observed["status"]
            else:
                parsed = None
                try:
                    parsed = plistlib.loads(content, dict_type=UniquePlistDict)
                except Refusal:
                    raise
                except Exception:
                    refuse("FAIL_INSTALLED_PLIST_SCHEMA")
                if not exact_plist_value(parsed, expected):
                    refuse("FAIL_INSTALLED_PLIST_TARGET_MISMATCH")
                result.update(
                    status="OBSERVED_INSTALLED_PLIST_CONFIGURATION_MATCH",
                    sha256=digest(content),
                )
        except Refusal as error:
            result["status"] = str(error)
        jobs.append(result)
    # Observations describe a bounded stable read interval, never a future lease.
    for path, before in observations.items():
        try:
            if observer(path, MAX_PUBLIC) != before:
                refuse("FAIL_INSTALLED_CHANGED")
        except Refusal as error:
            jobs.append({"path": path, "status": str(error)})
    if reader(descriptor, MAX_DESCRIPTOR) != raw:
        refuse("FAIL_INSTALLED_DESCRIPTOR_CHANGED")
    return {
        "schema": 1,
        "operation": "READ_ONLY_INSTALLED_PLIST_OBSERVATION",
        "target_id": target["target_id"],
        "profile": target["profile"],
        "descriptor_sha256": digest(raw),
        "expected_job_count": len(installed_plist_specs(target, descriptor)),
        "plists": jobs,
        "status": (
            "FAIL" if any(j["status"].startswith("FAIL")
                          for j in jobs) else "UNKNOWN"
        ),
        "qualified": False,
        "artifact_provenance": "UNKNOWN_NOT_OBSERVED",
        "launchd_loaded_state": "UNKNOWN_NO_LAUNCHCTL_QUERY",
        "service_readiness": "UNKNOWN_NO_SERVICE_QUERY",
        "authority_verification": "UNKNOWN_NOT_OBSERVED",
        "physical_readiness": "UNKNOWN_NO_PHYSICAL_CEREMONY",
        "owner_coverage": "UNKNOWN_UNOBSERVED_PROCESS_OWNERS",
    }


def socket_observation(path, uid, gid, metadata=os.lstat):
    """Metadata only. No connect, authenticated peer, or service-health claim."""
    if path is None:
        return {"status": "UNKNOWN_CONSOLE_SESSION"}
    try:
        # Match the protected readers: Darwin's fixed /var,/tmp,/etc aliases
        # are resolved lexically before arbitrary ancestor links are refused.
        if sys.platform == "darwin":
            path = normalized(path)
        # No arbitrary ancestor link is followed, including intermediate paths.
        for ancestor in reversed(PurePosixPath(path).parents):
            if stat.S_ISLNK(metadata(str(ancestor)).st_mode):
                refuse("SOCKET_ANCESTOR_SYMLINK")
        value = metadata(path)
        if (
            not stat.S_ISSOCK(value.st_mode)
            or value.st_uid != uid
            or value.st_gid != gid
        ):
            refuse("SOCKET_METADATA_MISMATCH")
        if stat.S_IMODE(value.st_mode) != 0o660:
            refuse("SOCKET_MODE_MISMATCH")
        return {
            "status": "OBSERVED_SOCKET_METADATA_ONLY",
            "uid": value.st_uid,
            "gid": value.st_gid,
            "mode": "0660",
            "device": value.st_dev,
            "inode": value.st_ino,
        }
    except FileNotFoundError:
        return {"status": "UNKNOWN_SOCKET_ABSENT"}
    except (OSError, Refusal):
        return {"status": "FAIL_SOCKET_METADATA"}


def bounded_command(argv, timeout=2.0, limit=65536):
    """No shell, input, inherited app environment or output files; total cap."""
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin"},
        start_new_session=True,
    )
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    try:
        for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        deadline = time.monotonic() + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                refuse("COMMAND_TIMEOUT")
            for key, _ in selector.select(remaining):
                block = os.read(key.fileobj.fileno(), 4096)
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                captured[key.data].extend(block)
                if sum(map(len, captured.values())) > limit:
                    refuse("COMMAND_OUTPUT_CAP")
        code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        return code, bytes(captured["stdout"]), bytes(captured["stderr"])
    except subprocess.TimeoutExpired:
        refuse("COMMAND_TIMEOUT")
    finally:
        selector.close()
        # The leader can already have exited while descendants retain pipes.
        # Always clean the isolated group, including after normal leader exit.
        import signal

        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if process.poll() is None:
            process.wait()
        process.stdout.close()
        process.stderr.close()


def config_check(target, descriptor, authority_sha256, runner):
    args = [
        target["layout"]["binary_dir"] + "/depot-enclave",
        "--json",
        "--profile",
        target["profile"],
        "--deployment-config",
        descriptor,
        "launchd",
        "custody-config-check",
        "--config",
        target["authority_config"],
    ]
    code, stdout, stderr = runner(args)
    if code != 0:
        refuse("CONFIG_ONLY_COMMAND_REFUSED")
    value = strict_json(stdout)
    if (
        not isinstance(value, dict)
        or value.get("profile") != target["profile"]
        or value.get("manifest_sha256") != authority_sha256
    ):
        refuse("CONFIG_ONLY_RECEIPT_MISMATCH")
    return {
        "status": "OBSERVED_CONFIG_ONLY_VERIFICATION",
        "stdout_sha256": digest(stdout),
        "stderr_sha256": digest(stderr),
        "exit_code": code,
    }


def inventory_binding(raw, target, descriptor_raw, pins_raw):
    """Local evidence binding only; a digest map cannot attest its own source."""
    inventory = strict_json(raw)
    if not isinstance(inventory, dict) or set(inventory) != INVENTORY_FIELDS:
        refuse("ARTIFACT_INVENTORY_SCHEMA")
    if (
        type(inventory["version"]) is not int
        or inventory["version"] != 1
        or inventory["kind"] != "depot-first-touch-artifact-inventory"
        or inventory["external_provenance"] != "UNKNOWN"
        or any(
            inventory[k] != target[k]
            for k in ("target_id", "profile", "signing_identity_mode")
        )
        or inventory["deployment_config_sha256"] != digest(descriptor_raw)
        or inventory["codesign_pins_sha256"] != digest(pins_raw)
        or inventory["staging_root"] != normalized(target["layout"]["staging_root"])
    ):
        refuse("ARTIFACT_INVENTORY_BINDING")
    if (
        not isinstance(inventory["source_git_commit"], str)
        or not re.fullmatch(r"[0-9a-f]{40}", inventory["source_git_commit"])
        or not sha256_value(inventory["source_manifest_sha256"])
        or type(inventory["source_input_count"]) is not int
        or not 0 < inventory["source_input_count"] <= 100000
        or not isinstance(inventory["files"], list)
        or not 0 < len(inventory["files"]) <= 4096
    ):
        refuse("ARTIFACT_INVENTORY_SCHEMA")
    files, folded, names = {}, set(), []
    for item in inventory["files"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "sha256", "size"}
            or not package_member(item["path"], target["layout"]["launchd_namespace"])
            or not sha256_value(item["sha256"])
            or type(item["size"]) is not int
            or not 0 <= item["size"] <= 536870912
        ):
            refuse("ARTIFACT_INVENTORY_FILE")
        name = item["path"]
        if name.casefold() in folded:
            refuse("ARTIFACT_INVENTORY_DUPLICATE")
        folded.add(name.casefold())
        names.append(name)
        files[name] = item
        if name.endswith(".json") and item["size"] > (
            MAX_PUBLIC if name == "codesign-pins.json" else 16 * MAX_PUBLIC
        ):
            refuse("ARTIFACT_INVENTORY_FILE")
        if (
            name in CUSTODY_RUNTIME_BOUNDS
            and not 0 < item["size"] <= CUSTODY_RUNTIME_BOUNDS[name]
        ):
            refuse("ARTIFACT_INVENTORY_FILE")
    if names != sorted(names) or not {"bin/depot-enclave", "codesign-pins.json"} <= set(
        files
    ):
        refuse("ARTIFACT_INVENTORY_ORDER_OR_REQUIRED_FILE")
    if sum(name.endswith(".root.json") for name in names) > 32:
        refuse("ARTIFACT_INVENTORY_ROOT_COUNT")
    if files["codesign-pins.json"]["sha256"] != digest(pins_raw) or files[
        "codesign-pins.json"
    ]["size"] != len(pins_raw):
        refuse("ARTIFACT_INVENTORY_PINS")
    pins = strict_json(pins_raw)
    if (
        set(pins) not in ({"v", "pins"}, {"v", "mode", "pins"})
        or not set(pins["pins"])
        <= {"com.enterprise.enclave." + suffix for suffix in PACKAGE_JOBS | {"ctl"}}
        or any(len(values) > 8 for values in pins["pins"].values())
    ):
        refuse("ARTIFACT_INVENTORY_PINS")
    return inventory


def protected_hash(path, maximum=536870912):
    """Stream exact regular-file bytes, held nofollow, root-protected and stable."""
    path_value(path)
    physical = normalized(path) if sys.platform == "darwin" else path
    directory = os.open(
        "/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        parts = physical.split("/")[1:]
        for index, part in enumerate(parts):
            parent = os.fstat(directory)
            if not stat.S_ISDIR(parent.st_mode) or not _protected(parent):
                refuse("CONFIG_COMMAND_PROTECTED_PATH")
            last = index == len(parts) - 1
            fd = os.open(
                part,
                os.O_RDONLY
                | os.O_NOFOLLOW
                | os.O_NONBLOCK
                | os.O_CLOEXEC
                | (0 if last else os.O_DIRECTORY),
                dir_fd=directory,
            )
            os.close(directory)
            directory = fd
            if last:
                before = os.fstat(fd)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or not _protected(before)
                    or before.st_nlink != 1
                    or not 0 < before.st_size <= maximum
                    or not before.st_mode & 0o111
                ):
                    refuse("CONFIG_COMMAND_PROTECTED_FILE")
                hasher, count = hashlib.sha256(), 0
                while count <= maximum:
                    block = os.read(fd, min(65536, maximum + 1 - count))
                    if not block:
                        break
                    hasher.update(block)
                    count += len(block)
                after = os.fstat(fd)
                fields = (
                    "st_dev",
                    "st_ino",
                    "st_uid",
                    "st_gid",
                    "st_mode",
                    "st_nlink",
                    "st_size",
                    "st_mtime_ns",
                    "st_ctime_ns",
                )
                before_stamp = tuple(getattr(before, key) for key in fields)
                after_stamp = tuple(getattr(after, key) for key in fields)
                # Reopen the exact path through the same protected traversal on
                # subsequent checks; the held inode's content cannot drift here.
                if before_stamp != after_stamp or count != before.st_size:
                    refuse("CONFIG_COMMAND_CHANGED")
                return {
                    "sha256": hasher.hexdigest(),
                    "size": count,
                    "stamp": after_stamp,
                }
    finally:
        os.close(directory)


def codesign_identity(path, target, pins, runner):
    verify = runner(["/usr/bin/codesign", "--verify", "--strict", path])
    if verify[0] != 0:
        refuse("CONFIG_CODESIGN_VERIFICATION_REFUSED")
    code, stdout, stderr = runner(
        ["/usr/bin/codesign", "-d", "--verbose=4", path])
    if code != 0:
        refuse("CONFIG_CODESIGN_DISPLAY_REFUSED")
    text = ""
    try:
        text = (stdout + b"\n" + stderr).decode("utf-8")
    except UnicodeError:
        refuse("CONFIG_CODESIGN_METADATA")
    values = {}
    for line in text.splitlines():
        for key in ("Identifier", "CDHash", "TeamIdentifier"):
            if line.startswith(key + "="):
                if key in values:
                    refuse("CONFIG_CODESIGN_METADATA")
                values[key] = line[len(key) + 1:]
        if line.startswith("CodeDirectory "):
            match = re.search(r"\bflags=0x([0-9a-fA-F]+)(?:\(|\s|$)", line)
            if "flags" in values or not match:
                refuse("CONFIG_CODESIGN_METADATA")
            values["flags"] = int(match.group(1), 16)
    if (
        set(values) != {"Identifier", "CDHash", "TeamIdentifier", "flags"}
        or values["Identifier"] != "com.enterprise.enclave.ctl"
        or not re.fullmatch(r"[0-9a-fA-F]{40}", values["CDHash"])
        or values["CDHash"].lower()
        not in {h.lower() for h in pins["pins"]["com.enterprise.enclave.ctl"]}
        or not values["flags"] & 0x10000
    ):
        refuse("CONFIG_CODESIGN_IDENTITY")
    team = values["TeamIdentifier"]
    present = bool(team and team != "not set")
    if present != (target["signing_identity_mode"] == "team-id"):
        refuse("CONFIG_CODESIGN_MODE")
    return {
        "status": "OBSERVED_CODESIGN_PIN_AND_RUNTIME",
        "cdhash": values["CDHash"].lower(),
        "team_id_binding": (
            "UNKNOWN_EXACT_COMPILED_TEAM_ID"
            if present
            else "OBSERVED_NO_TEAM_IDENTIFIER"
        ),
        "team_identifier_sha256": digest(team.encode("utf-8")),
        "verify_output_sha256": digest(verify[1] + b"\n" + verify[2]),
        "display_output_sha256": digest(stdout + b"\n" + stderr),
    }


def verified_config_check(
    target,
    descriptor,
    descriptor_raw,
    authority_raw,
    pins_raw,
    artifact_raw,
    inventory,
    reader,
    runner,
    hasher,
):
    # Only the descriptor's fixed CLI destination and fixed inventory role are
    # eligible. No manifest-provided executable/argv/destination is ever run.
    path = target["layout"]["binary_dir"] + "/depot-enclave"
    expected = next(
        item for item in inventory["files"] if item["path"] == "bin/depot-enclave"
    )
    before = hasher(path)
    if before["sha256"] != expected["sha256"] or before["size"] != expected["size"]:
        refuse("CONFIG_COMMAND_ARTIFACT_MISMATCH")
    identity = codesign_identity(path, target, strict_json(pins_raw), runner)
    if hasher(path) != before:
        refuse("CONFIG_COMMAND_CHANGED")

    # Trust inputs must still be the exact public bytes whose hashes bound the
    # observation before the sole permitted configuration-only command starts.
    def current_inputs():
        for name, original, maximum in (
            (descriptor, descriptor_raw, MAX_DESCRIPTOR),
            (target["authority_config"], authority_raw, 16 * 1024),
            (target["codesign_pins_file"], pins_raw, MAX_PUBLIC),
            (target["expected_artifacts_manifest"], artifact_raw, MAX_PUBLIC),
        ):
            current = reader(name, maximum)
            if current != original:
                refuse("CONFIG_INPUT_CHANGED")
            if (
                name == target["expected_artifacts_manifest"]
                and inventory_binding(current, target, descriptor_raw, pins_raw)
                != inventory
            ):
                refuse("CONFIG_INPUT_CHANGED")

    current_inputs()
    receipt = config_check(target, descriptor, digest(authority_raw), runner)
    if hasher(path) != before:
        refuse("CONFIG_COMMAND_CHANGED")
    current_inputs()
    receipt["code_identity"] = identity
    receipt["artifact_sha256"] = before["sha256"]
    receipt["source_provenance"] = "UNKNOWN_EXTERNAL_SOURCE_ATTESTATION"
    return receipt


def authority_observation(raw, target, reader):
    """Bounded public input inventory, without replacing Rust signature checks."""
    value = strict_json(raw)
    paths = (
        "asset_policy_file",
        "asset_policy_key_file",
        "asset_inventory_key_file",
        "envelope_policy_key_file",
    )
    scopes = (
        "asset_host_id",
        "asset_id",
        "asset_custodian_id",
        "envelope_policy_subject",
        "envelope_policy_namespace",
    )
    if (
        not isinstance(value, dict)
        or set(value) != {"v", "profile", *paths, *scopes}
        or type(value["v"]) is not int
        or value["v"] != 1
        or value["profile"] != target["profile"]
        or any(
            not isinstance(value[k], str)
            or not 0 < len(value[k].encode("utf-8")) <= 256
            or any(unicodedata.category(c) == "Cc" for c in value[k])
            for k in scopes
        )
    ):
        refuse("AUTHORITY_CONFIG_SCHEMA")
    hashes = {}
    for key in paths:
        path_value(value[key])
        content = reader(value[key], 16 * 1024 if key ==
                         "asset_policy_file" else 128)
        if key != "asset_policy_file" and not re.fullmatch(
            rb"[0-9a-fA-F]{64}", content.strip()
        ):
            refuse("AUTHORITY_PUBLIC_KEY_FORMAT")
        hashes[key + "_sha256"] = digest(content)
    return {
        "status": "UNKNOWN_AUTHORITY_SIGNATURE_NOT_CHECKED",
        "public_input_sha256": hashes,
    }


def audit(
    descriptor,
    peer=None,
    plists=None,
    console=None,
    run_config=False,
    reader=protected_read,
    metadata=os.lstat,
    runner=bounded_command,
    hasher=protected_hash,
):
    raw = reader(descriptor, MAX_DESCRIPTOR)
    target = validate_target(strict_json(raw))
    descriptor_location(target, descriptor)
    authority = reader(target["authority_config"], 16 * 1024)
    authority_result = authority_observation(authority, target, reader)
    artifacts = reader(target["expected_artifacts_manifest"], MAX_PUBLIC)
    pins_raw = reader(target["codesign_pins_file"], MAX_PUBLIC)
    pins = strict_json(pins_raw)
    if (
        not isinstance(pins, dict)
        or type(pins.get("v")) is not int
        or pins.get("v") != 1
        or not isinstance(pins.get("pins"), dict)
        or any(
            not isinstance(hs, list)
            or not hs
            or any(
                not isinstance(h, str) or not re.fullmatch(
                    r"[0-9a-fA-F]{40}", h)
                for h in hs
            )
            for hs in pins["pins"].values()
        )
    ):
        refuse("CODESIGN_PINS_INVALID")
    if "mode" in pins and pins["mode"] != target["signing_identity_mode"]:
        refuse("CODESIGN_PINS_MODE_MISMATCH")
    required = ["com.enterprise.enclave." + suffix for suffix, *_ in DAEMONS]
    required += ["com.enterprise.enclave.intent", "com.enterprise.enclave.ctl"]
    if target["broker"]:
        reader(target["broker"]["tuf_root_file"], 4 * MAX_PUBLIC)
        required.append("com.enterprise.enclave.apfs-broker")
    if any(identifier not in pins["pins"] for identifier in required):
        refuse("CODESIGN_PINS_MISSING")
    inventory = inventory_binding(artifacts, target, raw, pins_raw)
    if peer:
        validate_pair(target, load_target(peer, reader))
    endpoints = routes(target, console)
    socket_results = {
        suffix: socket_observation(
            endpoints[suffix], uid, uid + 8010, metadata)
        for suffix, uid, *_ in DAEMONS
    }
    socket_results["intent"] = socket_observation(
        endpoints["intent"], console, 8703, metadata
    )
    socket_results["supervisor"] = socket_observation(
        endpoints["supervisor"], 0, 8716, metadata
    )
    if target["broker"]:
        socket_results["apfs-broker"] = socket_observation(
            endpoints["apfs-broker"], 0, 8702, metadata
        )
    report = {
        "schema": 1,
        "target_id": target["target_id"],
        "profile": target["profile"],
        "operation": "READ_ONLY_FIRST_TOUCH_PREFLIGHT",
        "descriptor_sha256": digest(raw),
        "authority_sha256": digest(authority),
        "pins_sha256": digest(pins_raw),
        "artifact_manifest_sha256": digest(artifacts),
        "routes": endpoints,
        "sockets": socket_results,
        "artifact_provenance": "UNKNOWN_ARTIFACT_PROVENANCE",
        "artifact_inventory": {
            "status": "OBSERVED_LOCAL_INVENTORY_BINDINGS",
            "external_provenance": "UNKNOWN",
            "source_git_commit": inventory["source_git_commit"],
            "source_manifest_sha256": inventory["source_manifest_sha256"],
            "source_input_count": inventory["source_input_count"],
            "file_count": len(inventory["files"]),
        },
        "compiled_signing_mode": "UNKNOWN_UNLESS_CONFIG_ONLY_CHECK_EXECUTED",
        "authority_verification": authority_result,
        "plists": "UNKNOWN_PLISTS_NOT_SUPPLIED",
        "peer_isolation": (
            "OBSERVED_PAIR_ISOLATED" if peer else "UNKNOWN_PEER_NOT_SUPPLIED"
        ),
        "live_cas_freshness": "UNKNOWN_NO_AUTHENTICATED_LIVE_CAS_QUERY",
        "physical_readiness": "UNKNOWN_NO_PHYSICAL_CEREMONY",
        "socket_ancestor_protection": "UNKNOWN_OWNER_MODE_NOT_VALIDATED",
        "owner_coverage": "UNKNOWN_UNOBSERVED_PROCESS_OWNERS",
        "qualified": False,
    }
    if plists:
        report["plists"] = check_plists(target, descriptor, plists, reader)
    if run_config:
        if sys.platform != "darwin":
            refuse("UNKNOWN_CONFIG_COMMAND_NATIVE_PLATFORM_REQUIRED")
        report["authority_verification"] = verified_config_check(
            target,
            descriptor,
            raw,
            authority,
            pins_raw,
            artifacts,
            inventory,
            reader,
            runner,
            hasher,
        )
        report["compiled_signing_mode"] = "OBSERVED_CONFIG_ONLY_BUILD_MODE_MATCH"
    report["status"] = (
        "FAIL"
        if any(v["status"].startswith("FAIL") for v in socket_results.values())
        else "UNKNOWN"
    )
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment-target", required=True)
    parser.add_argument("--peer-deployment-target")
    parser.add_argument("--plists-dir")
    parser.add_argument(
        "--observe-installed-plists",
        action="store_true",
        help="Standalone static observation of fixed /Library launchd paths; no service/config command",
    )
    parser.add_argument(
        "--console-uid",
        type=int,
        help="Supplied UID only; not proof of a current console session",
    )
    parser.add_argument(
        "--observe-console",
        action="store_true",
        help="Read Darwin /dev/console owner only",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="Explicitly run target CLI public configuration-only verifier",
    )
    args = parser.parse_args(argv)
    try:
        if args.observe_installed_plists:
            if any(
                (
                    args.peer_deployment_target,
                    args.plists_dir,
                    args.console_uid is not None,
                    args.observe_console,
                    args.check_config,
                )
            ):
                refuse("AMBIGUOUS_INSTALLED_OBSERVATION_MODE")
            report = installed_plist_audit(args.deployment_target)
            print(json.dumps(report, sort_keys=True, indent=2))
            return 1 if report["status"] == "FAIL" else 2
        if args.observe_console and args.console_uid is not None:
            refuse("AMBIGUOUS_CONSOLE_SOURCE")
        console = args.console_uid
        source = (
            "SUPPLIED_UNVERIFIED_UID"
            if console is not None
            else "UNKNOWN_CONSOLE_SESSION"
        )
        if args.observe_console and sys.platform == "darwin":
            observed_uid = os.stat("/dev/console").st_uid
            console = observed_uid if 500 <= observed_uid < 2**32 - 1 else None
            source = (
                "OBSERVED_DEV_CONSOLE_OWNER_ONLY"
                if console is not None
                else "UNKNOWN_CONSOLE_SESSION"
            )
        if console is not None and not 500 <= console < 2**32 - 1:
            refuse("DEPLOYMENT_CONSOLE_UID")
        report = audit(
            args.deployment_target,
            args.peer_deployment_target,
            args.plists_dir,
            console,
            args.check_config,
        )
        report["console_source"] = source
    except (
        Refusal,
        OSError,
        TypeError,
        KeyError,
        UnicodeError,
        RecursionError,
    ) as error:
        unknown = isinstance(error, Refusal) and str(
            error).startswith("UNKNOWN_")
        report = {
            "schema": 1,
            "status": "UNKNOWN" if unknown else "FAIL",
            "qualified": False,
            "reason": (
                str(error)
                if isinstance(error, Refusal)
                else "INPUT_OR_OBSERVATION_REFUSED"
            ),
        }
    print(json.dumps(report, sort_keys=True, indent=2))
    # UNKNOWN is deliberately distinct from successful readiness/qualification.
    return 1 if report["status"] == "FAIL" else 2


if __name__ == "__main__":
    sys.exit(main())
