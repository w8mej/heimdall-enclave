#!/usr/bin/env python3
"""Hash a declared public candidate and verified source snapshot; stdout only.

The inventory records local observations. External provenance is UNKNOWN.
No build, signing, installation, service, key or hardware operation is invoked.
"""

import argparse
import contextlib
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

MAX_FILES = 4096
MAX_FILE = 512 * 1024 * 1024
MAX_JSON = 32 * 1024 * 1024
MAX_INVENTORY = 1024 * 1024
MAX_PACKAGE_FILES = 128
MAX_PACKAGE_BYTES = 2 * 1024 * 1024 * 1024
ROOT_FIELDS = {
    "binary_dir",
    "custody_bundle",
    "sandbox_dir",
    "socket_root",
    "state_root",
    "audit_root",
    "cas_store_root",
    "staging_root",
    "support_root",
}
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
BINARIES = {
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
PUBLIC_TUF = {
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
}
# Actual UID 703 custody target bounds, independent of the generic JSON cap.
CUSTODY_RUNTIME_BOUNDS = {
    "tuf/repo/fido-mds-allowlist.json": 256 * 1024,
    "tuf/repo/custody-envelope-policy-v1.json": 16 * 1024,
}
JOB_SUFFIXES = {
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
PIN_IDS = {"com.enterprise.enclave." + name for name in JOB_SUFFIXES | {"ctl"}}
PRIVATE_MATERIAL = re.compile(
    rb'-----BEGIN [^-\r\n]*PRIVATE KEY-----|"(?:private|private_key|secret|secret_key|seed|signing_seed)"\s*:'
)
_read_chunk = os.read


class Refusal(Exception):
    """Fixed non-secret refusal code, never arbitrary input/error text."""


def require(condition, reason):
    if not condition:
        raise Refusal(reason)


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    def constant(_):
        raise Refusal("JSON_CONSTANT")

    try:
        return json.loads(
            raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant
        )
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Refusal("JSON_SCHEMA") from error


def canonical(path, absolute=True):
    require(
        isinstance(path, str) and path and len(
            path.encode("utf-8")) <= 4096, "PATH"
    )
    require(path.isascii(), "PATH")
    require(
        not any(ord(c) < 32 or ord(c) ==
                127 or c in "'\"`$;&|<>()\\" for c in path),
        "PATH",
    )
    require(path.startswith("/") == absolute, "PATH")
    parts = path.split("/")
    require(
        all(part not in ("", ".", "..")
            for part in (parts[1:] if absolute else parts)),
        "PATH",
    )
    if absolute:
        first = parts[1]
        require(
            first.lower() not in ("var", "tmp", "etc", "private")
            or first == first.lower(),
            "PATH",
        )
        if first == "private" and len(parts) > 2:
            second = parts[2]
            require(
                second.lower() not in ("var", "tmp", "etc") or second == second.lower(),
                "PATH",
            )
    return path


def normalized(path):
    canonical(path)
    for alias in ("/var", "/tmp", "/etc"):
        if path == alias or path.startswith(alias + "/"):
            return "/private" + path
    return path


def stamp(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


@contextlib.contextmanager
def directory(path):
    if str(path) != "/":
        canonical(str(path))
    opened = (
        normalized(str(path))
        if sys.platform == "darwin" and str(path) != "/"
        else str(path)
    )
    fd = os.open("/", DIR_FLAGS)
    try:
        components = opened.split("/")[1:] if opened != "/" else ()
        for component in components:
            child = os.open(component, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


@contextlib.contextmanager
def parent_at(root, relative):
    canonical(relative, absolute=False)
    parts = relative.split("/")
    fd = os.dup(root)
    try:
        for component in parts[:-1]:
            child = os.open(component, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd, parts[-1]
    finally:
        os.close(fd)


def hash_at(
    parent,
    name,
    maximum=MAX_FILE,
    capture=False,
    output_identity=None,
    expected_stamp=None,
):
    fd = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent
    )
    try:
        before = os.fstat(fd)
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and before.st_size <= maximum,
            "REGULAR_SINGLE_LINK_BOUNDED_FILE_REQUIRED",
        )
        require(output_identity != (before.st_dev,
                before.st_ino), "OUTPUT_IN_STAGING")
        require(
            expected_stamp is None or stamp(before) == expected_stamp,
            "FILE_CHANGED_BEFORE_READ",
        )
        digest, count, chunks = hashlib.sha256(), 0, []
        while True:
            chunk = _read_chunk(fd, min(1024 * 1024, maximum + 1 - count))
            if not chunk:
                break
            count += len(chunk)
            require(count <= maximum, "FILE_SIZE")
            digest.update(chunk)
            if capture:
                chunks.append(chunk)
        after = os.fstat(fd)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(
            stamp(before) == stamp(after) == stamp(
                named) and count == before.st_size,
            "FILE_CHANGED",
        )
        return digest.hexdigest(), count, stamp(after), b"".join(chunks)
    finally:
        os.close(fd)


def read_absolute(path, maximum):
    canonical(str(path))
    with directory(str(Path(path).parent)) as parent:
        return hash_at(parent, Path(path).name, maximum, capture=True)


def target_from(raw):
    value = strict_json(raw)
    require(
        isinstance(value, dict)
        and set(value) == TARGET_FIELDS
        and type(value["version"]) is int
        and value["version"] == 1,
        "DEPLOYMENT_SCHEMA",
    )
    require(
        isinstance(value["target_id"], str)
        and re.fullmatch(r"[a-z](?:[a-z0-9-]{0,62}[a-z0-9])?", value["target_id"]),
        "TARGET_ID",
    )
    require(
        value["profile"] in ("L2", "L3")
        and value["role"] in ("dedicated-test", "existing-upgrade")
        and value["signing_identity_mode"] in ("local-pins", "team-id"),
        "DEPLOYMENT_SCHEMA",
    )
    layout = value["layout"]
    require(
        isinstance(layout, dict)
        and set(layout) == ROOT_FIELDS | {"launchd_namespace", "mach_service"},
        "DEPLOYMENT_SCHEMA",
    )
    for field in ROOT_FIELDS:
        canonical(layout[field])
    for field, maximum in (("launchd_namespace", 112), ("mach_service", 128)):
        name = layout[field]
        require(
            isinstance(name, str)
            and len(name) <= maximum
            and len(name.split(".")) >= 2
            and all(
                re.fullmatch(r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in name.split(".")
            ),
            "DEPLOYMENT_NAME",
        )
    for field in (
        "authority_config",
        "expected_artifacts_manifest",
        "codesign_pins_file",
    ):
        canonical(value[field])
    shared = value["shared_read_only_inputs"]
    require(isinstance(shared, list) and len(shared) <= 8, "DEPLOYMENT_SCHEMA")
    for path in shared:
        canonical(path)
    broker = value["broker"]
    if value["profile"] == "L2":
        require(broker is None, "DEPLOYMENT_SCHEMA")
    else:
        require(
            isinstance(broker, dict) and set(broker) == {
                "base_dir", "tuf_root_file"},
            "DEPLOYMENT_SCHEMA",
        )
        canonical(broker["base_dir"])
        canonical(broker["tuf_root_file"])
        require(
            normalized(broker["base_dir"])
            == normalized(layout["state_root"] + "/apfs-broker"),
            "DEPLOYMENT_SCHEMA",
        )
    return value


def allowed_file(path, namespace):
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
        return parts[1] in BINARIES
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
        return parts[1] in {"provision-accounts.sh", "enclave-daemon.entitlements"} | {
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
        } | {namespace + "." + suffix + ".plist" for suffix in JOB_SUFFIXES}
    if len(parts) == 3 and parts[:2] == ["tuf", "repo"]:
        name = parts[2]
        return name in PUBLIC_TUF or bool(
            re.fullmatch(r"[1-9][0-9]{0,9}\.root\.json", name)
            and int(name.split(".")[0]) <= 2147483647
        )
    return False


def allowed_directory(path):
    if path in {"bin", "launchd", "fido-mds", "tuf", "tuf/repo"}:
        return True
    return any(
        path == bundle + suffix
        for bundle in ("EnclaveCustody.app", "EnclaveOIDC.app")
        for suffix in ("", "/Contents", "/Contents/MacOS", "/Contents/_CodeSignature")
    )


def validate_pins(raw, mode):
    pins = strict_json(raw)
    require(
        isinstance(pins, dict)
        and set(pins) in ({"v", "pins"}, {"v", "mode", "pins"})
        and type(pins["v"]) is int
        and pins["v"] == 1,
        "PINS_SCHEMA",
    )
    require("mode" not in pins or pins["mode"] == mode, "PINS_MODE")
    require(
        isinstance(pins["pins"], dict)
        and pins["pins"]
        and set(pins["pins"]) <= PIN_IDS,
        "PINS_SCHEMA",
    )
    for hashes in pins["pins"].values():
        require(
            isinstance(hashes, list)
            and 0 < len(hashes) <= 8
            and all(
                isinstance(h, str) and re.fullmatch(r"[a-fA-F0-9]{40}", h)
                for h in hashes
            ),
            "PINS_SCHEMA",
        )


def prestage_required():
    """The existing DedicatedL2 candidate closure before its twenty renders.

    These are paths, never a signature/provenance or authorization judgment.
    SHA256SUMS is generated separately and covers only the other prestage files.
    """
    return (
        {"bin/" + name for name in BINARIES}
        | {"tuf/repo/" + name for name in PUBLIC_TUF}
        | {
            "codesign-pins.json",
            "SHA256SUMS",
            "custody.entitlements",
            "yubikey-transport",
            "install.sh",
            "uninstall.sh",
            "public-trust.sh",
            "fido-mds/yubico.json",
        }
        | {
            bundle + "/Contents/" + member
            for bundle, executable in (
                ("EnclaveCustody.app", "enclave-custody-vaultd"),
                ("EnclaveOIDC.app", "enclave-oidc"),
            )
            for member in (
                "Info.plist",
                "_CodeSignature/CodeResources",
                "MacOS/" + executable,
            )
        }
    )


def prestage_public_json(relative):
    return relative == "codesign-pins.json" or relative.startswith(
        ("tuf/repo/", "fido-mds/")
    )


def prestage_limit(relative):
    canonical(relative, absolute=False)
    require(
        relative != "SHA256SUMS"
        and not relative.startswith("launchd/")
        and allowed_file(relative, ""),
        "PRESTAGE_PATH",
    )
    if relative == "codesign-pins.json":
        return 1024 * 1024
    if relative == "tuf/repo/enclave-host-config.json":
        return 64 * 1024
    if relative in CUSTODY_RUNTIME_BOUNDS:
        return CUSTODY_RUNTIME_BOUNDS[relative]
    if (
        relative
        in {
            "tuf/repo/" + name
            for name in ("root.json", "timestamp.json", "snapshot.json", "targets.json")
        }
        or relative.startswith("tuf/repo/")
        and relative.endswith(".root.json")
    ):
        return 4 * 1024 * 1024
    return 16 * 1024 * 1024 if prestage_public_json(relative) else MAX_FILE


def prestage_sources(sources):
    """Pure closed public plan validation; no files opened or authority made."""
    require(
        isinstance(sources, list)
        and 0 < len(sources)
        and len(sources) + 1 + 20 <= MAX_PACKAGE_FILES,
        "PRESTAGE_COUNT",
    )
    required = prestage_required() - {"SHA256SUMS"}
    seen, originals, total, rotations, rotation_bytes, runtime_bytes = (
        set(),
        set(),
        0,
        0,
        0,
        0,
    )
    runtime = {
        "tuf/repo/" + name
        for name in (
            "root.json",
            "timestamp.json",
            "snapshot.json",
            "targets.json",
            "enclave-host-config.json",
            "fido-mds-allowlist.json",
            "custody-envelope-policy-v1.json",
        )
    }
    for item in sources:
        require(
            isinstance(item, dict)
            and set(item) == {"relative", "path", "sha256", "size"},
            "PRESTAGE_SCHEMA",
        )
        relative, original = item["relative"], item["path"]
        maximum = prestage_limit(relative)
        canonical(original)
        require(
            relative.casefold() not in seen
            and normalized(original).casefold() not in originals,
            "PRESTAGE_ALIAS",
        )
        seen.add(relative.casefold())
        originals.add(normalized(original).casefold())
        require(
            isinstance(item["sha256"], str)
            and re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
            and type(item["size"]) is int
            and 0 < item["size"] <= maximum,
            "PRESTAGE_BOUND_OR_HASH",
        )
        total += item["size"]
        rotation = relative.startswith(
            "tuf/repo/") and relative.endswith(".root.json")
        if rotation:
            rotations += 1
            rotation_bytes += item["size"]
        if rotation or relative in runtime:
            runtime_bytes += item["size"]
    require(
        required <= {item["relative"]
                     for item in sources}, "PRESTAGE_REQUIRED_FILES"
    )
    require(
        rotations <= 32
        and rotation_bytes <= 16 * 1024 * 1024
        and runtime_bytes <= 33 * 1024 * 1024,
        "PRESTAGE_RUNTIME_BOUND",
    )
    # Reserve the exact deterministic checksums member, never assume it is free.
    checksums_size = sum(
        64 + 2 + len(item["relative"]) + 1 for item in sources)
    require(total + checksums_size <= MAX_PACKAGE_BYTES, "PRESTAGE_TOTAL_BOUND")
    return sorted(sources, key=lambda item: item["relative"])


def validate_prestage_public(relative, raw):
    """Structural public-data checks only; native trust admission stays later."""
    if relative == "yubikey-transport":
        require(raw == b"hid\n", "PRESTAGE_TRANSPORT")
    elif prestage_public_json(relative):
        require(PRIVATE_MATERIAL.search(raw) is None, "PRIVATE_MATERIAL")
        value = strict_json(raw)
        require(isinstance(value, dict), "PRESTAGE_PUBLIC_JSON")
        # Inspect decoded keys too; JSON escapes must not hide a known private
        # field from the existing conservative public-material deny pattern.
        require(
            PRIVATE_MATERIAL.search(
                json.dumps(value, ensure_ascii=True,
                           separators=(",", ":")).encode()
            )
            is None,
            "PRIVATE_MATERIAL",
        )
        if relative == "codesign-pins.json":
            validate_pins(raw, "local-pins")
            expected = PIN_IDS - {
                "com.enterprise.enclave.supervisor",
                "com.enterprise.enclave.hydrate",
            }
            require(
                set(value) == {"v", "mode", "pins"}
                and value["mode"] == "local-pins"
                and set(value["pins"]) == expected,
                "PRESTAGE_PIN_IDENTIFIERS",
            )
            require(
                all(
                    len({h.lower() for h in hashes}) == len(hashes)
                    for hashes in value["pins"].values()
                ),
                "PRESTAGE_PIN_DUPLICATE",
            )


def verify_observations(root, observations):
    for path, expected in observations.items():
        with parent_at(root, path) as (parent, name):
            require(
                stamp(os.stat(name, dir_fd=parent,
                      follow_symlinks=False)) == expected,
                "TREE_CHANGED",
            )


def overlaps(left, right):
    left, right = normalized(str(left)).casefold(
    ), normalized(str(right)).casefold()
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


def external_stage(target, package_root, deployment_config, source_snapshot):
    """Validate public allocation/path data, never deployment authority.

    The allocated root is obtained from the nonce already in the descriptor;
    this tool neither generates a birth nor opens any allocated destination.
    A descriptor copy may live outside that root for an independent producer.
    """
    canonical(os.fspath(package_root))
    require(
        target["role"] == "dedicated-test"
        and target["profile"] == "L2"
        and target["signing_identity_mode"] == "local-pins"
        and target["broker"] is None
        and not target["shared_read_only_inputs"],
        "EXTERNAL_PACKAGE_DEDICATED_L2_REQUIRED",
    )
    match = re.fullmatch(r"ykft-([0-9a-f]{32})", target["target_id"])
    require(match is not None, "EXTERNAL_PACKAGE_ALLOCATION_REQUIRED")
    token = match.group(1)
    roots = set()
    for path in [
        *(target["layout"][key] for key in ROOT_FIELDS),
        *(
            target[key]
            for key in (
                "authority_config",
                "expected_artifacts_manifest",
                "codesign_pins_file",
            )
        ),
    ]:
        parts = normalized(path).split("/")
        require(
            parts.count(token) == 1 and parts[-1] != token,
            "EXTERNAL_PACKAGE_ALLOCATION_SCOPE",
        )
        roots.add("/".join(parts[: parts.index(token) + 1]))
    require(len(roots) == 1, "EXTERNAL_PACKAGE_ALLOCATION_SCOPE")
    for original in [next(iter(roots)), deployment_config, source_snapshot.parent]:
        require(not overlaps(package_root, original),
                "EXTERNAL_PACKAGE_OVERLAP")
    return os.fspath(package_root)


def staged_source_list(observed_inventory, package_root):
    """Project the SAME scan into inert transport expectations, including pins."""
    canonical(os.fspath(package_root))
    return [
        {
            "relative": item["path"],
            "path": normalized(str(Path(package_root) / item["path"])),
            "sha256": item["sha256"],
            "size": item["size"],
        }
        for item in observed_inventory["files"]
    ]


def inventory(
    deployment_config, source_snapshot, output_identity=None, package_root=None
):
    for path in (deployment_config, source_snapshot):
        value = os.fspath(path)
        canonical(value, absolute=value.startswith("/"))
    deployment_config, source_snapshot = (
        Path(deployment_config).absolute(),
        Path(source_snapshot).absolute(),
    )
    require(source_snapshot.name == "snapshot.json", "SOURCE_SNAPSHOT")
    descriptor_hash, descriptor_size, descriptor_stamp, raw = read_absolute(
        deployment_config, 65536
    )
    target = target_from(raw)
    snapshot_hash, snapshot_size, snapshot_stamp, raw = read_absolute(
        source_snapshot, MAX_JSON
    )
    snapshot = strict_json(raw)
    require(
        isinstance(snapshot, dict)
        and type(snapshot.get("schema")) is int
        and snapshot["schema"] == 1
        and isinstance(snapshot.get("head"), str)
        and re.fullmatch(r"[0-9a-f]{40}", snapshot["head"]),
        "SOURCE_SNAPSHOT",
    )
    inputs = snapshot.get("source_sha256")
    require(isinstance(inputs, dict) and 0 < len(
        inputs) <= 100000, "SOURCE_SNAPSHOT")
    stage_path = (
        target["layout"]["staging_root"]
        if package_root is None
        else external_stage(target, package_root, deployment_config, source_snapshot)
    )
    if package_root is not None:
        require(
            output_identity not in (descriptor_stamp[:2], snapshot_stamp[:2]),
            "OUTPUT_IN_SOURCE",
        )
    source_seen, source_ids, source_observations = set(), set(), {}
    with directory(str(source_snapshot.parent)) as source_root, directory(
        stage_path
    ) as stage:
        source_identity, stage_identity = os.fstat(
            source_root), os.fstat(stage)
        for path, expected in sorted(inputs.items()):
            canonical(path, absolute=False)
            require(
                path.casefold() not in source_seen
                and isinstance(expected, str)
                and re.fullmatch(r"[0-9a-f]{64}", expected),
                "SOURCE_SNAPSHOT",
            )
            source_seen.add(path.casefold())
            with parent_at(source_root, path) as (parent, name):
                actual, _, observed, _ = hash_at(parent, name)
                require(actual == expected, "SOURCE_DRIFT")
                require(observed[:2] not in source_ids, "SOURCE_PATH_ALIAS")
                if package_root is not None:
                    require(output_identity !=
                            observed[:2], "OUTPUT_IN_SOURCE")
                source_ids.add(observed[:2])
                source_observations[path] = observed
        files, observed_files, observed_dirs, staged_seen, staged_ids = (
            [],
            {},
            {},
            set(),
            set(),
        )
        pins_hash, package_bytes = None, 0

        def walk(fd, prefix=""):
            nonlocal pins_hash, package_bytes
            before = os.fstat(fd)
            entries = sorted(os.listdir(fd))
            require(len(entries) <= MAX_FILES, "FILE_COUNT")
            for name in entries:
                relative = prefix + name
                canonical(relative, absolute=False)
                require(relative.casefold() not in staged_seen,
                        "STAGED_PATH_ALIAS")
                staged_seen.add(relative.casefold())
                metadata = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode):
                    require(allowed_directory(relative),
                            "UNSUPPORTED_STAGED_DIRECTORY")
                    child = os.open(name, DIR_FLAGS, dir_fd=fd)
                    try:
                        require(
                            (metadata.st_dev, metadata.st_ino)
                            == (os.fstat(child).st_dev, os.fstat(child).st_ino),
                            "TREE_CHANGED",
                        )
                        walk(child, relative + "/")
                    finally:
                        os.close(child)
                else:
                    require(
                        allowed_file(
                            relative, target["layout"]["launchd_namespace"]),
                        "UNSUPPORTED_STAGED_FILE",
                    )
                    require(len(files) < MAX_FILES, "FILE_COUNT")
                    if package_root is not None:
                        require(
                            0 < metadata.st_size <= MAX_FILE
                            and len(files) < MAX_PACKAGE_FILES,
                            "EXTERNAL_PACKAGE_BOUND",
                        )
                        package_bytes += metadata.st_size
                        require(
                            package_bytes <= MAX_PACKAGE_BYTES, "EXTERNAL_PACKAGE_BOUND"
                        )
                    public_json = (
                        relative == "codesign-pins.json"
                        or relative.startswith(("tuf/repo/", "fido-mds/"))
                    )
                    maximum = (
                        min(
                            MAX_FILE,
                            (
                                1024 * 1024
                                if relative == "codesign-pins.json"
                                else 16 * 1024 * 1024
                            ),
                        )
                        if public_json
                        else MAX_FILE
                    )
                    maximum = CUSTODY_RUNTIME_BOUNDS.get(relative, maximum)
                    if package_root is not None:
                        # Keep later growth bounded by the original aggregate
                        # reservation, with at most one extra EOF-probe byte.
                        maximum = min(maximum, metadata.st_size)
                    digest, size, observed, payload = hash_at(
                        fd,
                        name,
                        maximum,
                        capture=public_json,
                        output_identity=output_identity,
                        expected_stamp=(
                            stamp(metadata) if package_root is not None else None
                        ),
                    )
                    require(observed[:2] not in staged_ids,
                            "STAGED_PATH_ALIAS")
                    if package_root is not None:
                        require(
                            observed[:2]
                            not in source_ids
                            | {descriptor_stamp[:2], snapshot_stamp[:2]},
                            "EXTERNAL_PACKAGE_INPUT_ALIAS",
                        )
                        require(
                            0 < size and len(files) < MAX_PACKAGE_FILES,
                            "EXTERNAL_PACKAGE_BOUND",
                        )
                    staged_ids.add(observed[:2])
                    if relative == "codesign-pins.json":
                        validate_pins(payload, target["signing_identity_mode"])
                        pins_hash = digest
                    elif public_json:
                        require(
                            PRIVATE_MATERIAL.search(
                                payload) is None, "PRIVATE_MATERIAL"
                        )
                    files.append(
                        {"path": relative, "sha256": digest, "size": size})
                    observed_files[relative] = observed
            require(stamp(before) == stamp(os.fstat(fd)), "TREE_CHANGED")
            observed_dirs[prefix[:-1]] = stamp(before)

        walk(stage)
        if package_root is not None:
            require(
                sum(item["size"] for item in files) <= MAX_PACKAGE_BYTES,
                "EXTERNAL_PACKAGE_BOUND",
            )
        require(
            pins_hash is not None and "bin/depot-enclave" in observed_files,
            "REQUIRED_CANDIDATE_FILES",
        )
        require(
            sum(path.endswith(".root.json") for path in observed_files) <= 32,
            "TUF_ROOT_COUNT",
        )
        verify_observations(source_root, source_observations)
        verify_observations(stage, observed_files)
        for path, expected in observed_dirs.items():
            if path:
                with parent_at(stage, path) as (parent, name):
                    require(
                        stamp(os.stat(name, dir_fd=parent, follow_symlinks=False))
                        == expected,
                        "TREE_CHANGED",
                    )
            else:
                require(stamp(os.fstat(stage)) == expected, "TREE_CHANGED")
        with directory(str(source_snapshot.parent)) as again:
            require(
                (os.fstat(again).st_dev, os.fstat(again).st_ino)
                == (source_identity.st_dev, source_identity.st_ino),
                "TREE_CHANGED",
            )
        with directory(stage_path) as again:
            require(
                (os.fstat(again).st_dev, os.fstat(again).st_ino)
                == (stage_identity.st_dev, stage_identity.st_ino),
                "TREE_CHANGED",
            )
    require(
        read_absolute(deployment_config, 65536)[:3]
        == (descriptor_hash, descriptor_size, descriptor_stamp),
        "DEPLOYMENT_CHANGED",
    )
    require(
        read_absolute(source_snapshot, MAX_JSON)[:3]
        == (snapshot_hash, snapshot_size, snapshot_stamp),
        "SOURCE_SNAPSHOT_CHANGED",
    )
    return {
        "version": 1,
        "kind": "depot-first-touch-artifact-inventory",
        "target_id": target["target_id"],
        "profile": target["profile"],
        "signing_identity_mode": target["signing_identity_mode"],
        "deployment_config_sha256": descriptor_hash,
        "source_git_commit": snapshot["head"],
        "source_manifest_sha256": snapshot_hash,
        "source_input_count": len(inputs),
        "codesign_pins_sha256": pins_hash,
        "staging_root": normalized(target["layout"]["staging_root"]),
        "external_provenance": "UNKNOWN",
        "files": sorted(files, key=lambda item: item["path"]),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--deployment-config", required=True, action="append")
    parser.add_argument("--source-snapshot", required=True, action="append")
    parser.add_argument(
        "--package-root",
        action="append",
        help="Read this external staging tree; keep the allocated staging scope in inventory",
    )
    parser.add_argument(
        "--staged-source-list",
        action="store_true",
        help="Emit inert external source entries from the same verified scan (requires --package-root)",
    )
    args = parser.parse_args(argv)
    try:
        require(
            len(args.deployment_config) == len(
                args.source_snapshot) == 1, "ARGUMENTS"
        )
        require(args.package_root is None or len(
            args.package_root) == 1, "ARGUMENTS")
        require(
            not args.staged_source_list or args.package_root is not None, "ARGUMENTS"
        )
        try:
            output = os.fstat(sys.stdout.fileno())
            output_identity = (
                (output.st_dev, output.st_ino) if stat.S_ISREG(
                    output.st_mode) else None
            )
        except (AttributeError, OSError, ValueError):
            output_identity = None
        package_root = args.package_root[0] if args.package_root else None
        result = inventory(
            args.deployment_config[0],
            args.source_snapshot[0],
            output_identity,
            package_root,
        )
        if args.staged_source_list:
            result = staged_source_list(result, package_root)
        serialized = json.dumps(result, sort_keys=True, indent=2) + "\n"
        require(len(serialized.encode("utf-8")) <=
                MAX_INVENTORY, "INVENTORY_SIZE")
        sys.stdout.write(serialized)
        return 0
    except (
        Refusal,
        OSError,
        UnicodeError,
        TypeError,
        KeyError,
        RecursionError,
    ) as error:
        reason = str(error) if isinstance(error, Refusal) else "INPUT_REFUSED"
        print("ARTIFACT_INVENTORY_REFUSED: " + reason, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
