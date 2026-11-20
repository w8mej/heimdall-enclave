#!/usr/bin/env python3
"""One bounded DedicatedL2 session and explicit public preparation; no authority.

assemble-stage, run, prepare and decide are separate operator invocations. No callback, signing,
factor operation, resume, repair or rollback is implemented. Native admission
belongs exclusively to the existing binary and its original owning chain.
"""

import argparse
import contextlib
import ctypes
import hashlib
import itertools
import json
import os
import re
import selectors
import stat
import subprocess
import sys
import time
import types
from pathlib import Path

FRAME = 1024 * 1024
COMMAND = 16 * 1024
STDERR = 65536
SETUP_NS = 900 * 10**9
FINISH_NS = 300 * 10**9
EXIT_NS = 5 * 10**9
FIVE_ROLES = {
    "custody_manifest",
    "custody_policy",
    "policy_issuer_key",
    "inventory_issuer_key",
    "envelope_issuer_key",
}
ROLE_CAP = {role: (128 if role.endswith("_key") else 16384) for role in FIVE_ROLES}
SEVEN_ROLES = FIVE_ROLES | {"inventory", "staged_pins"}
EFFECTS = {
    "external_jobs_may_have_been_published",
    "namespace_visibility_may_have_changed",
    "denial_may_have_been_removed",
    "registration_may_have_changed",
    "explicit_startup_release_may_have_occurred",
}
ERRNOS = {
    "EACCES",
    "EPERM",
    "E2BIG",
    "EAGAIN",
    "EINVAL",
    "ESTALE",
    "EALREADY",
    "ETIMEDOUT",
    "ENOMEM",
    "EDQUOT",
    "EIO",
    "ENOSYS",
}
PROGRESS = {
    "operation",
    "root",
    "descriptor",
    "target_id",
    "attempted",
    "created_directories",
    "created_files",
    "existing_names",
    "synced",
    "seeds_complete",
    "denial_prepared",
    "pending_descriptor_sha256",
    "pending_inventory_sha256",
    "complete",
    "uncertain_effects",
    "mutation_allowed",
    "inactivity_proven",
    "activation_allowed",
    "installation_supported",
    "qualified",
}


class Refusal(Exception):
    """Only fixed non-secret reason codes are emitted."""

    def __init__(self, reason, evidence=None):
        super().__init__(reason)
        self.evidence = evidence


def need(condition, reason):
    if not condition:
        raise Refusal(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def lower_hash(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def fields(value, expected):
    need(isinstance(value, dict) and set(value) == set(expected), "JSON_FIELDS")


def loads(raw, maximum=FRAME, wire=False):
    need(0 < len(raw) <= maximum and raw.isascii(), "JSON_BOUND_OR_ENCODING")
    need(not wire or b"\\" not in raw, "WIRE_ESCAPES")

    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "JSON_DUPLICATE")
            result[key] = value
        return result

    def constant(_):
        raise Refusal("JSON_NUMBER")

    try:
        return json.loads(
            raw, object_pairs_hook=pairs, parse_constant=constant, parse_float=constant
        )
    except (ValueError, UnicodeError, RecursionError):
        raise Refusal("JSON_SCHEMA") from None


def encoded(value, maximum=FRAME):
    raw = (
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
        + b"\n"
    )
    need(len(raw) <= maximum, "JSON_OUTPUT_BOUND")
    return raw


def path(value, relative=False):
    need(
        isinstance(value, str) and 0 < len(value.encode()) <= 4096 and value.isascii(),
        "PATH",
    )
    need(
        not any(ord(c) < 32 or ord(c) == 127 or c in "'\"`$;&|<>()\\" for c in value),
        "PATH",
    )
    parts = value.split("/")
    need(
        value.startswith("/") != relative
        and all(p not in ("", ".", "..") for p in parts[int(not relative) :]),
        "PATH",
    )
    need(len(parts) <= 96 and all(len(p) <= 255 for p in parts), "PATH")
    if not relative:
        need(parts[1].lower() not in {"var", "tmp", "etc"}, "NORMALIZED_PATH_REQUIRED")
        if parts[1].lower() == "private":
            need(
                parts[1] == "private"
                and (
                    len(parts) < 3
                    or parts[2].lower() not in {"var", "tmp", "etc"}
                    or parts[2] in {"var", "tmp", "etc"}
                ),
                "NORMALIZED_PATH_REQUIRED",
            )
    return value


def overlaps(a, b):
    a, b = path(a).lower(), path(b).lower()
    return a == b or a.startswith(b + "/") or b.startswith(a + "/")


def beneath(child, parent):
    path(child)
    path(parent)
    need(child.startswith(parent + "/"), "EXTERNAL_CONTAINER")


_TEMPORARIES = itertools.count()


def publish(directory, temporary, final):
    """One atomic no-replace rename; no overwrite or hardlink-window fallback."""
    libc = ctypes.CDLL(None, use_errno=True)
    name = (
        "renameat2"
        if sys.platform == "linux"
        else "renameatx_np" if sys.platform == "darwin" else None
    )
    need(name is not None and hasattr(libc, name), "ATOMIC_NOREPLACE_UNAVAILABLE")
    operation = getattr(libc, name)
    operation.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    operation.restype = ctypes.c_int
    flags = (
        1 if sys.platform == "linux" else 4
    )  # RENAME_NOREPLACE / Darwin RENAME_EXCL.
    if (
        operation(
            directory,
            temporary.encode("ascii"),
            directory,
            final.encode("ascii"),
            flags,
        )
        != 0
    ):
        raise OSError(ctypes.get_errno(), "PUBLIC_ATOMIC_PUBLISH_REFUSED")


def identity(m):
    return (
        m.st_dev,
        m.st_ino,
        m.st_uid,
        m.st_gid,
        m.st_mode,
        getattr(m, "st_flags", 0),
    )


def stamp(m):
    return identity(m) + (m.st_nlink, m.st_size, m.st_mtime_ns, m.st_ctime_ns)


def protected(m):
    return m.st_uid in {0, os.geteuid()} and m.st_mode & 0o022 == 0


class Directory:
    """Original nofollow ancestry. strict is mandatory for code and mutations.

    Public DATA reads alone may retain writable ancestors. Neither variant is
    native ACL admission. There is no trusted-prefix or filesystem test bypass.
    """

    def __init__(self, name, strict=False, private=False):
        self.path, self.chain, self.strict = (
            ("/" if name == "/" else path(name)),
            [],
            strict,
        )
        try:
            fd = os.open(
                "/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            )
            self.chain.append((fd, None, None, identity(os.fstat(fd))))
            for component in (self.path.split("/")[1:] if self.path != "/" else []):
                parent = self.chain[-1][0]
                fd = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=parent,
                )
                self.chain.append((fd, parent, component, identity(os.fstat(fd))))
            self.current()
            if private:
                m = os.fstat(self.fd)
                need(
                    m.st_uid == os.geteuid() and stat.S_IMODE(m.st_mode) == 0o700,
                    "PRIVATE_DIRECTORY",
                )
        except BaseException:
            self.close()
            raise

    @property
    def fd(self):
        return self.chain[-1][0]

    def current(self):
        for fd, parent, name, original in self.chain:
            m = os.fstat(fd)
            need(
                stat.S_ISDIR(m.st_mode) and m.st_nlink > 0 and identity(m) == original,
                "DIRECTORY_CHANGED",
            )
            need(not self.strict or protected(m), "PROTECTED_ANCESTRY_REQUIRED")
            if parent is not None:
                need(
                    identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
                    == original,
                    "DIRECTORY_NAME_CHANGED",
                )

    def empty(self):
        self.current()
        need(not os.listdir(self.fd), "EMPTY_DIRECTORY_REQUIRED")
        self.current()

    def write(self, name, raw):
        need(
            "/" not in path(name, relative=True) and 0 < len(raw) <= FRAME,
            "OUTPUT_NAME_OR_BOUND",
        )
        need(self.strict, "PROTECTED_MUTATION_REQUIRED")
        self.current()
        temporary = ".pending-" + str(os.getpid()) + "-" + str(next(_TEMPORARIES))
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=self.fd,
        )
        try:
            offset = 0
            while offset < len(raw):
                count = os.write(fd, raw[offset : offset + 65536])
                need(count > 0, "OUTPUT_WRITE")
                offset += count
            os.fsync(fd)
            m = os.fstat(fd)
            need(
                m.st_uid == os.geteuid()
                and stat.S_IMODE(m.st_mode) == 0o600
                and m.st_nlink == 1
                and m.st_size == len(raw),
                "OUTPUT_PROTECTION",
            )
            need(
                stamp(os.stat(temporary, dir_fd=self.fd, follow_symlinks=False))
                == stamp(m),
                "OUTPUT_NAME_CHANGED",
            )
            self.current()
            publish(self.fd, temporary, name)
            m = os.fstat(fd)
            need(
                m.st_nlink == 1
                and stamp(os.stat(name, dir_fd=self.fd, follow_symlinks=False))
                == stamp(m),
                "OUTPUT_NAME_CHANGED",
            )
            self.current()
            os.fsync(self.fd)
            return {
                "path": self.path + "/" + name,
                "sha256": digest(raw),
                "size": len(raw),
            }
        finally:
            os.close(fd)

    def close(self):
        for fd, _, _, _ in reversed(self.chain):
            os.close(fd)
        self.chain = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class Reader:
    """Bounded original regular DATA or strict code file; retained until close."""

    def __init__(self, name, maximum, strict=False, capture=True):
        self.path, self.fd, self.directory = path(name), None, None
        self.raw = None
        try:
            self.directory = Directory(str(Path(name).parent), strict=strict)
            self.fd = os.open(
                Path(name).name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=self.directory.fd,
            )
            m = os.fstat(self.fd)
            need(
                stat.S_ISREG(m.st_mode)
                and m.st_nlink == 1
                and protected(m)
                and 0 < m.st_size <= maximum,
                "REGULAR_PROTECTED_BOUNDED_FILE",
            )
            self.original, self.size = stamp(m), m.st_size
            h, chunks, count = hashlib.sha256(), [], 0
            while True:
                chunk = os.read(self.fd, min(65536, maximum + 1 - count))
                if not chunk:
                    break
                count += len(chunk)
                need(count <= maximum, "READ_BOUND")
                h.update(chunk)
                if capture:
                    chunks.append(chunk)
            need(count == self.size, "READ_CHANGED")
            self.sha256 = h.hexdigest()
            self.raw = b"".join(chunks) if capture else None
            self.current()
        except BaseException:
            self.close()
            raise

    def current(self):
        self.directory.current()
        need(stamp(os.fstat(self.fd)) == self.original, "FILE_CHANGED")
        need(
            stamp(
                os.stat(
                    Path(self.path).name,
                    dir_fd=self.directory.fd,
                    follow_symlinks=False,
                )
            )
            == self.original,
            "FILE_NAME_CHANGED",
        )
        self.directory.current()

    def record(self, role=None):
        value = {"path": self.path, "sha256": self.sha256, "size": self.size}
        if role is not None:
            value["role"] = role
        return value

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.directory is not None:
            self.directory.close()
            self.directory = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def inventory_module():
    # Fixed sibling CODE only, never --source-snapshot or another CLI path.
    name = str(Path(__file__).absolute().with_name("prepare-first-touch-artifacts.py"))
    with Reader(name, 131072, strict=True) as source:
        module = types.ModuleType("mcpmac_fixed_inventory")
        module.__file__ = name
        exec(
            compile(source.raw, name, "exec"), module.__dict__
        )  # nosec B102: strictly pinned sibling module read via O_NOFOLLOW Reader
        source.current()
        return module, source.record()


def copy_public(source, output, name, executable=False):
    """Stream from the retained original; exclusively publish verified new bytes.

    This copies data, including signatures if present; it does not verify them.
    Failed temporaries remain as evidence. No prior file is replaced or adopted.
    """
    need(
        "/" not in path(name, relative=True) and output.strict,
        "PROTECTED_COPY_REQUIRED",
    )
    source.current()
    output.current()
    temporary = ".pending-" + str(os.getpid()) + "-" + str(next(_TEMPORARIES))
    fd = os.open(
        temporary,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
        dir_fd=output.fd,
    )
    try:
        os.lseek(source.fd, 0, os.SEEK_SET)
        copied, hashed = 0, hashlib.sha256()
        while copied < source.size:
            chunk = os.read(source.fd, min(65536, source.size - copied))
            need(bool(chunk), "COPY_SOURCE_CHANGED")
            hashed.update(chunk)
            copied += len(chunk)
            offset = 0
            while offset < len(chunk):
                count = os.write(fd, chunk[offset:])
                need(0 < count <= len(chunk) - offset, "COPY_WRITE")
                offset += count
        need(
            not os.read(source.fd, 1) and hashed.hexdigest() == source.sha256,
            "COPY_SOURCE_CHANGED",
        )
        source.current()
        mode = 0o500 if executable else 0o600
        os.fchmod(fd, mode)
        os.fsync(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        observed, size = hashlib.sha256(), 0
        while size < copied:
            chunk = os.read(fd, min(65536, copied - size))
            need(bool(chunk), "COPY_DESTINATION_CHANGED")
            observed.update(chunk)
            size += len(chunk)
        need(
            not os.read(fd, 1) and observed.hexdigest() == source.sha256,
            "COPY_DESTINATION_CHANGED",
        )
        m = os.fstat(fd)
        need(
            stat.S_ISREG(m.st_mode)
            and m.st_uid == os.geteuid()
            and stat.S_IMODE(m.st_mode) == mode
            and m.st_nlink == 1
            and m.st_size == source.size,
            "COPY_DESTINATION_PROTECTION",
        )
        need(
            stamp(os.stat(temporary, dir_fd=output.fd, follow_symlinks=False))
            == stamp(m),
            "COPY_NAME_CHANGED",
        )
        source.current()
        output.current()
        publish(output.fd, temporary, name)
        m = os.fstat(fd)
        need(
            m.st_nlink == 1
            and stamp(os.stat(name, dir_fd=output.fd, follow_symlinks=False))
            == stamp(m),
            "COPY_NAME_CHANGED",
        )
        source.current()
        output.current()
        os.fsync(output.fd)
        return {
            "path": output.path + "/" + name,
            "sha256": source.sha256,
            "size": source.size,
            "observed": stamp(m),
        }
    finally:
        os.close(fd)


def prestage_current(held, directories, observations):
    for source in held:
        source.current()
    entries = set(directories) | set(observations)
    for relative, directory in directories.items():
        directory.current()
        expected = {
            Path(entry).name
            for entry in entries
            if entry
            and ("" if str(Path(entry).parent) == "." else str(Path(entry).parent))
            == relative
        }
        need(set(os.listdir(directory.fd)) == expected, "ASSEMBLY_TREE_CHANGED")
        directory.current()
    for relative, original in observations.items():
        parent = str(Path(relative).parent)
        directory = directories["" if parent == "." else parent]
        need(
            stamp(
                os.stat(Path(relative).name, dir_fd=directory.fd, follow_symlinks=False)
            )
            == original,
            "ASSEMBLY_COPY_CHANGED",
        )


def assemble_stage(args):
    """Create only a closed public prestage, without a native session or trust."""
    held, module, started = [], None, False
    try:
        module, module_record = inventory_module()
        with contextlib.ExitStack() as stack:
            output = stack.enter_context(
                Directory(args.output_dir, strict=True, private=True)
            )
            output.empty()
            inputs_file = Reader(args.inputs, FRAME, strict=True)
            held.append(inputs_file)
            inputs = loads(inputs_file.raw, wire=True)
            fields(inputs, {"version", "kind", "stage_root", "sources"})
            need(
                type(inputs["version"]) is int
                and inputs["version"] == 1
                and inputs["kind"] == "mcpmac-dedicated-birth-prestage-inputs",
                "ASSEMBLY_SCHEMA",
            )
            stage_path = path(inputs["stage_root"])
            code = str(Path(__file__).absolute().parent)
            need(not overlaps(stage_path, output.path), "ASSEMBLY_OUTPUT_OVERLAP")
            for mutation in (stage_path, output.path):
                need(
                    not overlaps(mutation, inputs_file.path)
                    and not overlaps(mutation, code),
                    "ASSEMBLY_INPUT_OVERLAP",
                )
            sources = module.prestage_sources(inputs["sources"])
            seen_names, seen_inodes, originals = (
                [inputs_file.path],
                {inputs_file.original[:2]},
                [],
            )
            for item in sources:
                name, relative = path(item["path"]), path(
                    item["relative"], relative=True
                )
                need(
                    not any(overlaps(name, old) for old in seen_names)
                    and not any(
                        overlaps(name, other)
                        for other in (stage_path, output.path, code)
                    ),
                    "ASSEMBLY_INPUT_OVERLAP",
                )
                source = Reader(
                    name,
                    module.prestage_limit(relative),
                    strict=True,
                    capture=module.prestage_public_json(relative)
                    or relative == "yubikey-transport",
                )
                held.append(source)
                need(source.original[:2] not in seen_inodes, "ASSEMBLY_INPUT_ALIAS")
                seen_names.append(name)
                seen_inodes.add(source.original[:2])
                need(
                    source.sha256 == item["sha256"] and source.size == item["size"],
                    "ASSEMBLY_SOURCE_CHANGED",
                )
                module.validate_prestage_public(relative, source.raw)
                originals.append((relative, source))
            names = {str(Path(relative).parent) for relative, _ in originals} - {"."}
            names |= {
                str(ancestor)
                for name in list(names)
                for ancestor in Path(name).parents
                if str(ancestor) != "."
            }
            need(
                all(
                    module.allowed_directory(name) and name != "launchd"
                    for name in names
                ),
                "ASSEMBLY_DIRECTORY",
            )
            parent = stack.enter_context(
                Directory(str(Path(stage_path).parent), strict=True)
            )
            leaf = Path(stage_path).name
            need(
                not any(
                    name.casefold() == leaf.casefold() for name in os.listdir(parent.fd)
                ),
                "ASSEMBLY_STAGE_EXISTS",
            )
            for source in held:
                source.current()
            parent.current()
            output.current()
            output.empty()
            # All plan/byte/identity checks above precede any output mutation.
            # A failure from here retains partial effects; no adoption/retry.
            started = True
            os.mkdir(leaf, mode=0o700, dir_fd=parent.fd)
            parent.current()
            os.fsync(parent.fd)
            stage = stack.enter_context(
                Directory(stage_path, strict=True, private=True)
            )
            directories = {"": stage}
            for relative in sorted(names, key=lambda name: (name.count("/"), name)):
                ancestor_name = str(Path(relative).parent)
                ancestor = directories.get(
                    "" if ancestor_name == "." else ancestor_name
                )
                need(ancestor is not None, "ASSEMBLY_DIRECTORY")
                ancestor.current()
                os.mkdir(Path(relative).name, mode=0o700, dir_fd=ancestor.fd)
                ancestor.current()
                os.fsync(ancestor.fd)
                directories[relative] = stack.enter_context(
                    Directory(stage.path + "/" + relative, strict=True, private=True)
                )
            copied, observations = [], {}
            for relative, source in originals:
                directory = directories[
                    (
                        ""
                        if str(Path(relative).parent) == "."
                        else str(Path(relative).parent)
                    )
                ]
                executable = (
                    relative.startswith("bin/") or "/Contents/MacOS/" in relative
                )
                record = copy_public(source, directory, Path(relative).name, executable)
                copied.append(
                    {
                        "relative": relative,
                        "sha256": record["sha256"],
                        "size": record["size"],
                    }
                )
                observations[relative] = record["observed"]
            sums = b"".join(
                (item["sha256"] + "  " + item["relative"] + "\n").encode("ascii")
                for item in copied
            )
            checksum = stage.write("SHA256SUMS", sums)
            copied.append(
                {
                    "relative": "SHA256SUMS",
                    "sha256": checksum["sha256"],
                    "size": checksum["size"],
                }
            )
            with Reader(checksum["path"], FRAME, strict=True, capture=False) as checked:
                need(
                    checked.sha256 == checksum["sha256"]
                    and checked.size == checksum["size"],
                    "ASSEMBLY_COPY_CHANGED",
                )
                observations["SHA256SUMS"] = checked.original
            prestage_current(held, directories, observations)
            parent.current()
            output.current()
            receipt = {
                "version": 1,
                "kind": "mcpmac-dedicated-birth-prestage-result",
                "data_only": True,
                "qualified": False,
                "external_provenance": "UNKNOWN",
                "native_signature_admission": "UNPERFORMED",
                "checksum_coverage": "PRESTAGE_ONLY",
                "rendered_files_covered": False,
                "stage_root": stage_path,
                "inputs": inputs_file.record(),
                "inventory_module": module_record,
                "files": sorted(copied, key=lambda item: item["relative"]),
                "file_count": len(copied),
            }
            output.write("assembly.json", encoded(receipt))
            prestage_current(held, directories, observations)
            parent.current()
            output.current()
            return 0
    except (Exception, KeyboardInterrupt) as error:
        reason = (
            str(error) if isinstance(error, Refusal) else "ASSEMBLY_INPUT_OR_IO_REFUSED"
        )
        if module is not None and isinstance(error, module.Refusal):
            reason = str(error)
            need(
                re.fullmatch("[A-Z0-9_]{1,160}", reason), "ASSEMBLY_VALIDATION_REFUSED"
            )
        if (
            started
            or isinstance(error, Refusal)
            or module is not None
            and isinstance(error, module.Refusal)
        ):
            raise Refusal(
                reason,
                {
                    "assembly_started": started,
                    "outputs_may_be_partial": started,
                    "rollback": "NONE",
                },
            ) from None
        raise
    finally:
        for source in reversed(held):
            source.close()


class Child:
    """Actual nonblocking pipes; exactly one immutable queued command frame."""

    def __init__(self, argv):
        pairs, self.process, self.selector = [], None, selectors.DefaultSelector()
        self.buffers = {"stdout": bytearray(), "stderr": bytearray()}
        self.hashes = {name: hashlib.sha256() for name in self.buffers}
        self.counts = {name: 0 for name in self.buffers}
        self.frames, self.eof = [], set()
        self.raw_frames, self.frame_records = [], []
        self.command, self.offset, self.attempted, self.complete = None, 0, False, False
        self.command_until = None
        self.write_fd, self.read_fds = None, {}
        try:
            for _ in range(3):
                pair = os.pipe()
                pairs.append(pair)
                for fd in pair:
                    os.set_blocking(fd, False)
            (child_in, parent_in), (parent_out, child_out), (parent_err, child_err) = (
                pairs
            )
            self.process = subprocess.Popen(
                argv,
                stdin=child_in,
                stdout=child_out,
                stderr=child_err,
                close_fds=True,
                env={"PATH": "/usr/bin:/bin", "LANG": "C"},
                start_new_session=True,
            )
            self.write_fd = parent_in
            self.read_fds = {"stdout": parent_out, "stderr": parent_err}
            for name, fd in self.read_fds.items():
                self.selector.register(fd, selectors.EVENT_READ, name)
            for fd in (child_in, child_out, child_err):
                os.close(fd)
        except BaseException:
            owned = {self.write_fd, *self.read_fds.values()}
            for pair in pairs:
                for fd in pair:
                    if fd not in owned:
                        try:
                            os.close(fd)
                        except OSError:
                            pass
            self.close()
            raise

    def queue(self, raw, until):
        need(self.command is None and not self.attempted, "ONE_COMMAND_ONLY")
        need(
            0 < len(raw) <= COMMAND and raw.endswith(b"\n") and raw.count(b"\n") == 1,
            "COMMAND_BOUND",
        )
        self.command = bytes(raw)
        self.command_until = until
        self.selector.register(self.write_fd, selectors.EVENT_WRITE, "stdin")

    def poll(self, until):
        remaining = (until - time.monotonic_ns()) / 10**9
        need(remaining > 0, "CONTROLLER_TIMEOUT")
        for key, _ in self.selector.select(min(remaining, 0.05)):
            name, fd = key.data, key.fd
            if name == "stdin":
                need(time.monotonic_ns() < self.command_until, "SETUP_EXPIRED")
                # Latch BEFORE first attempted write, including EAGAIN/EINTR.
                self.attempted = True
                try:
                    count = os.write(fd, self.command[self.offset :])
                except (BlockingIOError, InterruptedError):
                    continue
                need(count > 0, "COMMAND_WRITE")
                self.offset += count
                if self.offset == len(self.command):
                    self.complete = True
                    self.selector.unregister(fd)
                    os.close(fd)
                    self.write_fd = None
                need(time.monotonic_ns() < self.command_until, "SETUP_EXPIRED")
                continue
            try:
                raw = os.read(fd, 65536)
            except (BlockingIOError, InterruptedError):
                continue
            if not raw:
                self.selector.unregister(fd)
                self.eof.add(name)
                need(name != "stdout" or not self.buffers[name], "PARTIAL_FRAME_EOF")
                continue
            self.counts[name] += len(raw)
            self.hashes[name].update(raw)
            need(
                self.counts[name] <= (2 * FRAME if name == "stdout" else STDERR),
                "CHILD_OUTPUT_BOUND",
            )
            if name == "stderr":
                continue  # Hash/count only. Never dump arbitrary child stderr.
            self.buffers[name].extend(raw)
            while b"\n" in self.buffers[name]:
                line, _, rest = self.buffers[name].partition(b"\n")
                need(len(line) + 1 <= FRAME, "FRAME_BOUND")
                need(len(self.raw_frames) < 2, "FRAME_COUNT")
                original = bytes(line) + b"\n"
                self.raw_frames.append(original)
                self.frame_records.append(
                    {"bytes": len(original), "sha256": digest(original)}
                )
                self.frames.append(loads(bytes(line)))
                self.buffers[name] = bytearray(rest)
                need(len(self.frames) <= 2, "FRAME_COUNT")
            need(len(self.buffers[name]) < FRAME, "FRAME_BOUND")
        need(time.monotonic_ns() < until, "CONTROLLER_TIMEOUT")

    def close(self):
        failure = None
        try:
            if self.process is not None and self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=1)
        except (Exception, KeyboardInterrupt):
            failure = "CHILD_CLEANUP_REFUSED_OR_UNKNOWN"
        finally:
            self.selector.close()
            for fd in [self.write_fd, *self.read_fds.values()]:
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        failure = "CHILD_CLEANUP_REFUSED_OR_UNKNOWN"
            self.write_fd, self.read_fds = None, {}
        return failure


def challenge(value):
    fields(
        value,
        {
            "version",
            "kind",
            "target_id",
            "root",
            "descriptor_path",
            "descriptor_utf8",
            "descriptor_sha256",
            "setup_input_wait_seconds",
            "data_only",
            "runtime_readiness",
            "qualified",
        },
    )
    need(
        type(value["version"]) is int
        and value["version"] == 1
        and value["kind"] == "mcpmac-dedicated-birth-public-challenge"
        and value["setup_input_wait_seconds"] == 900
        and type(value["setup_input_wait_seconds"]) is int
        and value["data_only"] is True
        and value["qualified"] is False
        and value["runtime_readiness"] == "UNKNOWN",
        "CHALLENGE_SCHEMA",
    )
    root = path(value["root"])
    token = Path(root).name
    need(
        re.fullmatch(r"[0-9a-f]{32}", token) is not None
        and value["target_id"] == "ykft-" + token
        and path(value["descriptor_path"]) == root + "/config/deployment.json",
        "CHALLENGE_SCOPE",
    )
    need(isinstance(value["descriptor_utf8"], str), "CHALLENGE_DESCRIPTOR")
    raw = value["descriptor_utf8"].encode()
    need(
        0 < len(raw) <= 65536
        and lower_hash(value["descriptor_sha256"])
        and digest(raw) == value["descriptor_sha256"],
        "CHALLENGE_DESCRIPTOR_HASH",
    )
    target = loads(raw, 65536)
    need(
        target.get("target_id") == value["target_id"]
        and target.get("profile") == "L2"
        and target.get("role") == "dedicated-test"
        and target.get("signing_identity_mode") == "local-pins"
        and target.get("broker") is None
        and target.get("shared_read_only_inputs") == [],
        "CHALLENGE_TARGET",
    )
    layout = target.get("layout")
    need(isinstance(layout, dict), "CHALLENGE_LAYOUT")
    need(
        layout.get("launchd_namespace") == "com.enterprise.enclave.ykft.n" + token
        and layout.get("mach_service")
        == "com.enterprise.enclave.ykft.n" + token + ".exception",
        "CHALLENGE_NAMESPACE",
    )
    for key in (
        "binary_dir",
        "custody_bundle",
        "sandbox_dir",
        "socket_root",
        "state_root",
        "audit_root",
        "cas_store_root",
        "staging_root",
        "support_root",
    ):
        beneath(path(layout.get(key)), root)
    for key in (
        "authority_config",
        "expected_artifacts_manifest",
        "codesign_pins_file",
    ):
        beneath(path(target.get(key)), root)
    return raw, target


def terminal(value):
    fields(
        value,
        {
            "version",
            "kind",
            "status",
            "stage",
            "error",
            "boundary_error_count",
            "boundary_errors",
            "final_errors",
            "progress",
            "effects",
            "owner_lifetime",
            "exit_behavior",
            "runtime_readiness",
            "runtime_pin_provenance_verified",
            "qualified",
        },
    )
    need(
        type(value["version"]) is int
        and value["version"] == 1
        and value["kind"] == "mcpmac-dedicated-birth-session-result"
        and value["status"] in {"refused", "startup_exclusion_released"}
        and isinstance(value["stage"], str)
        and re.fullmatch("[a-z_]{1,96}", value["stage"]),
        "TERMINAL_SCHEMA",
    )
    need(
        value["runtime_readiness"] == "UNKNOWN"
        and value["runtime_pin_provenance_verified"] is False
        and value["qualified"] is False
        and value["owner_lifetime"]
        == "ACTUAL_OWNERS_RETAINED_THROUGH_TERMINAL_OUTPUT_ATTEMPT"
        and value["exit_behavior"]
        == "TERMINAL_TEARDOWN_CLOSES_DESCRIPTORS_NO_ROLLBACK_OR_CONTINUING_INHIBITION_CLAIM",
        "TERMINAL_CLAIM",
    )
    fields(value["effects"], EFFECTS)
    need(all(type(v) is bool for v in value["effects"].values()), "TERMINAL_EFFECTS")
    need(
        isinstance(value["boundary_errors"], list)
        and isinstance(value["final_errors"], list)
        and type(value["boundary_error_count"]) is int
        and value["boundary_error_count"] == len(value["boundary_errors"]),
        "TERMINAL_ERRORS",
    )
    for error in [value["error"], *value["boundary_errors"], *value["final_errors"]]:
        if error is None:
            continue
        fields(error, {"errno", "reason"})
        need(
            error["errno"] in ERRNOS
            and isinstance(error["reason"], str)
            and re.fullmatch("[A-Z0-9_]{1,160}", error["reason"]),
            "TERMINAL_ERROR",
        )
    need(
        all(
            isinstance(v, dict)
            for v in value["boundary_errors"] + value["final_errors"]
        ),
        "TERMINAL_ERRORS",
    )
    progress = value["progress"]
    if progress is not None:
        fields(progress, PROGRESS)
        # Public path progress only; no extension/body accepted into receipts.
        for key in (
            "attempted",
            "created_directories",
            "created_files",
            "existing_names",
            "synced",
        ):
            need(
                isinstance(progress[key], list) and len(progress[key]) <= 4096,
                "TERMINAL_PROGRESS",
            )
            for name in progress[key]:
                path(name)
        for key in ("root", "descriptor"):
            if progress[key] is not None:
                path(progress[key])
        need(
            isinstance(progress["operation"], str)
            and re.fullmatch("[a-z_]{1,96}", progress["operation"]),
            "TERMINAL_PROGRESS",
        )
        for key in ("pending_descriptor_sha256", "pending_inventory_sha256"):
            need(
                progress[key] is None or lower_hash(progress[key]), "TERMINAL_PROGRESS"
            )
        need(
            progress["target_id"] is None
            or re.fullmatch("ykft-[0-9a-f]{32}", progress["target_id"]),
            "TERMINAL_PROGRESS",
        )
        for key in PROGRESS - {
            "operation",
            "root",
            "descriptor",
            "target_id",
            "attempted",
            "created_directories",
            "created_files",
            "existing_names",
            "synced",
            "pending_descriptor_sha256",
            "pending_inventory_sha256",
        }:
            need(type(progress[key]) is bool, "TERMINAL_PROGRESS")
    success = value["status"] == "startup_exclusion_released"
    need(
        (
            success
            and value["error"] is None
            and value["stage"] == "release"
            and value["progress"] is None
            and value["boundary_error_count"] == 0
            and not value["boundary_errors"]
            and not value["final_errors"]
            and all(value["effects"].values())
        )
        or (not success and value["error"] is not None),
        "TERMINAL_STATUS",
    )
    return value


def validate_pickup(value, public):
    fields(
        value,
        {
            "version",
            "kind",
            "target_id",
            "descriptor_sha256",
            "package_root",
            "initial_sources",
            "remaining_staged_sources",
            "software_release_config",
            "operator_runtime_pin_record",
        },
    )
    need(
        type(value["version"]) is int
        and value["version"] == 1
        and value["kind"] == "mcpmac-dedicated-birth-public-inputs"
        and value["target_id"] == public["target_id"]
        and value["descriptor_sha256"] == public["descriptor_sha256"],
        "PICKUP_SCOPE",
    )
    package = path(value["package_root"])
    need(not overlaps(package, public["root"]), "PICKUP_EXTERNAL")
    initial, staged = value["initial_sources"], value["remaining_staged_sources"]
    need(
        isinstance(initial, list)
        and len(initial) == 7
        and isinstance(staged, list)
        and 1 <= len(staged) <= 128,
        "PICKUP_COUNT",
    )
    roles, names, relatives, totals = set(), [], set(), {True: 0, False: 0}
    for item, first in [(v, True) for v in initial] + [(v, False) for v in staged]:
        fields(item, {"role" if first else "relative", "path", "sha256", "size"})
        name = path(item["path"])
        beneath(name, package)
        need(not any(overlaps(name, old) for old in names), "PICKUP_ALIAS")
        names.append(name)
        need(
            lower_hash(item["sha256"])
            and type(item["size"]) is int
            and 0 < item["size"] <= 512 * 1024**2,
            "PICKUP_EXPECTATION",
        )
        # These are the actual TWO independent source owners' bounds; do not
        # silently subtract control-file bytes from the artifact-tree budget.
        totals[first] += item["size"]
        need(totals[first] <= 2 * 1024**3, "PICKUP_TOTAL")
        if first:
            role = item["role"]
            need(
                isinstance(role, str) and role in SEVEN_ROLES and role not in roles,
                "PICKUP_ROLES",
            )
            roles.add(role)
            cap = ROLE_CAP.get(role, FRAME)
            need(item["size"] <= cap, "PICKUP_ROLE_BOUND")
        else:
            relative = path(item["relative"], relative=True)
            need(
                relative.lower() != "codesign-pins.json"
                and relative.lower() not in relatives,
                "PICKUP_STAGED_ALIAS",
            )
            relatives.add(relative.lower())
    need(roles == SEVEN_ROLES, "PICKUP_ROLES")
    for key in ("software_release_config", "operator_runtime_pin_record"):
        need(not overlaps(path(value[key]), public["root"]), "PICKUP_APPROVAL_EXTERNAL")
    return value


def read_exchange(directory, held):
    public_file = Reader(directory.path + "/challenge.json", FRAME, strict=True)
    held.append(public_file)
    public = loads(public_file.raw)
    descriptor, target = challenge(public)
    copy = Reader(directory.path + "/descriptor.json", 65536, strict=True)
    held.append(copy)
    need(copy.raw == descriptor, "EXCHANGE_DESCRIPTOR")
    meta_file = Reader(directory.path + "/controller.json", 16384, strict=True)
    held.append(meta_file)
    meta = loads(meta_file.raw)
    fields(
        meta,
        {
            "version",
            "kind",
            "binary",
            "binary_sha256",
            "binary_size",
            "target_id",
            "descriptor_sha256",
            "setup_deadline_monotonic_ns",
        },
    )
    need(
        type(meta["version"]) is int
        and meta["version"] == 1
        and meta["kind"] == "mcpmac-dedicated-birth-controller"
        and meta["target_id"] == public["target_id"]
        and meta["descriptor_sha256"] == public["descriptor_sha256"]
        and lower_hash(meta["binary_sha256"])
        and type(meta["binary_size"]) is int
        and meta["binary_size"] > 0
        and type(meta["setup_deadline_monotonic_ns"]) is int,
        "EXCHANGE_METADATA",
    )
    path(meta["binary"])
    directory.current()
    return public, target, meta


def command_value(value):
    need(
        isinstance(value, dict) and value.get("op") in {"continue", "cancel"},
        "COMMAND_SCHEMA",
    )
    fields(
        value,
        (
            {"version", "op", "input_manifest"}
            if value["op"] == "continue"
            else {"version", "op"}
        ),
    )
    need(type(value["version"]) is int and value["version"] == 1, "COMMAND_VERSION")
    if value["op"] == "continue":
        path(value["input_manifest"])
    return value


def terminal_summary(value):
    """Bounded VALIDATED metadata; every full error/progress byte stays separate."""
    return {
        key: value[key]
        for key in (
            "version",
            "kind",
            "status",
            "stage",
            "error",
            "boundary_error_count",
            "effects",
            "runtime_readiness",
            "runtime_pin_provenance_verified",
            "qualified",
        )
    } | {
        "final_error_count": len(value["final_errors"]),
        "full_errors_and_progress": "ORIGINAL_TERMINAL_FRAME",
    }


def controller_result_bytes(report):
    """Separate result budget, with a closed fallback containing no input body."""
    try:
        return encoded(report, maximum=65536)
    except (Exception, KeyboardInterrupt):
        # Even a later accidental report extension must not erase all refusal
        # evidence. This fallback uses only bounded internally generated data.
        reason = report.get("controller_error")
        safe_reason = (
            reason
            if isinstance(reason, str) and re.fullmatch("[A-Z0-9_]{1,192}", reason)
            else None
        )
        return encoded(
            {
                "version": 1,
                "kind": "mcpmac-dedicated-birth-controller-result",
                "controller_error": "RESULT_ENCODING_REFUSED",
                "prior_controller_error": safe_reason,
                "terminal": None,
                "effects_known": False,
                "raw_frame_observations": report.get("raw_frame_observations", []),
                "terminal_frame": report.get("terminal_frame"),
                "runtime_readiness": "UNKNOWN",
                "qualified": False,
                "teardown": "NO_ROLLBACK_NO_CONTINUING_INHIBITION_CLAIM",
            },
            maximum=65536,
        )


def run_session(args):
    # This endpoint is established BEFORE spawn or challenge and never reset.
    setup_until = time.monotonic_ns() + SETUP_NS
    held, child, report, public, actual_terminal = [], None, None, None, None
    observed_terminal, observed_terminal_record, terminal_raw = None, None, None
    failure, terminal_seen_at, sent_at, handled = None, None, None, 0
    spawn_attempted = False
    with Directory(args.exchange_dir, strict=True, private=True) as exchange:
        exchange.empty()
        try:
            binary = Reader(args.binary, 512 * 1024**2, strict=True, capture=False)
            held.append(binary)
            need(
                os.fstat(binary.fd).st_mode & 0o111 != 0
                and not overlaps(args.binary, exchange.path),
                "BINARY_ROUTE",
            )
            argv = [
                binary.path,
                "--profile",
                "L2",
                "dedicated-birth-session",
                "--template",
                path(args.template),
                "--template-root",
                path(args.template_root),
                "--allocator-parent",
                path(args.allocator_parent),
            ]
            # Hashing and original currentness can consume the setup budget.
            # An expired controller must never start a fresh native allocation.
            binary.current()
            exchange.current()
            need(time.monotonic_ns() < setup_until, "SETUP_EXPIRED_BEFORE_SPAWN")
            spawn_attempted = True
            child = Child(argv)
            binary.current()
            while True:
                until = (
                    terminal_seen_at + EXIT_NS
                    if terminal_seen_at
                    else sent_at + FINISH_NS if sent_at else setup_until
                )
                child.poll(until)
                for value in child.frames[handled:]:
                    handled += 1
                    if value.get("kind") == "mcpmac-dedicated-birth-public-challenge":
                        need(
                            public is None and actual_terminal is None,
                            "CHALLENGE_ORDER",
                        )
                        raw, _ = challenge(value)
                        public = value
                        need(
                            not overlaps(exchange.path, public["root"])
                            and not overlaps(binary.path, public["root"]),
                            "EXCHANGE_EXTERNAL",
                        )
                        exchange.write("challenge.json", encoded(public))
                        exchange.write("descriptor.json", raw)
                        exchange.write(
                            "controller.json",
                            encoded(
                                {
                                    "version": 1,
                                    "kind": "mcpmac-dedicated-birth-controller",
                                    "binary": binary.path,
                                    "binary_sha256": binary.sha256,
                                    "binary_size": binary.size,
                                    "target_id": public["target_id"],
                                    "descriptor_sha256": public["descriptor_sha256"],
                                    "setup_deadline_monotonic_ns": setup_until,
                                }
                            ),
                        )
                    else:
                        need(actual_terminal is None, "TERMINAL_ORDER")
                        observed_terminal = value
                        observed_terminal_record = child.frame_records[handled - 1]
                        actual_terminal = terminal(value)
                        terminal_raw = child.raw_frames[handled - 1]
                        terminal_seen_at = time.monotonic_ns()
                if actual_terminal is not None:
                    need(handled == len(child.frames), "AFTER_TERMINAL_FRAME")
                    if child.process.poll() is not None and child.eof == {
                        "stdout",
                        "stderr",
                    }:
                        code = child.process.returncode
                        need(
                            code
                            == (
                                0
                                if actual_terminal["status"]
                                == "startup_exclusion_released"
                                else 3
                            ),
                            "TERMINAL_EXIT_MISMATCH",
                        )
                        need(
                            actual_terminal["status"] != "startup_exclusion_released"
                            or (
                                public is not None
                                and child.complete
                                and command_value(
                                    loads(child.command, COMMAND, wire=True)
                                )["op"]
                                == "continue"
                            ),
                            "SUCCESS_WITHOUT_CONTINUE",
                        )
                        break
                elif "stdout" in child.eof:
                    raise Refusal("TERMINAL_MISSING")
                elif public is not None and child.command is None:
                    exchange.current()
                    try:
                        decision = Reader(
                            exchange.path + "/command.json", COMMAND, strict=True
                        )
                    except FileNotFoundError:
                        continue
                    held.append(decision)
                    value = command_value(loads(decision.raw, COMMAND, wire=True))
                    if value["op"] == "continue":
                        pickup = Reader(value["input_manifest"], FRAME)
                        held.append(pickup)
                        validate_pickup(loads(pickup.raw, wire=True), public)
                    for source in held:
                        source.current()
                    need(time.monotonic_ns() < setup_until, "SETUP_EXPIRED")
                    child.queue(encoded(value), setup_until)
                    sent_at = time.monotonic_ns()
        except (Exception, KeyboardInterrupt) as error:
            failure = (
                str(error)
                if isinstance(error, Refusal)
                else (
                    "CONTROLLER_INTERRUPTED"
                    if isinstance(error, KeyboardInterrupt)
                    else "CONTROLLER_IO_REFUSED"
                )
            )
            # Only before ANY queued/attempted command can failure offer cancel.
            # A queued or short-written continue is never replaced/reconstructed.
            if (
                child is not None
                and public is not None
                and actual_terminal is None
                and child.command is None
                and not child.attempted
            ):
                try:
                    need(time.monotonic_ns() < setup_until, "SETUP_EXPIRED")
                    child.queue(encoded({"version": 1, "op": "cancel"}), setup_until)
                    cancel_until = min(setup_until, time.monotonic_ns() + EXIT_NS)
                    while time.monotonic_ns() < cancel_until:
                        child.poll(cancel_until)
                        for value in child.frames[handled:]:
                            handled += 1
                            if actual_terminal is None:
                                observed_terminal = value
                                observed_terminal_record = child.frame_records[
                                    handled - 1
                                ]
                                actual_terminal = terminal(value)
                                terminal_raw = child.raw_frames[handled - 1]
                        if child.process.poll() is not None and child.eof == {
                            "stdout",
                            "stderr",
                        }:
                            break
                except (Exception, KeyboardInterrupt):
                    pass  # Original controller failure and I/O uncertainty survive.
        finally:
            if child is not None:
                cleanup_error = None
                try:
                    cleanup_error = child.close()
                except (Exception, KeyboardInterrupt):
                    cleanup_error = "CHILD_CLEANUP_REFUSED_OR_UNKNOWN"
                finally:
                    failure = failure or cleanup_error
                    terminal_frame = None
                    if actual_terminal is not None:
                        terminal_frame = {
                            **observed_terminal_record,
                            "name": "terminal-frame.json",
                            "storage": "UNKNOWN",
                        }
                        try:
                            # ORIGINAL validated public bytes are <= native FRAME.
                            # No canonical expansion or result-envelope overflow.
                            exchange.write("terminal-frame.json", terminal_raw)
                            terminal_frame["storage"] = "WRITTEN_ORIGINAL_BYTES"
                        except (Exception, KeyboardInterrupt):
                            terminal_frame["storage"] = "REFUSED_OR_UNKNOWN"
                            failure = failure or "TERMINAL_ARTIFACT_REFUSED_OR_UNKNOWN"
                    report = {
                        "version": 1,
                        "kind": "mcpmac-dedicated-birth-controller-result",
                        "controller_error": failure,
                        "terminal": (
                            terminal_summary(actual_terminal)
                            if actual_terminal is not None
                            else None
                        ),
                        "terminal_frame": terminal_frame,
                        "raw_frame_observations": child.frame_records,
                        "rejected_terminal": (
                            {
                                "status": "REJECTED_UNTRUSTED",
                                "original_frame": observed_terminal_record,
                                "reported_effects": (
                                    observed_terminal.get("effects")
                                    if isinstance(observed_terminal, dict)
                                    and isinstance(
                                        observed_terminal.get("effects"), dict
                                    )
                                    and set(observed_terminal["effects"]) == EFFECTS
                                    and all(
                                        type(v) is bool
                                        for v in observed_terminal["effects"].values()
                                    )
                                    else None
                                ),
                            }
                            if observed_terminal is not None and actual_terminal is None
                            else None
                        ),
                        "child_exit_code": (
                            child.process.returncode if child.process else None
                        ),
                        "spawn_attempted": spawn_attempted,
                        "cleanup_error": cleanup_error,
                        "command_attempted": child.attempted,
                        "command_frame_complete": child.complete,
                        "stream_bytes": child.counts,
                        "stream_sha256": {
                            k: v.hexdigest() for k, v in child.hashes.items()
                        },
                        "runtime_readiness": "UNKNOWN",
                        "qualified": False,
                        "effects_known": actual_terminal is not None,
                        "teardown": "OWNED_PROCESS_ONLY_NO_ROLLBACK_NO_CONTINUING_INHIBITION_CLAIM",
                    }
            elif spawn_attempted:
                report = {
                    "version": 1,
                    "kind": "mcpmac-dedicated-birth-controller-result",
                    "controller_error": failure,
                    "spawn_attempted": True,
                    "child_exit_code": None,
                    "terminal": None,
                    "effects_known": False,
                    "cleanup_error": "CONSTRUCTOR_REFUSED_PROCESS_STATE_UNKNOWN",
                    "runtime_readiness": "UNKNOWN",
                    "qualified": False,
                    "teardown": "NO_ROLLBACK_NO_CONTINUING_INHIBITION_CLAIM",
                }
            for source in reversed(held):
                source.close()
        need(report is not None, failure or "SESSION_NOT_STARTED")
        raw_report = controller_result_bytes(report)
        exchange.write("result.json", raw_report)
        if loads(raw_report, 65536)["controller_error"] == "RESULT_ENCODING_REFUSED":
            return 3
        return (
            0
            if failure is None
            and actual_terminal
            and actual_terminal["status"] == "startup_exclusion_released"
            else 3
        )


def render(binary, descriptor, descriptor_copy, manifest, until):
    need(time.monotonic_ns() < until, "SETUP_EXPIRED")
    child, failure, files = None, None, None
    receipt = {
        "spawn_constructor_attempted": True,
        "exit_code": None,
        "cleanup_error": "PROCESS_STATE_UNKNOWN",
    }
    try:
        child = Child(
            [
                binary,
                "--profile",
                "L2",
                "dedicated-birth-render",
                "--descriptor",
                descriptor,
                "--descriptor-input",
                descriptor_copy,
                "--custody-manifest",
                manifest,
            ]
        )
        while child.process.poll() is None or child.eof != {"stdout", "stderr"}:
            child.poll(until)
        need(child.process.returncode == 0 and len(child.frames) == 1, "RENDER_PROCESS")
        value = child.frames[0]
        fields(value, {"version", "kind", "files", "data_only", "qualified"})
        need(
            type(value["version"]) is int
            and value["version"] == 1
            and value["kind"] == "mcpmac-dedicated-birth-public-rendering"
            and value["data_only"] is True
            and value["qualified"] is False,
            "RENDER_SCHEMA",
        )
        files = value["files"]
    except (Exception, KeyboardInterrupt) as error:
        failure = (
            str(error)
            if isinstance(error, Refusal)
            else "RENDER_PROCESS_REFUSED_OR_UNKNOWN"
        )
    finally:
        if child is not None:
            try:
                cleanup_error = child.close()
            except (Exception, KeyboardInterrupt):
                cleanup_error = "CHILD_CLEANUP_REFUSED_OR_UNKNOWN"
            receipt = {
                "spawn_constructor_attempted": True,
                "exit_code": child.process.returncode,
                "stream_bytes": child.counts,
                "stream_sha256": {k: v.hexdigest() for k, v in child.hashes.items()},
                "cleanup_error": cleanup_error,
            }
        receipt["failure_reason"] = failure
    if failure or receipt["cleanup_error"]:
        raise Refusal(failure or receipt["cleanup_error"], {"renderer": receipt})
    return files, receipt


def renderer_names(target):
    namespace = target["layout"]["launchd_namespace"]
    jobs = {
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
    }
    return (
        {"launchd/" + namespace + "." + suffix + ".plist" for suffix in jobs}
        | {
            "launchd/" + suffix + ".sb"
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
        | {"launchd/provision-accounts.sh", "launchd/enclave-daemon.entitlements"}
    )


def materialize(stage, target, files, until):
    need(
        isinstance(files, dict)
        and set(files) == renderer_names(target)
        and len(files) == 20,
        "RENDER_EXACT_FILE_SET",
    )
    need(
        all(isinstance(v, str) and v and v.isascii() for v in files.values())
        and sum(len(v) for v in files.values()) <= FRAME,
        "RENDER_BODY_BOUND",
    )
    stage.current()
    need(time.monotonic_ns() < until, "SETUP_EXPIRED")
    os.mkdir(
        "launchd", mode=0o700, dir_fd=stage.fd
    )  # Refuse every prior name, including an empty directory.
    stage.current()
    os.fsync(stage.fd)
    with Directory(stage.path + "/launchd", strict=True, private=True) as output:
        records = []
        for relative, body in sorted(files.items()):
            need(time.monotonic_ns() < until, "SETUP_EXPIRED")
            records.append(output.write(relative.split("/")[1], body.encode()))
            need(time.monotonic_ns() < until, "SETUP_EXPIRED")
        output.current()
        return records


def prepare(args):
    held = []
    try:
        with Directory(
            args.exchange_dir, strict=True, private=True
        ) as exchange, Directory(args.output_dir, strict=True, private=True) as output:
            output.empty()
            public, target, meta = read_exchange(exchange, held)
            need(
                time.monotonic_ns() < meta["setup_deadline_monotonic_ns"],
                "SETUP_EXPIRED",
            )
            inputs_file = Reader(args.inputs, FRAME)
            held.append(inputs_file)
            inputs = loads(inputs_file.raw, wire=True)
            fields(
                inputs,
                {
                    "version",
                    "kind",
                    "package_root",
                    "stage_root",
                    "initial_sources",
                    "software_release_config",
                    "operator_runtime_pin_record",
                },
            )
            need(
                type(inputs["version"]) is int
                and inputs["version"] == 1
                and inputs["kind"] == "mcpmac-dedicated-birth-preparation-inputs",
                "PREPARATION_SCHEMA",
            )
            package, stage_path = path(inputs["package_root"]), path(
                inputs["stage_root"]
            )
            beneath(stage_path, package)
            beneath(output.path, package)
            need(
                not overlaps(package, public["root"])
                and not overlaps(stage_path, output.path),
                "PREPARATION_EXTERNAL",
            )
            for mutation in (stage_path, output.path):
                for original in (
                    exchange.path,
                    str(Path(path(args.source_snapshot)).parent),
                    path(meta["binary"]),
                    str(Path(__file__).absolute()),
                ):
                    need(not overlaps(mutation, original), "MUTATION_INPUT_OVERLAP")
            module, module_record = inventory_module()
            binary = Reader(meta["binary"], 512 * 1024**2, strict=True, capture=False)
            held.append(binary)
            need(
                binary.sha256 == meta["binary_sha256"]
                and binary.size == meta["binary_size"]
                and os.fstat(binary.fd).st_mode & 0o111 != 0,
                "RENDER_BINARY_CHANGED",
            )
            supplied = inputs["initial_sources"]
            need(isinstance(supplied, list) and len(supplied) == 5, "INITIAL_ROLE_SET")
            sources, seen_roles, seen_names, seen_inodes = [], set(), [], set()
            for item in supplied:
                fields(item, {"role", "path", "sha256", "size"})
                role = item["role"]
                need(
                    isinstance(role, str)
                    and role in FIVE_ROLES
                    and role not in seen_roles,
                    "INITIAL_ROLE_SET",
                )
                seen_roles.add(role)
                name = path(item["path"])
                beneath(name, package)
                need(
                    not overlaps(name, stage_path) and not overlaps(name, output.path),
                    "CONTROL_SOURCE_OVERLAP",
                )
                source = Reader(name, ROLE_CAP[role])
                held.append(source)
                need(
                    type(item["size"]) is int
                    and source.size == item["size"]
                    and source.sha256 == item["sha256"],
                    "SUPPLIED_CONTROL_CHANGED",
                )
                need(
                    not any(overlaps(name, old) for old in seen_names)
                    and source.original[:2] not in seen_inodes,
                    "CONTROL_ALIAS",
                )
                seen_names.append(name)
                seen_inodes.add(source.original[:2])
                sources.append(source.record(role))
            need(seen_roles == FIVE_ROLES, "INITIAL_ROLE_SET")
            for key in ("software_release_config", "operator_runtime_pin_record"):
                name = path(inputs[key])
                need(
                    not overlaps(name, public["root"])
                    and not overlaps(name, stage_path)
                    and not overlaps(name, output.path),
                    "APPROVAL_SOURCE_OVERLAP",
                )
                source = Reader(name, 65536)
                held.append(source)
                need(
                    not any(overlaps(name, old) for old in seen_names)
                    and source.original[:2] not in seen_inodes,
                    "APPROVAL_ALIAS",
                )
                seen_names.append(name)
                seen_inodes.add(source.original[:2])
            with Directory(stage_path, strict=True, private=True) as stage:
                for source in held:
                    source.current()
                need(
                    time.monotonic_ns() < meta["setup_deadline_monotonic_ns"],
                    "SETUP_EXPIRED",
                )
                manifest = next(
                    v["path"] for v in sources if v["role"] == "custody_manifest"
                )
                files, renderer_receipt = render(
                    binary.path,
                    public["descriptor_path"],
                    exchange.path + "/descriptor.json",
                    manifest,
                    min(
                        meta["setup_deadline_monotonic_ns"],
                        time.monotonic_ns() + EXIT_NS,
                    ),
                )
                binary.current()
                for source in held:
                    source.current()
                stage.current()
                exchange.current()
                output.current()
                need(
                    time.monotonic_ns() < meta["setup_deadline_monotonic_ns"],
                    "SETUP_EXPIRED",
                )
                rendered_records = materialize(
                    stage, target, files, meta["setup_deadline_monotonic_ns"]
                )
                # ONE existing verified source/stage scan, then a PURE projection
                # of this exact returned object. Never call inventory twice.
                need(
                    time.monotonic_ns() < meta["setup_deadline_monotonic_ns"],
                    "SETUP_EXPIRED",
                )
                try:
                    observed = module.inventory(
                        exchange.path + "/descriptor.json",
                        path(args.source_snapshot),
                        package_root=stage_path,
                    )
                except module.Refusal as error:
                    reason = str(error)
                    need(re.fullmatch("[A-Z0-9_]{1,160}", reason), "INVENTORY_REFUSED")
                    raise Refusal("INVENTORY_" + reason) from None
                need(
                    time.monotonic_ns() < meta["setup_deadline_monotonic_ns"],
                    "SETUP_EXPIRED",
                )
                projected = module.staged_source_list(observed, stage_path)
                need(
                    observed["target_id"] == public["target_id"]
                    and observed["deployment_config_sha256"]
                    == public["descriptor_sha256"]
                    and observed["external_provenance"] == "UNKNOWN",
                    "INVENTORY_SCOPE",
                )
                pins = [v for v in projected if v["relative"] == "codesign-pins.json"]
                need(len(pins) == 1, "PINS_SET")
                initial_pins = {
                    key: value for key, value in pins[0].items() if key != "relative"
                }
                initial_pins["role"] = "staged_pins"
                sources.append(initial_pins)
                for source in held:
                    source.current()
                stage.current()
                exchange.current()
                output.current()
                need(
                    time.monotonic_ns() < meta["setup_deadline_monotonic_ns"],
                    "SETUP_EXPIRED",
                )
                inventory_record = output.write("inventory.json", encoded(observed))
                inventory_record["role"] = "inventory"
                need(
                    time.monotonic_ns() < meta["setup_deadline_monotonic_ns"],
                    "SETUP_EXPIRED",
                )
                pickup = {
                    "version": 1,
                    "kind": "mcpmac-dedicated-birth-public-inputs",
                    "target_id": public["target_id"],
                    "descriptor_sha256": public["descriptor_sha256"],
                    "package_root": package,
                    "initial_sources": [inventory_record, *sources],
                    "remaining_staged_sources": [
                        v for v in projected if v["relative"] != "codesign-pins.json"
                    ],
                    "software_release_config": inputs["software_release_config"],
                    "operator_runtime_pin_record": inputs[
                        "operator_runtime_pin_record"
                    ],
                }
                validate_pickup(pickup, public)
                for source in held:
                    source.current()
                need(
                    time.monotonic_ns() < meta["setup_deadline_monotonic_ns"],
                    "SETUP_EXPIRED",
                )
                output.write("pickup.json", encoded(pickup))
                need(
                    time.monotonic_ns() < meta["setup_deadline_monotonic_ns"],
                    "SETUP_EXPIRED",
                )
                output.write(
                    "preparation.json",
                    encoded(
                        {
                            "version": 1,
                            "kind": "mcpmac-dedicated-birth-preparation-result",
                            "data_only": True,
                            "qualified": False,
                            "external_provenance": "UNKNOWN",
                            "inventory_module": module_record,
                            "inputs": inputs_file.record(),
                            "source_snapshot": path(args.source_snapshot),
                            "renderer_file_count": 20,
                            "source_snapshot_sha256": observed[
                                "source_manifest_sha256"
                            ],
                            "source_git_commit": observed["source_git_commit"],
                            "rendered_files": rendered_records,
                            "renderer": renderer_receipt,
                            "inventory_sha256": inventory_record["sha256"],
                            "pickup_sha256": digest(encoded(pickup)),
                        }
                    ),
                )
                for source in held:
                    source.current()
                stage.current()
                output.current()
                exchange.current()
                need(
                    time.monotonic_ns() < meta["setup_deadline_monotonic_ns"],
                    "SETUP_EXPIRED",
                )
                return 0
    finally:
        for source in reversed(held):
            source.close()


def decide(args):
    held = []
    try:
        with Directory(args.exchange_dir, strict=True, private=True) as exchange:
            public, _, meta = read_exchange(exchange, held)
            need(
                time.monotonic_ns() < meta["setup_deadline_monotonic_ns"],
                "SETUP_EXPIRED",
            )
            value = {"version": 1, "op": "cancel"}
            if args.pickup:
                pickup = Reader(args.pickup, FRAME)
                held.append(pickup)
                validate_pickup(loads(pickup.raw, wire=True), public)
                value = {"version": 1, "op": "continue", "input_manifest": pickup.path}
            for source in held:
                source.current()
            need(
                time.monotonic_ns() < meta["setup_deadline_monotonic_ns"],
                "SETUP_EXPIRED",
            )
            exchange.write("command.json", encoded(value))
            return 0
    finally:
        for source in reversed(held):
            source.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    sub = parser.add_subparsers(dest="operation", required=True)
    assembly = sub.add_parser("assemble-stage", allow_abbrev=False)
    for name in ("inputs", "output-dir"):
        assembly.add_argument("--" + name, required=True)
    run = sub.add_parser("run", allow_abbrev=False)
    for name in (
        "binary",
        "template",
        "template-root",
        "allocator-parent",
        "exchange-dir",
    ):
        run.add_argument("--" + name, required=True)
    prep = sub.add_parser("prepare", allow_abbrev=False)
    for name in ("exchange-dir", "inputs", "source-snapshot", "output-dir"):
        prep.add_argument("--" + name, required=True)
    decision = sub.add_parser("decide", allow_abbrev=False)
    decision.add_argument("--exchange-dir", required=True)
    group = decision.add_mutually_exclusive_group(required=True)
    group.add_argument("--pickup")
    group.add_argument("--cancel", action="store_true")
    args = parser.parse_args(argv)
    try:
        return {
            "assemble-stage": assemble_stage,
            "run": run_session,
            "prepare": prepare,
            "decide": decide,
        }[args.operation](args)
    except (Exception, KeyboardInterrupt) as error:
        reason = (
            str(error)
            if isinstance(error, Refusal)
            else (
                "CONTROLLER_INTERRUPTED"
                if isinstance(error, KeyboardInterrupt)
                else "INPUT_OR_IO_REFUSED"
            )
        )
        if args.operation == "prepare":
            try:
                with Directory(args.output_dir, strict=True, private=True) as output:
                    output.write(
                        "preparation-refusal.json",
                        encoded(
                            {
                                "version": 1,
                                "kind": "mcpmac-dedicated-birth-preparation-refusal",
                                "reason": reason,
                                "outputs_may_be_partial": True,
                                "qualified": False,
                                "external_provenance": "UNKNOWN",
                                "observed_errors": (
                                    error.evidence
                                    if isinstance(error, Refusal)
                                    else None
                                ),
                                "supersedes_any_preparation_result": True,
                                "rollback": "NONE",
                            }
                        ),
                    )
            except (Exception, KeyboardInterrupt):
                pass  # Never replace originals or hide the primary refusal.
        if (
            args.operation == "assemble-stage"
            and isinstance(error, Refusal)
            and error.evidence
            and error.evidence.get("assembly_started")
        ):
            try:
                with Directory(args.output_dir, strict=True, private=True) as output:
                    output.write(
                        "assembly-refusal.json",
                        encoded(
                            {
                                "version": 1,
                                "kind": "mcpmac-dedicated-birth-prestage-refusal",
                                "reason": reason,
                                "outputs_may_be_partial": True,
                                "qualified": False,
                                "external_provenance": "UNKNOWN",
                                "supersedes_any_assembly_result": True,
                                "rollback": "NONE",
                            }
                        ),
                    )
            except (Exception, KeyboardInterrupt):
                pass
        print("DEDICATED_BIRTH_CONTROLLER_REFUSED: " + reason, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
