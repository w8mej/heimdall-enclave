"""Public transport/data tests only; no native owner or genuine authority.

Full protected filesystem routes require the coordinator's actual private-root
Python runner. Outside it they are SKIPPED, never reported as native acceptance.
"""

import argparse
import importlib.util
import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "birth_controller", REPO / "scripts/dedicated-birth-controller.py"
)
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


def public_challenge(root="/state/public-fixture/" + "12" * 16):
    token = Path(root).name
    target = {
        "version": 1,
        "target_id": "ykft-" + token,
        "role": "dedicated-test",
        "profile": "L2",
        "signing_identity_mode": "local-pins",
        "broker": None,
        "shared_read_only_inputs": [],
    }
    target["layout"] = {
        name: root + "/" + name
        for name in (
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
    }
    target["layout"].update(
        launchd_namespace="com.enterprise.enclave.ykft.n" + token,
        mach_service="com.enterprise.enclave.ykft.n" + token + ".exception",
    )
    for key in (
        "authority_config",
        "expected_artifacts_manifest",
        "codesign_pins_file",
    ):
        target[key] = root + "/config/" + key + ".json"
    raw = C.encoded(target)
    value = {
        "version": 1,
        "kind": "depot-dedicated-birth-public-challenge",
        "target_id": target["target_id"],
        "root": root,
        "descriptor_path": root + "/config/deployment.json",
        "descriptor_utf8": raw.decode(),
        "descriptor_sha256": C.digest(raw),
        "setup_input_wait_seconds": 900,
        "data_only": True,
        "runtime_readiness": "UNKNOWN",
        "qualified": False,
    }
    return value, target


def refused_terminal():
    return {
        "version": 1,
        "kind": "depot-dedicated-birth-session-result",
        "status": "refused",
        "stage": "fixture",
        "error": {"errno": "EACCES", "reason": "FIXTURE_PUBLIC_TRANSPORT_ONLY"},
        "boundary_error_count": 0,
        "boundary_errors": [],
        "final_errors": [],
        "progress": None,
        "effects": {k: False for k in C.EFFECTS},
        "owner_lifetime": "ACTUAL_OWNERS_RETAINED_THROUGH_TERMINAL_OUTPUT_ATTEMPT",
        "exit_behavior": "TERMINAL_TEARDOWN_CLOSES_DESCRIPTORS_NO_ROLLBACK_OR_CONTINUING_INHIBITION_CLAIM",
        "runtime_readiness": "UNKNOWN",
        "runtime_pin_provenance_verified": False,
        "qualified": False,
    }


WRITE = """
def write(fd, raw):
    offset = 0
    while offset < len(raw):
        try:
            offset += os.write(fd, raw[offset:offset+4096])
        except BlockingIOError:
            select.select([], [fd], [], 0.1)
"""


class OrdinaryPublicPrimitiveTests(unittest.TestCase):
    def collect(self, code, command=None):
        child = C.Child([sys.executable, "-c", code])
        try:
            until = time.monotonic_ns() + 5 * 10**9
            if command:
                child.queue(command, until)
            while child.process.poll() is None or child.eof != {"stdout", "stderr"}:
                child.poll(until)
            return child.frames, child.counts, child.attempted, child.complete
        finally:
            child.close()

    def test_actual_inherited_nonblocking_pipes_fragmented_frames_and_single_command(
        self,
    ):
        code = (
            """import fcntl,json,os,select,stat,time
assert all(fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_NONBLOCK for fd in (0,1))
assert all(stat.S_ISFIFO(os.fstat(fd).st_mode) for fd in (0,1))
"""
            + WRITE
            + """
write(1,b'{"fi');time.sleep(0.01);write(1,b'xture":true}\\n')
raw=b''
while b'\\n' not in raw:
    select.select([0],[],[],2)
    try: raw+=os.read(0,4096)
    except BlockingIOError: pass
assert raw==b'{"op":"cancel","version":1}\\n'
write(1,b'{"one_command":true}\\n')
"""
        )
        frames, _, attempted, complete = self.collect(
            code, C.encoded({"version": 1, "op": "cancel"})
        )
        self.assertEqual(frames, [{"fixture": True}, {"one_command": True}])
        self.assertTrue(attempted and complete)

    def test_actual_partial_eof_and_output_bound_refuse(self):
        for code, reason in [
            ("import os;os.write(1,b'{')", "PARTIAL_FRAME_EOF"),
            (
                "import os,select\n" + WRITE + "write(1,b'x'*(1024*1024+1))",
                "FRAME_BOUND",
            ),
        ]:
            with self.subTest(reason=reason), self.assertRaisesRegex(C.Refusal, reason):
                self.collect(code)

    def test_actual_stderr_is_bounded_and_never_added_as_json(self):
        frames, counts, _, _ = self.collect(
            "import os;os.write(2,b'PUBLIC-FIXTURE-STDERR');os.write(1,b'{}\\n')"
        )
        self.assertEqual(frames, [{}])
        self.assertEqual(counts["stderr"], 21)
        with self.assertRaisesRegex(C.Refusal, "CHILD_OUTPUT_BOUND"):
            self.collect("import os,select\n" + WRITE + "write(2,b'x'*65537)")

    def test_queued_frame_cannot_be_replaced_and_expired_endpoint_is_not_attempted(
        self,
    ):
        child = C.Child([sys.executable, "-c", "import time;time.sleep(1)"])
        try:
            child.queue(
                C.encoded(
                    {
                        "version": 1,
                        "op": "continue",
                        "input_manifest": "/state/public.json",
                    }
                ),
                time.monotonic_ns() - 1,
            )
            with self.assertRaisesRegex(C.Refusal, "SETUP_EXPIRED"):
                child.poll(time.monotonic_ns() + 10**9)
            self.assertFalse(child.attempted)
            with self.assertRaisesRegex(C.Refusal, "ONE_COMMAND_ONLY"):
                child.queue(
                    C.encoded({"version": 1, "op": "cancel"}),
                    time.monotonic_ns() + 10**9,
                )
        finally:
            child.close()

    def test_first_failed_write_latches_even_when_no_bytes_were_delivered(self):
        child = C.Child(
            [
                sys.executable,
                "-c",
                "import os,time;os.close(0);os.write(1,b'{}\\n');time.sleep(2)",
            ]
        )
        try:
            until = time.monotonic_ns() + 5 * 10**9
            while not child.frames:
                child.poll(until)
            child.queue(C.encoded({"version": 1, "op": "cancel"}), until)
            with self.assertRaises(BrokenPipeError):
                while True:
                    child.poll(until)
            self.assertTrue(child.attempted)
            self.assertFalse(child.complete)
            with self.assertRaisesRegex(C.Refusal, "ONE_COMMAND_ONLY"):
                child.queue(C.encoded({"version": 1, "op": "cancel"}), until)
        finally:
            child.close()

    def test_strict_schema_hash_scope_and_terminal_claim_refusals(self):
        value, _ = public_challenge()
        C.challenge(value)
        for change in (
            {"descriptor_sha256": "00" * 32},
            {"target_id": "old"},
            {"qualified": True},
            {"extra": True},
        ):
            changed = {**value, **change}
            with self.assertRaises(C.Refusal):
                C.challenge(changed)
        for raw in (
            b'{"version":1,"version":1}',
            b'{"x":NaN}',
            b'{"x":1.0}',
            b'{"op":"cancel","version":true}',
        ):
            with self.assertRaises(C.Refusal):
                C.command_value(C.loads(raw, wire=True))
        with self.assertRaisesRegex(C.Refusal, "WIRE_ESCAPES"):
            C.loads(b'{"x":"\\u0070"}', wire=True)
        report = refused_terminal()
        C.terminal(report)
        report["final_errors"] = [None]
        with self.assertRaises(C.Refusal):
            C.terminal(report)
        report = refused_terminal()
        report.update(status="startup_exclusion_released",
                      stage="release", error=None)
        with self.assertRaisesRegex(C.Refusal, "TERMINAL_STATUS"):
            C.terminal(report)
        report["effects"] = {k: True for k in C.EFFECTS}
        report["final_errors"] = [
            {"errno": "EIO", "reason": "PUBLIC_FIXTURE_FINAL_ERROR"}
        ]
        with self.assertRaisesRegex(C.Refusal, "TERMINAL_STATUS"):
            C.terminal(report)
        with self.assertRaisesRegex(C.Refusal, "EXTERNAL_CONTAINER"):
            C.beneath("/state/PACKAGE/source", "/state/package")


PRIVATE = os.environ.get("depot_PRIVATE_PYTHON_FIXTURE") == "/state/repo"


@unittest.skipUnless(
    PRIVATE, "requires coordinator actual protected /state/repo private Python fixture"
)
class ProtectedPublicFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(), 0)
        self.assertEqual(str(REPO), "/state/repo")
        # Validate actual ancestry, never a configurable product trust bypass.
        with C.Directory(str(REPO), strict=True):
            pass
        root = REPO / "target"
        root.mkdir(mode=0o700, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(
            prefix="public-birth-", dir=root)
        self.base = Path(self.temp.name)
        with C.Directory(str(self.base), strict=True, private=True):
            pass

    def tearDown(self):
        self.temp.cleanup()  # Synthetic public fixture outputs only.

    def mkdir(self, name):
        result = self.base / name
        result.mkdir(mode=0o700, parents=True)
        return result

    def put(self, name, raw, mode=0o600):
        name = Path(name)
        name.write_bytes(raw)
        name.chmod(mode)
        return name

    def fixture_binary(self, name, body):
        # Public protocol fixture, explicitly no native owner/authority model.
        return self.put(
            self.base / name,
            b"#!" + sys.executable.encode() + b"\n" + body.encode(),
            0o500,
        )

    def fixture_package(self):
        exchange = self.mkdir("exchange")
        package = self.mkdir("package")
        stage = self.mkdir("package/stage")
        output = self.mkdir("package/output")
        controls = self.mkdir("package/controls")
        self.mkdir("package/stage/bin")
        native = self.put(
            stage / "bin/depot-enclave",
            b"INERT PUBLIC NATIVE SOURCE FIXTURE, NEVER EXECUTED",
        )
        self.put(
            stage / "codesign-pins.json",
            C.encoded(
                {"v": 1, "pins": {"com.enterprise.enclave.ctl": ["ab" * 20]}}),
        )
        public, target = public_challenge(str(self.base / ("12" * 16)))
        files = {
            name: "PUBLIC RENDER PROTOCOL FIXTURE ONLY\n"
            for name in C.renderer_names(target)
        }
        binary = self.fixture_binary(
            "renderer-fixture",
            "import fcntl,json,os,select,sys\n"
            "assert sys.argv[1:4]==['--profile','L2','dedicated-birth-render']\n"
            "assert fcntl.fcntl(1,fcntl.F_GETFL)&os.O_NONBLOCK\n"
            + WRITE
            + "write(1,"
            + repr(
                C.encoded(
                    {
                        "version": 1,
                        "kind": "depot-dedicated-birth-public-rendering",
                        "data_only": True,
                        "qualified": False,
                        "files": files,
                    }
                )
            )
            + ")\n",
        )
        self.put(exchange / "challenge.json", C.encoded(public))
        self.put(exchange / "descriptor.json",
                 public["descriptor_utf8"].encode())
        meta = {
            "version": 1,
            "kind": "depot-dedicated-birth-controller",
            "binary": str(binary),
            "binary_sha256": C.digest(binary.read_bytes()),
            "binary_size": binary.stat().st_size,
            "target_id": public["target_id"],
            "descriptor_sha256": public["descriptor_sha256"],
            "setup_deadline_monotonic_ns": time.monotonic_ns() + 30 * 10**9,
        }
        self.put(exchange / "controller.json", C.encoded(meta))
        supplied = []
        for role in sorted(C.FIVE_ROLES):
            # These bytes are expected public data only. Native crypto would
            # reject them; the assembler must never attest their provenance.
            source = self.put(
                controls / role, b"PUBLIC UNADMITTED " + role.encode())
            supplied.append(
                {
                    "role": role,
                    "path": str(source),
                    "sha256": C.digest(source.read_bytes()),
                    "size": source.stat().st_size,
                }
            )
        software = self.put(
            self.base / "software-config", b"PUBLIC UNADMITTED SOFTWARE REFERENCE"
        )
        operator = self.put(
            self.base / "operator-record", b"PUBLIC UNADMITTED OPERATOR REFERENCE"
        )
        inputs = {
            "version": 1,
            "kind": "depot-dedicated-birth-preparation-inputs",
            "package_root": str(package),
            "stage_root": str(stage),
            "initial_sources": supplied,
            "software_release_config": str(software),
            "operator_runtime_pin_record": str(operator),
        }
        input_file = self.put(self.base / "inputs.json", C.encoded(inputs))
        source_dir = self.mkdir("source")
        self.put(source_dir / "one.rs", b"PUBLIC SOURCE REVISION")
        snapshot = self.put(
            source_dir / "snapshot.json",
            C.encoded(
                {
                    "schema": 1,
                    "head": "a" * 40,
                    "source_sha256": {"one.rs": C.digest(b"PUBLIC SOURCE REVISION")},
                }
            ),
        )
        args = argparse.Namespace(
            exchange_dir=str(exchange),
            output_dir=str(output),
            inputs=str(input_file),
            source_snapshot=str(snapshot),
        )
        return args, public, target, inputs, meta, native, files

    def fixture_prestage(self, optional=()):
        # All candidate/signature bytes here are inert public fixtures. They
        # deliberately cannot establish actual native signature admission.
        case = Path(tempfile.mkdtemp(prefix="prestage-", dir=self.base))
        sources = case / "sources"
        sources.mkdir(mode=0o700)
        output = case / "receipts"
        output.mkdir(mode=0o700)
        module, _ = C.inventory_module()
        identifiers = (
            "ctl",
            "adapter",
            "cas",
            "apfs-broker",
            "ifc",
            "zk",
            "browser",
            "gateway",
            "intent",
            "custody",
            "oidc-broker",
        )
        pins = {
            "v": 1,
            "mode": "local-pins",
            "pins": {
                "com.enterprise.enclave." + name: ["ab" * 20] for name in identifiers
            },
        }
        rows, payloads = [], {}
        for index, relative in enumerate(
            sorted(module.prestage_required() -
                   {"SHA256SUMS"}) + list(optional)
        ):
            raw = b"INERT PUBLIC DATA, NOT A SIGNATURE: " + relative.encode() + b"\n"
            if relative == "codesign-pins.json":
                raw = C.encoded(pins)
            elif module.prestage_public_json(relative):
                raw = b'{"public_fixture_only":true}\n'
            elif relative == "yubikey-transport":
                raw = b"hid\n"
            source = self.put(sources / ("file-" + str(index)), raw)
            payloads[relative] = raw
            rows.append(
                {
                    "relative": relative,
                    "path": str(source),
                    "sha256": C.digest(raw),
                    "size": len(raw),
                }
            )
        plan = {
            "version": 1,
            "kind": "depot-dedicated-birth-prestage-inputs",
            "stage_root": str(case / "stage"),
            "sources": rows,
        }
        inputs = self.put(case / "inputs.json", C.encoded(plan))
        return (
            argparse.Namespace(inputs=str(inputs), output_dir=str(output)),
            plan,
            payloads,
        )

    def write_prestage_plan(self, args, plan):
        self.put(args.inputs, C.encoded(plan))

    def test_assemble_exact_public_closure_preserves_sources_and_leaves_launchd_absent(
        self,
    ):
        args, plan, payloads = self.fixture_prestage()
        before = {
            row["path"]: (
                Path(row["path"]).read_bytes(),
                C.stamp(Path(row["path"]).stat()),
            )
            for row in plan["sources"]
        }
        # Assembly must never spawn/sign/build/run an installer or renderer.
        with mock.patch.object(
            C, "Child", side_effect=AssertionError("assembly spawned a child")
        ), mock.patch.object(
            C.subprocess,
            "Popen",
            side_effect=AssertionError("assembly invoked a process"),
        ):
            self.assertEqual(C.assemble_stage(args), 0)
        stage = Path(plan["stage_root"])
        observed = {str(p.relative_to(stage))
                    for p in stage.rglob("*") if p.is_file()}
        self.assertEqual(observed, set(payloads) | {"SHA256SUMS"})
        self.assertEqual(len(observed), 33)
        self.assertFalse((stage / "launchd").exists())
        for relative, raw in payloads.items():
            self.assertEqual((stage / relative).read_bytes(), raw)
            expected_mode = (
                0o500
                if relative.startswith("bin/") or "/Contents/MacOS/" in relative
                else 0o600
            )
            self.assertEqual(
                C.stat.S_IMODE(
                    (stage / relative).stat().st_mode), expected_mode
            )
        for name, (raw, stamp) in before.items():
            self.assertEqual(Path(name).read_bytes(), raw)
            self.assertEqual(C.stamp(Path(name).stat()), stamp)
        sums = (stage / "SHA256SUMS").read_text().splitlines()
        self.assertEqual(sums, sorted(
            sums, key=lambda line: line.split("  ", 1)[1]))
        self.assertEqual({line.split("  ", 1)[1]
                         for line in sums}, set(payloads))
        for line in sums:
            sha256, relative = line.split("  ", 1)
            self.assertEqual(C.digest((stage / relative).read_bytes()), sha256)
        receipt = C.loads(
            (Path(args.output_dir) / "assembly.json").read_bytes())
        self.assertEqual(receipt["file_count"], 33)
        self.assertEqual(receipt["checksum_coverage"], "PRESTAGE_ONLY")
        self.assertFalse(receipt["rendered_files_covered"])
        self.assertEqual(receipt["native_signature_admission"], "UNPERFORMED")
        self.assertEqual(receipt["external_provenance"], "UNKNOWN")
        self.assertTrue(receipt["data_only"])
        self.assertFalse(receipt["qualified"])

    def test_assemble_supported_optional_members_and_large_copy_handle_actual_short_writes(
        self,
    ):
        optional = ("tuf/repo/2.root.json", "EnclaveOIDC.app/Contents/PkgInfo")
        args, plan, payloads = self.fixture_prestage(optional)
        row = next(
            row for row in plan["sources"] if row["relative"] == "bin/depot-enclave"
        )
        raw = b"INERT PUBLIC COPY FIXTURE\n" * (C.FRAME // 20 + 1)
        self.assertGreater(len(raw), C.FRAME)
        self.put(row["path"], raw)
        row.update(sha256=C.digest(raw), size=len(raw))
        payloads[row["relative"]] = raw
        self.write_prestage_plan(args, plan)
        actual_write = C.os.write

        def short_write(fd, value):
            return actual_write(fd, value[:8191])

        with mock.patch.object(C.os, "write", side_effect=short_write):
            self.assertEqual(C.assemble_stage(args), 0)
        stage = Path(plan["stage_root"])
        self.assertEqual((stage / "bin/depot-enclave").read_bytes(), raw)
        self.assertEqual(len([p for p in stage.rglob("*") if p.is_file()]), 35)
        self.assertEqual(
            (stage / optional[0]).read_bytes(), payloads[optional[0]])
        self.assertFalse((stage / "launchd").exists())

    def test_assemble_preflight_schema_hash_secret_alias_and_missing_sources_leave_no_outputs(
        self,
    ):
        def private_json(plan):
            row = next(
                row
                for row in plan["sources"]
                if row["relative"] == "tuf/repo/root.json"
            )
            raw = b'{"private\\u005fkey":"PUBLIC NEGATIVE FIXTURE"}'
            self.put(row["path"], raw)
            row.update(sha256=C.digest(raw), size=len(raw))

        changes = [
            lambda plan: plan.update(extra=True),
            lambda plan: plan["sources"].pop(),
            lambda plan: plan["sources"].append(dict(plan["sources"][0])),
            lambda plan: plan["sources"][0].update(sha256="0" * 64),
            lambda plan: plan["sources"][0].update(size=0),
            lambda plan: plan["sources"][1].update(
                path=plan["sources"][0]["path"].upper()
            ),
            lambda plan: Path(plan["sources"][0]["path"]).unlink(),
            private_json,
        ]
        for index, change in enumerate(changes):
            args, plan, _ = self.fixture_prestage()
            change(plan)
            self.write_prestage_plan(args, plan)
            with self.subTest(index=index), self.assertRaises((C.Refusal, OSError)):
                C.assemble_stage(args)
            self.assertFalse(Path(plan["stage_root"]).exists())
            self.assertEqual(list(Path(args.output_dir).iterdir()), [])
        args, plan, _ = self.fixture_prestage()
        self.put(args.inputs, C.encoded(plan)[:-2] + b',"version":1}\n')
        with self.assertRaisesRegex(C.Refusal, "JSON_DUPLICATE"):
            C.assemble_stage(args)
        self.assertFalse(Path(plan["stage_root"]).exists())
        self.assertEqual(list(Path(args.output_dir).iterdir()), [])

    def test_assemble_symlinks_hardlinks_special_and_writable_sources_refuse_before_creation(
        self,
    ):
        for kind in ("symlink", "hardlink", "fifo", "writable-file", "writable-parent"):
            args, plan, _ = self.fixture_prestage()
            source = Path(plan["sources"][0]["path"])
            if kind == "symlink":
                original = source.with_name("retained-original")
                source.rename(original)
                source.symlink_to(original)
            elif kind == "hardlink":
                os.link(source, source.with_name("another-name"))
            elif kind == "fifo":
                source.unlink()
                os.mkfifo(source)
            elif kind == "writable-file":
                source.chmod(0o666)
            else:
                source.parent.chmod(0o777)
            with self.subTest(kind=kind), self.assertRaises((C.Refusal, OSError)):
                C.assemble_stage(args)
            self.assertFalse(Path(plan["stage_root"]).exists())
            self.assertEqual(list(Path(args.output_dir).iterdir()), [])

    def test_assemble_existing_case_alias_stage_and_source_code_receipt_overlap_never_adopt(
        self,
    ):
        for kind in ("existing", "case-alias", "symlink", "inputs", "code", "receipt"):
            args, plan, _ = self.fixture_prestage()
            stage = Path(plan["stage_root"])
            if kind in {"existing", "case-alias"}:
                (
                    stage if kind == "existing" else stage.with_name(
                        stage.name.upper())
                ).mkdir(mode=0o700)
            elif kind == "symlink":
                stage.symlink_to(
                    Path(plan["sources"][0]["path"]
                         ).parent, target_is_directory=True
                )
            elif kind == "inputs":
                plan["stage_root"] = str(Path(args.inputs).parent)
            elif kind == "code":
                plan["stage_root"] = str(
                    REPO / "scripts/never-created-assembly-stage")
            else:
                plan["stage_root"] = args.output_dir
            self.write_prestage_plan(args, plan)
            with self.subTest(kind=kind), self.assertRaises(C.Refusal):
                C.assemble_stage(args)
            self.assertFalse(
                (Path(args.output_dir) / "assembly.json").exists())
            if kind == "existing":
                self.assertEqual(list(stage.iterdir()), [])
            if kind in {"inputs", "code", "receipt"}:
                self.assertFalse(stage.exists())

    def test_assemble_write_and_fsync_faults_retain_partial_stage_and_never_report_success(
        self,
    ):
        for fault in ("write", "fsync", "publish"):
            args, plan, _ = self.fixture_prestage()
            actual_write, actual_sync, actual_publish = (
                C.os.write,
                C.os.fsync,
                C.publish,
            )
            state = {"attempted": False}

            def fail_write(fd, raw):
                if not state["attempted"]:
                    state["attempted"] = True
                    actual_write(fd, raw[:3])
                    raise OSError("PUBLIC FIXTURE COPY FAILURE")
                return actual_write(fd, raw)

            def fail_sync(fd):
                if C.stat.S_ISREG(os.fstat(fd).st_mode) and not state["attempted"]:
                    state["attempted"] = True
                    raise OSError("PUBLIC FIXTURE COPY FAILURE")
                return actual_sync(fd)

            def fail_publish(directory, temporary, final):
                if not state["attempted"]:
                    state["attempted"] = True
                    raise OSError("PUBLIC FIXTURE COPY FAILURE")
                return actual_publish(directory, temporary, final)

            target, replacement = {
                "write": ("write", fail_write),
                "fsync": ("fsync", fail_sync),
                "publish": ("publish", fail_publish),
            }[fault]
            owner = C if fault == "publish" else C.os
            errors = io.StringIO()
            with self.subTest(fault=fault), mock.patch.object(
                owner, target, side_effect=replacement
            ), mock.patch.object(C.sys, "stderr", errors):
                self.assertEqual(
                    C.main(
                        [
                            "assemble-stage",
                            "--inputs",
                            args.inputs,
                            "--output-dir",
                            args.output_dir,
                        ]
                    ),
                    2,
                )
            self.assertTrue(state["attempted"])
            self.assertTrue(Path(plan["stage_root"]).is_dir())
            self.assertTrue(list(Path(plan["stage_root"]).rglob(".pending-*")))
            self.assertFalse(
                (Path(args.output_dir) / "assembly.json").exists())
            refusal = C.loads(
                (Path(args.output_dir) / "assembly-refusal.json").read_bytes()
            )
            self.assertTrue(refusal["outputs_may_be_partial"])
            self.assertTrue(refusal["supersedes_any_assembly_result"])
            self.assertEqual(refusal["rollback"], "NONE")
            self.assertNotIn("PUBLIC FIXTURE COPY FAILURE", errors.getvalue())

    def test_assemble_source_drift_and_postcopy_replacement_refuse_without_success(
        self,
    ):
        for fault in ("source", "destination", "extra-member"):
            args, plan, _ = self.fixture_prestage()
            actual_copy = C.copy_public
            state = {"attempted": False}

            def copy(source, output, name, executable=False):
                if not state["attempted"] and fault == "source":
                    state["attempted"] = True
                    Path(source.path).write_bytes(
                        b"CHANGED INERT PUBLIC SOURCE")
                record = actual_copy(source, output, name, executable)
                if not state["attempted"]:
                    state["attempted"] = True
                    if fault == "destination":
                        replacement = Path(record["path"]).with_name(
                            "fixture-replacement"
                        )
                        self.put(
                            replacement, b"CHANGED INERT PUBLIC DESTINATION")
                        os.replace(replacement, record["path"])
                    else:
                        self.put(
                            Path(plan["stage_root"]) / "unexpected",
                            b"INERT UNDECLARED MEMBER",
                        )
                return record

            with self.subTest(fault=fault), mock.patch.object(
                C, "copy_public", side_effect=copy
            ), self.assertRaises(C.Refusal):
                C.assemble_stage(args)
            self.assertTrue(state["attempted"])
            self.assertTrue(Path(plan["stage_root"]).is_dir())
            self.assertFalse(
                (Path(args.output_dir) / "assembly.json").exists())

    def test_assembled_stage_enters_existing_prepare_render20_then_exactly_one_inventory(
        self,
    ):
        args, _, _, inputs, _, _, files = self.fixture_package()
        assembly, plan, _ = self.fixture_prestage()
        plan["stage_root"] = str(
            Path(inputs["package_root"]) / "assembled-stage")
        self.write_prestage_plan(assembly, plan)
        self.assertEqual(C.assemble_stage(assembly), 0)
        inputs["stage_root"] = plan["stage_root"]
        self.put(args.inputs, C.encoded(inputs))
        actual_loader, observed = C.inventory_module, {}

        def instrument():
            module, record = actual_loader()
            inventory, projection = module.inventory, module.staged_source_list

            def scan(*a, **kw):
                self.assertNotIn("inventory", observed)
                observed["inventory"] = inventory(*a, **kw)
                return observed["inventory"]

            def project(value, *a):
                self.assertIs(value, observed["inventory"])
                self.assertNotIn("projection", observed)
                observed["projection"] = True
                return projection(value, *a)

            module.inventory, module.staged_source_list = scan, project
            return module, record

        with mock.patch.object(C, "inventory_module", side_effect=instrument):
            self.assertEqual(C.prepare(args), 0)
        self.assertTrue(observed["projection"])
        self.assertEqual(len(observed["inventory"]["files"]), 53)
        for relative, raw in files.items():
            self.assertEqual(
                (Path(plan["stage_root"]) / relative).read_text(), raw)
        receipt = C.loads((Path(assembly.output_dir) /
                          "assembly.json").read_bytes())
        self.assertFalse(receipt["rendered_files_covered"])

    def test_data_reads_allow_writable_ancestor_but_mutation_code_and_leaf_do_not(self):
        writable = self.mkdir("writable")
        writable.chmod(0o777)
        source = self.put(writable / "public.json", b"PUBLIC")
        with C.Reader(str(source), 10) as read:
            self.assertEqual(read.raw, b"PUBLIC")
        with self.assertRaisesRegex(C.Refusal, "PROTECTED_ANCESTRY_REQUIRED"):
            C.Directory(str(writable), strict=True)
        with self.assertRaisesRegex(C.Refusal, "PROTECTED_ANCESTRY_REQUIRED"):
            C.Reader(str(source), 10, strict=True)
        source.chmod(0o666)
        with self.assertRaises(C.Refusal):
            C.Reader(str(source), 10)

    def test_create_only_output_original_name_replacement_hardlinks_and_symlinks(self):
        output = self.mkdir("output")
        with C.Directory(str(output), strict=True, private=True) as directory:
            directory.write("data.json", b"PUBLIC")
            with self.assertRaises(FileExistsError):
                directory.write("data.json", b"OTHER")
        source = output / "data.json"
        with C.Reader(str(source), 10) as original:
            replacement = self.put(output / "replacement", b"PUBLIC")
            os.replace(replacement, source)
            with self.assertRaises(C.Refusal):
                original.current()
        os.link(source, output / "hardlink")
        with self.assertRaises(C.Refusal):
            C.Reader(str(source), 10)
        os.symlink(source, output / "symlink")
        with self.assertRaises(OSError):
            C.Reader(str(output / "symlink"), 10)

    def test_atomic_publication_exposes_only_complete_single_link_file_and_retains_failed_temp(
        self,
    ):
        output = self.mkdir("output")
        actual_publish, observed = C.publish, []

        def publication(directory, temporary, final):
            self.assertFalse((output / final).exists())
            self.assertEqual((output / temporary).read_bytes(),
                             b"PUBLIC COMPLETE")
            self.assertEqual((output / temporary).stat().st_nlink, 1)
            actual_publish(directory, temporary, final)
            self.assertEqual((output / final).read_bytes(), b"PUBLIC COMPLETE")
            self.assertEqual((output / final).stat().st_nlink, 1)
            observed.append(final)

        with C.Directory(str(output), strict=True, private=True) as directory:
            with mock.patch.object(C, "publish", side_effect=publication):
                directory.write("complete.json", b"PUBLIC COMPLETE")
            actual_write = os.write
            state = {"written": False}

            def partial_then_fail(fd, raw):
                if not state["written"]:
                    state["written"] = True
                    return actual_write(fd, raw[:3])
                raise OSError("PUBLIC FIXTURE DISK REFUSAL")

            with mock.patch.object(C.os, "write", side_effect=partial_then_fail):
                with self.assertRaises(OSError):
                    directory.write("partial.json", b"PUBLIC PARTIAL")
        self.assertEqual(observed, ["complete.json"])
        self.assertFalse((output / "partial.json").exists())
        pending = list(output.glob(".pending-*"))
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].read_bytes(), b"PUB")

    def test_prepare_preserves_supplied_sources_exact20_outputs_and_same_scan_pins_split(
        self,
    ):
        args, public, _, inputs, _, native, files = self.fixture_package()
        before = {
            item["path"]: Path(item["path"]).read_bytes()
            for item in inputs["initial_sources"]
        }
        native_before = native.read_bytes()
        actual_loader, observed = C.inventory_module, {}

        def instrument():
            module, record = actual_loader()
            inventory, project = module.inventory, module.staged_source_list

            def scan(*a, **kw):
                self.assertNotIn("inventory", observed)
                result = inventory(*a, **kw)
                observed["inventory"] = result
                return result

            def projection(value, *a):
                self.assertIs(value, observed["inventory"])
                self.assertNotIn("projected", observed)
                observed["projected"] = True
                return project(value, *a)

            module.inventory, module.staged_source_list = scan, projection
            return module, record

        with mock.patch.object(C, "inventory_module", side_effect=instrument):
            self.assertEqual(C.prepare(args), 0)
        self.assertTrue(observed["projected"])
        for relative, body in files.items():
            self.assertEqual(
                (Path(inputs["stage_root"]) / relative).read_text(), body)
        self.assertEqual(native.read_bytes(), native_before)
        self.assertEqual({p: Path(p).read_bytes() for p in before}, before)
        self.assertFalse(Path(public["root"]).exists())
        pickup = C.loads(
            (Path(args.output_dir) / "pickup.json").read_bytes(), wire=True
        )
        C.validate_pickup(pickup, public)
        self.assertEqual({v["role"]
                         for v in pickup["initial_sources"]}, C.SEVEN_ROLES)
        self.assertNotIn(
            "codesign-pins.json",
            {v["relative"] for v in pickup["remaining_staged_sources"]},
        )
        inventory = next(
            v for v in pickup["initial_sources"] if v["role"] == "inventory"
        )
        self.assertEqual(
            inventory["sha256"], C.digest(Path(inventory["path"]).read_bytes())
        )
        receipt = C.loads(
            (Path(args.output_dir) / "preparation.json").read_bytes())
        self.assertEqual(receipt["external_provenance"], "UNKNOWN")
        self.assertFalse(receipt["qualified"])
        decision = argparse.Namespace(
            exchange_dir=args.exchange_dir,
            pickup=str(Path(args.output_dir) / "pickup.json"),
            cancel=False,
        )
        self.assertFalse((Path(args.exchange_dir) / "command.json").exists())
        self.assertEqual(C.decide(decision), 0)
        with self.assertRaises(FileExistsError):
            C.decide(decision)

    def test_stale_supplied_bytes_and_expired_setup_refuse_before_stage_mutation(self):
        args, _, _, inputs, meta, _, _ = self.fixture_package()
        first = Path(inputs["initial_sources"][0]["path"])
        first.write_bytes(b"CHANGED PUBLIC SOURCE")
        with self.assertRaisesRegex(C.Refusal, "SUPPLIED_CONTROL_CHANGED"):
            C.prepare(args)
        self.assertFalse((Path(inputs["stage_root"]) / "launchd").exists())
        meta["setup_deadline_monotonic_ns"] = time.monotonic_ns() - 1
        self.put(Path(args.exchange_dir) / "controller.json", C.encoded(meta))
        with self.assertRaisesRegex(C.Refusal, "SETUP_EXPIRED"):
            C.prepare(args)
        self.assertFalse(list(Path(args.output_dir).iterdir()))

    def test_recorded_binary_inside_stage_is_never_executed_and_wrong_render_set_never_written(
        self,
    ):
        args, _, target, inputs, meta, native, _ = self.fixture_package()
        meta["binary"] = str(native)
        self.put(Path(args.exchange_dir) / "controller.json", C.encoded(meta))
        with self.assertRaisesRegex(C.Refusal, "MUTATION_INPUT_OVERLAP"):
            C.prepare(args)
        stage = Path(inputs["stage_root"])
        with C.Directory(str(stage), strict=True, private=True) as held:
            with self.assertRaisesRegex(C.Refusal, "RENDER_EXACT_FILE_SET"):
                C.materialize(
                    held,
                    target,
                    {"launchd/../escape": "PUBLIC"},
                    time.monotonic_ns() + 10**9,
                )
        self.assertFalse((stage / "launchd").exists())

    def test_original_endpoint_crossed_by_binary_read_prevents_any_spawn(self):
        exchange = self.mkdir("exchange")
        binary = self.fixture_binary(
            "must-not-execute", "raise AssertionError('must not execute')\n"
        )
        args = argparse.Namespace(
            binary=str(binary),
            exchange_dir=str(exchange),
            template="/state/template.json",
            template_root="/state/template",
            allocator_parent="/state/allocator",
        )
        start = time.monotonic_ns()
        # Explicit software clock fault; no native ceremony/timing claim.
        with mock.patch.object(
            C.time, "monotonic_ns", side_effect=[start, start + C.SETUP_NS + 1]
        ), mock.patch.object(
            C, "Child", side_effect=AssertionError("expired setup spawned")
        ) as spawned:
            with self.assertRaisesRegex(C.Refusal, "SETUP_EXPIRED_BEFORE_SPAWN"):
                C.run_session(args)
            spawned.assert_not_called()
        self.assertEqual(list(exchange.iterdir()), [])

    def test_actual_renderer_then_expired_original_endpoint_prevents_materialization(
        self,
    ):
        args, _, _, inputs, _, _, _ = self.fixture_package()
        actual_render, actual_clock = C.render, time.monotonic_ns
        state = {"late": False}

        def render_then_expire(*a, **kw):
            result = actual_render(*a, **kw)
            state["late"] = True
            return result

        def clock():
            return actual_clock() + (C.SETUP_NS if state["late"] else 0)

        with mock.patch.object(
            C, "render", side_effect=render_then_expire
        ), mock.patch.object(C.time, "monotonic_ns", side_effect=clock):
            with self.assertRaisesRegex(C.Refusal, "SETUP_EXPIRED"):
                C.prepare(args)
        self.assertFalse((Path(inputs["stage_root"]) / "launchd").exists())
        self.assertEqual(list(Path(args.output_dir).iterdir()), [])

    def test_late_inventory_output_is_retained_with_explicit_refusal_and_no_pickup(
        self,
    ):
        args, _, _, inputs, _, _, _ = self.fixture_package()
        actual_write, actual_clock = C.Directory.write, time.monotonic_ns
        state = {"late": False}

        def write_then_expire(directory, name, raw):
            record = actual_write(directory, name, raw)
            if name == "inventory.json":
                state["late"] = True
            return record

        def clock():
            return actual_clock() + (C.SETUP_NS if state["late"] else 0)

        with mock.patch.object(
            C.Directory, "write", autospec=True, side_effect=write_then_expire
        ), mock.patch.object(C.time, "monotonic_ns", side_effect=clock):
            code = C.main(
                [
                    "prepare",
                    "--exchange-dir",
                    args.exchange_dir,
                    "--inputs",
                    args.inputs,
                    "--source-snapshot",
                    args.source_snapshot,
                    "--output-dir",
                    args.output_dir,
                ]
            )
        self.assertEqual(code, 2)
        output = Path(args.output_dir)
        self.assertTrue((output / "inventory.json").is_file())
        self.assertFalse((output / "pickup.json").exists())
        self.assertTrue((Path(inputs["stage_root"]) / "launchd").is_dir())
        refusal = C.loads((output / "preparation-refusal.json").read_bytes())
        self.assertEqual(refusal["reason"], "SETUP_EXPIRED")
        self.assertTrue(refusal["outputs_may_be_partial"])

    def run_public_session_fixture(
        self, exit_code, raw_terminal=None, valid_terminal=True
    ):
        exchange = self.mkdir("exchange")
        public, _ = public_challenge(str(self.base / ("34" * 16)))
        refusal = refused_terminal()
        refusal["effects"]["namespace_visibility_may_have_changed"] = True
        code = "import fcntl,json,os,select,sys,time\n" + WRITE
        code += "assert sys.argv[1:4]==['--profile','L2','dedicated-birth-session']\n"
        code += (
            "assert all(fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_NONBLOCK for fd in (0,1))\n"
        )
        code += "write(1," + repr(C.encoded(public)) + ")\n"
        code += "raw=b'';until=time.monotonic()+5\nwhile b'\\n' not in raw and time.monotonic()<until:\n"
        code += "    select.select([0],[],[],0.1)\n    try: raw+=os.read(0,4096)\n    except BlockingIOError: pass\n"
        code += "assert json.loads(raw)=={'version':1,'op':'cancel'}\n"
        code += (
            "write(2,b'PUBLIC STDERR BODY MUST NOT BE LOGGED')\nwrite(1,"
            + repr(raw_terminal if raw_terminal is not None else C.encoded(refusal))
            + ")\nraise SystemExit("
            + str(exit_code)
            + ")\n"
        )
        binary = self.fixture_binary("session-fixture", code)
        errors = []

        def independent_decision():
            try:
                until = time.monotonic() + 5
                while (
                    not (exchange / "controller.json").exists()
                    and time.monotonic() < until
                ):
                    time.sleep(0.01)
                C.decide(
                    argparse.Namespace(
                        exchange_dir=str(exchange), pickup=None, cancel=True
                    )
                )
            except BaseException as error:
                errors.append(error)

        operator = threading.Thread(target=independent_decision)
        operator.start()
        result = C.run_session(
            argparse.Namespace(
                binary=str(binary),
                exchange_dir=str(exchange),
                template="/state/public-template.json",
                template_root="/state/public-template",
                allocator_parent="/state/public-allocator",
            )
        )
        operator.join(timeout=6)
        self.assertFalse(operator.is_alive())
        self.assertEqual(errors, [])
        receipt = C.loads((exchange / "result.json").read_bytes())
        self.assertEqual(result, 3)
        self.assertTrue(
            receipt["command_attempted"] and receipt["command_frame_complete"]
        )
        if valid_terminal:
            self.assertEqual(receipt["terminal"]
                             ["effects"], refusal["effects"])
        else:
            self.assertIsNone(receipt["terminal"])
        self.assertNotIn(b"STDERR BODY", (exchange /
                         "result.json").read_bytes())
        return receipt

    def test_actual_protected_route_fixture_retains_terminal_refusal_and_effects(self):
        receipt = self.run_public_session_fixture(3)
        self.assertIsNone(receipt["controller_error"])
        self.assertEqual(receipt["runtime_readiness"], "UNKNOWN")
        self.assertFalse(receipt["qualified"])

    def test_contradictory_exit_is_refused_while_actual_terminal_effects_survive(self):
        receipt = self.run_public_session_fixture(0)
        self.assertEqual(receipt["controller_error"], "TERMINAL_EXIT_MISMATCH")
        self.assertTrue(receipt["effects_known"])

    def test_cleanup_exception_cannot_erase_terminal_or_bypass_result_file(self):
        actual_close = C.Child.close

        def close_then_refuse(child):
            actual_close(child)
            raise OSError("PUBLIC FIXTURE CLEANUP REFUSAL")

        with mock.patch.object(
            C.Child, "close", autospec=True, side_effect=close_then_refuse
        ):
            receipt = self.run_public_session_fixture(3)
        self.assertEqual(
            receipt["controller_error"], "CHILD_CLEANUP_REFUSED_OR_UNKNOWN"
        )
        self.assertEqual(receipt["cleanup_error"],
                         "CHILD_CLEANUP_REFUSED_OR_UNKNOWN")
        self.assertIsNotNone(receipt["terminal"])

    def test_rejected_literal_del_frame_keeps_raw_hash_without_canonical_expansion_or_body(
        self,
    ):
        raw = (
            b'{"version":1,"kind":"depot-dedicated-birth-session-result","payload":"'
            + b"\x7f" * 180000
            + b'"}\n'
        )
        self.assertLess(len(raw), C.FRAME)
        receipt = self.run_public_session_fixture(3, raw, valid_terminal=False)
        self.assertEqual(receipt["controller_error"], "JSON_FIELDS")
        self.assertEqual(
            receipt["rejected_terminal"]["original_frame"],
            {"bytes": len(raw), "sha256": C.digest(raw)},
        )
        self.assertFalse((self.base / "exchange/terminal-frame.json").exists())
        self.assertLess(
            (self.base / "exchange/result.json").stat().st_size, 65536)
        self.assertNotIn(
            b"\x7f", (self.base / "exchange/result.json").read_bytes())

    def test_near_frame_valid_terminal_retains_original_bytes_outside_bounded_result(
        self,
    ):
        terminal = refused_terminal()
        terminal["effects"]["namespace_visibility_may_have_changed"] = True
        progress = {key: False for key in C.PROGRESS}
        progress.update(
            operation="fixture",
            root=None,
            descriptor=None,
            target_id=None,
            attempted=[],
            created_directories=[],
            created_files=[],
            existing_names=[],
            synced=[],
            pending_descriptor_sha256=None,
            pending_inventory_sha256=None,
        )
        terminal["progress"] = progress

        def raw_value():
            return (
                json.dumps(terminal, sort_keys=True,
                           separators=(",", ":")).encode()
                + b"\n"
            )

        def public_path(length):
            name = "/state/"
            while len(name) < length:
                remaining = length - len(name)
                name += "p" * min(200, remaining)
                if len(name) < length:
                    # Reserve the following component so no trailing slash.
                    if length - len(name) == 1:
                        name += "p"
                    else:
                        name += "/"
            return name

        long_name = public_path(4000)
        target_size = C.FRAME - 16
        while len(raw_value()) + len(long_name) + 3 < target_size:
            progress["attempted"].append(long_name)
        remaining = target_size - len(raw_value())
        if remaining < 11:
            progress["attempted"].pop()
            remaining = target_size - len(raw_value())
        progress["attempted"].append(public_path(remaining - 3))
        raw = raw_value()
        self.assertEqual(len(raw), target_size)
        # Closed public schema only, not native authority.
        C.terminal(terminal)
        receipt = self.run_public_session_fixture(3, raw)
        self.assertIsNone(receipt["controller_error"])
        original = self.base / "exchange/terminal-frame.json"
        self.assertEqual(original.read_bytes(), raw)
        self.assertEqual(receipt["terminal_frame"]["sha256"], C.digest(raw))
        self.assertEqual(receipt["terminal_frame"]["bytes"], len(raw))
        self.assertLess(
            (self.base / "exchange/result.json").stat().st_size, 65536)

    def test_synthetic_public_continue_prepare_decide_and_success_transport_branch(
        self,
    ):
        args, public, _, inputs, meta, native, files = self.fixture_package()
        exchange = Path(args.exchange_dir)
        # Remove only this test's synthetic setup metadata before starting the
        # one real controller child. This is no production rollback/adoption.
        for name in ("challenge.json", "descriptor.json", "controller.json"):
            (exchange / name).unlink()
        unchanged = {
            v["path"]: Path(v["path"]).read_bytes() for v in inputs["initial_sources"]
        }
        unchanged[str(native)] = native.read_bytes()
        success = refused_terminal()
        success.update(
            status="startup_exclusion_released",
            stage="release",
            error=None,
            effects={key: True for key in C.EFFECTS},
        )
        renderer = {
            "version": 1,
            "kind": "depot-dedicated-birth-public-rendering",
            "files": files,
            "data_only": True,
            "qualified": False,
        }
        pickup = str(Path(args.output_dir) / "pickup.json")
        code = "import fcntl,json,os,select,sys,time\n" + WRITE
        code += (
            "assert all(fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_NONBLOCK for fd in (0,1))\n"
        )
        code += "assert sys.argv[1:3]==['--profile','L2']\n"
        code += (
            "if sys.argv[3]=='dedicated-birth-render':\n    write(1,"
            + repr(C.encoded(renderer))
            + ");raise SystemExit(0)\n"
        )
        code += (
            "assert sys.argv[3]=='dedicated-birth-session'\nwrite(1,"
            + repr(C.encoded(public))
            + ")\n"
        )
        code += "raw=b'';until=time.monotonic()+15\nwhile b'\\n' not in raw and time.monotonic()<until:\n"
        code += "    select.select([0],[],[],0.1)\n    try: raw+=os.read(0,4096)\n    except BlockingIOError: pass\n"
        code += "assert raw.count(b'\\n')==1 and raw.endswith(b'\\n')\n"
        code += (
            "assert json.loads(raw)=="
            + repr({"version": 1, "op": "continue", "input_manifest": pickup})
            + "\n"
        )
        code += "with open(" + repr(pickup) + \
            ",'rb') as f: supplied=json.load(f)\n"
        code += "assert supplied['target_id']==" + \
            repr(public["target_id"]) + "\n"
        code += "write(1," + repr(C.encoded(success)) + ")\n"
        binary = self.fixture_binary(
            "continue-session-and-renderer-fixture", code)
        errors = []

        def independent_preparation():
            try:
                until = time.monotonic() + 5
                while (
                    not (exchange / "controller.json").exists()
                    and time.monotonic() < until
                ):
                    time.sleep(0.01)
                self.assertEqual(C.prepare(args), 0)
                self.assertEqual(
                    C.decide(
                        argparse.Namespace(
                            exchange_dir=args.exchange_dir, pickup=pickup, cancel=False
                        )
                    ),
                    0,
                )
            except BaseException as error:
                errors.append(error)

        preparer = threading.Thread(target=independent_preparation)
        preparer.start()
        result = C.run_session(
            argparse.Namespace(
                binary=str(binary),
                exchange_dir=args.exchange_dir,
                template="/state/public-template.json",
                template_root="/state/public-template",
                allocator_parent="/state/public-allocator",
            )
        )
        preparer.join(timeout=16)
        self.assertFalse(preparer.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(result, 0)
        receipt = C.loads((exchange / "result.json").read_bytes())
        self.assertIsNone(receipt["controller_error"])
        self.assertEqual(receipt["terminal"]["status"],
                         "startup_exclusion_released")
        self.assertTrue(
            receipt["command_attempted"] and receipt["command_frame_complete"]
        )
        self.assertEqual(receipt["runtime_readiness"], "UNKNOWN")
        self.assertFalse(receipt["qualified"])
        self.assertEqual(receipt["terminal_frame"]
                         ["storage"], "WRITTEN_ORIGINAL_BYTES")
        self.assertEqual(
            {name: Path(name).read_bytes() for name in unchanged}, unchanged
        )
        self.assertFalse(Path(public["root"]).exists())


if __name__ == "__main__":
    unittest.main()
