"""Private file fixtures only; no build, signing, services or hardware."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "first_touch_artifacts",
    Path(__file__).resolve().parents[1] / "prepare-first-touch-artifacts.py",
)
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


class PrestageDataTests(unittest.TestCase):
    """Inert public plans; no signature or issuer authenticity is exercised."""

    def sources(self):
        return [
            {
                "relative": name,
                "path": "/state/public-inputs/file-" + str(index),
                "sha256": "a" * 64,
                "size": 1,
            }
            for index, name in enumerate(sorted(P.prestage_required() - {"SHA256SUMS"}))
        ]

    def pins(self):
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
        return {
            "v": 1,
            "mode": "local-pins",
            "pins": {
                "com.enterprise.enclave." + name: ["ab" * 20] for name in identifiers
            },
        }

    def test_closed_complete_plan_is_pure_sorted_and_includes_all_eleven_executables(
        self,
    ):
        sources = list(reversed(self.sources()))
        original = json.loads(json.dumps(sources))
        with mock.patch.object(
            P.os, "open", side_effect=AssertionError("pure validation opened a file")
        ):
            observed = P.prestage_sources(sources)
        self.assertEqual(sources, original)
        self.assertEqual(len(observed), 32)
        self.assertEqual(len(P.prestage_required()), 33)
        self.assertEqual(
            [item["relative"] for item in observed],
            sorted(item["relative"] for item in sources),
        )
        self.assertEqual(
            sum(item["relative"].startswith("bin/") for item in observed), 9
        )
        self.assertEqual(
            sum("/Contents/MacOS/" in item["relative"] for item in observed), 2
        )
        self.assertIn(
            "bin/enclave-apfs-broker", {item["relative"] for item in observed}
        )
        for name in (
            "tuf/repo/1.root.json",
            "tuf/repo/2147483647.root.json",
            "EnclaveOIDC.app/Contents/PkgInfo",
            "EnclaveCustody.app/Contents/embedded.provisionprofile",
        ):
            sources.append(
                {
                    "relative": name,
                    "path": "/state/public-inputs/optional-" + str(len(sources)),
                    "sha256": "b" * 64,
                    "size": 1,
                }
            )
        self.assertEqual(len(P.prestage_sources(sources)), 36)

    def test_missing_unknown_duplicate_and_noncanonical_plans_refuse(self):
        changes = [
            lambda rows: rows.pop(),
            lambda rows: rows.append(dict(rows[0])),
            lambda rows: rows[0].update(extra=True),
            lambda rows: rows[0].update(size=True),
            lambda rows: rows[0].update(size=0),
            lambda rows: rows[0].update(sha256="A" * 64),
            lambda rows: rows[0].update(relative="SHA256SUMS"),
            lambda rows: rows[0].update(relative="launchd/custody.sb"),
            lambda rows: rows[0].update(relative="bin/../mcp-enclave"),
            lambda rows: rows[0].update(relative="tuf/repo/01.root.json"),
            lambda rows: rows[0].update(relative="tuf/repo/2147483648.root.json"),
            lambda rows: rows[0].update(path="relative"),
            lambda rows: rows[1].update(path=rows[0]["path"].upper()),
        ]
        for index, change in enumerate(changes):
            rows = self.sources()
            change(rows)
            with self.subTest(index=index), self.assertRaises(P.Refusal):
                P.prestage_sources(rows)

    def test_transport_specific_limits_rotation_count_and_total_refuse(self):
        limits = {
            "codesign-pins.json": 1024 * 1024,
            "tuf/repo/root.json": 4 * 1024 * 1024,
            "tuf/repo/enclave-host-config.json": 64 * 1024,
            "tuf/repo/fido-mds-allowlist.json": 256 * 1024,
            "tuf/repo/custody-envelope-policy-v1.json": 16 * 1024,
            "tuf/repo/vk_manifest.json": 16 * 1024 * 1024,
            "bin/mcp-enclave": 512 * 1024 * 1024,
        }
        for relative, maximum in limits.items():
            rows = self.sources()
            next(item for item in rows if item["relative"] == relative)["size"] = (
                maximum + 1
            )
            with self.subTest(relative=relative), self.assertRaises(P.Refusal):
                P.prestage_sources(rows)
        for count, length in ((33, 1), (5, 4 * 1024 * 1024)):
            rows = self.sources() + [
                {
                    "relative": "tuf/repo/" + str(i) + ".root.json",
                    "path": "/state/rotation-" + str(i),
                    "sha256": "b" * 64,
                    "size": length,
                }
                for i in range(1, count + 1)
            ]
            with self.subTest(count=count), self.assertRaisesRegex(
                P.Refusal, "PRESTAGE_RUNTIME_BOUND"
            ):
                P.prestage_sources(rows)
        # The checksum member itself must fit in the aggregate reservation.
        rows = self.sources()
        with mock.patch.object(
            P, "MAX_PACKAGE_BYTES", sum(item["size"] for item in rows)
        ), self.assertRaises(P.Refusal):
            P.prestage_sources(rows)

    def test_public_json_duplicate_escape_private_and_transport_bytes_refuse(self):
        P.validate_prestage_public(
            "tuf/repo/root.json", b'{"public_fixture_only":true}'
        )
        P.validate_prestage_public("yubikey-transport", b"hid\n")
        for raw in (
            b"{",
            b"[]",
            b'{"v":1,"v":2}',
            b'{"private_key":"PUBLIC FIXTURE"}',
            b'{"private\\u005fkey":"PUBLIC FIXTURE"}',
            b'{"x":"-----BEGIN PRIVATE KEY-----"}',
        ):
            with self.subTest(raw=raw), self.assertRaises(P.Refusal):
                P.validate_prestage_public("tuf/repo/root.json", raw)
        for raw in (b"hid", b"hid\r\n", b"HID\n"):
            with self.subTest(raw=raw), self.assertRaises(P.Refusal):
                P.validate_prestage_public("yubikey-transport", raw)

    def test_pins_need_exact_eleven_structurally_valid_unique_ids_and_hashes(self):
        P.validate_prestage_public(
            "codesign-pins.json", json.dumps(self.pins()).encode()
        )
        changes = [
            lambda pins: pins.pop("mode"),
            lambda pins: pins.update(mode="team-id"),
            lambda pins: pins["pins"].pop("com.enterprise.enclave.custody"),
            lambda pins: pins["pins"].update(
                {"com.enterprise.enclave.supervisor": ["ab" * 20]}
            ),
            lambda pins: pins["pins"].update(
                {"com.enterprise.enclave.ctl": ["ab" * 20, "AB" * 20]}
            ),
        ]
        for index, change in enumerate(changes):
            pins = self.pins()
            change(pins)
            with self.subTest(index=index), self.assertRaises(P.Refusal):
                P.validate_prestage_public(
                    "codesign-pins.json", json.dumps(pins).encode()
                )


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.stage = self.root / "stage"
        self.source.mkdir()
        self.stage.mkdir()
        (self.source / "input.rs").write_bytes(b"immutable source input")
        self.snapshot = self.source / "snapshot.json"
        self.source_map = {
            "input.rs": hashlib.sha256(
                (self.source / "input.rs").read_bytes()
            ).hexdigest()
        }
        self.write_snapshot()
        self.target = {
            "version": 1,
            "target_id": "fixture-a",
            "role": "dedicated-test",
            "profile": "L2",
            "authority_config": str(self.root / "support/authority.json"),
            "expected_artifacts_manifest": str(self.root / "support/inventory.json"),
            "codesign_pins_file": str(self.root / "support/installed-pins.json"),
            "signing_identity_mode": "local-pins",
            "broker": None,
            "shared_read_only_inputs": [],
        }
        self.target["layout"] = {name: str(self.root / name) for name in P.ROOT_FIELDS}
        self.target["layout"].update(
            staging_root=str(self.stage),
            launchd_namespace="com.fixture.a",
            mach_service="com.fixture.a.exception",
        )
        self.config = self.root / "target.json"
        self.write_config()
        (self.stage / "bin").mkdir()
        (self.stage / "bin/mcp-enclave").write_bytes(
            b"inert candidate binary, never invoked"
        )
        self.pin_bytes = json.dumps(
            {
                "v": 1,
                "mode": "local-pins",
                "pins": {"com.enterprise.enclave.ctl": ["ab" * 20]},
            }
        ).encode()
        (self.stage / "codesign-pins.json").write_bytes(self.pin_bytes)

    def write_snapshot(self):
        self.snapshot.write_text(
            json.dumps(
                {"schema": 1, "head": "a" * 40, "source_sha256": self.source_map}
            )
        )

    def write_config(self):
        self.config.write_text(json.dumps(self.target))

    def collect(self):
        return P.inventory(self.config, self.snapshot)

    def allocate_descriptor(self):
        token = "12" * 16
        allocated = self.root / "allocated" / token
        self.target["target_id"] = "ykft-" + token
        self.target["layout"].update(
            {name: str(allocated / name) for name in P.ROOT_FIELDS}
        )
        for name in (
            "authority_config",
            "expected_artifacts_manifest",
            "codesign_pins_file",
        ):
            self.target[name] = str(allocated / "config" / (name + ".json"))
        self.write_config()
        return allocated

    def test_external_package_preserves_allocated_scope_without_opening_or_creating_birth(
        self,
    ):
        allocated = self.allocate_descriptor()
        result = P.inventory(self.config, self.snapshot, package_root=self.stage)
        self.assertFalse(allocated.exists())
        self.assertEqual(
            result["staging_root"], P.normalized(self.target["layout"]["staging_root"])
        )
        self.assertEqual(result["external_provenance"], "UNKNOWN")
        entries = P.staged_source_list(result, self.stage)
        self.assertEqual(
            [entry["relative"] for entry in entries],
            ["bin/mcp-enclave", "codesign-pins.json"],
        )
        for entry in entries:
            self.assertEqual(set(entry), {"relative", "path", "sha256", "size"})
            path = self.stage / entry["relative"]
            self.assertEqual(entry["path"], P.normalized(str(path)))
            self.assertEqual(
                entry["sha256"], hashlib.sha256(path.read_bytes()).hexdigest()
            )
            self.assertEqual(entry["size"], path.stat().st_size)
        for extra, expected in [([], result), (["--staged-source-list"], entries)]:
            output, errors = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                status = P.main(
                    [
                        "--deployment-config",
                        str(self.config),
                        "--source-snapshot",
                        str(self.snapshot),
                        "--package-root",
                        str(self.stage),
                        *extra,
                    ]
                )
            self.assertEqual(status, 0, errors.getvalue())
            self.assertEqual(json.loads(output.getvalue()), expected)
        self.assertFalse(allocated.exists())

    def test_external_package_rejects_allocation_source_descriptor_and_case_alias_overlap_before_io(
        self,
    ):
        allocated = self.allocate_descriptor()
        for package in (
            allocated,
            allocated / "unused",
            allocated.parent,
            self.root,
            self.source,
            self.source / "child",
            self.config,
            Path(str(allocated).upper()),
            Path(str(allocated) + "/../other"),
            Path("relative"),
        ):
            with self.subTest(package=package), self.assertRaises(P.Refusal):
                P.inventory(self.config, self.snapshot, package_root=package)
        alias = self.root / "package-alias"
        alias.symlink_to(self.stage, target_is_directory=True)
        with self.assertRaises(OSError):
            P.inventory(self.config, self.snapshot, package_root=alias)
        self.assertFalse(allocated.exists())

    def test_external_package_requires_exact_born_l2_local_pins_and_one_shared_nonce_scope(
        self,
    ):
        self.allocate_descriptor()
        original = json.loads(json.dumps(self.target))
        for key, value in [
            ("target_id", "fixture-a"),
            ("role", "existing-upgrade"),
            ("signing_identity_mode", "team-id"),
            ("shared_read_only_inputs", ["/input.json"]),
        ]:
            self.target = json.loads(json.dumps(original))
            self.target[key] = value
            self.write_config()
            with self.subTest(key=key), self.assertRaises(P.Refusal):
                P.inventory(self.config, self.snapshot, package_root=self.stage)
        for path in (
            str(self.root / "foreign/staging"),
            original["layout"]["staging_root"].replace("/allocated/", "/different/"),
            original["layout"]["staging_root"] + "/" + "12" * 16 + "/child",
        ):
            self.target = json.loads(json.dumps(original))
            self.target["layout"]["staging_root"] = path
            self.write_config()
            with self.subTest(path=path), self.assertRaises(P.Refusal):
                P.inventory(self.config, self.snapshot, package_root=self.stage)

    def test_external_package_cannot_hide_input_or_output_inode_aliases(self):
        self.allocate_descriptor()
        for path in (
            self.config,
            self.snapshot,
            self.source / "input.rs",
            self.stage / "codesign-pins.json",
        ):
            metadata = path.stat()
            with self.subTest(path=path), self.assertRaises(P.Refusal):
                P.inventory(
                    self.config,
                    self.snapshot,
                    (metadata.st_dev, metadata.st_ino),
                    self.stage,
                )

    def test_external_package_enforces_actual_import_count_total_and_nonempty_bounds(
        self,
    ):
        self.allocate_descriptor()
        for name, limit in [("MAX_PACKAGE_FILES", 1), ("MAX_PACKAGE_BYTES", 1)]:
            with self.subTest(bound=name), mock.patch.object(
                P, name, limit
            ), self.assertRaises(P.Refusal):
                P.inventory(self.config, self.snapshot, package_root=self.stage)
        (self.stage / "bin/mcp-enclave").write_bytes(b"")
        with self.assertRaises(P.Refusal):
            P.inventory(self.config, self.snapshot, package_root=self.stage)

    def test_external_package_actual_mutation_during_same_scan_refuses_without_output(
        self,
    ):
        allocated = self.allocate_descriptor()
        candidate = self.stage / "bin/mcp-enclave"
        metadata = candidate.stat()
        identity = (metadata.st_dev, metadata.st_ino)
        original_read, changed, actual_reads = P._read_chunk, False, []
        original_size = metadata.st_size

        def mutate(fd, size):
            nonlocal changed
            chunk = original_read(fd, size)
            current = os.fstat(fd)
            if (current.st_dev, current.st_ino) == identity:
                actual_reads.append(len(chunk))
            if not changed and (current.st_dev, current.st_ino) == identity:
                changed = True
                with candidate.open("ab") as output:
                    output.write(b"actual foreign growth" * 100)
            return chunk

        output, errors = io.StringIO(), io.StringIO()
        with mock.patch.object(
            P, "_read_chunk", side_effect=mutate
        ), contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            status = P.main(
                [
                    "--deployment-config",
                    str(self.config),
                    "--source-snapshot",
                    str(self.snapshot),
                    "--package-root",
                    str(self.stage),
                    "--staged-source-list",
                ]
            )
        self.assertEqual(status, 2)
        self.assertTrue(changed)
        self.assertLessEqual(sum(actual_reads), original_size + 1)
        self.assertEqual(output.getvalue(), "")
        self.assertFalse(allocated.exists())

    def test_external_package_prehash_growth_cannot_replace_aggregate_budget_baseline(
        self,
    ):
        allocated = self.allocate_descriptor()
        candidate = self.stage / "bin/mcp-enclave"
        original_hash, original_read = P.hash_at, P._read_chunk
        changed, candidate_reads = False, []

        def grow_before_open(parent, name, *args, **kwargs):
            nonlocal changed
            if name == "mcp-enclave" and not changed:
                changed = True
                candidate.write_bytes(
                    b"larger stable replacement before actual file open" * 10
                )
            return original_hash(parent, name, *args, **kwargs)

        def counted_read(fd, size):
            current, actual = os.fstat(fd), candidate.stat()
            if (current.st_dev, current.st_ino) == (actual.st_dev, actual.st_ino):
                candidate_reads.append(size)
            return original_read(fd, size)

        budget = candidate.stat().st_size + len(self.pin_bytes)
        with mock.patch.object(P, "MAX_PACKAGE_BYTES", budget), mock.patch.object(
            P, "hash_at", side_effect=grow_before_open
        ), mock.patch.object(
            P, "_read_chunk", side_effect=counted_read
        ), self.assertRaises(
            P.Refusal
        ):
            P.inventory(self.config, self.snapshot, package_root=self.stage)
        self.assertTrue(changed)
        self.assertEqual(
            candidate_reads,
            [],
            "changed prehash baseline must refuse before reading any candidate byte",
        )
        self.assertFalse(allocated.exists())

    def test_external_package_duplicate_and_incomplete_cli_modes_refuse_without_output(
        self,
    ):
        self.allocate_descriptor()
        for extra in (
            ["--staged-source-list"],
            ["--package-root", str(self.stage), "--package-root", str(self.stage)],
        ):
            output, errors = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                status = P.main(
                    [
                        "--deployment-config",
                        str(self.config),
                        "--source-snapshot",
                        str(self.snapshot),
                        *extra,
                    ]
                )
            self.assertEqual(status, 2)
            self.assertEqual(output.getvalue(), "")

    def test_stable_identity_and_closed_stdout_inventory(self):
        first, second = self.collect(), self.collect()
        self.assertEqual(first, second)
        self.assertEqual(
            set(first),
            {
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
            },
        )
        self.assertEqual(first["kind"], "mcpmac-first-touch-artifact-inventory")
        self.assertEqual(first["external_provenance"], "UNKNOWN")
        self.assertEqual(
            first["codesign_pins_sha256"], hashlib.sha256(self.pin_bytes).hexdigest()
        )
        self.assertFalse(
            Path(self.target["codesign_pins_file"]).exists(),
            "installed pin path is not required or written",
        )
        self.assertEqual(
            first["deployment_config_sha256"],
            hashlib.sha256(self.config.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            first["source_manifest_sha256"],
            hashlib.sha256(self.snapshot.read_bytes()).hexdigest(),
        )
        self.assertEqual(first["source_input_count"], 1)
        self.assertEqual(
            [item["path"] for item in first["files"]],
            ["bin/mcp-enclave", "codesign-pins.json"],
        )
        for item in first["files"]:
            self.assertEqual(set(item), {"path", "sha256", "size"})
            self.assertEqual(
                item["sha256"],
                hashlib.sha256((self.stage / item["path"]).read_bytes()).hexdigest(),
            )
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            self.assertEqual(
                P.main(
                    [
                        "--deployment-config",
                        str(self.config),
                        "--source-snapshot",
                        str(self.snapshot),
                    ]
                ),
                0,
            )
        self.assertEqual(json.loads(output.getvalue()), first)
        self.assertEqual(errors.getvalue(), "")

    def test_runtime_custody_bytes_are_inventoried_without_becoming_trust(self):
        repository = self.stage / "tuf/repo"
        repository.mkdir(parents=True)
        for name in ("fido-mds-allowlist.json", "custody-envelope-policy-v1.json"):
            (repository / name).write_bytes(b'{"fixture":"unverified public bytes"}')
        result = self.collect()
        self.assertEqual(result["external_provenance"], "UNKNOWN")
        for name in ("fido-mds-allowlist.json", "custody-envelope-policy-v1.json"):
            entry = next(
                item for item in result["files"] if item["path"] == "tuf/repo/" + name
            )
            self.assertEqual(
                entry["sha256"],
                hashlib.sha256((repository / name).read_bytes()).hexdigest(),
            )
            self.assertEqual(set(entry), {"path", "sha256", "size"})
        (repository / "custody-envelope-policy-v2.json").write_bytes(b"{}")
        with self.assertRaises(P.Refusal):
            self.collect()

    def test_runtime_custody_transport_uses_actual_consumer_size_limits(self):
        repository = self.stage / "tuf/repo"
        repository.mkdir(parents=True)
        for name, maximum in (
            ("fido-mds-allowlist.json", 256 * 1024),
            ("custody-envelope-policy-v1.json", 16 * 1024),
        ):
            path = repository / name
            path.write_bytes(b"{}" + b" " * (maximum - 2))
            entry = next(
                item
                for item in self.collect()["files"]
                if item["path"] == "tuf/repo/" + name
            )
            self.assertEqual(entry["size"], maximum)
            path.write_bytes(b"{}" + b" " * (maximum - 1))
            with self.assertRaises(P.Refusal):
                self.collect()
            path.unlink()

    def test_scope_substitution_changes_identity_and_only_declared_stage_is_read(self):
        original = self.collect()
        other = self.root / "other-stage"
        other.mkdir()
        (other / "bin").mkdir()
        (other / "bin/mcp-enclave").write_bytes(b"different candidate")
        (other / "codesign-pins.json").write_bytes(self.pin_bytes)
        self.target["target_id"] = "fixture-b"
        self.target["layout"]["staging_root"] = str(other)
        self.write_config()
        changed = self.collect()
        self.assertNotEqual(
            original["deployment_config_sha256"], changed["deployment_config_sha256"]
        )
        self.assertNotEqual(original["files"], changed["files"])
        self.assertEqual(changed["staging_root"], P.normalized(str(other)))
        self.assertEqual(changed["target_id"], "fixture-b")

    def test_ascii_paths_and_fixed_root_alias_spelling(self):
        for path in (
            "/VAR/run/fixture",
            "/Tmp/fixture",
            "/ETC/fixture",
            "/PRIVATE/var/fixture",
            "/private/VAR/fixture",
            "/private/Tmp/fixture",
            "/private/ETC/fixture",
            "/fixture/\u00e9",
            "/fixture/e\u0301",
        ):
            with self.subTest(path=path), self.assertRaises(P.Refusal):
                P.canonical(path)
        for path in ("input-\u00e9.rs", "input-e\u0301.rs"):
            with self.subTest(source=path), self.assertRaises(P.Refusal):
                P.canonical(path, absolute=False)
        self.assertEqual(P.normalized("/var/run/fixture"), "/private/var/run/fixture")
        self.assertEqual(
            P.normalized("/Fixture/CasePreserved"), "/Fixture/CasePreserved"
        )
        self.target["layout"]["staging_root"] = "/fixture/\u00e9"
        self.write_config()
        with self.assertRaises(P.Refusal):
            self.collect()

    def test_closed_descriptor_and_duplicate_argv_refuse_without_output(self):
        raw = self.config.read_text()
        for value in (
            raw.replace("{", '{"version":1,', 1),
            json.dumps(dict(self.target, unexpected="ignored")),
        ):
            self.config.write_text(value)
            with self.assertRaises(P.Refusal):
                self.collect()
        self.config.write_text(raw)
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            status = P.main(
                [
                    "--deployment-config",
                    str(self.config),
                    "--source-snapshot",
                    str(self.snapshot),
                    "--deployment-config",
                    str(self.config),
                ]
            )
        self.assertEqual(status, 2)
        self.assertEqual(output.getvalue(), "")

    def test_serialized_inventory_cap_refuses_before_any_stdout(self):
        output, errors = io.StringIO(), io.StringIO()
        with mock.patch.object(P, "MAX_INVENTORY", 1), contextlib.redirect_stdout(
            output
        ), contextlib.redirect_stderr(errors):
            status = P.main(
                [
                    "--deployment-config",
                    str(self.config),
                    "--source-snapshot",
                    str(self.snapshot),
                ]
            )
        self.assertEqual(status, 2)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("INVENTORY_SIZE", errors.getvalue())

    def test_source_drift_escape_duplicate_and_alias_inputs_refuse(self):
        (self.source / "input.rs").write_bytes(b"changed source")
        with self.assertRaises(P.Refusal):
            self.collect()
        (self.source / "input.rs").write_bytes(b"immutable source input")
        for name in (
            "../input.rs",
            "./input.rs",
            "sub//input.rs",
            "/input.rs",
            "input.rs/",
        ):
            self.source_map = {name: "a" * 64}
            self.write_snapshot()
            with self.subTest(name=name), self.assertRaises(P.Refusal):
                self.collect()
        self.snapshot.write_text(
            '{"schema":1,"head":"'
            + "a" * 40
            + '","source_sha256":{"input.rs":"'
            + "a" * 64
            + '","input.rs":"'
            + "b" * 64
            + '"}}'
        )
        with self.assertRaises(P.Refusal):
            self.collect()

    def test_symlink_hardlink_and_ancestor_symlink_refuse(self):
        candidate = self.stage / "bin/mcp-enclave"
        saved = self.root / "saved-candidate"
        candidate.rename(saved)
        candidate.symlink_to(saved)
        with self.assertRaises((P.Refusal, OSError)):
            self.collect()
        candidate.unlink()
        os.link(saved, candidate)
        with self.assertRaises(P.Refusal):
            self.collect()
        candidate.unlink()
        saved.rename(candidate)
        alias = self.root / "alias-stage"
        alias.symlink_to(self.stage, target_is_directory=True)
        self.target["layout"]["staging_root"] = str(alias)
        self.write_config()
        with self.assertRaises(OSError):
            self.collect()

    def test_mutation_during_hash_and_source_file_replacement_refuse(self):
        candidate = self.stage / "bin/mcp-enclave"
        identity = (candidate.stat().st_dev, candidate.stat().st_ino)
        original_read, changed = P._read_chunk, False

        def mutate(fd, size):
            nonlocal changed
            result = original_read(fd, size)
            metadata = os.fstat(fd)
            if not changed and (metadata.st_dev, metadata.st_ino) == identity:
                changed = True
                with candidate.open("ab") as output:
                    output.write(b"mutation")
            return result

        with mock.patch.object(P, "_read_chunk", side_effect=mutate), self.assertRaises(
            P.Refusal
        ):
            self.collect()
        self.assertTrue(changed)
        source = self.source / "input.rs"
        saved = self.root / "saved-source"
        source.rename(saved)
        source.symlink_to(saved)
        with self.assertRaises(OSError):
            self.collect()

    def test_secret_unknown_file_pin_mode_and_stdout_in_stage_refuse(self):
        secret = self.stage / "keys.json"
        secret.write_text('{"private_key":"DO_NOT_EMIT_SECRET"}')
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            self.assertEqual(
                P.main(
                    [
                        "--deployment-config",
                        str(self.config),
                        "--source-snapshot",
                        str(self.snapshot),
                    ]
                ),
                2,
            )
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn("DO_NOT_EMIT_SECRET", errors.getvalue())
        secret.unlink()
        (self.stage / "codesign-pins.json").write_text(
            json.dumps(
                {
                    "v": 1,
                    "mode": "team-id",
                    "pins": {"com.enterprise.enclave.ctl": ["ab" * 20]},
                }
            )
        )
        with self.assertRaises(P.Refusal):
            self.collect()
        (self.stage / "codesign-pins.json").write_bytes(self.pin_bytes)
        with (self.stage / "SHA256SUMS").open("wb") as output:
            identity = os.fstat(output.fileno())
            with self.assertRaises(P.Refusal):
                P.inventory(
                    self.config, self.snapshot, (identity.st_dev, identity.st_ino)
                )

    def test_declared_stage_aliases_size_count_and_special_files_refuse(self):
        for path in (
            str(self.stage) + "/",
            str(self.stage) + "/../stage",
            str(self.stage) + "//child",
        ):
            self.target["layout"]["staging_root"] = path
            self.write_config()
            with self.subTest(path=path), self.assertRaises(P.Refusal):
                self.collect()
        self.target["layout"]["staging_root"] = str(self.stage)
        self.write_config()
        with mock.patch.object(P, "MAX_FILES", 1), self.assertRaises(P.Refusal):
            self.collect()
        candidate = self.stage / "bin/mcp-enclave"
        with candidate.open("r+b") as output:
            output.truncate(P.MAX_FILE + 1)
        with self.assertRaises(P.Refusal):
            self.collect()
        candidate.unlink()
        os.mkfifo(candidate)
        with self.assertRaises(P.Refusal):
            self.collect()


if __name__ == "__main__":
    unittest.main()
