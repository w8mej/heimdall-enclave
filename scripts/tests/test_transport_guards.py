"""Source mutation controls plus actual Lean reproof of regenerated bad guards."""

import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

if __package__:
    from .lean_fixture import copy_guard_inputs
else:
    from lean_fixture import copy_guard_inputs

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "proofs/lean4"
SPEC = importlib.util.spec_from_file_location(
    "transport_guards", ROOT / "scripts/check-transport-guards.py"
)
GUARDS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARDS)


class GuardFixture:
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(
            prefix="depot-guard-source-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        copy_guard_inputs(ROOT, self.root)
        target = self.root / GUARDS.OUTPUT
        target.parent.mkdir(parents=True)
        shutil.copy2(ROOT / GUARDS.OUTPUT, target)
        self.assertEqual(
            GUARDS.check(self.root)["status"],
            "PASS",
            "mutation fixture must first pass the actual source checker",
        )

    def change(self, index, old, new):
        import re

        path = self.root / GUARDS.SOURCES[index]
        source = path.read_text()
        if source.count(old) == 1:
            path.write_text(source.replace(old, new, 1))
            return
        # rustfmt-resilient fallback: match the exact token sequence with optional whitespace
        pat = r"\s*".join(re.escape(tok) for tok in GUARDS.tokens(old))
        matches = list(re.finditer(pat, source))
        self.assertEqual(len(matches), 1, old)
        m = matches[0]
        path.write_text(source[: m.start()] + new + source[m.end():])

    def reject(self):
        with self.assertRaises((ValueError, FileNotFoundError)):
            GUARDS.check(self.root)

    def reject_translation(self, reason):
        with self.assertRaisesRegex(ValueError, reason):
            GUARDS.derive(self.root)


class SourceTests(GuardFixture, unittest.TestCase):
    def test_current_source_and_generated_projection_agree(self):
        self.assertEqual(GUARDS.check(self.root)["status"], "PASS")

    def test_changed_chunk_constant(self):
        self.change(0, "CHUNK_OVERHEAD:usize=16;", "CHUNK_OVERHEAD:usize=17;")
        self.reject()

    def test_removed_empty_chunk_check(self):
        self.change(0, "if plain.is_empty() || plain.len()", "if plain.len()")
        self.reject()

    def test_altered_finality(self):
        self.change(0, "(!final_chunk && plain.len()",
                    "(final_chunk && plain.len()")
        self.reject()

    def test_guard_must_be_first_statement(self):
        self.change(
            0, "    if plain.is_empty()", "    unsafe_operation(); if plain.is_empty()"
        )
        self.reject_translation("first executable")

    def test_duplicate_function_is_not_ambiguously_selected(self):
        path = self.root / GUARDS.SOURCES[0]
        path.write_text(path.read_text() + "\nfn encrypt_chunk() {}\n")
        self.reject_translation("unique function")

    def test_changed_signature(self):
        self.change(
            1,
            "fn complete_query_bytes(got: libc::c_int",
            "fn complete_query_bytes(got: usize",
        )
        self.reject_translation("signature")

    def test_changed_errno_or_reason(self):
        self.change(
            0,
            'fail!(EINVAL,"NAMESPACE_CHUNK_LENGTH")',
            'fail!(EACCES,"NAMESPACE_CHUNK_LENGTH")',
        )
        self.reject_translation("guard failure")

    def test_modulo_guard_reordering_is_rejected(self):
        self.change(
            1,
            "item == 0 || got as usize % item != 0",
            "got as usize % item != 0 || item == 0",
        )
        self.reject_translation("short-circuit dominance")

    def test_removed_modulo_zero_check_is_rejected(self):
        self.change(1, "|| item == 0 ||", "||")
        self.reject_translation("short-circuit dominance")

    def test_query_returned_value_is_checked(self):
        self.change(1, "Ok(got as usize)", "Ok(capacity)")
        self.reject_translation("helper return/tail")

    def test_extra_query_statement_is_rejected(self):
        self.change(1, "    Ok(got as usize)",
                    "    side_effect(); Ok(got as usize)")
        self.reject_translation("helper return/tail")

    def test_query_status_mutation_changes_projection(self):
        self.change(
            1, "if result != 0 || got != expected", "if result == 0 || got != expected"
        )
        self.reject()

    def test_namespace_byte_predicate_cannot_be_silently_changed(self):
        self.change(0, 'b"._-".contains(&b)', 'b"._-/".contains(&b)')
        self.reject()

    def test_uppercase_hex_is_not_accepted_as_lowercase(self):
        self.change(0, "(b'a'..=b'f').contains(&b)",
                    "(b'A'..=b'F').contains(&b)")
        self.reject()

    def test_independent_wrapping_epoch_check_cannot_be_removed(self):
        self.change(0, "|| self.wrapping_epoch==0", "")
        self.reject()

    def test_monitor_profile_change_changes_projection(self):
        self.change(
            2,
            "Err(_) if profile == crate::profile::Profile::L1",
            "Err(_) if profile == crate::profile::Profile::L2",
        )
        self.reject()

    def test_monitor_cannot_skip_callback(self):
        self.change(
            2,
            "    match start() {",
            "    if profile == crate::profile::Profile::L1 { return Ok(None); } match start() {",
        )
        self.reject()

    def test_disk_addition_cannot_be_saturating(self):
        self.change(
            3,
            "DISK_RESERVE.checked_add(outstanding)",
            "DISK_RESERVE.saturating_add(outstanding)",
        )
        self.reject()

    def test_append_cannot_change_comparison(self):
        self.change(
            4,
            "if bytes.len() as u64 > self.expected",
            "if bytes.len() as u64 >= self.expected",
        )
        self.reject()

    def test_append_cannot_skip_copy(self):
        self.change(4, "        self.bytes.extend_from_slice(bytes);", "")
        self.reject()

    def test_nested_block_comment_cannot_expose_a_fake_guard(self):
        # Rust treats all of this as one nested comment; a non-nested regex can
        # mistakenly expose fake code after the first */. Unsupported: refuse.
        guard = 'if plain.is_empty() || plain.len()>PLAINTEXT_SIZE || (!final_chunk && plain.len()!=PLAINTEXT_SIZE) {fail!(EINVAL,"NAMESPACE_CHUNK_LENGTH");}'
        self.change(
            0,
            guard,
            "/* outer /* inner */ "
            + guard
            + ' */ if false {fail!(EINVAL,"NAMESPACE_CHUNK_LENGTH");}',
        )
        self.reject_translation("nested block comments")

    def test_unknown_expression_cannot_be_ignored(self):
        self.change(
            0, "if plain.is_empty() ||", "if new_permission() || plain.is_empty() ||"
        )
        self.reject_translation("unknown expression")

    def test_tautological_nat_subtraction_cannot_hide_rust_underflow(self):
        self.change(
            0,
            "if plain.is_empty() ||",
            "if ((plain.len() - PLAINTEXT_SIZE) > plain.len()) || plain.is_empty() ||",
        )
        self.reject_translation("dynamic machine arithmetic")

    def test_unguarded_remainder_cannot_hide_rust_panic(self):
        self.change(
            0,
            "if plain.is_empty() ||",
            "if (plain.len() % 0 != plain.len()) || plain.is_empty() ||",
        )
        self.reject_translation("unguarded partial remainder")

    def test_constant_underflow_cannot_be_hidden_by_nat_truncation(self):
        self.change(0, "CHUNK_OVERHEAD:usize=16;",
                    "CHUNK_OVERHEAD:usize=(0-1)+16;")
        self.reject_translation("constant machine arithmetic")

    def test_raw_string_cannot_expose_fake_source_tokens(self):
        path = self.root / GUARDS.SOURCES[0]
        path.write_text(
            'const FAKE: &str = r#"quoted " fn spoof() {}"#;\n' + path.read_text()
        )
        self.reject_translation("raw strings unsupported")

    def test_forged_generated_model_is_rejected(self):
        path = self.root / GUARDS.OUTPUT
        path.write_text(path.read_text().replace("decide (plain = 0)", "true"))
        self.reject()

    def test_actual_gate_rejects_changed_source_and_invalidates_stale_pass(self):
        shutil.copytree(
            PACKAGE,
            self.root / "proofs/lean4",
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns(".lake", "__pycache__"),
        )
        shutil.copy2(
            ROOT / "scripts/check-lean.py", self.root / "scripts/check-lean.py"
        )
        report = self.root / "reports/lean-build.json"
        report.parent.mkdir()
        report.write_text('{"result":"PASS","stale":true}\n')
        self.change(0, "CHUNK_OVERHEAD:usize=16;", "CHUNK_OVERHEAD:usize=17;")
        result = subprocess.run(
            [os.sys.executable, "-B",
                str(self.root / "scripts/check-lean.py")],
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "source-derived transport guard check failed", result.stderr)
        self.assertFalse(report.exists())


class KernelMutationTests(GuardFixture, unittest.TestCase):
    # Do not inherit all source tests: one focused method exercises a fresh actual
    # kernel check of each regenerated mutation against independent unchanged specs.
    def test_regenerated_bad_source_still_fails_independent_lean_proofs(self):
        source = (PACKAGE / "Enclave/TransportGuardRefinement.lean").read_text()
        source = source.replace("import Enclave.TransportGuardSource\n", "")
        controls = (
            PACKAGE / "Test/TransportGuardRefinementTest.lean").read_text()
        controls = controls.replace(
            "import Enclave.TransportGuardRefinement\n", "")
        mutations = [
            (
                0,
                "CHUNK_OVERHEAD:usize=16;",
                "CHUNK_OVERHEAD:usize=17;",
                "changed-tag-geometry",
            ),
            (
                0,
                "plain.is_empty() || plain.len()>PLAINTEXT_SIZE || (!final_chunk && plain.len()!=PLAINTEXT_SIZE)",
                "plain.len() >= 0",
                "always-refuse",
            ),
            (
                1,
                "if result != 0 || got != expected",
                "if result == 0 || got != expected",
                "query-status-inverted",
            ),
            (
                2,
                "Err(_) if profile == crate::profile::Profile::L1",
                "Err(_) if profile == crate::profile::Profile::L2",
                "optional-profile-changed",
            ),
            (
                0,
                "self.envelope_hex.len()!=144",
                "self.envelope_hex.len()!=142",
                "envelope-length-changed",
            ),
        ]
        fixture = self.root / "Mutation.lean"
        original = {p: (self.root / p).read_text() for p in GUARDS.SOURCES}

        def compile_projection():
            fixture.write_text(
                GUARDS.derive(self.root) + "\n" + source + "\n" + controls
            )
            return subprocess.run(
                [shutil.which("lake"), "env", "lean", str(fixture)],
                cwd=PACKAGE,
                capture_output=True,
                text=True,
                timeout=90,
            )

        for index, old, new, name in mutations:
            for path, content in original.items():
                (self.root / path).write_text(content)
            baseline = compile_projection()
            self.assertEqual(baseline.returncode, 0,
                             baseline.stdout + baseline.stderr)
            self.change(index, old, new)
            mutation = compile_projection()
            print(
                json.dumps(
                    {
                        "mutation": name,
                        "baseline_exit": baseline.returncode,
                        "mutated_exit": mutation.returncode,
                    }
                ),
                flush=True,
            )
            print(mutation.stdout + mutation.stderr, flush=True)
            self.assertNotEqual(mutation.returncode, 0, name)
            self.assertIn("error:", mutation.stdout + mutation.stderr)


if __name__ == "__main__":
    unittest.main()
