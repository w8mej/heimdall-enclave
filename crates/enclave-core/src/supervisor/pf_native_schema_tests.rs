//! Compiler/advisory goldens are captured native no-load output. Info/root and
//! compile-derived live forms are SOFTWARE examples, not kernel acceptance.
use super::*;

const INFO: &[u8] = b"Status: Enabled for 0 days 00:01:02           Debug: Urgent\n\nState Table Total Rate\n current entries 0\n searches 12 0.0/s\n inserts 1 0.0/s\n removals 1 0.0/s\nCounters\n match 4 0.0/s\n bad-offset 0 0.0/s\n";
const ROOT: &[u8] =
    b"anchor \"com.enterprise.llm.isolation\" all\nanchor \"com.enterprise.cas.swarm\" all\n";
const LLM: &[u8] = OBSERVED_LLM_RULES.as_bytes();
const CAS: &[u8] = OBSERVED_CAS_RULES.as_bytes();
fn stderr(query: Query) -> &'static [u8] {
    if matches!(query, Query::CompileLlm | Query::CompileCas) {
        COMPILE_ADVISORY
    } else {
        b""
    }
}
fn complete() -> Components {
    let mut components = Components::new(fixture_schema());
    for (query, bytes) in [
        (Query::Info, INFO),
        (Query::RootRules, ROOT),
        (Query::LlmRules, LLM),
        (Query::CasRules, CAS),
        (Query::CompileLlm, OBSERVED_LLM_COMPILE.as_bytes()),
        (Query::CompileCas, OBSERVED_CAS_COMPILE.as_bytes()),
        (Query::RootTranslations, b"".as_slice()),
    ] {
        components.observe(query, bytes, stderr(query)).unwrap();
    }
    components
}

#[test]
fn native_profile_requires_exact_observed_tool_hash_size_and_actual_platform() {
    let hash: [u8; 32] = hex::decode(TOOL_SHA256).unwrap().try_into().unwrap();
    let actual = SupportedSchema::from_original(&hash, TOOL_SIZE);
    assert_eq!(
        actual.is_ok(),
        cfg!(all(target_os = "macos", target_arch = "aarch64"))
    );
    assert!(matches!(
        SupportedSchema::from_original(&[0; 32], TOOL_SIZE),
        Err(Error::UnsupportedTool)
    ));
    assert!(matches!(
        SupportedSchema::from_original(&hash, TOOL_SIZE + 1),
        Err(Error::UnsupportedTool)
    ));
}

#[test]
fn captured_no_load_compiler_goldens_preserve_exact_native_receipt_identity() {
    for (bytes, length, expected_sha256) in [
        (
            OBSERVED_LLM_COMPILE.as_bytes(),
            567,
            "87b31cef54d85624dd20efd2fd8ab78df87099392972b70ce8bde372b9bf1cea",
        ),
        (
            OBSERVED_CAS_COMPILE.as_bytes(),
            589,
            "ce36d2eefe4b4678651db144ab73e0d8946c15eccfe75166a7ce75fecfa586ee",
        ),
        (
            COMPILE_ADVISORY,
            158,
            "2373d766849ba0ddfe875af802abe97a74c0306e6d91d0ca42aac5e136782b54",
        ),
    ] {
        assert_eq!(bytes.len(), length);
        assert_eq!(hex::encode(Sha256::digest(bytes)), expected_sha256);
    }
}

#[test]
fn complete_distinct_component_examples_can_be_positive_without_an_enforcement_permit() {
    let components = complete();
    assert_eq!(components.enabled(), Some(true));
    assert_eq!(components.state_count(), Some(StateCount::ZeroAtSnapshot));
    assert!(components.root_linkage_order() && components.llm_equal() && components.cas_equal());
    // Components has no enforcement/readiness constructor or permit accessor.
}

#[test]
fn disabled_is_distinct_from_unknown_and_partial_or_ambiguous_status_refuses() {
    let disabled = String::from_utf8(INFO.to_vec())
        .unwrap()
        .replace("Enabled", "Disabled");
    assert_eq!(
        info(disabled.as_bytes(), b""),
        Ok(Info {
            enabled: false,
            states: StateCount::ZeroAtSnapshot
        })
    );
    for bytes in [
        b"Status: Enabled".as_slice(),
        b"Status: Enabled\nStatus: Disabled\n",
        b"Enabled",
        b"Status: Unknown for 0 days 00:00:00 Debug: Urgent\n",
        b"",
    ] {
        assert!(info(bytes, b"").is_err());
    }
    for (old, new) in [
        ("00:01:02", "24:01:02"),
        ("00:01:02", "00:61:02"),
        ("0 days", "-1 days"),
        ("match 4", "unknown 4"),
        ("4 0.0/s", "4 NaN/s"),
    ] {
        let changed = String::from_utf8(INFO.to_vec()).unwrap().replace(old, new);
        assert!(info(changed.as_bytes(), b"").is_err());
    }
}

#[test]
fn status_rejects_missing_duplicate_unknown_and_trailing_rows() {
    for suffix in [
        "\nunknown native counter 0 0.0/s\n",
        "\nmatch 4 0.0/s\n",
        "\nStatus: Disabled\n",
    ] {
        let mut changed = INFO.to_vec();
        changed.extend_from_slice(suffix.as_bytes());
        assert!(info(&changed, b"").is_err());
    }
    let missing = String::from_utf8(INFO.to_vec())
        .unwrap()
        .replace("Counters\n match 4 0.0/s\n bad-offset 0 0.0/s\n", "");
    assert!(info(missing.as_bytes(), b"").is_err());
}

#[test]
fn info_state_count_preserves_zero_nonzero_and_maximum_as_snapshot_only() {
    for count in [0, 1, 42, u64::MAX] {
        let bytes = String::from_utf8(INFO.to_vec())
            .unwrap()
            .replace("current entries 0", &format!("current entries {count}"));
        let mut components = Components::new(fixture_schema());
        components
            .observe(Query::Info, bytes.as_bytes(), b"")
            .unwrap();
        assert_eq!(components.enabled(), Some(true));
        assert_eq!(
            components.state_count(),
            Some(if count == 0 {
                StateCount::ZeroAtSnapshot
            } else {
                StateCount::NonzeroAtSnapshot(count)
            })
        );
        assert!(
            !components.root_linkage_order() && !components.llm_equal() && !components.cas_equal()
        );
    }
}

#[test]
fn info_state_count_refuses_missing_duplicate_malformed_and_overflow_before_publication() {
    for replacement in [
        "",
        "current entries",
        "current entries -1",
        "current entries +1",
        "current entries 1.0",
        "current entries 1 extra",
        "current entries 18446744073709551616",
        "current entries 0\ncurrent entries 0",
        "current entries 0\ncurrent entries 1",
    ] {
        let bytes = String::from_utf8(INFO.to_vec())
            .unwrap()
            .replace("current entries 0", replacement);
        let mut components = Components::new(fixture_schema());
        assert!(
            components
                .observe(Query::Info, bytes.as_bytes(), b"")
                .is_err(),
            "{replacement:?}"
        );
        assert_eq!(components.state_count(), None);
        assert_eq!(
            components.enabled(),
            None,
            "partial status cannot publish even its earlier enabled flag"
        );
    }
}

#[test]
fn root_linkage_is_ordered_unconditional_exact_and_never_discards_other_rules() {
    root(ROOT, b"").unwrap();
    for changed in [
        "anchor \"com.enterprise.cas.swarm\" all\nanchor \"com.enterprise.llm.isolation\" all\n",
        "anchor \"com.enterprise.llm.isolation\" on en0\nanchor \"com.enterprise.cas.swarm\" all\n",
        "anchor \"com.enterprise.llm.isolation\" all\n",
        "anchor \"com.enterprise.llm.isolation/*\" all\nanchor \"com.enterprise.cas.swarm\" all\n",
        "pass quick all\nanchor \"com.enterprise.llm.isolation\" all\nanchor \"com.enterprise.cas.swarm\" all\n",
        "anchor \"com.enterprise.llm.isolation\" all\nanchor \"com.enterprise.cas.swarm\" all\npass all\n",
        "anchor \"com.apple/*\" all\nanchor \"com.enterprise.llm.isolation\" all\nanchor \"com.enterprise.cas.swarm\" all\n",
        "set skip on lo0\nanchor \"com.enterprise.llm.isolation\" all\nanchor \"com.enterprise.cas.swarm\" all\n",
    ] { assert_eq!(root(changed.as_bytes(), b""), Err(Error::RootPolicy)); }
}

#[test]
fn both_anchors_must_independently_match_every_ordered_compiler_token() {
    for llm in [false, true] {
        let mut components = complete();
        let original = if llm {
            OBSERVED_LLM_COMPILE.as_bytes()
        } else {
            OBSERVED_CAS_COMPILE.as_bytes()
        };
        let query = if llm {
            Query::CompileLlm
        } else {
            Query::CompileCas
        };
        for changed in [
            String::from_utf8(original.to_vec())
                .unwrap()
                .replace("quick", ""),
            String::from_utf8(original.to_vec())
                .unwrap()
                .replace("tcp", "udp"),
            String::from_utf8(original.to_vec())
                .unwrap()
                .lines()
                .rev()
                .collect::<Vec<_>>()
                .join("\n"),
        ] {
            assert_eq!(
                components.observe(query, changed.as_bytes(), stderr(query)),
                Err(Error::CanonicalMismatch)
            );
        }
    }
}

#[test]
fn numeric_group_and_user_identity_cannot_be_replaced_with_names_or_other_ids() {
    for changed in ["_llmagent", "0", "8702", "87010"] {
        let bytes = String::from_utf8(LLM.to_vec())
            .unwrap()
            .replace("8701", changed);
        assert!(rules(bytes.as_bytes(), b"", false, true).is_err());
    }
    for changed in ["_enclavecas", "0", "8701"] {
        let bytes = String::from_utf8(CAS.to_vec())
            .unwrap()
            .replace("8702", changed);
        assert!(rules(bytes.as_bytes(), b"", false, false).is_err());
    }
    let bytes = String::from_utf8(CAS.to_vec())
        .unwrap()
        .replace("501", "502");
    assert!(rules(bytes.as_bytes(), b"", false, false).is_err());
}

#[test]
fn empty_unknown_and_cross_channel_rule_outputs_do_not_establish_comparison() {
    for bytes in [
        b"".as_slice(),
        b"no rules loaded\n",
        b"table <allow> persist\n",
        b"# ignored?\n",
        b"anchor \"other\" all\n",
    ] {
        assert!(rules(bytes, b"", false, true).is_err());
    }
    assert!(rules(b"", LLM, true, true).is_err());
    assert!(rules(LLM, b"unexplained warning\n", true, true).is_err());
    assert!(info(b"", INFO).is_err());
    assert!(root(b"", ROOT).is_err());
}

#[test]
fn only_exact_closed_macro_echoes_are_accepted_for_compiled_streams() {
    let mut compiled = b"loopback_if = \"lo0\"\nllm_group = \"_llmagent\"\n".to_vec();
    compiled.extend_from_slice(LLM);
    assert_eq!(
        rules(&compiled, COMPILE_ADVISORY, true, true)
            .unwrap()
            .lines,
        rules(LLM, b"", false, true).unwrap().lines
    );
    assert!(rules(&compiled, b"", false, true).is_err());
    for prefix in [
        "unknown = \"lo0\"\n",
        "llm_group = \"staff\"\n",
        "llm_group = \"_llmagent\"\nllm_group = \"_llmagent\"\n",
    ] {
        let mut bytes = prefix.as_bytes().to_vec();
        bytes.extend_from_slice(LLM);
        assert!(rules(&bytes, COMPILE_ADVISORY, true, true).is_err());
    }
}

#[test]
fn stream_encoding_size_and_diagnostic_framing_are_strict_and_redacted() {
    for bytes in [
        b"\xff".as_slice(),
        b"pass\0out",
        b"pass\rout",
        b"pass\x1bout",
    ] {
        assert!(lines(bytes).is_err());
    }
    assert_eq!(lines(&vec![b'x'; MAX_STREAM + 1]), Err(Error::Size));
    assert_eq!(lines(&vec![b'x'; MAX_LINE + 1]), Err(Error::Size));
    clean_stderr(COMPILE_ADVISORY, true).unwrap();
    assert!(clean_stderr(COMPILE_ADVISORY, false).is_err());
    assert!(clean_stderr(b"", true).is_err());
    let mut changed = COMPILE_ADVISORY.to_vec();
    changed.extend_from_slice(b"malicious trailing text\n");
    assert!(clean_stderr(&changed, true).is_err());
    let parsed = rules(LLM, b"", false, true).unwrap();
    assert!(!format!("{parsed:?}").contains("pass out"));
}

#[test]
fn root_translation_output_accepts_only_exact_empty_streams_without_normalizing_unknown_content() {
    assert_eq!(
        root_translations(b"", b""),
        Ok(RootTranslationOutput::EmptyAtSnapshot)
    );
    for stdout in [
        b" ".as_slice(),
        b"\n",
        b"\t",
        b"\r\n",
        b"\x00",
        b"\xff",
        b"TRANSLATION RULES:",
        b"nat all",
        b"rdr all",
        b"binat all",
        b"nat64 all",
        b"nat-anchor system/*",
        b"rdr-anchor system/*",
        b"binat-anchor system/*",
    ] {
        assert_eq!(
            root_translations(stdout, b""),
            Err(Error::RootTranslationOutput)
        );
    }
    for stderr in [
        b" ".as_slice(),
        b"\n",
        b"diagnostic",
        COMPILE_ADVISORY,
        b"No ALTQ support in kernel\nALTQ related functions disabled\n",
        b"\x00\xff",
    ] {
        assert_eq!(root_translations(b"", stderr), Err(Error::Channel));
    }
}
#[test]
fn root_translation_output_enforces_stream_caps_and_refusal_clears_an_earlier_empty_snapshot() {
    let oversize = vec![b'x'; MAX_STREAM + 1];
    assert_eq!(root_translations(&oversize, b""), Err(Error::Size));
    assert_eq!(root_translations(b"", &oversize), Err(Error::Size));
    for (stdout, stderr) in [
        (b"nat-anchor system/*".as_slice(), b"".as_slice()),
        (b"", b"unexpected diagnostic"),
    ] {
        let mut components = complete();
        assert_eq!(
            components.root_translation_output(),
            Some(RootTranslationOutput::EmptyAtSnapshot)
        );
        assert!(components
            .observe(Query::RootTranslations, stdout, stderr)
            .is_err());
        assert_eq!(components.root_translation_output(), None);
    }
}
#[test]
fn root_translation_snapshot_clears_with_sample_while_same_admitted_schema_is_retained() {
    let mut components = complete();
    let schema = &components._schema as *const SupportedSchema;
    assert_eq!(
        components.root_translation_output(),
        Some(RootTranslationOutput::EmptyAtSnapshot)
    );
    components.clear_observations();
    assert_eq!(components.root_translation_output(), None);
    assert_eq!(&components._schema as *const SupportedSchema, schema);
    components
        .observe(Query::RootTranslations, b"", b"")
        .unwrap();
    assert_eq!(
        components.root_translation_output(),
        Some(RootTranslationOutput::EmptyAtSnapshot)
    );
    assert_eq!(components.enabled(), None);
    assert_eq!(components.state_count(), None);
    assert!(!components.root_linkage_order() && !components.llm_equal() && !components.cas_equal());
}
#[test]
fn empty_root_translation_output_does_not_erase_independent_nonzero_existing_state_snapshot() {
    let mut components = complete();
    let nonzero = String::from_utf8(INFO.to_vec())
        .unwrap()
        .replace("current entries 0", "current entries 41");
    components
        .observe(Query::Info, nonzero.as_bytes(), b"")
        .unwrap();
    assert_eq!(
        components.root_translation_output(),
        Some(RootTranslationOutput::EmptyAtSnapshot)
    );
    assert_eq!(
        components.state_count(),
        Some(StateCount::NonzeroAtSnapshot(41))
    );
    // Neither component exposes translation policy, state safety or a permit.
}
