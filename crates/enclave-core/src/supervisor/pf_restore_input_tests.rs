use super::*;

fn refusal(root: &[u8], llm: &[u8], cas: &[u8]) -> ContentRefusal {
    CanonicalFilterImage::require(root, llm, cas)
        .err()
        .expect("noncanonical input must refuse")
}

#[test]
fn exact_image_borrows_all_three_supplied_buffers_without_replacing_content() {
    let root = render_root_filter().to_vec();
    let llm = LLM_POLICY.to_vec();
    let cas = CAS_POLICY.to_vec();
    let image = CanonicalFilterImage::require(&root, &llm, &cas).unwrap();
    assert!(std::ptr::eq(image.root_bytes().as_ptr(), root.as_ptr()));
    assert!(std::ptr::eq(image.llm_bytes().as_ptr(), llm.as_ptr()));
    assert!(std::ptr::eq(image.cas_bytes().as_ptr(), cas.as_ptr()));
    assert!(std::str::from_utf8(image.root_bytes())
        .unwrap()
        .contains(LLM_FILE));
    assert!(std::str::from_utf8(image.root_bytes())
        .unwrap()
        .contains(CAS_FILE));
}

#[test]
fn root_cannot_adopt_unrelated_policy_options_dynamic_includes_or_third_anchors() {
    for suffix in [
        "include \"/etc/pf.conf\"\n",
        "set skip on lo0\n",
        "pass quick all\n",
        "anchor \"com.apple/*\"\n",
        "load anchor \"third\" from \"/tmp/other\"\n",
        "table <extern> persist\n",
        "rdr pass on lo0 proto tcp to any port 80 -> 127.0.0.1 port 81\n",
    ] {
        let mut changed = render_root_filter().to_vec();
        changed.extend_from_slice(suffix.as_bytes());
        assert_eq!(
            refusal(&changed, LLM_POLICY, CAS_POLICY),
            ContentRefusal::RootFilter
        );
    }
}

#[test]
fn root_cannot_widen_paths_rename_reorder_duplicate_or_omit_a_sibling() {
    let canonical = std::str::from_utf8(render_root_filter()).unwrap();
    let llm = "anchor \"com.enterprise.llm.isolation\"\n";
    let cas = "anchor \"com.enterprise.cas.swarm\"\n";
    for changed in [
        canonical.replace("/private/etc/pf.anchors/", "/tmp/"),
        canonical.replace("com.enterprise.cas.swarm", "../com.enterprise.cas.swarm"),
        canonical.replace("com.enterprise.cas.swarm", "different"),
        canonical.replace(llm, ""),
        canonical.replace(cas, ""),
        canonical.replace(llm, &format!("{llm}{llm}")),
        canonical
            .replace(llm, "REORDER\n")
            .replace(cas, llm)
            .replace("REORDER\n", cas),
    ] {
        assert_eq!(
            refusal(changed.as_bytes(), LLM_POLICY, CAS_POLICY),
            ContentRefusal::RootFilter
        );
    }
}

#[test]
fn each_child_requires_its_own_complete_canonical_policy_not_nonempty_or_hash_claims() {
    assert_eq!(
        refusal(render_root_filter(), CAS_POLICY, LLM_POLICY),
        ContentRefusal::LlmPolicy
    );
    for llm in [
        b"".as_slice(),
        &LLM_POLICY[..LLM_POLICY.len() - 1],
        b"pass quick all\n",
    ] {
        assert_eq!(
            refusal(render_root_filter(), llm, CAS_POLICY),
            ContentRefusal::LlmPolicy
        );
    }
    for cas in [
        b"".as_slice(),
        &CAS_POLICY[..CAS_POLICY.len() - 1],
        b"pass quick all\n",
    ] {
        assert_eq!(
            refusal(render_root_filter(), LLM_POLICY, cas),
            ContentRefusal::CasPolicy
        );
    }
    let mut llm = LLM_POLICY.to_vec();
    llm.extend_from_slice(b"pass quick all\n");
    assert_eq!(
        refusal(render_root_filter(), &llm, CAS_POLICY),
        ContentRefusal::LlmPolicy
    );
    let mut cas = CAS_POLICY.to_vec();
    cas.extend_from_slice(b"pass quick all\n");
    assert_eq!(
        refusal(render_root_filter(), LLM_POLICY, &cas),
        ContentRefusal::CasPolicy
    );
}

#[test]
fn superficially_equivalent_or_partial_root_bytes_do_not_create_an_accepted_image() {
    let canonical = std::str::from_utf8(render_root_filter()).unwrap();
    for root in [
        b"".to_vec(),
        render_root_filter()[..ROOT_FILTER.len() - 1].to_vec(),
        canonical.replace('\n', "\r\n").into_bytes(),
        canonical.replace("anchor ", "anchor  ").into_bytes(),
        [render_root_filter(), &[0]].concat(),
    ] {
        assert_eq!(
            refusal(&root, LLM_POLICY, CAS_POLICY),
            ContentRefusal::RootFilter
        );
    }
}
